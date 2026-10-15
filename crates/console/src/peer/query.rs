//! Peer queries (Zig's `peer_query.zig` and `peer_query_client.zig`): another node's
//! retained seconds (timeline) or current-minute rankings, asked over that node's
//! authenticated management stream on behalf of an HTTP caller.
//!
//! ```text
//! HTTP handler                 Peers (per peer, <= 8)         outbound worker (Session)
//!   submit(node, kind, cursor) -> queue of Queued ----take---->  {"op":"peer_query",...}
//!   Ticket::wait (<= 5 s)                                         <- {"op":"peer_result",...}
//!   <- Outcome ------------------------------------------ finish (validated page or status)
//! ```
//!
//! Every queued value is owned, so an HTTP caller that gives up only drops its [`Ticket`];
//! the worker skips a query nobody waits for and never reuses its slot while it is on the
//! wire. Queries carry the connection generation and boot they were asked under: a
//! reconnect fails them instead of replaying a cursor against another boot. One query is on
//! the wire per connection; an unanswered one ends the connection after five seconds.

use std::fmt;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console_protocol::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, WireEnum, decode_byte_array,
    field, to_json,
};
use sibuna_console_protocol::{rankings, timeline};
use sibuna_json::{Value, Writer};

use super::Peers;
use super::store::Handle;

/// The largest page a peer may return, in JSON bytes.
pub const MAX_BODY: usize = 12_000;
/// Queries a peer may have queued or on the wire at once.
pub const MAX_OUTSTANDING: usize = 8;
/// Rows a peer page carries at most.
pub const MAX_ROWS: u8 = 8;
/// How long a query may stay unanswered, on the wire and for its HTTP caller.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// How often a waiting caller checks whether the console stops.
const WAIT_SLICE: Duration = Duration::from_millis(100);

/// What a query reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// One page of the retained seconds.
    Timeline,
    /// The current minute's rankings.
    Rankings,
}

impl WireEnum for Kind {
    const ALL: &'static [Kind] = &[Kind::Timeline, Kind::Rankings];

    fn name(self) -> &'static str {
        match self {
            Kind::Timeline => "timeline",
            Kind::Rankings => "rankings",
        }
    }
}

/// How a query ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// The page follows.
    Ok,
    /// The cursor belongs to another epoch or boot.
    Conflict,
    /// The query is malformed.
    Invalid,
    /// The peer could not answer.
    Unavailable,
    /// The console stopped first.
    Cancelled,
}

impl WireEnum for Status {
    const ALL: &'static [Status] =
        &[Status::Ok, Status::Conflict, Status::Invalid, Status::Unavailable, Status::Cancelled];

    fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Conflict => "conflict",
            Status::Invalid => "invalid",
            Status::Unavailable => "unavailable",
            Status::Cancelled => "cancelled",
        }
    }
}

/// Why a query or a peer's answer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryError {
    /// The cursor is incomplete, malformed or asks for no rows.
    InvalidCursor,
    /// The query on the wire was not answered within [`TIMEOUT`].
    Timeout,
    /// An answer arrived with no query on the wire.
    UnexpectedReply,
    /// The answer names another query, node or boot, or its page breaks the rules.
    InvalidReply,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            QueryError::InvalidCursor => "invalid peer query cursor",
            QueryError::Timeout => "the peer did not answer its query in time",
            QueryError::UnexpectedReply => "unexpected peer query answer",
            QueryError::InvalidReply => "invalid peer query answer",
        })
    }
}

impl std::error::Error for QueryError {}

/// A timeline cursor (empty for the newest page) and a row limit of 1 to [`MAX_ROWS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Continue before this sequence.
    pub before: Option<u64>,
    /// The epoch the cursor belongs to.
    pub epoch: Option<u32>,
    /// The boot the cursor belongs to, 32 hex digits.
    pub boot: Option<String>,
    /// Rows wanted.
    pub limit: u8,
}

impl Default for Cursor {
    fn default() -> Cursor {
        Cursor { before: None, epoch: None, boot: None, limit: MAX_ROWS }
    }
}

impl Cursor {
    /// Returns the cursor of the browser's timeline `query`, its limit capped at
    /// [`MAX_ROWS`].
    ///
    /// Fails with [`QueryError::InvalidCursor`] for a limit of 0 or above
    /// [`timeline::MAX_ROWS`], a cursor that has some of `before`, `epoch` and `boot` but
    /// not all, or a boot that is not 32 hex digits.
    pub fn from_query(query: &timeline::Query) -> Result<Cursor, QueryError> {
        if query.limit == 0 || usize::from(query.limit) > timeline::MAX_ROWS {
            return Err(QueryError::InvalidCursor);
        }
        let cursor = Cursor {
            before: query.before,
            epoch: query.epoch,
            boot: query.boot.clone(),
            limit: query.limit.min(MAX_ROWS),
        };
        if cursor.is_valid() { Ok(cursor) } else { Err(QueryError::InvalidCursor) }
    }

    /// Returns true when the limit is 1 to [`MAX_ROWS`] and the cursor is complete or empty.
    pub fn is_valid(&self) -> bool {
        let boot_ok = self
            .boot
            .as_ref()
            .is_none_or(|boot| boot.len() == 32 && boot.bytes().all(|b| b.is_ascii_hexdigit()));
        let complete = self.before.is_some() == self.epoch.is_some()
            && self.before.is_some() == self.boot.is_some();
        (1..=MAX_ROWS).contains(&self.limit) && complete && boot_ok
    }

    /// Returns the local timeline query this cursor asks for.
    pub fn query(&self) -> timeline::Query {
        timeline::Query {
            node: None,
            before: self.before,
            epoch: self.epoch,
            boot: self.boot.clone(),
            limit: self.limit,
        }
    }
}

impl Encode for Cursor {
    fn encode<W: fmt::Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "before", &self.before)?;
        field(json, "epoch", &self.epoch)?;
        field(json, "boot", &self.boot)?;
        field(json, "limit", &self.limit)?;
        json.end_object()
    }
}

impl Decode for Cursor {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Cursor, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let cursor = Cursor {
            before: fields.or_default("before")?,
            epoch: fields.or_default("epoch")?,
            boot: fields.or_default("boot")?,
            limit: fields.or("limit", MAX_ROWS)?,
        };
        fields.finish()?;
        Ok(cursor)
    }
}

/// A query on the wire: `{"op":"peer_query","id":...,"kind":...,"cursor":{...}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wire {
    /// The asker's id for the query; never 0.
    pub id: u64,
    /// What it reads.
    pub kind: Kind,
    /// The timeline cursor; the default for rankings.
    pub cursor: Cursor,
}

impl Encode for Wire {
    fn encode<W: fmt::Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "op", "peer_query")?;
        field(json, "id", &self.id)?;
        field(json, "kind", &self.kind)?;
        field(json, "cursor", &self.cursor)?;
        json.end_object()
    }
}

impl Decode for Wire {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Wire, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let op: String = fields.required("op")?;
        let wire = Wire {
            id: fields.required("id")?,
            kind: fields.required("kind")?,
            cursor: fields.or("cursor", Cursor::default())?,
        };
        fields.finish()?;
        if op != "peer_query" {
            return Err(DecodeError::new(path.key("op"), DecodeErrorKind::Invalid("not a query")));
        }
        Ok(wire)
    }
}

/// What a query produced: a validated page (JSON) or the reason there is none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The page, re-encoded after validation.
    Page(String),
    /// The failure.
    Failed(Status),
}

/// Where a query's outcome is left for its caller.
#[derive(Debug, Default)]
struct Cell {
    outcome: Mutex<Option<Outcome>>,
    ready: Condvar,
}

/// The caller's side of a submitted query. Dropping it abandons the query.
#[derive(Debug)]
pub struct Ticket {
    cell: Arc<Cell>,
}

impl Ticket {
    /// Waits until the query is answered, `deadline` passes or `stopping` returns true
    /// (checked every 100 ms); returns the outcome, or `None` when there is none yet.
    pub fn wait(&self, deadline: Instant, stopping: impl Fn() -> bool) -> Option<Outcome> {
        let mut outcome = self.cell.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(done) = outcome.take() {
                return Some(done);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || stopping() {
                return None;
            }
            outcome = self
                .cell
                .ready
                .wait_timeout(outcome, left.min(WAIT_SLICE))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// A query owned by the peer's queue or by the worker that put it on the wire.
#[derive(Debug)]
pub struct Queued {
    /// The query's id on the wire.
    pub id: u64,
    /// The connection generation it was asked under.
    pub generation: u64,
    /// The peer boot it was asked under.
    pub boot: [u8; 16],
    /// What it reads.
    pub kind: Kind,
    /// The timeline cursor.
    pub cursor: Cursor,
    cell: Arc<Cell>,
}

impl Queued {
    /// Returns a query and the ticket its caller waits on.
    pub fn new(id: u64, handle: &Handle, kind: Kind, cursor: Cursor) -> (Queued, Ticket) {
        let cell = Arc::new(Cell::default());
        let ticket = Ticket { cell: Arc::clone(&cell) };
        let queued =
            Queued { id, generation: handle.generation, boot: handle.boot, kind, cursor, cell };
        (queued, ticket)
    }

    /// Returns true when its caller has given up (dropped the ticket).
    pub fn is_abandoned(&self) -> bool {
        Arc::strong_count(&self.cell) == 1
    }

    /// Leaves `outcome` for the caller and wakes it.
    pub fn answer(&self, outcome: Outcome) {
        let mut slot = self.cell.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = Some(outcome);
        self.cell.ready.notify_all();
    }

    /// Returns the wire text of this query.
    pub fn wire(&self) -> String {
        to_json(&Wire { id: self.id, kind: self.kind, cursor: self.cursor.clone() })
    }
}

/// The worker's side of the queries of one connection.
#[derive(Debug)]
pub struct Session<'p> {
    peers: &'p Peers,
    handle: Handle,
    node: u32,
    pending: Option<Queued>,
    sent_at: Instant,
}

impl<'p> Session<'p> {
    /// Returns the session of the connection `handle` to peer `node`.
    pub fn new(peers: &'p Peers, handle: Handle, node: u32) -> Session<'p> {
        Session { peers, handle, node, pending: None, sent_at: Instant::now() }
    }

    /// Returns the next query to send, as wire text, when none is on the wire. Queries of
    /// an earlier connection fail as unavailable and abandoned ones are dropped, one per
    /// call.
    ///
    /// Fails with [`QueryError::Timeout`] when the query on the wire is overdue.
    pub fn next(&mut self) -> Result<Option<String>, QueryError> {
        if self.pending.is_some() {
            if self.sent_at.elapsed() >= TIMEOUT {
                return Err(QueryError::Timeout);
            }
            return Ok(None);
        }
        let Some(queued) = self.peers.take_query(self.handle.index) else { return Ok(None) };
        let fenced =
            queued.generation != self.handle.generation || queued.boot != self.handle.boot;
        if fenced || queued.is_abandoned() {
            self.peers.finish_query(
                self.handle.index,
                &queued,
                Outcome::Failed(Status::Unavailable),
            );
            return Ok(None);
        }
        let text = queued.wire();
        self.pending = Some(queued);
        self.sent_at = Instant::now();
        Ok(Some(text))
    }

    /// Makes the query on the wire overdue (tests).
    #[cfg(test)]
    pub fn overdue(&mut self) {
        let past = Instant::now().checked_sub(TIMEOUT + Duration::from_secs(1));
        self.sent_at = past.unwrap_or(self.sent_at);
    }

    /// Receives `value` when it is a query answer (`op` is `peer_result`) and returns true;
    /// returns false for any other message.
    ///
    /// Fails with [`QueryError::UnexpectedReply`] when no query is on the wire and
    /// [`QueryError::InvalidReply`] when the answer names another query, node or boot, or
    /// its page breaks the rules; the query then stays on the wire.
    pub fn receive(&mut self, value: &Value<'_>) -> Result<bool, QueryError> {
        let op = value.as_object().and_then(|object| object.get("op")).and_then(Value::as_str);
        if op != Some("peer_result") {
            return Ok(false);
        }
        let pending = self.pending.as_ref().ok_or(QueryError::UnexpectedReply)?;
        let answer = Answer::decode(value, Path::Root).map_err(|_| QueryError::InvalidReply)?;
        if answer.id != pending.id || answer.node != self.node || answer.boot != self.handle.boot {
            return Err(QueryError::InvalidReply);
        }
        let outcome = match answer.status {
            Status::Ok => {
                Outcome::Page(validate(pending.kind, answer.data, self.node, &self.handle.boot)?)
            }
            _ if !answer.data.is_null() => return Err(QueryError::InvalidReply),
            status => Outcome::Failed(status),
        };
        if let Some(pending) = self.pending.take() {
            self.peers.finish_query(self.handle.index, &pending, outcome);
        }
        Ok(true)
    }
}

impl Drop for Session<'_> {
    /// A connection that ends fails its query on the wire.
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.peers.finish_query(
                self.handle.index,
                &pending,
                Outcome::Failed(Status::Unavailable),
            );
        }
    }
}

/// A peer's answer: `{"op":"peer_result","id":...,"node":...,"boot":...,"status":...,
/// "data":...}`.
struct Answer<'v, 'a> {
    id: u64,
    node: u32,
    boot: [u8; 16],
    status: Status,
    data: &'v Value<'a>,
}

impl<'v, 'a> Answer<'v, 'a> {
    fn decode(value: &'v Value<'a>, path: Path<'_>) -> Result<Answer<'v, 'a>, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let _op: String = fields.required("op")?;
        let id = fields.required("id")?;
        let node = fields.required("node")?;
        let boot = fields
            .take("boot")
            .ok_or_else(|| DecodeError::new(path.key("boot"), DecodeErrorKind::Missing))?;
        let boot = decode_byte_array::<16>(boot, path.key("boot"))?;
        let status = fields.required("status")?;
        let data = fields
            .take("data")
            .ok_or_else(|| DecodeError::new(path.key("data"), DecodeErrorKind::Missing))?;
        fields.finish()?;
        Ok(Answer { id, node, boot, status, data })
    }
}

/// Returns a peer's answer to the query `id`, from node `node` at `boot`: the JSON `page`
/// when `status` is [`Status::Ok`], `null` otherwise.
pub fn answer_text(id: u64, node: u32, boot: &[u8; 16], status: Status, page: &str) -> String {
    let data = if status == Status::Ok { page } else { "null" };
    let mut boot_json = String::with_capacity(64);
    // Writing into a String cannot fail.
    let _ = sibuna_console_protocol::codec::byte_array(&mut Writer::new(&mut boot_json), boot);
    format!(
        "{{\"op\":\"peer_result\",\"id\":{id},\"node\":{node},\"boot\":{boot_json},\
         \"status\":\"{}\",\"data\":{data}}}",
        status.name()
    )
}

/// Checks a peer's page of `kind` for peer `node` at `boot` and returns it re-encoded.
///
/// Fails with [`QueryError::InvalidReply`] for a page that does not decode, names another
/// node, boot or format, has more than [`MAX_ROWS`] rows, an overlong key, an error bound
/// above its estimate, or exceeds [`MAX_BODY`].
fn validate(
    kind: Kind,
    data: &Value<'_>,
    node: u32,
    boot: &[u8; 16],
) -> Result<String, QueryError> {
    let invalid = QueryError::InvalidReply;
    let text = match kind {
        Kind::Timeline => {
            let page = timeline::Page::decode(data, Path::Root).map_err(|_| invalid)?;
            if page.version != 1
                || page.node != node
                || page.rows.len() > usize::from(MAX_ROWS)
                || page.boot != sibuna_encoding::hex::encode(boot)
            {
                return Err(invalid);
            }
            to_json(&page)
        }
        Kind::Rankings => {
            let page = rankings::Page::decode(data, Path::Root).map_err(|_| invalid)?;
            let row_ok = |row: &rankings::Row| {
                let limit = if row.encoding == rankings::Encoding::Hex { 256 } else { 128 };
                row.key.len() <= limit && row.error_bound <= row.estimate
            };
            if page.node != node
                || page.rows.len() > usize::from(MAX_ROWS)
                || page.boot != *boot
                || page.kind != "path_prefix"
                || page.sampling_probability != "1/64"
                || !page.rows.iter().all(row_ok)
            {
                return Err(invalid);
            }
            to_json(&page)
        }
    };
    if text.len() > MAX_BODY {
        return Err(invalid);
    }
    Ok(text)
}

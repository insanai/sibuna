//! The serving side of peer queries (Zig's `peer_query_queue.zig` and
//! `peer_query_server.zig`): the inbound stream's reader hands queries to its writer
//! through a bounded [`Inbox`], and the writer answers each from this node's own live views.
//! A slow answer never stops the reader from taking pings, closes or subscription commands,
//! and this route never relays another node's data.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use sibuna_console_protocol::codec::{Decode, Path, to_json};
use sibuna_http::websocket::MAX_MESSAGE;
use sibuna_json::Value;

use super::query::{MAX_ROWS, QueryError, Status, Wire, answer_text};
use crate::collector::LiveError;
use crate::shared::Shared;

/// Queries one inbound stream may have waiting for its writer.
pub const INBOX_CAPACITY: usize = 8;

/// The queries an inbound stream's reader passed to its writer, oldest first.
#[derive(Debug, Default)]
pub struct Inbox {
    queries: Mutex<VecDeque<Wire>>,
}

impl Inbox {
    /// Queues `wire`; false when [`INBOX_CAPACITY`] queries are already waiting.
    pub fn push(&self, wire: Wire) -> bool {
        let mut queries = self.queries.lock().unwrap_or_else(PoisonError::into_inner);
        if queries.len() == INBOX_CAPACITY {
            return false;
        }
        queries.push_back(wire);
        true
    }

    /// Takes the oldest waiting query.
    pub fn take(&self) -> Option<Wire> {
        self.queries.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
    }
}

/// Reads `value`, a message from a peer: `Ok(None)` when it is not a query (`op` is not
/// `peer_query`), the query otherwise.
///
/// Fails with [`QueryError::InvalidCursor`] for a query that does not decode, has id 0, or
/// asks for no rows or more than eight.
pub fn accept(value: &Value<'_>) -> Result<Option<Wire>, QueryError> {
    let op = value.as_object().and_then(|object| object.get("op")).and_then(Value::as_str);
    if op != Some("peer_query") {
        return Ok(None);
    }
    let wire = Wire::decode(value, Path::Root).map_err(|_| QueryError::InvalidCursor)?;
    if wire.id == 0 || wire.cursor.limit == 0 || wire.cursor.limit > MAX_ROWS {
        return Err(QueryError::InvalidCursor);
    }
    Ok(Some(wire))
}

/// Returns the answer to `wire` from this node's live views. The answer fits one WebSocket
/// message: a page that does not is read again with half the rows, and `unavailable` is
/// answered when even one row does not fit.
pub fn respond(shared: &Shared, wire: &Wire) -> String {
    let node = shared.live.node();
    let boot = shared.identity.boot;
    let mut rows = wire.cursor.limit.clamp(1, MAX_ROWS);
    loop {
        let (status, page) = page(shared, wire, rows);
        let text = answer_text(wire.id, node, &boot, status, &page);
        if text.len() <= MAX_MESSAGE {
            return text;
        }
        if rows <= 1 {
            return answer_text(wire.id, node, &boot, Status::Unavailable, "");
        }
        rows /= 2;
    }
}

/// Reads the page `wire` asks for with at most `rows` rows.
fn page(shared: &Shared, wire: &Wire, rows: u8) -> (Status, String) {
    match wire.kind {
        super::Kind::Timeline => {
            let query =
                sibuna_console_protocol::timeline::Query { limit: rows, ..wire.cursor.query() };
            match shared.live.timeline(shared, &query) {
                Ok(page) => (Status::Ok, to_json(&page)),
                Err(LiveError::HistoryChanged) => (Status::Conflict, String::new()),
                Err(LiveError::InvalidQuery) => (Status::Invalid, String::new()),
                Err(LiveError::Unavailable) => (Status::Unavailable, String::new()),
            }
        }
        super::Kind::Rankings => match shared.live.rankings(shared) {
            Ok(mut page) => {
                page.rows.truncate(usize::from(rows));
                page.referrers.truncate(usize::from(rows));
                (Status::Ok, to_json(&page))
            }
            Err(_) => (Status::Unavailable, String::new()),
        },
    }
}

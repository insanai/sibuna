//! The outbound worker of one configured peer (Zig's `peer_client.zig` and `peer_job.zig`).
//!
//! ```text
//! loop until the console stops:
//!   resolve the origin's host (ConfiguredManagement policy) -> TLS (peer CA file, host name)
//!   GET /console/peer with the proved transcript -> 101 with the peer's boot and proof
//!   activate (new generation) -> {"op":"sub","topic":"stats","args":{}}
//!   read frames (masked writes, unmasked reads), publish each completed stats view,
//!     send queued queries, answer pings, at most 128 messages per second
//!   ends on error, close, 10 s without an accepted snapshot, or after one hour
//!   -> peer stale (or rejected: one `peer.rejected` audit row when it becomes so),
//!      back off 1, 2, 4 ... 30 s plus up to 0.9 s of jitter
//! ```
//!
//! The worker reads with a socket deadline of at most 250 ms and polls between reads, so a
//! query waits at most that long to be sent and the console's stop is seen as quickly.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::subscription_client::{Client, Event as ViewEvent};
use sibuna_console_protocol::subscriptions::Topic;
use sibuna_console_storage::audit::{AuditAction, AuditRow, append_audit};
use sibuna_http::websocket::{
    Event, FrameError, FrameReader, MAX_HEADER, MAX_MESSAGE, Opcode, ReceiveError, Receiver, Role,
    encode,
};
use sibuna_net::outbound::{self, OutboundError, Policy};
use sibuna_tls::{Connector, TlsError, TlsStream, Trust};

use super::auth::Transcript;
use super::query::{QueryError, Session};
use super::store::{Handle, StoreError, Update};
use super::wire::{self, WireError};
use crate::config::{PeerOrigin, parse_peer_origin};
use crate::random::{self, RandomError};
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The longest a connection may go without an accepted snapshot (and the connect bound).
const PROGRESS: Duration = Duration::from_secs(10);
/// The longest a connection lives before it is renewed.
const CONNECTION_CAP: Duration = Duration::from_secs(3600);
/// The longest a read waits before the worker looks around.
const POLL: Duration = Duration::from_millis(250);
/// The longest a write may take.
const WRITE: Duration = Duration::from_secs(10);
/// The longest reply head accepted.
const MAX_HEAD: usize = 16 * 1024;
/// Messages a peer may send per second.
const EVENTS_PER_SECOND: u32 = 128;
/// The longest backoff, in seconds.
const MAX_BACKOFF: u64 = 30;
/// The subscription the worker sends once connected.
const SUBSCRIBE: &[u8] = b"{\"op\":\"sub\",\"topic\":\"stats\",\"args\":{}}";

/// Why a connection ended.
#[derive(Debug)]
enum WorkerError {
    /// The peer's origin is invalid or this console has no peer key.
    Configuration,
    /// Resolution or the address policy refused the host.
    Outbound(OutboundError),
    /// TLS failed: trust store, connection, handshake or certificate.
    Tls(TlsError),
    /// The upgrade reply was refused.
    Wire(WireError),
    /// The store refused the connection or a snapshot.
    Store(StoreError),
    /// A query failed on the wire.
    Query(QueryError),
    /// A frame was refused or reading failed.
    Receive(ReceiveError),
    /// Writing failed.
    Io(io::Error),
    /// No random bytes.
    Random,
    /// A message breaks the subscription protocol.
    Protocol,
    /// The peer's view needs a new subscription (gap or unauthorized).
    Resync,
    /// The peer sent more than 128 messages in a second.
    RateLimit,
    /// No snapshot was accepted for ten seconds, or the hour is over.
    Deadline,
}

impl WorkerError {
    /// Returns why the peer itself was refused (its configuration, its upgrade reply or
    /// proof, or its certificate), or `None` for an unreachable or silent peer.
    fn rejection(&self) -> Option<&'static str> {
        match self {
            WorkerError::Configuration => Some("configuration"),
            WorkerError::Wire(WireError::InvalidProof) => Some("proof"),
            WorkerError::Wire(WireError::InvalidRequest) => Some("upgrade"),
            WorkerError::Tls(TlsError::Certificate { .. }) => Some("certificate"),
            _ => None,
        }
    }
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::Configuration => f.write_str("invalid peer configuration"),
            WorkerError::Outbound(error) => error.fmt(f),
            WorkerError::Tls(error) => error.fmt(f),
            WorkerError::Wire(error) => error.fmt(f),
            WorkerError::Store(error) => error.fmt(f),
            WorkerError::Query(error) => error.fmt(f),
            WorkerError::Receive(error) => error.fmt(f),
            WorkerError::Io(error) => error.fmt(f),
            WorkerError::Random => f.write_str("no random bytes"),
            WorkerError::Protocol => f.write_str("invalid peer message"),
            WorkerError::Resync => f.write_str("the peer's view needs a new subscription"),
            WorkerError::RateLimit => f.write_str("the peer sent too many messages"),
            WorkerError::Deadline => f.write_str("the peer made no progress"),
        }
    }
}

impl From<RandomError> for WorkerError {
    fn from(_: RandomError) -> WorkerError {
        WorkerError::Random
    }
}

impl From<io::Error> for WorkerError {
    fn from(error: io::Error) -> WorkerError {
        WorkerError::Io(error)
    }
}

impl From<StoreError> for WorkerError {
    fn from(error: StoreError) -> WorkerError {
        WorkerError::Store(error)
    }
}

impl From<QueryError> for WorkerError {
    fn from(error: QueryError) -> WorkerError {
        WorkerError::Query(error)
    }
}

impl From<FrameError> for WorkerError {
    fn from(error: FrameError) -> WorkerError {
        WorkerError::Receive(ReceiveError::Frame(error))
    }
}

/// The worker of peer `index`: connects, receives, backs off, until the console stops.
pub fn run(shared: &Shared, index: usize) {
    let mut backoff: u64 = 1;
    let mut connector = None;
    // The reason of a refusal not yet audited.
    let mut unaudited = None;
    while !shared.is_stopping() {
        let started = Instant::now();
        let ended = attempt(shared, index, &mut connector);
        if shared.is_stopping() {
            return;
        }
        let rejection = ended.as_ref().err().and_then(WorkerError::rejection);
        if shared.peers.failed(index, rejection.is_some()) {
            unaudited = rejection;
        }
        if let Some(reason) = unaudited
            && audit_rejection(shared, index, reason)
        {
            unaudited = None;
        }
        if started.elapsed() >= PROGRESS {
            backoff = 1;
        }
        let jitter = random::array::<1>().map_or(0, |byte| u64::from(byte[0] % 10));
        let pause = Duration::from_millis((backoff * 10 + jitter) * 100);
        if !shared.sleep(pause) {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Submits the `peer.rejected` audit row of peer `index`, refused for `reason`, as a
/// background job. Returns false when the background allowance or the queue is full, so the
/// caller tries again after its backoff; true once submitted (or when storage has stopped).
fn audit_rejection(shared: &Shared, index: usize, reason: &'static str) -> bool {
    let Some(target) = shared.peers.targets().get(index) else { return true };
    // An origin is printable ASCII; the audit target holds at most 128 bytes.
    let origin = target.origin.get(..target.origin.len().min(128)).unwrap_or_default();
    let row = AuditRow {
        subject: Some(u64::from(target.node)),
        target: Some(origin.to_owned()),
        after: Some(format!("{{\"reason\":\"{reason}\"}}")),
        ..AuditRow::new(AuditAction::PeerRejected, shared.now())
    };
    let submitted = shared.storage.submit_background(move |tx| {
        Box::pin(async move { append_audit(tx, &row).await.map(drop) })
    });
    !matches!(submitted, Err(StorageFailure::Busy | StorageFailure::Deferred))
}

/// One connection: connect, authenticate, subscribe and receive until it ends.
fn attempt(
    shared: &Shared,
    index: usize,
    connector: &mut Option<Connector>,
) -> Result<(), WorkerError> {
    let peers = &shared.peers;
    let target = peers.targets().get(index).ok_or(WorkerError::Configuration)?;
    let key = peers.key().ok_or(WorkerError::Configuration)?;
    let origin = parse_peer_origin(&target.origin).map_err(|_| WorkerError::Configuration)?;
    let authority = target.origin.strip_prefix("https://").ok_or(WorkerError::Configuration)?;
    if connector.is_none() {
        let trust =
            shared.config.peers.ca_file.clone().map_or_else(Trust::default, Trust::from_ca_file);
        *connector = Some(Connector::load(&trust).map_err(WorkerError::Tls)?);
    }
    let connector = connector.as_ref().ok_or(WorkerError::Configuration)?;
    let deadline = Instant::now() + PROGRESS;
    let mut stream = connect(connector, &origin, deadline)?;
    let transcript = Transcript {
        from: peers.self_node(),
        to: target.node,
        timestamp: shared.now(),
        nonce: random::array()?,
        websocket_key: random::array()?,
    };
    stream.write_all(wire::request_head(authority, key, &transcript).as_bytes())?;
    stream.flush()?;
    let head = read_head(&mut stream)?;
    let reply = wire::check_reply(&head, key, &transcript).map_err(WorkerError::Wire)?;
    let handle = peers.activate(index, reply.boot)?;
    send(&mut stream, Opcode::Text, SUBSCRIBE)?;
    receive(shared, handle, target.node, FrameReader::new(stream))
}

/// Resolves `origin` under the management policy and connects TLS to the first address
/// that answers, authenticating the origin's host, before `deadline`.
fn connect(
    connector: &Connector,
    origin: &PeerOrigin,
    deadline: Instant,
) -> Result<TlsStream, WorkerError> {
    let addresses = outbound::resolve(&origin.host, origin.port, Policy::ConfiguredManagement)
        .map_err(WorkerError::Outbound)?;
    let mut last = WorkerError::Outbound(OutboundError::HostUnresolved);
    for address in addresses.iter() {
        match connector.connect_address(address, &origin.host, deadline) {
            Ok(stream) => return Ok(stream),
            // A refused name or certificate is refused on every address, and a timeout
            // means the deadline has passed.
            Err(
                error @ (TlsError::Certificate { .. }
                | TlsError::InvalidServerName(_)
                | TlsError::ConnectTimeout
                | TlsError::HandshakeTimeout),
            ) => return Err(WorkerError::Tls(error)),
            Err(error) => last = WorkerError::Tls(error),
        }
    }
    Err(last)
}

/// Reads the reply head up to its blank line, one byte at a time so that no frame behind
/// it is consumed, at most [`MAX_HEAD`] bytes.
fn read_head(stream: &mut TlsStream) -> Result<Vec<u8>, WorkerError> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_HEAD {
            return Err(WorkerError::Wire(WireError::InvalidRequest));
        }
        match stream.read(&mut byte) {
            Ok(0) => return Err(WorkerError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(_) => head.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WorkerError::Io(error)),
        }
    }
    Ok(head)
}

/// Sends one masked frame within [`WRITE`].
fn send(stream: &mut TlsStream, opcode: Opcode, payload: &[u8]) -> Result<(), WorkerError> {
    let mask = random::array::<4>()?;
    let mut buffer = [0u8; MAX_HEADER + MAX_MESSAGE];
    let frame = encode(&mut buffer, opcode, true, payload, Role::Client, Some(mask))?;
    stream.set_deadline(Some(Instant::now() + WRITE))?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

/// What one connection keeps while it receives.
struct Receiving<'s> {
    shared: &'s Shared,
    handle: Handle,
    session: Session<'s>,
    client: Client,
    /// The connection's start and the last accepted snapshot.
    started: Instant,
    progress: Instant,
    /// The second the message allowance counts in, and the messages in it.
    second: u64,
    events: u32,
}

/// Receives frames on connection `handle` to peer `node` until it ends.
fn receive(
    shared: &Shared,
    handle: Handle,
    node: u32,
    mut frames: FrameReader<TlsStream>,
) -> Result<(), WorkerError> {
    let now = Instant::now();
    let mut state = Receiving {
        shared,
        handle,
        session: Session::new(&shared.peers, handle, node),
        client: Client::new(),
        started: now,
        progress: now,
        second: shared.now(),
        events: 0,
    };
    let mut receiver = Box::new(Receiver::new());
    while !shared.is_stopping() {
        if let Some(text) = state.session.next()? {
            send(frames.inner_mut(), Opcode::Text, text.as_bytes())?;
        }
        let now = Instant::now();
        let limit = (state.progress + PROGRESS).min(state.started + CONNECTION_CAP);
        if now >= limit {
            return Err(WorkerError::Deadline);
        }
        frames.inner_mut().set_deadline(Some((now + POLL).min(limit)))?;
        let event = match frames.receive(&mut receiver, Role::Client) {
            Ok(event) => event,
            Err(ReceiveError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(WorkerError::Receive(error)),
        };
        state.count()?;
        match event {
            Event::Fragment | Event::Pong(_) => {}
            Event::Ping(payload) => send(frames.inner_mut(), Opcode::Pong, payload)?,
            Event::Close(payload) => {
                send(frames.inner_mut(), Opcode::Close, payload)?;
                return Ok(());
            }
            Event::Binary(_) => return Err(WorkerError::Protocol),
            Event::Text(text) => state.update(text)?,
        }
    }
    Ok(())
}

impl Receiving<'_> {
    /// Counts one message against the allowance of the current second.
    fn count(&mut self) -> Result<(), WorkerError> {
        let now = self.shared.now();
        if now != self.second {
            (self.second, self.events) = (now, 0);
        }
        if self.events == EVENTS_PER_SECOND {
            return Err(WorkerError::RateLimit);
        }
        self.events += 1;
        Ok(())
    }

    /// Receives one text message: a query answer, or a frame of the statistics view, which
    /// is published once complete. An accepted snapshot is progress.
    fn update(&mut self, text: &str) -> Result<(), WorkerError> {
        let value = sibuna_json::parse(text.as_bytes()).map_err(|_| WorkerError::Protocol)?;
        if self.session.receive(&value)? {
            return Ok(());
        }
        match self.client.receive(&value).map_err(|_| WorkerError::Protocol)? {
            ViewEvent::None => return Ok(()),
            ViewEvent::Unauthorized | ViewEvent::Gap(_) => return Err(WorkerError::Resync),
            ViewEvent::Changed(Topic::Stats) => {}
            ViewEvent::Changed(_) => return Err(WorkerError::Protocol),
        }
        // A view without a position has no counters yet and is never published as zero.
        let position = self.client.position(Topic::Stats).ok_or(WorkerError::Protocol)?;
        let view = self.client.view(Topic::Stats);
        let value =
            StatsSnapshot::from_json(view.as_bytes()).map_err(|_| WorkerError::Protocol)?;
        let update = Update {
            value: &value,
            watermark: position.watermark,
            sequence: position.sequence,
            received_at: self.shared.now(),
        };
        if self.shared.peers.publish(&self.handle, &update)? {
            self.progress = Instant::now();
        }
        Ok(())
    }
}

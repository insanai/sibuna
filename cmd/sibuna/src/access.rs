//! What the edge observes of each HTTP request (SID 0020): one access log entry, the
//! counters of its frontend and server, and who may read the internal routes.
//!
//! A request path lends a [`Trace`] to each request. The dispatch fills it and captures an
//! [`Entry`] at its end. The path that owns the response settles the entry when the
//! response ends: [`Observe::settle`] updates the counters and offers the entry to the
//! log. The daemon of SID 0002 has no [`Observe`], and then none of this runs.

mod sink;

use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sibuna_http::Request;
use sibuna_http::response::{self, Extra, Status};
use sibuna_lb::{Forwarded, FrontendInfo, ObserveOptions, ServerInfo, Stats};

pub(crate) use self::sink::AccessLog;
use crate::client_writer::Tally;
use crate::connection::{Ingress, UNKNOWN_LENGTH};
use crate::context::Ctx;
use crate::server::Server;
use crate::telemetry::Outcome;

/// The longest host and path an entry keeps.
const MAX_HOST: usize = 255;
const MAX_PATH: usize = 1024;

/// What an edge server shares for observation.
pub(crate) struct Observe {
    /// Who may read the internal routes.
    pub options: ObserveOptions,
    /// The access log, when the topology has one.
    pub log: Option<AccessLog>,
    /// The counters of the frontends and servers.
    pub stats: Arc<Stats>,
    /// The node stopped taking new work. Release on store, acquire on load.
    pub draining: AtomicBool,
    /// Connections of PROXY frontends that sent a valid header, and those closed.
    pub proxy_accepted: AtomicU64,
    pub proxy_rejected: AtomicU64,
}

impl Observe {
    /// The shared state of one edge server, with the log already open.
    pub(crate) fn new(options: ObserveOptions, log: Option<AccessLog>, stats: Arc<Stats>) -> Self {
        Self {
            options,
            log,
            stats,
            draining: AtomicBool::new(false),
            proxy_accepted: AtomicU64::new(0),
            proxy_rejected: AtomicU64::new(0),
        }
    }

    /// True until the node drains.
    pub(crate) fn is_ready(&self) -> bool {
        !self.draining.load(Ordering::Acquire)
    }

    /// Ends an entry at `now`: counts it and offers it to the log. Never waits.
    pub(crate) fn settle(&self, mut entry: Entry, now: Instant) {
        entry.elapsed = now.saturating_duration_since(entry.started);
        if let Some(front) = &entry.frontend {
            front.stats.record(entry.status, entry.bytes_in, entry.bytes_out, entry.elapsed);
        }
        if let Some(server) = &entry.server {
            server.stats.record(entry.status, entry.first_byte);
        }
        if let Some(log) = &self.log {
            log.offer(entry);
        }
    }

    /// Writes the series of SID 0020 in the Prometheus text format.
    pub(crate) fn write_prometheus(&self, out: &mut String) {
        use std::fmt::Write as _;
        // Writing to a string cannot fail.
        let _ = self.stats.write_prometheus(out);
        let (written, dropped, errors) = self.log.as_ref().map_or((0, 0, 0), AccessLog::counts);
        let series = [
            ("sibuna_edge_ready", "gauge", u64::from(self.is_ready())),
            ("sibuna_edge_access_log_written_total", "counter", written),
            ("sibuna_edge_access_log_dropped_total", "counter", dropped),
            ("sibuna_edge_access_log_errors_total", "counter", errors),
            (
                "sibuna_edge_proxy_protocol_accepted_total",
                "counter",
                self.proxy_accepted.load(Ordering::Relaxed),
            ),
            (
                "sibuna_edge_proxy_protocol_rejected_total",
                "counter",
                self.proxy_rejected.load(Ordering::Relaxed),
            ),
        ];
        for (name, kind, value) in series {
            let _ = writeln!(out, "# TYPE {name} {kind}\n{name} {value}");
        }
    }
}

/// One request for the access log and the counters.
pub(crate) struct Entry {
    /// When the request was dispatched: the wall clock in Unix milliseconds, and the
    /// monotonic clock the durations are measured from.
    pub time_ms: u64,
    pub started: Instant,
    /// The client, host, method and path, one after another, and where each ends. Empty
    /// without a log.
    text: Vec<u8>,
    cuts: [u16; 3],
    pub frontend: Option<Arc<FrontendInfo>>,
    pub server: Option<ServerInfo>,
    pub protocol: &'static str,
    pub verdict: &'static str,
    /// The status sent to the client, or zero.
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The wait for the first response byte of the server.
    pub first_byte: Option<Duration>,
    /// From the dispatch to the end of the response. Set by [`Observe::settle`].
    pub elapsed: Duration,
}

impl Entry {
    /// An entry for a request that never reached the dispatch: only its client is known.
    fn unparsed(
        client: &[u8],
        frontend: Option<Arc<FrontendInfo>>,
        protocol: &'static str,
    ) -> Self {
        let mut entry = Self {
            time_ms: crate::context::unix_ms(),
            started: Instant::now(),
            text: Vec::new(),
            cuts: [0; 3],
            frontend,
            server: None,
            protocol,
            verdict: "-",
            status: 0,
            bytes_in: 0,
            bytes_out: 0,
            first_byte: None,
            elapsed: Duration::ZERO,
        };
        entry.set_text(client, b"", b"-", b"-");
        entry
    }

    fn set_text(&mut self, client: &[u8], host: &[u8], method: &[u8], path: &[u8]) {
        let host = host.get(..MAX_HOST).unwrap_or(host);
        let method = method.get(..32).unwrap_or(method);
        let path = path.get(..MAX_PATH).unwrap_or(path);
        let client = client.get(..64).unwrap_or(client);
        self.text.clear();
        self.text.reserve(client.len() + host.len() + method.len() + path.len());
        for (cut, part) in self.cuts.iter_mut().zip([client, host, method]) {
            self.text.extend_from_slice(part);
            // The four parts hold at most 1,375 bytes.
            *cut = self.text.len() as u16;
        }
        self.text.extend_from_slice(path);
    }

    fn part(&self, index: usize) -> &[u8] {
        let start = if index == 0 { 0 } else { usize::from(self.cuts[index - 1]) };
        let end = self.cuts.get(index).map_or(self.text.len(), |&cut| usize::from(cut));
        self.text.get(start..end).unwrap_or_default()
    }

    /// The address the request was judged by.
    pub(crate) fn client(&self) -> &[u8] {
        self.part(0)
    }

    /// The `Host` field.
    pub(crate) fn host(&self) -> &[u8] {
        self.part(1)
    }

    /// The request method.
    pub(crate) fn method(&self) -> &[u8] {
        self.part(2)
    }

    /// The path in normal form, without the query.
    pub(crate) fn path(&self) -> &[u8] {
        self.part(3)
    }
}

/// What a request path lends to each request it serves.
#[derive(Default)]
pub(crate) struct Trace {
    /// When the request context was built.
    started: Option<Instant>,
    /// What the firewall decided, as the log names it.
    pub verdict: &'static str,
    /// The protocol the client speaks, when the path knows better than the socket.
    pub protocol: &'static str,
    /// The frontend the request arrived on.
    pub front: Option<Arc<FrontendInfo>>,
    /// The server the request was sent to.
    pub server: Option<ServerInfo>,
    /// The entry of the request, from the end of its dispatch until it is settled.
    pub entry: Option<Entry>,
}

impl Trace {
    /// Starts the trace of one request. Without an [`Observe`] this does nothing.
    pub(crate) fn begin(&mut self, server: &Server, ingress: Option<Ingress>) {
        if server.observe.is_none() {
            return;
        }
        self.started = Some(Instant::now());
        self.verdict = "-";
        self.server = None;
        self.entry = None;
        self.front = match (&server.edge_routes, ingress) {
            (Some(routes), Some(ingress)) => routes.frontend(ingress.vip),
            _ => None,
        };
    }
}

/// The name of an outcome in the log.
pub(crate) fn verdict_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Admitted => "pass",
        Outcome::Challenged => "challenge",
        Outcome::Denied => "deny",
        Outcome::RateLimited => "rate_limited",
        Outcome::Banned => "banned",
        Outcome::Other => "-",
    }
}

/// The protocol of a request whose path does not name one.
fn protocol_of(trace: &Trace, ingress: Option<Ingress>) -> &'static str {
    match (trace.protocol, ingress) {
        ("", Some(ingress)) if ingress.secure => "https",
        ("", _) => "http/1.1",
        (named, _) => named,
    }
}

/// Finds the client of `request` among its forwarded entries, when the socket peer is a
/// proxy the frontend trusts. Returns `None` when the peer is the client.
pub(crate) fn forwarded_client<'c>(
    server: &Server,
    front: &FrontendInfo,
    request: &Request<'c>,
    peer: Option<IpAddr>,
) -> Option<(&'c [u8], IpAddr)> {
    if front.trusted.is_empty() || !peer.is_some_and(|peer| front.trusts(peer)) {
        return None;
    }
    let entries = request
        .headers()
        .iter()
        .rev()
        .filter(|header| header.name.eq_ignore_ascii_case(b"x-forwarded-for"))
        .flat_map(|header| header.value.rsplit(|&byte| byte == b','))
        .map(|entry| entry.trim_ascii());
    match front.forwarded_client(entries) {
        Forwarded::Client(text, address) => Some((text, address)),
        Forwarded::Malformed => {
            server.metrics.forwarded_invalid.bump();
            None
        }
        Forwarded::Absent => None,
    }
}

/// Captures the entry of a dispatched request from its context. The path that owns the
/// response settles it.
pub(crate) fn capture<W>(ctx: &mut Ctx<'_, W>) {
    let Some(observe) = &ctx.server.observe else { return };
    let request = &ctx.request;
    let head: usize = request.headers().iter().map(|h| h.name.len() + h.value.len() + 4).sum();
    let line = request.method_text.len() + request.path.len() + request.query.len() + 14;
    let body =
        if ctx.declared_body == UNKNOWN_LENGTH { request.body.len() } else { ctx.declared_body };
    let trace = &mut *ctx.trace;
    let verdict = if ctx.internal && trace.verdict == "-" { "internal" } else { trace.verdict };
    let mut entry = Entry {
        time_ms: ctx.now_ms,
        started: trace.started.take().unwrap_or_else(Instant::now),
        text: Vec::new(),
        cuts: [0; 3],
        frontend: trace.front.take(),
        server: trace.server.take(),
        protocol: protocol_of(trace, ctx.ingress),
        verdict,
        status: 0,
        bytes_in: (line + head + body) as u64,
        bytes_out: 0,
        first_byte: None,
        elapsed: Duration::ZERO,
    };
    if observe.log.is_some() {
        let host = request.header(b"host").unwrap_or_default();
        entry.set_text(ctx.client_ip, host, request.method_text, request.path);
    }
    trace.entry = Some(entry);
}

/// Notes the server an admitted request goes to.
pub(crate) fn selected<W>(ctx: &mut Ctx<'_, W>, target: Option<&sibuna_lb::HttpTarget>) {
    if ctx.server.observe.is_some() {
        ctx.trace.server = target.and_then(|target| target.server().cloned());
    }
}

/// Hands the entry of an admitted in-process exchange to the protocol runtime, which
/// reports the outcome once.
#[cfg(feature = "https")]
pub(crate) fn report(
    server: &Server,
    trace: &mut Trace,
) -> Option<Box<dyn sibuna_ingress::Report>> {
    let observe = server.observe.clone()?;
    let entry = trace.entry.take()?;
    Some(Box::new(Pending { observe, entry, sent: Instant::now() }))
}

/// An entry that waits for the protocol runtime to finish its exchange.
#[cfg(feature = "https")]
struct Pending {
    observe: Arc<Observe>,
    entry: Entry,
    /// When the request was handed to the runtime. Its waits are measured from here.
    sent: Instant,
}

#[cfg(feature = "https")]
impl sibuna_ingress::Report for Pending {
    fn done(self: Box<Self>, completion: &sibuna_ingress::Completion) {
        let Pending { observe, mut entry, sent } = *self;
        entry.status = completion.status;
        entry.bytes_out = completion.bytes_out;
        let decided = sent.saturating_duration_since(entry.started);
        entry.first_byte = completion.first_byte.map(|wait| decided + wait);
        observe.settle(entry, Instant::now());
    }
}

/// Settles the request that a response writer answered: Sibuna's own response on every
/// path, and a relayed one on the thread-per-connection path. A request that never
/// reached the dispatch is logged with what the writer saw. `peer` is the socket peer.
pub(crate) fn settle_written(
    server: &Server,
    trace: &mut Trace,
    tally: Tally,
    ingress: Option<Ingress>,
    peer: &[u8],
) {
    let Some(observe) = &server.observe else { return };
    let entry = match trace.entry.take() {
        Some(entry) => Some(entry),
        // Nothing was dispatched. A response still deserves its line.
        None if tally.status != 0 => {
            let front = match (&server.edge_routes, ingress) {
                (Some(routes), Some(ingress)) => routes.frontend(ingress.vip),
                _ => None,
            };
            Some(Entry::unparsed(peer, front, protocol_of(trace, ingress)))
        }
        None => None,
    };
    let Some(mut entry) = entry else { return };
    entry.status = tally.status;
    entry.bytes_out = tally.bytes;
    if entry.server.is_some() && tally.status != 0 && !own_gateway_error(tally.status) {
        entry.first_byte = tally.first.map(|at| at.saturating_duration_since(entry.started));
    }
    observe.settle(entry, Instant::now());
}

/// True for the statuses Sibuna answers itself when a server fails. On the
/// thread-per-connection path the writer cannot tell them from a server's own.
fn own_gateway_error(status: u16) -> bool {
    matches!(status, 502 | 504)
}

/// True when the request may read the health, readiness and metrics routes. The daemon
/// has no access control here. An edge requires the socket peer and the client inside
/// `internal_allow`, and no forwarding field: a proxy on this host speaks for anyone.
pub(crate) fn may_inspect<W>(ctx: &Ctx<'_, W>) -> bool {
    let Some(observe) = &ctx.server.observe else { return true };
    let peer = sibuna_cidr::parse_ip(ctx.peer).ok();
    let inside = |address: Option<IpAddr>| address.is_some_and(|a| observe.options.allows(a));
    let forwarded = ctx.request.headers().iter().any(|header| {
        [&b"x-forwarded-for"[..], b"x-real-ip", b"forwarded"]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
    });
    inside(peer) && inside(ctx.client_address) && !forwarded
}

/// Answers the readiness route: 200 while the node serves, 503 once it drains.
pub(crate) fn ready<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let ready = ctx.server.observe.as_ref().is_none_or(|observe| observe.is_ready())
        && !ctx.server.is_stopping();
    let (status, body) = ready_answer(ready);
    let extra = Extra { keep_alive: ctx.keep_alive, ..Extra::default() };
    response::write_response(ctx.writer, status, b"application/json", body, extra)
}

/// The status and body of a readiness answer.
pub(crate) fn ready_answer(ready: bool) -> (Status, &'static [u8]) {
    if ready {
        (Status::Ok, b"{\"status\":\"ready\"}")
    } else {
        (Status::ServiceUnavailable, b"{\"status\":\"draining\"}")
    }
}

/// The metrics text of an edge: the process counters, then the series of SID 0020.
pub(crate) fn metrics_text(server: Option<&Server>, observe: &Observe) -> String {
    let mut text = String::with_capacity(8192);
    if let Some(server) = server {
        // Writing to a string cannot fail.
        let _ = server.metrics.write_prometheus(&mut text);
    }
    observe.write_prometheus(&mut text);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_keeps_its_four_texts_within_their_bounds() {
        let mut entry = Entry::unparsed(b"203.0.113.7", None, "http/1.1");
        assert_eq!(
            (entry.client(), entry.method(), entry.path()),
            (&b"203.0.113.7"[..], &b"-"[..], &b"-"[..])
        );
        assert_eq!(entry.host(), b"");
        let long = vec![b'a'; 5000];
        entry.set_text(b"::1", &long, b"GET", &long);
        assert_eq!((entry.client(), entry.method()), (&b"::1"[..], &b"GET"[..]));
        assert_eq!((entry.host().len(), entry.path().len()), (MAX_HOST, MAX_PATH));
    }

    #[test]
    fn readiness_is_200_or_503() {
        assert_eq!(ready_answer(true).0, Status::Ok);
        assert_eq!(ready_answer(false).0, Status::ServiceUnavailable);
    }
}

//! Counters per frontend and per server, and their Prometheus text (SID 0020).
//!
//! A block of counters is found by name once, when a topology is bound or reloaded. A
//! request then holds the block and bumps atomics. The registry keeps the blocks across
//! reloads, so a counter continues while its name stays in the topology.

use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

mod top;
mod view;
pub use top::TopSource;
pub use view::{FrontendView, Latency, ServerView, StatsView};

/// The upper bounds of the latency buckets, in microseconds.
const BOUNDS_MICROS: [u64; 14] = [
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000,
    5_000_000, 10_000_000, 30_000_000,
];

/// The label of each bucket bound, in seconds.
const BOUND_LABELS: [&str; 14] = [
    "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5",
    "10", "30",
];

/// The status classes a response is counted in: `1xx` to `5xx`, then no status.
const CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "none"];

/// A latency histogram with fixed bounds from 1 ms to 30 s.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; 14],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    /// Counts one observation.
    pub fn observe(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if let Some(at) = BOUNDS_MICROS.iter().position(|&bound| micros <= bound) {
            self.buckets[at].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// The number of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Writes the `_bucket`, `_sum` and `_count` lines of the series `name` with `labels`.
    fn write(&self, out: &mut impl Write, name: &str, labels: &str) -> fmt::Result {
        let mut running = 0u64;
        for (bucket, bound) in self.buckets.iter().zip(BOUND_LABELS) {
            running = running.saturating_add(bucket.load(Ordering::Relaxed));
            writeln!(out, "{name}_bucket{{{labels},le=\"{bound}\"}} {running}")?;
        }
        let count = self.count();
        writeln!(out, "{name}_bucket{{{labels},le=\"+Inf\"}} {count}")?;
        let micros = self.sum_micros.load(Ordering::Relaxed);
        writeln!(out, "{name}_sum{{{labels}}} {}.{:06}", micros / 1_000_000, micros % 1_000_000)?;
        writeln!(out, "{name}_count{{{labels}}} {count}")
    }
}

/// Responses by status class.
#[derive(Debug, Default)]
struct Classes([AtomicU64; 6]);

impl Classes {
    fn count(&self, status: u16) {
        let class = match status {
            100..=599 => usize::from(status / 100) - 1,
            _ => 5,
        };
        self.0[class].fetch_add(1, Ordering::Relaxed);
    }

    fn write(&self, out: &mut impl Write, name: &str, labels: &str) -> fmt::Result {
        for (count, class) in self.0.iter().zip(CLASSES) {
            let count = count.load(Ordering::Relaxed);
            writeln!(out, "{name}{{{labels},code=\"{class}\"}} {count}")?;
        }
        Ok(())
    }
}

/// The counters of one frontend.
#[derive(Debug, Default)]
pub struct FrontendStats {
    requests: Classes,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    duration: Histogram,
    flows: AtomicU64,
}

impl FrontendStats {
    /// Counts one finished HTTP request. A `status` of zero is an exchange that ended
    /// before a response head.
    pub fn record(&self, status: u16, bytes_in: u64, bytes_out: u64, elapsed: Duration) {
        self.requests.count(status);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        self.duration.observe(elapsed);
    }

    /// Counts one accepted TCP connection or UDP mapping.
    pub fn flow(&self) {
        self.flows.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of finished HTTP requests.
    pub fn request_count(&self) -> u64 {
        self.duration.count()
    }
}

/// The counters and the health state of one server of one backend.
#[derive(Debug, Default)]
pub struct ServerStats {
    requests: Classes,
    failures: AtomicU64,
    /// Requests whose client left before this server answered. No failure of the server.
    client_closed: AtomicU64,
    /// Requests that left this server for another one (SID 0019).
    failovers: AtomicU64,
    /// Times passive health ejected this server (SID 0019).
    ejections: AtomicU64,
    response: Histogram,
    /// HTTP requests that chose this server and have not ended.
    active: AtomicU64,
    /// The flag of the health checker. A pool without checks has none.
    health: Mutex<Option<Arc<AtomicBool>>>,
}

impl ServerStats {
    /// Counts one request this server was chosen for. `first_byte` is the wait for the
    /// first response byte, or `None` when the server did not answer.
    pub fn record(&self, status: u16, first_byte: Option<Duration>) {
        self.requests.count(status);
        match first_byte {
            Some(wait) => self.response.observe(wait),
            None => {
                self.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Counts a request that its client gave up before this server answered: the client
    /// closed its connection or reset its stream. The server did not fail, so this is
    /// neither a failure nor a request with a status.
    pub fn record_client_closed(&self) {
        self.client_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of requests whose client left before this server answered.
    pub fn client_closed_count(&self) -> u64 {
        self.client_closed.load(Ordering::Relaxed)
    }

    /// Counts a request that this server did not answer and that moved to another
    /// server of the pool (SID 0019). The request itself is counted once, under the
    /// server that ends it.
    pub fn record_failover(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.failovers.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one ejection of this server by passive health (SID 0019).
    pub fn record_ejection(&self) {
        self.ejections.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of requests that left this server for another one.
    pub fn failover_count(&self) -> u64 {
        self.failovers.load(Ordering::Relaxed)
    }

    /// The number of times passive health ejected this server.
    pub fn ejection_count(&self) -> u64 {
        self.ejections.load(Ordering::Relaxed)
    }

    /// The number of requests that ended without a response of this server.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// The number of HTTP requests that chose this server and have not ended.
    pub fn active_count(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// True when the last health check passed, or the pool has no check.
    pub fn is_up(&self) -> bool {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health.as_ref().is_none_or(|flag| flag.load(Ordering::Relaxed))
    }

    pub(crate) fn set_health(&self, flag: Option<Arc<AtomicBool>>) {
        *self.health.lock().unwrap_or_else(PoisonError::into_inner) = flag;
    }
}

/// The server a request was sent to, for the access log and the counters.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    /// The name of the backend pool.
    pub backend: Arc<str>,
    /// The name of the server.
    pub server: Arc<str>,
    /// The counters of the server.
    pub stats: Arc<ServerStats>,
}

impl ServerInfo {
    /// Counts a request that chose this server as active until the result is dropped.
    pub fn begin_request(&self) -> ActiveRequest {
        self.stats.active.fetch_add(1, Ordering::Relaxed);
        ActiveRequest(Arc::clone(&self.stats))
    }
}

/// One request in the active gauge of its server. Dropping it ends the count, however
/// the request ended.
#[derive(Debug)]
pub struct ActiveRequest(Arc<ServerStats>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

type Fronts = BTreeMap<Arc<str>, Arc<FrontendStats>>;
type Servers = BTreeMap<(Arc<str>, Arc<str>), Arc<ServerStats>>;

/// The counters of one edge. Create one with `Stats::default()`; [`crate::Edge`] owns one
/// and shares it through [`crate::Edge::stats`].
#[derive(Debug, Default)]
pub struct Stats {
    fronts: Mutex<Fronts>,
    servers: Mutex<Servers>,
    flows_active: AtomicU64,
    flows_limit: AtomicU64,
    drops: AtomicU64,
    proxy_accepted: AtomicU64,
    proxy_rejected: AtomicU64,
    refused: [AtomicU64; Refusal::ALL.len()],
    flow_log_dropped: AtomicU64,
    /// What peer forwarding did (SID 0026). The series appear once it is on.
    pub(crate) forward: Arc<crate::forward::Counters>,
    /// The wall-clock second of the last refusal line, and the lines of that second.
    refusal_lines: AtomicU64,
    /// The addresses with the most refusals this minute (SID 0034).
    top: Mutex<top::Sketch>,
    /// 1 while pressure mode is on (SID 0034).
    pressure: AtomicU64,
    /// How often pressure mode switched on or off.
    pressure_switches: AtomicU64,
    /// Refusals that counted as a strike against their address.
    strikes: AtomicU64,
    /// Addresses banned for their strikes.
    auto_bans: AtomicU64,
}

/// The most log lines for refused connections in one second, for the whole node. A
/// flood of refusals is counted in full and logged at this rate.
pub const REFUSAL_LINES_PER_SECOND: u64 = 10;

/// Why a connection or a request was refused before the firewall decided on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The client opened connections faster than `rate_limit.conn_per_10s` allows.
    RateLimit,
    /// The node holds `global.max_flows` flows.
    FlowLimit,
    /// The node drains and accepts nothing new.
    Draining,
    /// The node holds `http.max_connections` HTTP connections.
    ConnectionLimit,
    /// The client holds `http.max_connections_per_ip` HTTP connections.
    ClientLimit,
    /// No thread was free to serve the connection.
    TaskLimit,
    /// The node runs as many HTTP/2 and HTTP/3 requests as it may.
    ExchangeLimit,
    /// The protocol runtime found the request malformed or unsupported.
    BadRequest,
    /// No server of the pool was eligible, or a rule denied the connection.
    NoServer,
    /// A datagram above `udp_defense.threshold_pps`.
    UdpRateLimit,
    /// No slot was free for a new UDP mapping.
    UdpFlowLimit,
    /// An answer of a UDP server larger than three times what its client sent.
    UdpReplyLimit,
    /// The client gave its request up before the firewall could decide on it. Nothing
    /// was refused: the reason keeps such a request apart from a malformed one.
    ClientClosed,
    /// A connection hook denied the connection or the UDP mapping (SID 0030).
    Hook,
    /// A rule or a fallback of a TLS passthrough inspection refused the connection
    /// (SID 0032).
    InspectDenied,
    /// A datagram that may not open a QUIC mapping: no padded long-header packet
    /// (SID 0032).
    UdpNotQuic,
    /// The client address is banned (SID 0034).
    Banned,
    /// Pressure mode is on and no token was left for a new address (SID 0034).
    Pressure,
    /// The frontend holds its `max_flows` flows (SID 0034).
    FrontendLimit,
    /// The client address holds `max_flows_per_ip` flows of the frontend (SID 0034).
    ClientFlowLimit,
    /// A datagram above `udp_defense.total_pps` of the frontend (SID 0034).
    UdpTotalLimit,
}

impl Refusal {
    /// Every reason, in the order of the series.
    pub const ALL: [Refusal; 21] = [
        Refusal::RateLimit,
        Refusal::FlowLimit,
        Refusal::Draining,
        Refusal::ConnectionLimit,
        Refusal::ClientLimit,
        Refusal::TaskLimit,
        Refusal::ExchangeLimit,
        Refusal::BadRequest,
        Refusal::NoServer,
        Refusal::UdpRateLimit,
        Refusal::UdpFlowLimit,
        Refusal::UdpReplyLimit,
        Refusal::ClientClosed,
        Refusal::Hook,
        Refusal::InspectDenied,
        Refusal::UdpNotQuic,
        Refusal::Banned,
        Refusal::Pressure,
        Refusal::FrontendLimit,
        Refusal::ClientFlowLimit,
        Refusal::UdpTotalLimit,
    ];

    /// The value of the `reason` label.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::RateLimit => "rate_limit",
            Refusal::FlowLimit => "flow_limit",
            Refusal::Draining => "draining",
            Refusal::ConnectionLimit => "connection_limit",
            Refusal::ClientLimit => "client_limit",
            Refusal::TaskLimit => "task_limit",
            Refusal::ExchangeLimit => "exchange_limit",
            Refusal::BadRequest => "bad_request",
            Refusal::NoServer => "no_server",
            Refusal::UdpRateLimit => "udp_rate_limit",
            Refusal::UdpFlowLimit => "udp_flow_limit",
            Refusal::UdpReplyLimit => "udp_reply_limit",
            Refusal::ClientClosed => "client_closed",
            Refusal::Hook => "hook",
            Refusal::InspectDenied => "inspect_denied",
            Refusal::UdpNotQuic => "udp_not_quic",
            Refusal::Banned => "banned",
            Refusal::Pressure => "pressure",
            Refusal::FrontendLimit => "frontend_limit",
            Refusal::ClientFlowLimit => "client_flow_limit",
            Refusal::UdpTotalLimit => "udp_total_limit",
        }
    }

    /// The `end` field of the log line of a connection refused for this reason.
    pub fn end(self) -> &'static str {
        match self {
            Refusal::RateLimit => "refused_rate_limit",
            Refusal::FlowLimit => "refused_flow_limit",
            Refusal::Draining => "refused_draining",
            Refusal::ConnectionLimit => "refused_connection_limit",
            Refusal::ClientLimit => "refused_client_limit",
            Refusal::TaskLimit => "refused_task_limit",
            Refusal::ExchangeLimit => "refused_exchange_limit",
            Refusal::BadRequest => "refused_bad_request",
            Refusal::NoServer => "refused_no_server",
            Refusal::UdpRateLimit => "refused_udp_rate_limit",
            Refusal::UdpFlowLimit => "refused_udp_flow_limit",
            Refusal::UdpReplyLimit => "refused_udp_reply_limit",
            Refusal::ClientClosed => "refused_client_closed",
            Refusal::Hook => "refused_hook",
            Refusal::InspectDenied => "inspect_denied",
            Refusal::UdpNotQuic => "refused_udp_not_quic",
            Refusal::Banned => "refused_banned",
            Refusal::Pressure => "refused_pressure",
            Refusal::FrontendLimit => "refused_frontend_limit",
            Refusal::ClientFlowLimit => "refused_client_flow_limit",
            Refusal::UdpTotalLimit => "refused_udp_total_limit",
        }
    }

    /// True when a refusal for this reason is a strike against its address: the
    /// address completed a TCP handshake, so it is real, and broke its own limit.
    pub fn is_strike(self) -> bool {
        matches!(self, Refusal::RateLimit | Refusal::ClientFlowLimit)
    }
}

impl Stats {
    /// Gives every frontend and server of `config` its block of counters, creating the
    /// blocks of new names and forgetting the names that `config` no longer has.
    pub(crate) fn adopt(&self, config: &mut crate::Config) {
        let mut fronts = self.fronts.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = Fronts::new();
        for front in config.listeners.values_mut() {
            let name = front.info.name.clone();
            let stats = fronts.get(&name).cloned().unwrap_or_default();
            kept.insert(name, stats.clone());
            front.info = Arc::new(crate::FrontendInfo { stats, ..(*front.info).clone() });
        }
        *fronts = kept;
        drop(fronts);
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = Servers::new();
        for (pool, backend) in &mut config.pools {
            let pool: Arc<str> = pool.as_str().into();
            for server in &mut backend.servers {
                let key = (pool.clone(), Arc::<str>::from(server.name.as_str()));
                let stats = servers.get(&key).cloned().unwrap_or_default();
                stats.set_health(server.healthy.clone());
                server.info =
                    Some(ServerInfo { backend: key.0.clone(), server: key.1.clone(), stats });
                if let Some(info) = &server.info {
                    kept.insert(key, info.stats.clone());
                }
            }
        }
        *servers = kept;
        self.flows_limit.store(config.limit as u64, Ordering::Relaxed);
    }

    /// The counters of a server that joins `pool` at run time (SID 0018). A name that
    /// was counted before continues.
    pub(crate) fn enlist(&self, pool: &str, server: &crate::config::Server) -> ServerInfo {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (Arc::<str>::from(pool), Arc::<str>::from(server.name.as_str()));
        let stats = servers.entry(key.clone()).or_default().clone();
        stats.set_health(server.healthy.clone());
        ServerInfo { backend: key.0, server: key.1, stats }
    }

    /// Forgets the series of a server that left `pool` at run time (SID 0018). Requests
    /// that still hold its counters end without a series.
    pub(crate) fn retire(&self, pool: &str, server: &str) {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        servers.retain(|(backend, name), _| !(&**backend == pool && &**name == server));
    }

    /// Counts one refusal by its reason.
    pub fn refuse(&self, reason: Refusal) {
        self.refused[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one refusal of the client at `address` by its reason, and counts the
    /// address in the sketch of the minute of the Unix second `now`. Under contention
    /// the sketch skips the refusal: the heavy sources stay heavy in a sample.
    pub fn refuse_from(&self, reason: Refusal, address: std::net::IpAddr, now: u64) {
        self.refuse(reason);
        let address =
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(sibuna_cidr::client_key(address, 64)));
        let address = address.to_canonical();
        if let Ok(mut top) = self.top.try_lock() {
            top.add(address, reason, now);
        }
    }

    /// The addresses with the most refusals in the minute of the Unix second `now`.
    pub fn top_sources(&self, now: u64) -> Vec<TopSource> {
        self.top.lock().unwrap_or_else(PoisonError::into_inner).top(now)
    }

    /// Publishes the pressure mode of the node. A change counts as a switch.
    pub fn set_pressure(&self, on: bool) {
        let previous = self.pressure.swap(u64::from(on), Ordering::Relaxed);
        if previous != u64::from(on) {
            self.pressure_switches.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// True while pressure mode is on.
    pub fn is_pressed(&self) -> bool {
        self.pressure.load(Ordering::Relaxed) == 1
    }

    /// Counts a strike, and with `banned` the automatic ban it caused.
    pub fn count_strike(&self, banned: bool) {
        self.strikes.fetch_add(1, Ordering::Relaxed);
        if banned {
            self.auto_bans.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The number of refusals for `reason`.
    pub fn refusal_count(&self, reason: Refusal) -> u64 {
        self.refused[reason as usize].load(Ordering::Relaxed)
    }

    /// True when a refused connection may write a log line now: at most
    /// [`REFUSAL_LINES_PER_SECOND`] per second. `now` is the Unix time in seconds.
    pub fn may_log_refusal(&self, now: u64) -> bool {
        let mut word = self.refusal_lines.load(Ordering::Acquire);
        loop {
            let (second, lines) = (word >> 8, word & 0xff);
            let next = if second != now {
                now << 8 | 1
            } else if lines < REFUSAL_LINES_PER_SECOND {
                word + 1
            } else {
                return false;
            };
            let swap = self.refusal_lines.compare_exchange_weak(
                word,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            match swap {
                Ok(_) => return true,
                Err(current) => word = current,
            }
        }
    }

    /// Counts a flow line that found its queue full.
    pub fn count_flow_log_drop(&self) {
        self.flow_log_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of flow lines dropped because a queue was full.
    pub fn flow_log_drop_count(&self) -> u64 {
        self.flow_log_dropped.load(Ordering::Relaxed)
    }

    /// Counts a connection of a PROXY frontend: one that sent a valid header, or one
    /// that was closed.
    pub fn count_proxy(&self, accepted: bool) {
        let counter = if accepted { &self.proxy_accepted } else { &self.proxy_rejected };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Publishes the size of the flow table and the drop counter of the edge.
    pub fn set_flows(&self, active: usize, drops: u64) {
        self.flows_active.store(active as u64, Ordering::Relaxed);
        self.drops.store(drops, Ordering::Relaxed);
    }

    /// Writes every series in the Prometheus text format.
    ///
    /// # Errors
    ///
    /// Only the error of `out`.
    pub fn write_prometheus(&self, out: &mut impl Write) -> fmt::Result {
        let gauges = [
            ("sibuna_edge_flows_active", "gauge", &self.flows_active),
            ("sibuna_edge_flows_limit", "gauge", &self.flows_limit),
            ("sibuna_edge_drops_total", "counter", &self.drops),
            ("sibuna_edge_proxy_protocol_accepted_total", "counter", &self.proxy_accepted),
            ("sibuna_edge_proxy_protocol_rejected_total", "counter", &self.proxy_rejected),
            ("sibuna_edge_flow_log_dropped_total", "counter", &self.flow_log_dropped),
            ("sibuna_edge_pressure", "gauge", &self.pressure),
            ("sibuna_edge_pressure_switches_total", "counter", &self.pressure_switches),
            ("sibuna_edge_strikes_total", "counter", &self.strikes),
            ("sibuna_edge_auto_bans_total", "counter", &self.auto_bans),
        ];
        for (name, kind, value) in gauges {
            writeln!(out, "# TYPE {name} {kind}\n{name} {}", value.load(Ordering::Relaxed))?;
        }
        out.write_str("# TYPE sibuna_edge_refused_total counter\n")?;
        for reason in Refusal::ALL {
            let count = self.refusal_count(reason);
            writeln!(out, "sibuna_edge_refused_total{{reason=\"{}\"}} {count}", reason.name())?;
        }
        self.forward.write_prometheus(out)?;
        let fronts = self.fronts.lock().unwrap_or_else(PoisonError::into_inner).clone();
        write_fronts(out, &fronts)?;
        let servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner).clone();
        write_servers(out, &servers)
    }
}

fn write_fronts(out: &mut impl Write, fronts: &Fronts) -> fmt::Result {
    out.write_str("# TYPE sibuna_edge_frontend_requests_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_frontend_bytes_in_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_frontend_bytes_out_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_frontend_flows_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_frontend_request_seconds histogram\n")?;
    let mut labels = String::new();
    for (name, stats) in fronts {
        labels.clear();
        labels.push_str("frontend=");
        write_label(&mut labels, name);
        stats.requests.write(out, "sibuna_edge_frontend_requests_total", &labels)?;
        let counters = [
            ("sibuna_edge_frontend_bytes_in_total", &stats.bytes_in),
            ("sibuna_edge_frontend_bytes_out_total", &stats.bytes_out),
            ("sibuna_edge_frontend_flows_total", &stats.flows),
        ];
        for (series, value) in counters {
            writeln!(out, "{series}{{{labels}}} {}", value.load(Ordering::Relaxed))?;
        }
        stats.duration.write(out, "sibuna_edge_frontend_request_seconds", &labels)?;
    }
    Ok(())
}

fn write_servers(out: &mut impl Write, servers: &Servers) -> fmt::Result {
    out.write_str("# TYPE sibuna_edge_server_requests_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_server_failures_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_server_client_closed_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_server_failovers_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_server_ejections_total counter\n")?;
    out.write_str("# TYPE sibuna_edge_server_up gauge\n")?;
    out.write_str("# TYPE sibuna_edge_server_active_requests gauge\n")?;
    out.write_str("# TYPE sibuna_edge_server_response_seconds histogram\n")?;
    let mut labels = String::new();
    for ((backend, server), stats) in servers {
        labels.clear();
        labels.push_str("backend=");
        write_label(&mut labels, backend);
        labels.push_str(",server=");
        write_label(&mut labels, server);
        stats.requests.write(out, "sibuna_edge_server_requests_total", &labels)?;
        let failures = stats.failure_count();
        writeln!(out, "sibuna_edge_server_failures_total{{{labels}}} {failures}")?;
        let left = stats.client_closed_count();
        writeln!(out, "sibuna_edge_server_client_closed_total{{{labels}}} {left}")?;
        let (moved, ejected) = (stats.failover_count(), stats.ejection_count());
        writeln!(out, "sibuna_edge_server_failovers_total{{{labels}}} {moved}")?;
        writeln!(out, "sibuna_edge_server_ejections_total{{{labels}}} {ejected}")?;
        writeln!(out, "sibuna_edge_server_up{{{labels}}} {}", u8::from(stats.is_up()))?;
        let active = stats.active_count();
        writeln!(out, "sibuna_edge_server_active_requests{{{labels}}} {active}")?;
        stats.response.write(out, "sibuna_edge_server_response_seconds", &labels)?;
    }
    Ok(())
}

/// Appends `value` as a quoted label value, escaping what the text format reserves.
fn write_label(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_histogram_is_cumulative_and_counts_every_observation() {
        let histogram = Histogram::default();
        histogram.observe(Duration::from_micros(900));
        histogram.observe(Duration::from_millis(3));
        histogram.observe(Duration::from_secs(45));
        let mut text = String::new();
        histogram.write(&mut text, "t", "a=\"b\"").unwrap();
        assert!(text.contains("t_bucket{a=\"b\",le=\"0.001\"} 1\n"), "{text}");
        assert!(text.contains("t_bucket{a=\"b\",le=\"0.005\"} 2\n"), "{text}");
        assert!(text.contains("t_bucket{a=\"b\",le=\"30\"} 2\n"), "{text}");
        assert!(text.contains("t_bucket{a=\"b\",le=\"+Inf\"} 3\n"), "{text}");
        assert!(text.contains("t_sum{a=\"b\"} 45.003900\n"), "{text}");
        assert!(text.contains("t_count{a=\"b\"} 3\n"), "{text}");
    }

    #[test]
    fn responses_are_counted_by_class_and_a_missing_status_has_its_own() {
        let stats = FrontendStats::default();
        stats.record(200, 10, 20, Duration::from_millis(1));
        stats.record(404, 1, 2, Duration::from_millis(1));
        stats.record(0, 0, 0, Duration::from_millis(1));
        let mut text = String::new();
        stats.requests.write(&mut text, "r", "f=\"x\"").unwrap();
        assert!(text.contains("r{f=\"x\",code=\"2xx\"} 1\n"), "{text}");
        assert!(text.contains("r{f=\"x\",code=\"4xx\"} 1\n"), "{text}");
        assert!(text.contains("r{f=\"x\",code=\"none\"} 1\n"), "{text}");
        assert_eq!(stats.request_count(), 3);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn a_server_without_an_answer_is_a_failure_and_health_follows_the_flag() {
        let stats = ServerStats::default();
        stats.record(200, Some(Duration::from_millis(2)));
        stats.record(502, None);
        assert_eq!(stats.failure_count(), 1);
        assert!(stats.is_up(), "no check means up");
        let flag = Arc::new(AtomicBool::new(false));
        stats.set_health(Some(flag.clone()));
        assert!(!stats.is_up());
        flag.store(true, Ordering::Relaxed);
        assert!(stats.is_up());
    }

    #[test]
    fn label_values_are_escaped() {
        let mut out = String::new();
        write_label(&mut out, "a\"b\\c\nd");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\"");
    }
}

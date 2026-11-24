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
    response: Histogram,
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

    /// The number of requests that ended without a response of this server.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
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
        ];
        for (name, kind, value) in gauges {
            writeln!(out, "# TYPE {name} {kind}\n{name} {}", value.load(Ordering::Relaxed))?;
        }
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
    out.write_str("# TYPE sibuna_edge_server_up gauge\n")?;
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
        writeln!(out, "sibuna_edge_server_up{{{labels}}} {}", u8::from(stats.is_up()))?;
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

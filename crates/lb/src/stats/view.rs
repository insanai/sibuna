//! The counters as plain data, for a reader that shows them (SID 0031). The metrics
//! endpoint writes the same counters as text. Reading them takes the two short locks of
//! the name tables and loads atomics. No request path waits for a reader.

use std::sync::Arc;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{BOUNDS_MICROS, Classes, Histogram, Refusal, Stats};

/// The latency of a series: its mean and the bound of the bucket of its 95th percentile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Latency {
    /// The number of observations.
    pub count: u64,
    /// The mean in microseconds, 0 without observations.
    pub mean_micros: u64,
    /// The upper bound of the bucket that holds the 95th percentile, in microseconds.
    /// `None` without observations, or when the percentile lies above 30 seconds.
    pub p95_micros: Option<u64>,
}

/// The counters of one frontend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontendView {
    /// The name of the frontend in the topology.
    pub name: Arc<str>,
    /// Finished HTTP requests.
    pub requests: u64,
    /// Accepted TCP connections and UDP mappings.
    pub flows: u64,
    /// Bytes received from clients.
    pub bytes_in: u64,
    /// Bytes sent to clients.
    pub bytes_out: u64,
    /// The duration of a request.
    pub latency: Latency,
}

/// The counters of one server of one backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerView {
    /// The name of the backend pool.
    pub backend: Arc<str>,
    /// The name of the server.
    pub server: Arc<str>,
    /// Requests the server was chosen for.
    pub requests: u64,
    /// Requests the server failed.
    pub failures: u64,
    /// Requests that chose the server and have not ended.
    pub active: u64,
    /// The wait for the first byte of a response.
    pub latency: Latency,
}

/// Every counter of an edge at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsView {
    /// The flows in the table.
    pub flows_active: u64,
    /// The size of the table (`global.max_flows`).
    pub flows_limit: u64,
    /// Flows and datagrams dropped by the edge.
    pub drops: u64,
    /// Refusals by reason, in the order of [`Refusal::ALL`].
    pub refused: Vec<(Refusal, u64)>,
    /// The addresses with the most refusals in the current minute (SID 0034).
    pub top_refused: Vec<super::TopSource>,
    /// Whether pressure mode is on (SID 0034).
    pub pressure: bool,
    /// Flow lines that found the queue of the access log full.
    pub flow_log_dropped: u64,
    /// The frontends, by name.
    pub frontends: Vec<FrontendView>,
    /// The servers, by backend and name.
    pub servers: Vec<ServerView>,
}

impl Histogram {
    /// The mean and the 95th percentile of the observations so far.
    fn latency(&self) -> Latency {
        let count = self.count();
        if count == 0 {
            return Latency::default();
        }
        let sum = self.sum_micros.load(Ordering::Relaxed);
        // The rank of the percentile, rounded up: the 95th of 20 observations is the 19th.
        let rank = (count.saturating_mul(95)).div_ceil(100);
        let mut running = 0u64;
        let mut p95_micros = None;
        for (bucket, bound) in self.buckets.iter().zip(BOUNDS_MICROS) {
            running = running.saturating_add(bucket.load(Ordering::Relaxed));
            if running >= rank {
                p95_micros = Some(bound);
                break;
            }
        }
        Latency { count, mean_micros: sum / count, p95_micros }
    }
}

impl Classes {
    /// The responses of every class together.
    fn total(&self) -> u64 {
        self.0.iter().map(|count| count.load(Ordering::Relaxed)).sum()
    }
}

/// The Unix time in seconds, zero before 1970.
fn unix_now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |since| since.as_secs())
}

impl Stats {
    /// Reads every counter. The result owns its data and borrows nothing.
    pub fn view(&self) -> StatsView {
        let fronts = self.fronts.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsView {
            flows_active: load(&self.flows_active),
            flows_limit: load(&self.flows_limit),
            drops: load(&self.drops),
            refused: Refusal::ALL.iter().map(|&r| (r, self.refusal_count(r))).collect(),
            top_refused: self.top_sources(unix_now()),
            pressure: self.is_pressed(),
            flow_log_dropped: self.flow_log_drop_count(),
            frontends: fronts
                .iter()
                .map(|(name, stats)| FrontendView {
                    name: name.clone(),
                    requests: stats.request_count(),
                    flows: load(&stats.flows),
                    bytes_in: load(&stats.bytes_in),
                    bytes_out: load(&stats.bytes_out),
                    latency: stats.duration.latency(),
                })
                .collect(),
            servers: servers
                .iter()
                .map(|((backend, server), stats)| ServerView {
                    backend: backend.clone(),
                    server: server.clone(),
                    requests: stats.requests.total(),
                    failures: stats.failure_count(),
                    active: stats.active_count(),
                    latency: stats.response.latency(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn the_percentile_is_the_bound_of_its_bucket() {
        let histogram = Histogram::default();
        assert_eq!(histogram.latency(), Latency::default());
        for _ in 0..19 {
            histogram.observe(Duration::from_micros(800));
        }
        histogram.observe(Duration::from_millis(40));
        let latency = histogram.latency();
        assert_eq!(latency.count, 20);
        assert_eq!(latency.p95_micros, Some(1_000), "the 19th of 20 is in the first bucket");
        assert_eq!(latency.mean_micros, (19 * 800 + 40_000) / 20);
        histogram.observe(Duration::from_millis(40));
        histogram.observe(Duration::from_millis(40));
        assert_eq!(histogram.latency().p95_micros, Some(50_000));
        let slow = Histogram::default();
        slow.observe(Duration::from_secs(90));
        assert_eq!(slow.latency().p95_micros, None, "above the last bound");
    }

    #[test]
    fn the_view_holds_what_the_metrics_hold() {
        let stats = Stats::default();
        stats.refuse(Refusal::FlowLimit);
        stats.refuse(Refusal::FlowLimit);
        stats.set_flows(3, 7);
        let view = stats.view();
        assert_eq!((view.flows_active, view.drops), (3, 7));
        assert_eq!(view.refused.len(), Refusal::ALL.len());
        assert!(view.refused.contains(&(Refusal::FlowLimit, 2)));
        assert!(view.frontends.is_empty() && view.servers.is_empty());
    }
}

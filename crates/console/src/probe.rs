//! Data-plane probes (unit U6; Zig's `cluster_probe.zig`): every 5 seconds, `GET
//! /__sibuna/health` and `/__sibuna/metrics` of each configured `--console-probe` target,
//! 2 seconds per probe, plain HTTP to numeric addresses only.
//!
//! One console thread probes the targets in turn; the results are copied under a mutex
//! that only that thread and readers of [`Probes::snapshot`] take. Nothing here runs on a
//! request thread or reads engine state. A target that answers 200 is healthy, 503
//! degraded (draining), anything else or no answer down; a healthy target that goes down
//! raises a `node_unhealthy` notification. `requests` is the difference of the
//! `sibuna_requests_total` counter between the last two successful probes.
//!
//! Changes from Zig: the reply buffer belongs to the probe thread instead of a
//! thread-local static; the thread is always started and returns at once when nothing is
//! configured, where Zig did not start it; and each socket step blocks at most 250 ms
//! before it checks whether the console is stopping, so a silent target never delays a
//! stop.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console_protocol::nodes::{Health, Probe};
use sibuna_console_protocol::notifications::Event;
use sibuna_net::parse_response_head;

use crate::client::Socket;
use crate::config::parse_probe;
use crate::shared::{Setup, Shared};

/// How often every target is probed.
pub const INTERVAL: Duration = Duration::from_secs(5);
/// The bound of one request.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// The most reply bytes read.
const REPLY_BYTES: usize = 4096;
/// The metrics family whose counter `requests` is derived from (the trailing space makes
/// the match exact).
const REQUESTS: &str = "sibuna_requests_total ";

/// One configured target.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    node: u32,
    address: SocketAddr,
    /// The host as written, for the `Host` field.
    host: String,
}

/// The latest verdict of every configured probe.
#[derive(Debug, Default)]
pub struct Probes {
    targets: Vec<Target>,
    results: Mutex<Vec<Probe>>,
}

impl Probes {
    /// Returns the probes of the configuration, all unprobed. The configuration was
    /// validated at start, so every probe parses.
    pub fn new(setup: &Setup<'_>) -> Probes {
        let targets: Vec<Target> = setup
            .config
            .probes
            .iter()
            .filter_map(|probe| {
                let parsed = parse_probe(&probe.url).ok()?;
                Some(Target { node: probe.node, address: parsed.address, host: parsed.host })
            })
            .collect();
        let results = targets.iter().map(|target| Probe { node: target.node, ..Probe::default() });
        Probes { results: Mutex::new(results.collect()), targets }
    }

    /// Replaces the contents of `out` with the latest verdict of each configured probe, in
    /// configuration order (at most eight).
    pub fn snapshot(&self, out: &mut Vec<Probe>) {
        out.clear();
        out.extend_from_slice(&self.results.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Stores `observed` as target `index`'s verdict and returns the previous one.
    fn store(&self, index: usize, observed: Probe) -> Option<Probe> {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = results.get_mut(index)?;
        Some(std::mem::replace(slot, observed))
    }

    fn result(&self, index: usize) -> Probe {
        let results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.get(index).copied().unwrap_or_default()
    }
}

/// The probe thread's body: returns at once without targets, otherwise when the console
/// stops.
pub fn run(shared: &Shared) {
    let probes = &shared.probes;
    if probes.targets.is_empty() {
        return;
    }
    let mut counters = vec![0u64; probes.targets.len()];
    let mut buffer = vec![0u8; REPLY_BYTES];
    loop {
        let started = Instant::now();
        for (index, target) in probes.targets.iter().enumerate() {
            if shared.is_stopping() {
                return;
            }
            let previous = probes.result(index);
            let counter = counters.get_mut(index);
            let observed = probe_one(shared, target, previous, counter, &mut buffer);
            let before = probes.store(index, observed).unwrap_or_default();
            if before.health == Health::Healthy && observed.health == Health::Down {
                let detail = format!("node {} unreachable", target.node);
                shared.notifier.raise(Event::NodeUnhealthy, observed.observed_at, &detail);
            }
        }
        if !shared.sleep(INTERVAL.saturating_sub(started.elapsed())) {
            return;
        }
    }
}

/// Probes `target` once and returns the new verdict, starting from `previous`.
fn probe_one(
    shared: &Shared,
    target: &Target,
    previous: Probe,
    counter: Option<&mut u64>,
    buffer: &mut [u8],
) -> Probe {
    let now = shared.now();
    let mut result = Probe { observed_at: now, ..previous };
    let started = Instant::now();
    let Some(health) = request(shared, target, "/__sibuna/health", buffer) else {
        result.health = Health::Down;
        return result;
    };
    let elapsed = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    result.latency_ms = elapsed;
    result.health = match health.status {
        200 => Health::Healthy,
        503 => Health::Degraded,
        _ => Health::Down,
    };
    if result.health == Health::Down {
        return result;
    }
    result.last_seen = now;
    result.draining = health.status == 503;
    if let (Some(metrics), Some(counter)) =
        (request(shared, target, "/__sibuna/metrics", buffer), counter)
        && let Some(total) =
            buffer.get(metrics.body).and_then(|body| requests_counter(body, REQUESTS))
    {
        if *counter != 0 && total >= *counter {
            result.requests = total - *counter;
        }
        *counter = total;
    }
    result
}

/// A reply: its status and where its body lies in the buffer.
struct Reply {
    status: u16,
    body: std::ops::Range<usize>,
}

/// One bounded `GET path`: connect, write and read until the target closes, all within
/// [`PROBE_TIMEOUT`], into `buffer`; then parse the status line. Every socket step blocks
/// at most 250 ms before it checks whether the console is stopping. Returns `None` when the
/// target cannot be reached, does not close in time, or answers no valid head.
fn request(shared: &Shared, target: &Target, path: &str, buffer: &mut [u8]) -> Option<Reply> {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let stopping = || shared.is_stopping();
    let mut socket = Socket::connect(target.address, deadline, &stopping).ok()?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         User-Agent: sibuna-console-probe\r\n\r\n",
        target.host
    );
    socket.write_all(head.as_bytes()).ok()?;
    let mut length = 0;
    while let Some(space) = buffer.get_mut(length..).filter(|space| !space.is_empty()) {
        match socket.read(space).ok()? {
            0 => break,
            count => length += count,
        }
    }
    let received = buffer.get(..length)?;
    let end = received.windows(4).position(|window| window == b"\r\n\r\n")?;
    let parsed = parse_response_head(received.get(..end + 4)?, false)?;
    Some(Reply { status: parsed.status, body: end + 4..length })
}

/// Returns the value of the first line that starts with `name` (the family name and a
/// space), as a decimal counter.
fn requests_counter(body: &[u8], name: &str) -> Option<u64> {
    let text = std::str::from_utf8(body).ok()?;
    let line = text.split('\n').find(|line| line.starts_with(name))?;
    line.get(name.len()..)?.trim_matches([' ', '\r']).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // cluster_probe.zig: "prometheus counters are located by exact family name".
    #[test]
    fn prometheus_counters_are_located_by_exact_family_name() {
        let body = b"# HELP x\nsibuna_requests_total 42\nsibuna_requests_total_other 7\n";
        assert_eq!(requests_counter(body, REQUESTS), Some(42));
        assert_eq!(requests_counter(body, "sibuna_denied_total "), None);
        assert_eq!(requests_counter(b"sibuna_requests_total x\n", REQUESTS), None);
        assert_eq!(requests_counter(b"sibuna_requests_total 5\r\n", REQUESTS), Some(5));
    }
}

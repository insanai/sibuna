//! The counters of peer forwarding (SID 0026). They are atomics, so the relay threads
//! and the metrics reader share them with the worker without a lock.

use std::fmt::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Why a flow of another node's client was served here.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Local {
    /// The owner answered that it cannot take the flow now.
    Declined,
    /// The connect to the owner failed.
    ConnectFailed,
    /// The owner did not answer in time.
    Timeout,
    /// This node forwards as many flows to the owner as it may.
    PeerLimit,
}

/// Why something on the forwarding port was refused.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Rejected {
    /// The source is no node of the roster.
    Stranger,
    /// The tag is wrong.
    BadTag,
    /// The header names another start of this node.
    Stale,
    /// The bytes are no header, or too few.
    Malformed,
    /// No such frontend, or no such forwarded client.
    Unknown,
}

const LOCAL: [&str; 4] = ["declined", "connect_failed", "timeout", "peer_limit"];
const REJECTED: [&str; 5] = ["stranger", "bad_tag", "stale", "malformed", "unknown"];

/// What forwarding did so far. The series appear once forwarding is on.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    on: AtomicBool,
    active: AtomicU64,
    eligible: AtomicU64,
    flows_out: AtomicU64,
    streams_out: AtomicU64,
    streams_in: AtomicU64,
    datagrams_out: AtomicU64,
    datagrams_in: AtomicU64,
    datagrams_returned: AtomicU64,
    denied: AtomicU64,
    local: [AtomicU64; LOCAL.len()],
    rejected: [AtomicU64; REJECTED.len()],
}

fn add(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl Counters {
    /// Makes the series appear: the edge has a forwarding port.
    pub fn turn_on(&self) {
        self.on.store(true, Ordering::Relaxed);
    }

    /// `active` says whether the node forwards now: the mesh is regional.
    pub fn set_gauges(&self, active: bool, eligible: u64, flows_out: u64) {
        self.active.store(u64::from(active), Ordering::Relaxed);
        self.eligible.store(eligible, Ordering::Relaxed);
        self.flows_out.store(flows_out, Ordering::Relaxed);
    }

    pub fn stream_out(&self) {
        add(&self.streams_out);
    }

    pub fn stream_in(&self) {
        add(&self.streams_in);
    }

    pub fn datagram_out(&self) {
        add(&self.datagrams_out);
    }

    pub fn datagram_in(&self) {
        add(&self.datagrams_in);
    }

    pub fn datagram_returned(&self) {
        add(&self.datagrams_returned);
    }

    pub fn denied(&self) {
        add(&self.denied);
    }

    pub fn local(&self, reason: Local) {
        add(&self.local[reason as usize]);
    }

    pub fn rejected(&self, reason: Rejected) {
        add(&self.rejected[reason as usize]);
    }

    /// Writes the series in the Prometheus text format, or nothing while forwarding is
    /// off.
    ///
    /// # Errors
    ///
    /// Only the error of `out`.
    pub fn write_prometheus(&self, out: &mut impl Write) -> fmt::Result {
        if !self.on.load(Ordering::Relaxed) {
            return Ok(());
        }
        let series = [
            ("sibuna_edge_forward_active", "gauge", &self.active),
            ("sibuna_edge_forward_peers_eligible", "gauge", &self.eligible),
            ("sibuna_edge_forward_flows_out", "gauge", &self.flows_out),
            ("sibuna_edge_forward_streams_out_total", "counter", &self.streams_out),
            ("sibuna_edge_forward_streams_in_total", "counter", &self.streams_in),
            ("sibuna_edge_forward_datagrams_out_total", "counter", &self.datagrams_out),
            ("sibuna_edge_forward_datagrams_in_total", "counter", &self.datagrams_in),
            ("sibuna_edge_forward_datagrams_returned_total", "counter", &self.datagrams_returned),
            ("sibuna_edge_forward_denied_total", "counter", &self.denied),
        ];
        for (name, kind, value) in series {
            writeln!(out, "# TYPE {name} {kind}\n{name} {}", value.load(Ordering::Relaxed))?;
        }
        let labelled = [
            ("sibuna_edge_forward_local_total", &LOCAL[..], &self.local[..]),
            ("sibuna_edge_forward_rejected_total", &REJECTED[..], &self.rejected[..]),
        ];
        for (name, reasons, values) in labelled {
            writeln!(out, "# TYPE {name} counter")?;
            for (reason, value) in reasons.iter().zip(values) {
                let value = value.load(Ordering::Relaxed);
                writeln!(out, "{name}{{reason=\"{reason}\"}} {value}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_series_appear_only_with_forwarding_on() {
        let counters = Counters::default();
        let mut text = String::new();
        counters.write_prometheus(&mut text).expect("write");
        assert!(text.is_empty());
        counters.turn_on();
        counters.local(Local::PeerLimit);
        counters.rejected(Rejected::Stranger);
        counters.stream_out();
        counters.set_gauges(true, 2, 5);
        counters.write_prometheus(&mut text).expect("write");
        for line in [
            "sibuna_edge_forward_peers_eligible 2",
            "sibuna_edge_forward_flows_out 5",
            "sibuna_edge_forward_streams_out_total 1",
            "sibuna_edge_forward_local_total{reason=\"peer_limit\"} 1",
            "sibuna_edge_forward_local_total{reason=\"declined\"} 0",
            "sibuna_edge_forward_rejected_total{reason=\"stranger\"} 1",
        ] {
            assert!(text.lines().any(|found| found == line), "{line} in\n{text}");
        }
    }
}

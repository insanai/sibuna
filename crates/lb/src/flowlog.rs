//! One log line per ended TCP connection or UDP mapping (SID 0020).
//!
//! ```text
//!  relay threads --try_send--+
//!                            v
//!  worker -------try_send--> [ 4,096 flow ends ] --> Edge::ended_flows()
//!                            | full: drop, count
//! ```
//!
//! A flow carries a [`FlowGuard`] from its first packet. Dropping the guard offers the
//! line, so a flow that ends anywhere in the worker or in a relay thread is logged once.
//! No thread waits here: a full channel drops the line and counts it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant, SystemTime};

use crate::Stats;

/// The most flow ends that wait for [`crate::Edge::ended_flows`].
const QUEUE: usize = 4096;

/// What became of one TCP connection or UDP mapping.
#[derive(Clone, Debug)]
pub struct FlowEnd {
    /// When the flow ended.
    pub ended: SystemTime,
    /// From the accepted connection, or the first datagram, to the end.
    pub duration: Duration,
    /// `tcp` or `udp`.
    pub protocol: &'static str,
    /// The client: the source of a PROXY header, or the socket peer.
    pub client: SocketAddr,
    /// The name of the frontend.
    pub frontend: Arc<str>,
    /// The name of the backend pool.
    pub backend: Arc<str>,
    /// The server the flow reached, if any.
    pub server: Option<SocketAddr>,
    /// Payload bytes from the client.
    pub bytes_in: u64,
    /// Payload bytes to the client.
    pub bytes_out: u64,
    /// Why the flow ended, such as `client_closed` or `idle_timeout`.
    pub end: &'static str,
}

/// The sending side of the flow lines, shared by the worker and the relay threads.
pub(crate) struct FlowLog {
    on: AtomicBool,
    sender: SyncSender<FlowEnd>,
    stats: Arc<Stats>,
}

impl FlowLog {
    /// A log that is off, and the receiving end of its lines.
    pub fn new(stats: Arc<Stats>) -> (Arc<Self>, Receiver<FlowEnd>) {
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        (Arc::new(Self { on: AtomicBool::new(false), sender, stats }), receiver)
    }

    /// Turns the lines on or off. Flows that began while they were off stay unlogged.
    pub fn set(&self, on: bool) {
        self.on.store(on, Ordering::Release);
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Acquire)
    }

    /// Offers one line. A full channel drops it and counts the drop. Never waits.
    pub fn offer(&self, end: FlowEnd) {
        if self.sender.try_send(end).is_err() {
            self.stats.count_flow_log_drop();
        }
    }

    /// Starts the line of a flow, or `None` while the lines are off.
    pub fn begin(
        self: &Arc<Self>,
        protocol: &'static str,
        client: SocketAddr,
        frontend: &Arc<str>,
        backend: &Arc<str>,
    ) -> Option<FlowGuard> {
        self.is_on().then(|| FlowGuard {
            log: Arc::clone(self),
            started: Instant::now(),
            protocol,
            client,
            frontend: Arc::clone(frontend),
            backend: Arc::clone(backend),
            server: None,
            bytes_in: 0,
            bytes_out: 0,
            end: "shutdown",
        })
    }
}

/// The line of one flow while the flow lives. Dropping it offers the line.
pub(crate) struct FlowGuard {
    log: Arc<FlowLog>,
    started: Instant,
    protocol: &'static str,
    client: SocketAddr,
    frontend: Arc<str>,
    pub backend: Arc<str>,
    pub server: Option<SocketAddr>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Why the flow ends, if it ended now.
    pub end: &'static str,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.log.offer(FlowEnd {
            ended: SystemTime::now(),
            duration: self.started.elapsed(),
            protocol: self.protocol,
            client: self.client,
            frontend: Arc::clone(&self.frontend),
            backend: Arc::clone(&self.backend),
            server: self.server,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            end: self.end,
        });
    }
}

/// Notes on the line of a flow, when it has one, why it would end now.
pub(crate) fn mark(guard: &mut Option<FlowGuard>, end: &'static str) {
    if let Some(guard) = guard {
        guard.end = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(log: &Arc<FlowLog>) -> Option<FlowGuard> {
        let name: Arc<str> = Arc::from("db");
        log.begin("tcp", "203.0.113.7:4000".parse().expect("address"), &name, &name)
    }

    #[test]
    fn a_dropped_guard_is_one_line_and_a_full_channel_counts_the_rest() {
        let stats = Arc::new(Stats::default());
        let (log, lines) = FlowLog::new(stats.clone());
        assert!(begin(&log).is_none(), "off until someone reads the lines");
        log.set(true);
        let mut guard = begin(&log);
        mark(&mut guard, "client_closed");
        if let Some(guard) = &mut guard {
            guard.bytes_in = 7;
        }
        drop(guard);
        let line = lines.try_recv().expect("one line");
        assert_eq!((line.end, line.bytes_in, line.protocol), ("client_closed", 7, "tcp"));
        assert!(lines.try_recv().is_err());
        for _ in 0..QUEUE + 5 {
            drop(begin(&log));
        }
        assert_eq!(stats.flow_log_drop_count(), 5);
        assert_eq!(lines.try_iter().count(), QUEUE);
    }
}

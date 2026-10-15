//! A bounded handoff of committed findings from the storage owner to the console collector.
//!
//! The storage thread publishes each finding only after its batch is durably committed;
//! the console collector drains the queue. The feed outlives the console, so shutdown
//! never leaves storage holding a pointer into the console. Publishing copies its input
//! and does no lookup or subscriber work.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ring::BoundedQueue;

/// The capacity of the queue.
pub const QUEUE_CAPACITY: usize = 1024;
/// The longest address a record holds.
pub const IP_CAPACITY: usize = 48;

/// One committed finding: when and from which address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The finding's time in seconds.
    pub second: u64,
    ip_len: u8,
    ip: [u8; IP_CAPACITY],
}

impl Record {
    /// Returns the client address.
    pub fn ip(&self) -> &[u8] {
        self.ip.get(..usize::from(self.ip_len)).unwrap_or(&self.ip)
    }
}

/// The feed of committed findings for the console.
#[derive(Debug, Default)]
pub struct ConsoleIncidents {
    /// Whether a console is listening; publishing is a no-op while false. Stored with
    /// `Release` and loaded with `Acquire` by the publisher.
    pub enabled: AtomicBool,
    /// Findings the collector drains.
    pub queue: BoundedQueue<Record, QUEUE_CAPACITY>,
    dropped: AtomicU64,
}

impl ConsoleIncidents {
    /// Returns a disabled feed with an empty queue (allocated here, about 57 KiB).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how many findings were dropped while enabled: addresses longer than
    /// [`IP_CAPACITY`] bytes and findings that met a full queue.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Copies a committed finding into the queue when enabled. Called by the storage owner
    /// only after the batch's durable receipt; never blocks and never fails, but counts a
    /// finding it cannot keep.
    pub fn publish(&self, second: u64, ip: &[u8]) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let mut record = Record { second, ip_len: 0, ip: [0; IP_CAPACITY] };
        let Some(slot) = record.ip.get_mut(..ip.len()) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        slot.copy_from_slice(ip);
        // `ip.len() <= IP_CAPACITY < 256`, so the length fits in `u8`.
        record.ip_len = ip.len() as u8;
        if self.queue.push(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_finding_handoff_copies_input_and_bounds_loss_independently_of_enablement() {
        let mut feed = ConsoleIncidents::new();
        feed.publish(100, b"8.8.8.8");
        assert_eq!(feed.queue.pop(), None);
        feed.enabled.store(true, Ordering::Release);
        let mut ip = *b"8.8.8.8";
        feed.publish(100, &ip);
        ip.fill(b'x');
        let record = feed.queue.pop().expect("one record");
        assert_eq!(record.ip(), b"8.8.8.8");
        for _ in 0..QUEUE_CAPACITY + 2 {
            feed.publish(100, b"::1");
        }
        assert_eq!(feed.dropped_count(), 2);
        feed.enabled.store(false, Ordering::Release);
        feed.publish(100, b"::1");
        assert_eq!(feed.dropped_count(), 2);
    }

    #[test]
    fn overlong_addresses_are_counted_not_cut() {
        let feed = ConsoleIncidents::new();
        feed.enabled.store(true, Ordering::Release);
        feed.publish(1, &[b'a'; IP_CAPACITY + 1]);
        feed.publish(1, &[b'a'; IP_CAPACITY]);
        assert_eq!(feed.dropped_count(), 1);
        let mut consumer = feed.queue.consumer().expect("first claim");
        assert_eq!(consumer.pop().map(|r| r.ip().len()), Some(IP_CAPACITY));
    }
}

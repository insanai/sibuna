//! A topic's journal (Zig's `topic_ring.zig`): the last [`RING_CAPACITY`] records of one
//! topic, numbered from 1, each at most [`RECORD_BYTES`] bytes.
//!
//! A reader keeps the sequence it wants next. A record that was overwritten before the
//! reader got to it is a gap: the reader learns how many records it missed and must obtain a
//! new snapshot instead of applying later deltas.
//!
//! The Zig ring was preallocated (1,024 records of 2 KiB) and guarded by its own mutex,
//! which a reader or the publisher only tried to take; a contended publication was lost and
//! reported to readers as a one-record gap. Here the ring belongs to the hub's topic state,
//! which one lock guards, so publication and reads are never concurrent and nothing is lost
//! to contention. Records are allocated as they are published, within the same bounds.

use std::collections::VecDeque;
use std::fmt;

use sibuna_console_protocol::subscriptions::{RECORD_BYTES, RING_CAPACITY};

/// Why a record was not published.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RingError {
    /// The payload is longer than a record may be.
    TooLarge,
    /// Every sequence number was used; the topic cannot publish again.
    SequenceExhausted,
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RingError::TooLarge => "a topic record is too large",
            RingError::SequenceExhausted => "the topic's sequence numbers are exhausted",
        })
    }
}

impl std::error::Error for RingError {}

/// One published record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<M> {
    /// What the hub needs to route and filter the record.
    pub metadata: M,
    /// The record's bytes.
    pub payload: String,
}

/// What a read found.
#[derive(Debug, PartialEq, Eq)]
pub enum Read<'r, M> {
    /// The record of the requested sequence.
    Record(&'r Record<M>),
    /// Nothing has been published at that sequence yet.
    Empty,
    /// The record was overwritten.
    Gap {
        /// Records the reader missed.
        dropped: u64,
        /// The oldest sequence still held.
        next: u64,
    },
}

/// The journal of one topic.
#[derive(Clone, Debug)]
pub struct Ring<M> {
    records: VecDeque<Record<M>>,
    /// The sequence of the newest record; 0 before the first.
    head: u64,
    capacity: usize,
    record_bytes: usize,
}

impl<M> Default for Ring<M> {
    fn default() -> Ring<M> {
        Ring::with_bounds(RING_CAPACITY, RECORD_BYTES)
    }
}

impl<M> Ring<M> {
    /// Returns an empty ring of `capacity` records of at most `record_bytes` bytes each.
    /// Panics when `capacity` is zero, an invariant of the caller.
    pub fn with_bounds(capacity: usize, record_bytes: usize) -> Ring<M> {
        assert!(capacity > 0, "a topic ring holds at least one record");
        Ring { records: VecDeque::new(), head: 0, capacity, record_bytes }
    }

    /// Returns the sequence of the newest record, 0 before the first.
    pub fn watermark(&self) -> u64 {
        self.head
    }

    /// Publishes `payload` with `metadata` as the next sequence, dropping the oldest record
    /// when the ring is full. Copies the payload.
    ///
    /// Fails with [`RingError::TooLarge`] for a payload longer than a record, and with
    /// [`RingError::SequenceExhausted`] once the sequence has reached `u64::MAX`.
    pub fn publish(&mut self, metadata: M, payload: &str) -> Result<(), RingError> {
        if payload.len() > self.record_bytes {
            return Err(RingError::TooLarge);
        }
        if self.head == u64::MAX {
            return Err(RingError::SequenceExhausted);
        }
        if self.records.len() == self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(Record { metadata, payload: payload.to_owned() });
        self.head += 1;
        Ok(())
    }

    /// Reads the record of `sequence` (1 or more), borrowing it.
    pub fn read(&self, sequence: u64) -> Read<'_, M> {
        if sequence == 0 || sequence > self.head {
            return Read::Empty;
        }
        // `records` holds the sequences `oldest..=head`, with `oldest` at index 0.
        let oldest = self.head - self.records.len() as u64 + 1;
        if sequence < oldest {
            return Read::Gap { dropped: oldest - sequence, next: oldest };
        }
        match usize::try_from(sequence - oldest).ok().and_then(|index| self.records.get(index)) {
            Some(record) => Read::Record(record),
            None => Read::Empty,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of topic_ring.zig "topic overwrite and contention report exact gaps without
    // borrowing payload storage". Publication cannot be contended here (the hub's lock
    // excludes readers), so the contention half is gone; the copy half holds by ownership:
    // a reader's copy is unaffected by later publications.
    #[test]
    fn topic_overwrite_reports_exact_gaps_without_borrowing_payload_storage() {
        let mut ring: Ring<u8> = Ring::with_bounds(4, 16);
        assert_eq!(ring.read(1), Read::Empty);
        for _ in 0..6 {
            ring.publish(7, "old").unwrap();
        }
        assert_eq!(ring.read(1), Read::Gap { dropped: 2, next: 3 });
        let Read::Record(record) = ring.read(3) else { panic!("record 3 is held") };
        let copy = record.clone();
        assert_eq!(copy.payload, "old");
        ring.publish(8, "new").unwrap();
        assert_eq!(copy.payload, "old");
        assert_eq!(ring.read(8), Read::Empty);
        let Read::Record(record) = ring.read(7) else { panic!("record 7 is held") };
        assert_eq!((record.metadata, record.payload.as_str()), (8, "new"));
        assert_eq!(ring.read(3), Read::Gap { dropped: 1, next: 4 });
        assert_eq!(ring.publish(0, &"a".repeat(17)), Err(RingError::TooLarge));
        assert_eq!(ring.watermark(), 7);
    }

    #[test]
    fn exhausted_sequences_refuse_publication() {
        let mut ring: Ring<()> = Ring::with_bounds(2, 4);
        ring.head = u64::MAX - 1;
        ring.publish((), "a").unwrap();
        assert_eq!(ring.publish((), "b"), Err(RingError::SequenceExhausted));
        assert!(matches!(ring.read(u64::MAX), Read::Record(_)));
        assert_eq!(ring.read(u64::MAX - 1), Read::Gap { dropped: 1, next: u64::MAX });
    }
}

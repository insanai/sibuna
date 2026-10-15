//! The challenge record journal (Zig's `challenge_records_journal.zig`): drains the data
//! plane's per-address challenge queue into batches of at most 32 records and records
//! adaptive-difficulty transitions once per second.
//!
//! One batch and one transition are in flight at a time. A batch without an acknowledgement
//! is counted as unconfirmed, never retried into duplicates; a change of difficulty observed
//! while a transition is still waiting is counted as missed.

use std::sync::atomic::Ordering;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::challenge_records::{
    Batch, MAX_BATCH, NO_CAUSE, Outcome as Kind, Record, Transition,
};
use sibuna_console_storage::observations::{record_transition, write_challenge_records};
use sibuna_store::ring::Consumer;
use sibuna_store::telemetry::{
    ChallengeOutcome, ChallengeRecord, ConsoleTelemetry, QUEUE_CAPACITY,
};

use super::{Lane, Outcome};
use crate::storage::{BACKGROUND_JOBS, ConsoleStorage};

/// The consumer of the data plane's challenge queue.
pub(crate) type ChallengeQueue<'a> = Consumer<'a, ChallengeRecord, QUEUE_CAPACITY>;

/// The coverage counters of the records journal since boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    /// Batches acknowledged.
    pub saved: u64,
    /// Batches without an acknowledgement; their rows may be absent.
    pub unconfirmed: u64,
    /// Transitions observed but not recorded: skipped while one waited, or unconfirmed.
    pub missed: u64,
}

/// The challenge record journal of this node and boot.
#[derive(Debug)]
pub(crate) struct RecordJournal {
    node: u32,
    boot: [u8; 16],
    batch: Lane<()>,
    transition: Option<Transition>,
    transition_lane: Lane<()>,
    last_bits: Option<u8>,
    observed_second: u64,
    counts: Counts,
}

impl RecordJournal {
    /// Returns an empty journal for `node` and `boot`.
    pub(crate) fn new(node: u32, boot: [u8; 16]) -> RecordJournal {
        RecordJournal {
            node,
            boot,
            batch: Lane::default(),
            transition: None,
            transition_lane: Lane::default(),
            last_bits: None,
            observed_second: 0,
            counts: Counts::default(),
        }
    }

    /// Returns the coverage counters.
    pub(crate) fn counts(&self) -> Counts {
        self.counts
    }

    /// Observes the effective adaptive bump once per second: a change since the last
    /// observed second becomes one transition carrying the smoothed rate at that moment.
    pub(crate) fn observe(&mut self, telemetry: &ConsoleTelemetry, now: u64) {
        if now == self.observed_second {
            return;
        }
        self.observed_second = now;
        let bits = telemetry.adaptive_bits.load(Ordering::Relaxed).min(255) as u8;
        let previous = self.last_bits.replace(bits);
        let Some(previous) = previous.filter(|&previous| previous != bits) else { return };
        if self.transition.is_some() {
            self.counts.missed = self.counts.missed.saturating_add(1);
            return;
        }
        self.transition = Some(Transition {
            node: self.node,
            boot: self.boot,
            second: now,
            previous_bits: previous,
            bits,
            rate_256: telemetry.adaptive_rate_256.load(Ordering::Relaxed),
        });
    }

    /// Takes up to [`MAX_BATCH`] records from `queue` into a batch stamped `now`; `None`
    /// when the queue is empty. `dropped` is the queue's loss counter.
    pub(crate) fn drain(
        &self,
        queue: &mut ChallengeQueue<'_>,
        dropped: u64,
        now: u64,
    ) -> Option<Batch> {
        let mut records = Vec::new();
        while records.len() < MAX_BATCH {
            let Some(record) = queue.pop() else { break };
            records.push(convert(&record, now));
        }
        if records.is_empty() {
            return None;
        }
        Some(Batch { node: self.node, boot: self.boot, records, dropped, now })
    }

    /// Records the outcome of a batch write.
    pub(crate) fn finish_batch<T>(&mut self, outcome: Outcome<T>) {
        match outcome {
            Outcome::Done(_) => self.counts.saved = self.counts.saved.saturating_add(1),
            _ => self.counts.unconfirmed = self.counts.unconfirmed.saturating_add(1),
        }
    }

    /// Records the outcome of a transition write.
    pub(crate) fn finish_transition<T>(&mut self, outcome: Outcome<T>) {
        if !matches!(outcome, Outcome::Done(_)) {
            self.counts.missed = self.counts.missed.saturating_add(1);
        }
    }

    /// Observes the difficulty, polls both writes and submits the next batch and transition;
    /// never waits.
    pub(crate) fn tick(
        &mut self,
        storage: &ConsoleStorage,
        telemetry: &ConsoleTelemetry,
        queue: Option<&mut ChallengeQueue<'_>>,
        now: u64,
        ms: u64,
    ) {
        self.observe(telemetry, now);
        if let Some(outcome) = self.batch.poll(ms) {
            self.finish_batch(outcome);
        }
        if let Some(outcome) = self.transition_lane.poll(ms) {
            self.finish_transition(outcome);
        }
        // Records leave the queue only when their batch can be queued at once.
        let room = storage.background_count() < BACKGROUND_JOBS;
        if let Some(queue) = queue.filter(|_| room && !self.batch.is_busy()) {
            let dropped = telemetry.challenge_dropped_count();
            if let Some(batch) = self.drain(queue, dropped, now) {
                let submitted = storage.submit_background(move |tx| {
                    Box::pin(async move { write_challenge_records(tx, &batch).await })
                });
                if let Some(outcome) = self.batch.start(submitted, ms) {
                    // The records left the queue; an unqueued batch is lost and counted.
                    self.finish_batch(outcome);
                }
            }
        }
        if self.transition_lane.is_busy() {
            return;
        }
        let Some(transition) = self.transition else { return };
        let submitted = storage.submit_background(move |tx| {
            Box::pin(async move { record_transition(tx, &transition).await })
        });
        match self.transition_lane.start(submitted, ms) {
            None => self.transition = None,
            // Not queued: the transition waits for the next tick.
            Some(Outcome::NotQueued) => {}
            Some(outcome) => {
                self.transition = None;
                self.finish_transition(outcome);
            }
        }
    }
}

/// Converts a data-plane event at `now` into a storage record: a second after `now` is
/// clamped to it, an unknown cause becomes [`NO_CAUSE`].
pub(crate) fn convert(record: &ChallengeRecord, now: u64) -> Record {
    let ip = std::str::from_utf8(record.ip()).ok().and_then(|ip| Text::new(ip).ok());
    Record {
        second: record.second.min(now),
        ip: ip.unwrap_or_default(),
        outcome: match record.outcome {
            ChallengeOutcome::Issued => Kind::Issued,
            ChallengeOutcome::Accepted => Kind::Accepted,
            ChallengeOutcome::Rejected => Kind::Rejected,
        },
        cause: record.cause.map_or(NO_CAUSE, |cause| cause as u8),
        algorithm: record.algorithm as u8,
        parameter: record.parameter,
        openings: record.openings,
        duration_ms: record.duration_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // challenge_records_journal.zig: "difficulty transitions are observed once per second
    // and records drain in batches".
    #[test]
    fn transitions_are_observed_once_per_second_and_records_drain_in_batches() {
        let telemetry = ConsoleTelemetry::new();
        let mut journal = RecordJournal::new(1, [1; 16]);
        journal.observe(&telemetry, 100);
        assert!(journal.transition.is_none());
        telemetry.adaptive_bits.store(2, Ordering::Relaxed);
        telemetry.adaptive_rate_256.store(300 * 256, Ordering::Relaxed);
        journal.observe(&telemetry, 100);
        assert!(journal.transition.is_none());
        journal.observe(&telemetry, 101);
        let change = journal.transition.unwrap();
        assert_eq!((change.previous_bits, change.bits), (0, 2));
        assert_eq!(change.rate_256, 300 * 256);
        // A further change while the first is still waiting is counted, never dropped.
        telemetry.adaptive_bits.store(3, Ordering::Relaxed);
        journal.observe(&telemetry, 102);
        assert_eq!(journal.transition.unwrap().bits, 2);
        assert_eq!(journal.counts().missed, 1);
        let mut record = ChallengeRecord::default();
        record.second = 100;
        record.set_ip(b"8.8.8.8");
        let converted = convert(&record, 101);
        assert_eq!(converted.ip.as_str(), "8.8.8.8");
        assert!(converted.duration_ms.is_none());
        assert_eq!(converted.cause, NO_CAUSE);
        // Batches hold at most 32 records; the rest wait for the next tick.
        for second in 0..40 {
            let mut event = record;
            event.second = second;
            telemetry.challenge_event(event);
        }
        let mut queue = telemetry.challenge_queue.consumer().unwrap();
        let batch = journal.drain(&mut queue, 0, 30).unwrap();
        assert_eq!(batch.records.len(), MAX_BATCH);
        assert_eq!(batch.records[31].second, 30);
        assert_eq!(journal.drain(&mut queue, 0, 50).unwrap().records.len(), 8);
        assert!(journal.drain(&mut queue, 0, 50).is_none());
        journal.finish_batch(Outcome::<()>::Unknown);
        journal.finish_transition(Outcome::<()>::failed());
        assert_eq!(journal.counts(), Counts { saved: 0, unconfirmed: 1, missed: 2 });
    }
}

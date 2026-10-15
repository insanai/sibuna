//! The challenge minute journal (Zig's `challenge_journal.zig`): per-minute deltas of the
//! boot-local challenge counters, written as S40 challenge minute rows the way traffic
//! minutes are written: two waiting snapshots, bounded retries, the open minute offered
//! every five seconds.

use std::sync::atomic::{AtomicU64, Ordering};

use sibuna_console_protocol::challenge_minutes::{Record, RecordWrite};
use sibuna_console_protocol::minutes::Cursor;
use sibuna_console_storage::observations::{MinuteWrite, write_minute};
use sibuna_store::challenge_metrics::{BIN_COUNT, BUCKET_COUNT, CAUSE_COUNT, Metrics};

use super::{Lane, OFFER_MS, Outcome, Pending, Snapshot};
use crate::storage::ConsoleStorage;

impl Snapshot for Record {
    fn cursor(&self) -> Cursor {
        Record::cursor(self)
    }

    fn end_ms(&self) -> u64 {
        self.end_ms
    }
}

/// A plain copy of one parameter bin's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Bin {
    issued: u64,
    accepted: u64,
    buckets: [u64; BUCKET_COUNT],
    missing: u64,
    invalid: u64,
    wasm: u64,
    javascript: u64,
    unknown_solver: u64,
}

/// A plain copy of every challenge counter; each load is atomic on its own, never a
/// transaction across counters.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Totals {
    submitted: u64,
    causes: [u64; CAUSE_COUNT],
    bins: [Bin; BIN_COUNT],
}

impl Default for Totals {
    fn default() -> Totals {
        Totals { submitted: 0, causes: [0; CAUSE_COUNT], bins: [Bin::default(); BIN_COUNT] }
    }
}

impl Totals {
    /// Loads every counter of `metrics` in place (the table is 47 KiB).
    fn load(&mut self, metrics: &Metrics) {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        self.submitted = load(&metrics.submitted);
        for (count, counter) in self.causes.iter_mut().zip(&metrics.causes) {
            *count = load(counter);
        }
        for (bin, source) in self.bins.iter_mut().zip(&metrics.bins) {
            bin.issued = load(&source.issued);
            bin.accepted = load(&source.accepted);
            bin.missing = load(&source.missing);
            bin.invalid = load(&source.invalid);
            bin.wasm = load(&source.wasm);
            bin.javascript = load(&source.javascript);
            bin.unknown_solver = load(&source.unknown_solver);
            for (count, counter) in bin.buckets.iter_mut().zip(&source.buckets) {
                *count = load(counter);
            }
        }
    }
}

/// The increase from `before` to `after`, at most `u32::MAX`.
fn delta(after: u64, before: u64) -> u32 {
    u32::try_from(after.saturating_sub(before)).unwrap_or(u32::MAX)
}

/// The challenge minute journal of this node and boot.
#[derive(Debug)]
pub(crate) struct ChallengeJournal {
    node: u32,
    boot: [u8; 16],
    /// The counters at the previous observation, and the observation being taken; boxed,
    /// as each is 47 KiB.
    last: Box<Totals>,
    scratch: Box<Totals>,
    baselined: bool,
    last_ms: u64,
    current: Option<Record>,
    pending: Pending<Record>,
    offered_ms: u64,
    lane: Lane<()>,
}

impl ChallengeJournal {
    /// Returns an empty journal for `node` and `boot`.
    pub(crate) fn new(node: u32, boot: [u8; 16]) -> ChallengeJournal {
        ChallengeJournal {
            node,
            boot,
            last: Box::default(),
            scratch: Box::default(),
            baselined: false,
            last_ms: 0,
            current: None,
            pending: Pending::default(),
            offered_ms: 0,
            lane: Lane::default(),
        }
    }

    /// Takes one observation of `metrics` at `now` (Unix seconds) and monotonic `ms`. The
    /// first call only sets the baseline; later calls attribute the interval since the
    /// previous one to the minute it ends in.
    pub(crate) fn observe(&mut self, metrics: &Metrics, now: u64, ms: u64) {
        self.scratch.load(metrics);
        if self.baselined && ms > self.last_ms {
            self.attribute(now / 60, ms);
        }
        std::mem::swap(&mut self.last, &mut self.scratch);
        self.baselined = true;
        self.last_ms = ms;
    }

    /// Adds the deltas from `last` to `scratch` to the open minute `minute`, sealing the
    /// open minute first when it is an earlier one.
    fn attribute(&mut self, minute: u64, ms: u64) {
        if self.current.as_ref().is_some_and(|current| current.minute != minute) {
            self.seal();
        }
        let current = self.current.get_or_insert_with(|| Record {
            node: self.node,
            boot: self.boot,
            epoch: 1,
            minute,
            start_ms: self.last_ms,
            end_ms: self.last_ms,
            ..Record::default()
        });
        // A delayed collector cannot attribute its interval to seconds; the minute stays.
        if ms - self.last_ms > 2000 {
            current.gap = true;
        }
        current.end_ms = ms;
        current.observed_ms = ms - current.start_ms;
        current.observations = current.observations.saturating_add(1);
        let (after, before) = (&self.scratch, &self.last);
        current.submitted =
            current.submitted.saturating_add(delta(after.submitted, before.submitted));
        for ((count, &next), &last) in
            current.causes.iter_mut().zip(&after.causes).zip(&before.causes)
        {
            *count = count.saturating_add(delta(next, last));
        }
        for (index, (next, last)) in after.bins.iter().zip(before.bins.iter()).enumerate() {
            if next == last {
                continue;
            }
            // `index` is below `BIN_COUNT` (256), so it fits in a byte.
            let Some(entry) = current.partition(index as u8) else {
                current.bins_dropped = current.bins_dropped.saturating_add(1);
                continue;
            };
            let add = |count: &mut u32, after: u64, before: u64| {
                *count = count.saturating_add(delta(after, before));
            };
            add(&mut entry.issued, next.issued, last.issued);
            add(&mut entry.accepted, next.accepted, last.accepted);
            add(&mut entry.missing, next.missing, last.missing);
            add(&mut entry.invalid, next.invalid, last.invalid);
            add(&mut entry.wasm, next.wasm, last.wasm);
            add(&mut entry.javascript, next.javascript, last.javascript);
            add(&mut entry.unknown_solver, next.unknown_solver, last.unknown_solver);
            for ((count, &after), &before) in
                entry.buckets.iter_mut().zip(&next.buckets).zip(&last.buckets)
            {
                add(count, after, before);
            }
        }
    }

    /// Seals the open minute and queues it.
    fn seal(&mut self) {
        let Some(mut record) = self.current.take() else { return };
        record.sealed = true;
        record.complete = !record.gap && (59_000..=61_000).contains(&record.observed_ms);
        self.pending.offer(record);
    }

    /// Returns the write to submit at monotonic `ms`, offering the open minute first when
    /// [`OFFER_MS`] have passed.
    pub(crate) fn next(&mut self, ms: u64) -> Option<Record> {
        if ms.saturating_sub(self.offered_ms) >= OFFER_MS {
            if let Some(current) = self.current.clone() {
                self.pending.offer(current);
            }
            self.offered_ms = ms;
        }
        self.pending.next(ms)
    }

    /// Records the outcome of the write [`ChallengeJournal::next`] handed out.
    pub(crate) fn finish<T>(&mut self, outcome: Outcome<T>, ms: u64) {
        self.pending.finish(outcome, ms);
    }

    /// Polls the write in flight and submits the next one; never waits.
    pub(crate) fn tick(&mut self, storage: &ConsoleStorage, now: u64, ms: u64) {
        if let Some(outcome) = self.lane.poll(ms) {
            self.finish(outcome, ms);
        }
        if self.lane.is_busy() {
            return;
        }
        let Some(record) = self.next(ms) else { return };
        let write = RecordWrite { record, now };
        let submitted = storage.submit_background(move |tx| {
            Box::pin(
                async move { write_minute(tx, MinuteWrite::Challenge(&write)).await.map(drop) },
            )
        });
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish(outcome, ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use sibuna_store::challenge_metrics::{Algorithm, Cause, Solver, Timing, index};

    use super::*;

    // challenge_journal.zig: "challenge journal attributes deltas to the ending minute and
    // seals on the roll".
    #[test]
    fn deltas_go_to_the_ending_minute_and_the_minute_seals_on_the_roll() {
        let metrics = Metrics::new();
        let mut journal = ChallengeJournal::new(1, [1; 16]);
        journal.observe(&metrics, 119, 1000);
        assert!(journal.current.is_none());
        metrics.issue(Algorithm::Posw, 13, 16);
        metrics.submitted.fetch_add(1, Ordering::Relaxed);
        metrics.reject(Cause::Replay);
        journal.observe(&metrics, 120, 1250);
        let current = journal.current.clone().unwrap();
        assert_eq!(current.minute, 2);
        assert_eq!(current.submitted, 1);
        assert_eq!(current.causes[Cause::Replay as usize], 1);
        assert_eq!(current.bins.len(), 1);
        assert_eq!(usize::from(current.bins[0].bin), index(Algorithm::Posw, 13, 16));
        assert_eq!(current.bins[0].bin, 133);
        assert_eq!(current.bins[0].issued, 1);
        metrics.accept(Algorithm::Posw, 13, 16, Timing::Milliseconds(8.0), Solver::Wasm);
        // The collector ticks four times a second; the minute rolls at the first tick past it.
        let mut ms = 1500;
        while ms < 60_500 {
            journal.observe(&metrics, 119 + ms / 1000, ms);
            ms += 250;
        }
        let open = journal.current.clone().unwrap();
        assert_eq!(open.bins[0].accepted, 1);
        assert!(open.bins[0].is_consistent());
        journal.observe(&metrics, 180, 60_500);
        assert_eq!(journal.pending.len(), 1);
        let sealed = journal.next(0).unwrap();
        assert!(sealed.sealed && sealed.complete && !sealed.gap);
        assert_eq!(sealed.minute, 2);
        assert_eq!(journal.current.as_ref().unwrap().minute, 3);
        assert!(journal.current.as_ref().unwrap().bins.is_empty());
        journal.observe(&metrics, 185, 66_000);
        assert!(journal.current.as_ref().unwrap().gap);
    }
}

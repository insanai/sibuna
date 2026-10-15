//! The traffic minute journal (Zig's `minute_journal.zig`): folds the timeline's observed
//! intervals into UTC minutes and writes them as S40 minute rows.
//!
//! A minute is sealed when an interval ends in a later minute or the timeline's epoch
//! changes. It is complete only when the previous minute ended exactly where it began,
//! nothing interrupted it and it was observed for 59 to 61 seconds; the first minute after
//! start is therefore never complete. The open minute is offered every five seconds as a
//! partial snapshot, so a crash loses at most five seconds.

use sibuna_console_protocol::minutes::{Cursor, Record, RecordWrite, Status};
use sibuna_console_protocol::timeline::{Bucket, Counts};
use sibuna_console_storage::observations::{MinuteWrite, write_minute};

use super::{Lane, OFFER_MS, Outcome, Pending, Snapshot};
use crate::collector::resources;
use crate::storage::ConsoleStorage;

impl Snapshot for Record {
    fn cursor(&self) -> Cursor {
        Record::cursor(self)
    }

    fn end_ms(&self) -> u64 {
        self.end_ms
    }
}

/// The traffic minute journal of this node and boot.
#[derive(Debug)]
pub(crate) struct MinuteJournal {
    node: u32,
    boot: [u8; 16],
    current: Option<Record>,
    last_cpu_ms: Option<u64>,
    /// The minute before the open one ended where the open one began.
    complete_candidate: bool,
    pending: Pending<Record>,
    offered_ms: u64,
    lane: Lane<()>,
}

impl MinuteJournal {
    /// Returns an empty journal for `node` and `boot`.
    pub(crate) fn new(node: u32, boot: [u8; 16]) -> MinuteJournal {
        MinuteJournal {
            node,
            boot,
            current: None,
            last_cpu_ms: None,
            complete_candidate: false,
            pending: Pending::default(),
            offered_ms: 0,
            lane: Lane::default(),
        }
    }

    /// Folds the interval the timeline just observed (if any) in timeline `epoch` into the
    /// open minute, sealing and queueing the open minute first when the interval ends in a
    /// later minute or the epoch changed.
    pub(crate) fn observe(&mut self, epoch: u32, interval: Option<&Bucket>) {
        if let Some(current) = &self.current {
            let rolled = interval.is_some_and(|next| next.utc_end / 60 != current.minute);
            if current.epoch != epoch || rolled {
                let contiguous = interval.is_some_and(|next| {
                    current.epoch == epoch
                        && next.utc_end / 60 == current.minute + 1
                        && !next.gap
                        && current.end_ms == next.start_ms
                });
                self.seal(contiguous);
            }
        }
        let Some(next) = interval else { return };
        let Some(current) = self.current.as_mut() else {
            self.current = Some(Record {
                node: self.node,
                boot: self.boot,
                epoch,
                minute: next.utc_end / 60,
                utc_start: next.utc_start,
                utc_end: next.utc_end,
                start_ms: next.start_ms,
                end_ms: next.end_ms,
                observed_ms: next.observed_ms,
                observations: 1,
                gap: next.gap,
                counts: next.counts,
                ..Record::default()
            });
            return;
        };
        // An interval that does not continue the open minute is an interruption.
        let continues = current.end_ms == next.start_ms;
        current.utc_end = current.utc_end.max(next.utc_end);
        current.end_ms = next.end_ms;
        current.observed_ms = current.observed_ms.saturating_add(next.observed_ms);
        current.observations = current.observations.saturating_add(1);
        current.gap = current.gap || next.gap || !continues || current.observed_ms > 61_000;
        // Monotonic source counters bound each sum; a counter that went backwards reset the
        // timeline's epoch instead.
        let sum = current.counts.values();
        let add = next.counts.values();
        let mut values = [0u64; 8];
        for ((value, before), delta) in values.iter_mut().zip(sum).zip(add) {
            *value = before.saturating_add(delta);
        }
        current.counts = Counts::from_values(values);
    }

    /// Seals the open minute, queues it and closes it.
    fn seal(&mut self, contiguous: bool) {
        let Some(mut record) = self.current.take() else { return };
        record.sealed = true;
        record.complete = self.complete_candidate
            && !record.gap
            && contiguous
            && (59_000..=61_000).contains(&record.observed_ms);
        self.pending.offer(record);
        self.complete_candidate = contiguous;
    }

    /// Records a resource sample in the open minute: resident memory as a level (last and
    /// peak), CPU time as the delta since the previous sample. A sample taken while no
    /// minute is open only moves the CPU baseline.
    pub(crate) fn gauges(&mut self, sample: &resources::Sample) {
        let previous = self.last_cpu_ms;
        self.last_cpu_ms = sample.cpu_ms.or(previous);
        let Some(current) = self.current.as_mut() else { return };
        current.rss_last_kib = sample.rss_kib;
        let peak =
            [sample.rss_max_kib, sample.rss_kib, current.rss_max_kib].into_iter().flatten().max();
        current.rss_max_kib = peak;
        if let (Some(before), Some(after)) = (previous, sample.cpu_ms) {
            let used = after.saturating_sub(before);
            current.cpu_ms = Some(current.cpu_ms.unwrap_or(0).saturating_add(used));
        }
    }

    /// Queues `record` as [`Pending::offer`] does.
    #[cfg(test)]
    pub(crate) fn offer(&mut self, record: Record) {
        self.pending.offer(record);
    }

    /// Returns the minute write to submit at monotonic `ms` (see [`Pending::next`]),
    /// offering the open minute first when [`OFFER_MS`] have passed.
    pub(crate) fn next(&mut self, ms: u64) -> Option<Record> {
        if ms.saturating_sub(self.offered_ms) >= OFFER_MS {
            if let Some(current) = self.current {
                self.pending.offer(current);
            }
            self.offered_ms = ms;
        }
        self.pending.next(ms)
    }

    /// Records the outcome of the write [`MinuteJournal::next`] handed out.
    pub(crate) fn finish<T>(&mut self, outcome: Outcome<T>, ms: u64) {
        self.pending.finish(outcome, ms);
    }

    /// Polls the write in flight and submits the next one; never waits. `now` is the
    /// writer's clock in Unix seconds, `ms` monotonic milliseconds.
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
            Box::pin(async move { write_minute(tx, MinuteWrite::Traffic(&write)).await.map(drop) })
        });
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish(outcome, ms);
        }
    }

    /// Returns the journal's health, with `retention_failures` from the retention job.
    pub(crate) fn status(&self, retention_failures: u64) -> Status {
        self.pending.status(retention_failures)
    }

    /// Returns the open minute, for tests.
    #[cfg(test)]
    pub(crate) fn current(&self) -> Option<&Record> {
        self.current.as_ref()
    }

    /// Returns how many snapshots wait.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval(index: u64) -> Bucket {
        Bucket {
            sequence: index / 4,
            utc_start: 100 + (index - 1) / 4,
            utc_end: 100 + index / 4,
            start_ms: (index - 1) * 250,
            end_ms: index * 250,
            observed_ms: 250,
            observations: 1,
            counts: Counts { admitted: 1, ..Counts::default() },
            ..Bucket::default()
        }
    }

    fn journal() -> MinuteJournal {
        MinuteJournal::new(1, [1; 16])
    }

    // minute_journal_test.zig: "minute aggregation distinguishes startup, complete
    // intervals, gaps and observation resets".
    #[test]
    fn minutes_distinguish_startup_complete_intervals_gaps_and_resets() {
        let mut journal = journal();
        for i in 1..321 {
            journal.observe(1, Some(&interval(i)));
        }
        assert_eq!(journal.waiting(), 2);
        let startup = journal.pending.jobs[0].record;
        let full = journal.pending.jobs[1].record;
        assert!(startup.sealed && !startup.complete);
        assert_eq!(startup.counts.admitted, 79);
        assert!(full.sealed && full.complete && !full.gap);
        assert_eq!(full.counts.admitted, 240);
        assert_eq!(full.observed_ms, 60_000);
        let open = journal.current().unwrap();
        assert!(!open.sealed && !open.complete);
        journal.observe(2, None);
        assert!(journal.current().is_none() && !journal.complete_candidate);
        assert_eq!(journal.status(0).unconfirmed_snapshots, 1);
        let mut gap = interval(321);
        gap.observed_ms = 10_000;
        gap.end_ms = gap.start_ms + gap.observed_ms;
        gap.utc_end = gap.utc_start + 10;
        gap.gap = true;
        journal.observe(2, Some(&gap));
        assert!(journal.current().unwrap().gap);
        assert_eq!(journal.current().unwrap().observed_ms, 10_000);
    }

    // minute_journal_test.zig: "pending partial snapshots coalesce without changing the
    // in-flight acknowledgement".
    #[test]
    fn partial_snapshots_coalesce_without_changing_the_write_in_flight() {
        let mut journal = journal();
        journal.observe(1, Some(&interval(1)));
        let first = journal.next(5000).unwrap();
        assert_eq!(first.counts.admitted, 1);
        journal.observe(1, Some(&interval(2)));
        assert!(journal.next(10_000).is_none());
        assert_eq!(journal.status(0).pending, 2);
        journal.observe(1, Some(&interval(3)));
        journal.offer(*journal.current().unwrap());
        journal.finish(Outcome::Done(()), 10_250);
        assert_eq!(journal.status(0).last_saved_end_ms, 250);
        let next = journal.next(10_500).unwrap();
        assert_eq!(next.counts.admitted, 3);
        journal.finish(Outcome::Done(()), 10_750);
        assert_eq!(journal.status(0).saved_snapshots, 2);
        assert_eq!(journal.status(0).pending, 0);
    }

    // minute_journal_test.zig: "timed out SQL retains ownership and newer samples do not
    // reset the bounded retry budget".
    #[test]
    fn newer_samples_do_not_reset_the_bounded_retry_budget() {
        let mut journal = journal();
        journal.offered_ms = u64::MAX;
        journal.observe(1, Some(&interval(1)));
        journal.offer(*journal.current().unwrap());
        assert!(journal.next(0).is_some());
        // The write did not answer within ten seconds: its outcome is unknown.
        journal.finish(Outcome::<()>::Unknown, 10_000);
        for attempt in 0..7u64 {
            journal.observe(1, Some(&interval(attempt + 2)));
            journal.offer(*journal.current().unwrap());
            let ms = 100_000 * (attempt + 1);
            assert!(journal.next(ms).is_some());
            journal.finish(Outcome::<()>::failed(), ms + 250);
        }
        let status = journal.status(0);
        assert_eq!(status.saved_snapshots, 0);
        assert_eq!(status.unconfirmed_snapshots, 1);
        assert_eq!(status.pending, 0);
    }

    // minute_journal_test.zig: "slow retention cannot starve minute writes and shutdown
    // releases queued work". Pruning moved to the retention job (SID 0013), so only the
    // second half remains: a refused submission keeps the snapshot and its retry budget.
    #[test]
    fn a_refused_submission_keeps_the_snapshot_and_its_budget() {
        let mut journal = journal();
        journal.offered_ms = u64::MAX;
        journal.observe(1, Some(&interval(1)));
        journal.offer(*journal.current().unwrap());
        assert!(journal.next(0).is_some());
        journal.finish(Outcome::<()>::NotQueued, 0);
        assert_eq!(journal.pending.jobs[0].retries, 0);
        assert!(journal.next(250).is_some());
        assert_eq!(journal.status(0).pending, 1);
    }
}

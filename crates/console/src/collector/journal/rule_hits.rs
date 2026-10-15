//! The rule-hit journal (Zig's `rule_hit_journal.zig` and the storage owner's
//! `console_policy_hits.zig`): samples the published engine's rule-hit counters once per
//! second through [`Node::sample_rule_hits`], folds them into ending-minute frames per
//! engine generation, and records each frame in steps of eight rules (S35).
//!
//! Frames own copies of the rule identities, so a retired engine can be dropped while its
//! frames still wait. At most four frames wait; a full queue, spent retries, a clock that
//! went backwards or a counter that saturated are visible in the status and never become
//! apparently complete zeroes.
//!
//! # Changes from the Zig version
//!
//! Zig's storage owner swapped the engine itself and read the retired generation's final
//! counters before it began the next one. Here the daemon publishes engines and the console
//! samples them: the daemon keeps the counters of the generation the console last sampled
//! until the next sample has read them (`RuleHitSample::retired`), and the journal folds
//! those final counters into the old generation's open frame before it seals it as a
//! cutover (never complete), so no hit counted before the publication is lost. A hit a
//! request records into the retired counters after that read (a request that began before
//! the publication) is not counted. The new generation's first interval starts at its
//! publication time when that time is plausible on the console's clocks (at most five
//! seconds before the first sample); otherwise it starts at the first sample, and hits
//! counted before it are reported as unconfirmed.

use std::collections::VecDeque;

use sibuna_console_protocol::rule_hits::{
    BATCH_ROWS, Clock, Entry, Frame, Generation, MAX_RULES, Span, Status,
};
use sibuna_console_storage::rule_hits::record_rule_hits;
use sibuna_store::rule_hits::Snapshot;

use super::{Lane, MAX_RETRIES, Outcome};
use crate::host::{Node, RuleHitSample};
use crate::storage::ConsoleStorage;

/// The counters of one generation at one moment.
type Counts = Snapshot<MAX_RULES>;

/// How many frames wait.
const FRAMES: usize = 4;
/// How long after its publication a generation's first sample may come for the interval to
/// start at the publication, in milliseconds.
const BORN_SLACK_MS: u64 = 5_000;
/// How often the counters are sampled, in milliseconds.
const SAMPLE_MS: u64 = 1_000;

/// The rule-hit journal of this node and boot.
#[derive(Debug)]
pub(crate) struct RuleHitJournal {
    generation: Option<Generation>,
    before: Box<Counts>,
    clock: Clock,
    current: Frame,
    candidate: bool,
    sequence: u64,
    frames: VecDeque<Frame>,
    offset: usize,
    status: Status,
    sample: RuleHitSample,
    next_sample_ms: u64,
    lane: Lane<u64>,
    /// How many entries the step in flight carries; `None` when none is in flight.
    in_flight: Option<usize>,
    retries: u8,
    retry_at: u64,
}

impl Default for RuleHitJournal {
    fn default() -> RuleHitJournal {
        RuleHitJournal {
            generation: None,
            before: Box::default(),
            clock: Clock::default(),
            current: Frame::default(),
            candidate: false,
            sequence: 0,
            frames: VecDeque::with_capacity(FRAMES),
            offset: 0,
            status: Status::default(),
            sample: RuleHitSample::default(),
            next_sample_ms: 0,
            lane: Lane::default(),
            in_flight: None,
            retries: 0,
            retry_at: 0,
        }
    }
}

impl RuleHitJournal {
    /// Returns the journal's health.
    #[cfg(test)]
    pub(crate) fn status(&self) -> Status {
        self.status
    }

    /// Starts counting `generation`. Its counters began at zero when it was published at
    /// `generation.born`; when that moment is plausible on the console's clocks (`now`),
    /// the first interval starts there, otherwise at `first`, the first sample, and any
    /// hit counted before it is reported as unconfirmed.
    pub(crate) fn begin(&mut self, generation: &Generation, first: &Counts, now: Clock) {
        let born = generation.born;
        let plausible = born.ms <= now.ms
            && born.utc <= now.utc
            && now.ms - born.ms <= BORN_SLACK_MS
            && born.ms != 0;
        if plausible {
            *self.before = Counts { generation: generation.number, ..Counts::default() };
            self.clock = born;
        } else {
            if first.overflow || first.values.iter().any(|&value| value != 0) {
                self.status.unconfirmed = self.status.unconfirmed.saturating_add(1);
            }
            *self.before = *first;
            self.clock = now;
        }
        let mut owned = generation.clone();
        owned.rules.truncate(MAX_RULES);
        self.generation = Some(owned);
        self.current = Frame::default();
        self.candidate = false;
    }

    /// Folds the counters `snapshot` of the current generation, read at `now`, into the
    /// open frame, sealing it first when `now` is in a later minute.
    pub(crate) fn observe(&mut self, snapshot: &Counts, now: Clock) {
        let Some(number) = self.generation.as_ref().map(|generation| generation.number) else {
            return;
        };
        if snapshot.generation != number || now == self.clock {
            return;
        }
        if now.ms <= self.clock.ms || now.utc < self.clock.utc {
            self.seal(false);
            self.status.clock_resets = self.status.clock_resets.saturating_add(1);
            self.status.unconfirmed = self.status.unconfirmed.saturating_add(1);
            *self.before = *snapshot;
            self.clock = now;
            return;
        }
        let mut delta = [0u64; MAX_RULES];
        let valid = snapshot.delta(&self.before, &mut delta).is_ok();
        let elapsed = now.ms - self.clock.ms;
        let utc_elapsed = (now.utc - self.clock.utc).saturating_mul(1000);
        let gap = elapsed > 2500
            || utc_elapsed > elapsed.saturating_add(1500)
            || elapsed > utc_elapsed.saturating_add(1500);
        let span = &self.current.span;
        if span.observations != 0 && now.utc / 60 != span.minute {
            let contiguous = now.utc / 60 == span.minute.saturating_add(1) && !gap;
            self.seal(contiguous);
            self.candidate = contiguous;
        }
        if self.current.span.observations == 0 {
            self.open(now);
        }
        let span = &mut self.current.span;
        span.utc_end = now.utc;
        span.end_ms = now.ms;
        span.observed_ms = span.observed_ms.saturating_add(elapsed);
        span.observations = span.observations.saturating_add(1);
        span.gap = span.gap || gap;
        for (entry, &delta) in self.current.entries.iter_mut().zip(&delta) {
            entry.hits = entry.hits.filter(|_| valid).and_then(|hits| hits.checked_add(delta));
            if entry.hits.is_none() {
                self.status.overflow = true;
            }
        }
        *self.before = *snapshot;
        self.clock = now;
    }

    /// Opens a frame at `now` for the current generation, starting where the previous
    /// observation ended.
    fn open(&mut self, now: Clock) {
        let Some(generation) = self.generation.as_ref() else { return };
        self.current.span = Span {
            node: generation.node,
            boot: generation.boot,
            generation: generation.number,
            revision: generation.revision,
            minute: now.utc / 60,
            utc_start: self.clock.utc,
            start_ms: self.clock.ms,
            ..Span::default()
        };
        self.current.entries = generation
            .rules
            .iter()
            .map(|identity| Entry { identity: identity.clone(), hits: Some(0) })
            .collect();
    }

    /// Ends the current generation: folds its final counters `last` (when known) and seals
    /// its open frame as a cutover, which is never complete.
    pub(crate) fn finish(&mut self, last: Option<(&Counts, Clock)>) {
        if let Some((snapshot, now)) = last {
            self.observe(snapshot, now);
            // Two publications within one clock tick: a zero-duration tail cannot be
            // represented as an observed interval.
            if snapshot.values != self.before.values {
                self.status.unconfirmed = self.status.unconfirmed.saturating_add(1);
            }
        }
        self.seal(false);
        self.generation = None;
    }

    /// Seals the open frame and queues it; a full queue counts it as unconfirmed.
    fn seal(&mut self, contiguous: bool) {
        if self.current.span.observations == 0 {
            return;
        }
        let mut frame = std::mem::take(&mut self.current);
        let span = &mut frame.span;
        span.complete = self.candidate
            && contiguous
            && !span.gap
            && (59_000..=61_000).contains(&span.observed_ms);
        self.sequence = self.sequence.saturating_add(1);
        span.sequence = self.sequence;
        span.unconfirmed = self.status.unconfirmed;
        self.candidate = false;
        if frame.entries.is_empty() {
            return;
        }
        if self.frames.len() == FRAMES || self.sequence > i64::MAX as u64 {
            self.status.unconfirmed = self.status.unconfirmed.saturating_add(1);
        } else {
            self.frames.push_back(frame);
            self.status.pending = self.frames.len() as u32;
        }
    }

    /// Returns the next step to record: the head frame's interval and at most
    /// [`BATCH_ROWS`] of its entries.
    pub(crate) fn pending(&self) -> Option<(&Span, &[Entry])> {
        let frame = self.frames.front()?;
        let end = frame.entries.len().min(self.offset + BATCH_ROWS);
        Some((&frame.span, frame.entries.get(self.offset..end)?))
    }

    /// Acknowledges the step [`RuleHitJournal::pending`] returned; the frame is confirmed
    /// when its last step is.
    pub(crate) fn acknowledge(&mut self) {
        let Some((span, entries)) = self.pending() else { return };
        let (utc_end, count) = (span.utc_end, entries.len());
        self.offset += count;
        if self.frames.front().is_some_and(|frame| self.offset >= frame.entries.len()) {
            self.status.confirmed = self.status.confirmed.saturating_add(1);
            self.status.last_stored_utc = utc_end;
            self.remove();
        }
    }

    /// Drops the head frame after bounded retries, making the loss visible.
    pub(crate) fn discard(&mut self) {
        if self.frames.is_empty() {
            return;
        }
        self.status.unconfirmed = self.status.unconfirmed.saturating_add(1);
        self.remove();
    }

    fn remove(&mut self) {
        self.frames.pop_front();
        self.offset = 0;
        self.status.pending = self.frames.len() as u32;
    }

    /// Takes one sample from `node` every second and records it at `now` (both clocks).
    pub(crate) fn sample(&mut self, node: &dyn Node, now: Clock) {
        if now.ms < self.next_sample_ms {
            return;
        }
        self.next_sample_ms = now.ms.saturating_add(SAMPLE_MS);
        let mut sample = std::mem::take(&mut self.sample);
        if node.sample_rule_hits(&mut sample) {
            self.record(&sample, now);
        }
        self.sample = sample;
    }

    /// Records one sample: a new generation retires the old one, folding the old one's
    /// final counters when the sample carries them, and begins.
    pub(crate) fn record(&mut self, sample: &RuleHitSample, now: Clock) {
        let number = sample.generation.number;
        if number == 0 || sample.counts.generation != number {
            return;
        }
        let current = self.generation.as_ref().map(|generation| generation.number);
        if current != Some(number) {
            if let Some(current) = current {
                let last = sample.retired.as_ref().filter(|retired| retired.generation == current);
                self.finish(last.map(|retired| (retired, now)));
            }
            self.begin(&sample.generation, &sample.counts, now);
        }
        self.observe(&sample.counts, now);
    }

    /// Polls the step in flight and submits the next; never waits. A failed step is retried
    /// after 2, 4, 8, ... seconds; after [`MAX_RETRIES`] the frame is discarded.
    pub(crate) fn tick(&mut self, storage: &ConsoleStorage, ms: u64) {
        if let Some(outcome) = self.lane.poll(ms) {
            self.finish_step(outcome, ms);
        }
        if self.lane.is_busy() || ms < self.retry_at {
            return;
        }
        let Some((span, entries)) = self.pending() else { return };
        let (span, entries) = (*span, entries.to_vec());
        self.in_flight = Some(entries.len());
        let submitted = storage.submit_background(move |tx| {
            Box::pin(async move { record_rule_hits(tx, &span, &entries).await })
        });
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish_step(outcome, ms);
        }
    }

    /// Records the outcome of the step in flight.
    pub(crate) fn finish_step<T>(&mut self, outcome: Outcome<T>, ms: u64) {
        if self.in_flight.take().is_none() {
            return;
        }
        match outcome {
            Outcome::Done(_) => {
                self.retries = 0;
                self.retry_at = 0;
                self.acknowledge();
            }
            Outcome::Failed(_) | Outcome::Unknown => {
                self.retries += 1;
                if self.retries >= MAX_RETRIES {
                    self.discard();
                    self.retries = 0;
                }
                self.retry_at = ms.saturating_add(1000 << self.retries);
            }
            Outcome::NotQueued => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use sibuna_console_protocol::rule_hits::{Identity, Key, Name};
    use sibuna_store::rule_hits::{Counters, Matches};

    use super::*;

    fn generation(number: u64, utc: u64, rules: usize) -> Generation {
        let identity = Identity {
            key: Key::new("m:rule").unwrap(),
            name: Name::new("Original name").unwrap(),
        };
        Generation {
            node: 1,
            boot: [1; 16],
            number,
            revision: number + 10,
            born: Clock { utc, ms: utc * 1000 },
            rules: vec![identity; rules],
        }
    }

    fn counters(number: u64) -> Counters<MAX_RULES> {
        Counters::new(NonZeroU64::new(number).unwrap())
    }

    fn read(counters: &Counters<MAX_RULES>) -> Counts {
        let mut snapshot = Counts::default();
        counters.read(&mut snapshot);
        snapshot
    }

    fn observe(journal: &mut RuleHitJournal, counters: &Counters<MAX_RULES>, utc: u64) {
        journal.observe(&read(counters), Clock { utc, ms: utc * 1000 });
    }

    // rule_hit_journal_test.zig: "whole ending-minute cohorts conserve exact counts and
    // immutable identities".
    #[test]
    fn ending_minute_cohorts_conserve_exact_counts_and_identities() {
        let mut journal = RuleHitJournal::default();
        let mut source = generation(1, 60, 9);
        let counters = counters(1);
        journal.begin(&source, &read(&counters), Clock { utc: 60, ms: 60_000 });
        source.rules[0].name = Name::new("Recycled name").unwrap();
        let mut matches = Matches::new();
        matches.set(0);
        for utc in 61..181 {
            counters.record(&matches);
            observe(&mut journal, &counters, utc);
        }
        let (span, entries) = journal.pending().unwrap();
        span.validate().unwrap();
        assert_eq!(entries[0].hits, Some(59));
        assert!(!span.complete);
        assert_eq!(entries[0].identity.name.as_str(), "Original name");
        journal.acknowledge();
        assert_eq!(journal.pending().unwrap().1.len(), 1);
        journal.acknowledge();
        let (span, entries) = journal.pending().unwrap();
        span.validate().unwrap();
        assert!(span.complete);
        assert_eq!(entries[0].hits, Some(60));
        assert_eq!(journal.status().confirmed, 1);
    }

    // rule_hit_journal_test.zig: "publication, failed writes and a full queue preserve
    // ownership and expose loss".
    #[test]
    fn publication_failed_writes_and_a_full_queue_expose_loss() {
        let mut journal = RuleHitJournal::default();
        for number in 1..7u64 {
            let source = generation(number, number * 60, 1);
            let mut counters = counters(number);
            journal.begin(
                &source,
                &read(&counters),
                Clock { utc: number * 60, ms: number * 60_000 },
            );
            let mut matches = Matches::new();
            matches.set(0);
            for _ in 0..number {
                counters.record(&matches);
            }
            let clock = Clock { utc: number * 60 + 1, ms: number * 60_000 + 1000 };
            journal.finish(Some((&read(&counters), clock)));
            counters.reset(NonZeroU64::new(number + 1).unwrap());
        }
        assert_eq!(journal.frames.len(), 4);
        assert_eq!(journal.status().unconfirmed, 2);
        let (span, entries) = journal.pending().unwrap();
        assert_eq!(span.generation, 1);
        assert_eq!(entries[0].hits, Some(1));
        assert!(!span.complete);
        journal.discard();
        assert_eq!(journal.status().unconfirmed, 3);
        assert_eq!(journal.pending().unwrap().0.generation, 2);
    }

    // rule_hit_journal_test.zig: "clock reset and saturated counters never become
    // apparently complete zeroes".
    #[test]
    fn clock_resets_and_saturated_counters_never_look_complete() {
        let mut journal = RuleHitJournal::default();
        let source = generation(1, 120, 1);
        let counters = counters(1);
        journal.begin(&source, &read(&counters), Clock { utc: 120, ms: 120_000 });
        observe(&mut journal, &counters, 119);
        assert_eq!(journal.status().clock_resets, 1);
        let mut saturated = read(&counters);
        saturated.overflow = true;
        journal.observe(&saturated, Clock { utc: 121, ms: 121_000 });
        journal.observe(&saturated, Clock { utc: 180, ms: 180_000 });
        let (span, entries) = journal.pending().unwrap();
        assert_eq!(entries[0].hits, None);
        assert!(!span.complete);
        assert!(journal.status().overflow);
    }

    // A new generation retires the old one without resetting either generation's counters,
    // folds the old one's final counters (no hit after its last sample is lost), and begins
    // at its publication.
    #[test]
    fn a_published_generation_retires_the_old_one_without_losing_hits() {
        let mut journal = RuleHitJournal::default();
        let old = counters(1);
        let mut matches = Matches::new();
        matches.set(0);
        old.record(&matches);
        let mut sample = RuleHitSample { generation: generation(1, 100, 1), ..Default::default() };
        sample.counts = read(&old);
        journal.record(&sample, Clock { utc: 101, ms: 101_000 });
        old.record(&matches);
        sample.counts = read(&old);
        journal.record(&sample, Clock { utc: 102, ms: 102_000 });
        // Two more hits after the last sample, before the publication.
        old.record(&matches);
        old.record(&matches);
        let new = counters(2);
        new.record(&matches);
        sample.generation = generation(2, 102, 1);
        sample.generation.born = Clock { utc: 102, ms: 102_500 };
        sample.counts = read(&new);
        sample.retired = Some(read(&old));
        journal.record(&sample, Clock { utc: 103, ms: 103_000 });
        let (span, entries) = journal.pending().unwrap();
        assert_eq!((span.generation, entries[0].hits, span.complete), (1, Some(4), false));
        assert_eq!(journal.current.span.generation, 2);
        assert_eq!(journal.current.span.start_ms, 102_500);
        assert_eq!(journal.current.entries[0].hits, Some(1));
        assert_eq!(journal.status().unconfirmed, 0);
        // A generation first seen long after its publication starts at the sample. Final
        // counters of a generation the journal did not follow are ignored.
        let late = counters(3);
        late.record(&matches);
        sample.generation = generation(3, 10, 1);
        sample.counts = read(&late);
        sample.retired = Some(read(&old));
        journal.record(&sample, Clock { utc: 104, ms: 104_000 });
        assert_eq!(journal.status().unconfirmed, 1);
        assert_eq!(journal.current.span.observations, 0);
    }
}

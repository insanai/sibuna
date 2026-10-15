//! The live timeline (Zig's `timeline.zig`): the exact outcome counters observed by the
//! collector, folded into one bucket per monotonic second for the last hour.
//!
//! Each observation adds the counter increase since the previous one to the bucket of the
//! monotonic second it ends in; the bucket keeps the interval's start and end on both clocks,
//! how long was observed and whether a delayed collector or a wall-clock jump prevents
//! per-second attribution (`gap`). A counter that went backwards or a clock that did not
//! advance starts a new epoch, which invalidates every cursor of the old one.

use sibuna_console_protocol::timeline::{Bucket, CAPACITY, Counts, MAX_ROWS, Page, Query};
use sibuna_store::telemetry::Totals;

use super::LiveError;

/// Buckets kept: one per second of the last hour.
const SLOTS: u64 = CAPACITY as u64;

/// One reading of the counters.
#[derive(Clone, Copy, Debug)]
struct Observation {
    utc: u64,
    ms: u64,
    counts: Totals,
}

/// The collector's timeline.
#[derive(Debug)]
pub(crate) struct Timeline {
    /// Indexed by sequence modulo [`SLOTS`]; a slot holds the bucket of one sequence.
    slots: Box<[Option<Bucket>]>,
    previous: Option<Observation>,
    epoch: u32,
    discarded: u64,
}

impl Default for Timeline {
    fn default() -> Timeline {
        Timeline {
            slots: vec![None; CAPACITY as usize].into_boxed_slice(),
            previous: None,
            epoch: 1,
            discarded: 0,
        }
    }
}

/// Returns the increase from `previous` to `next`, or `None` when a counter went backwards.
fn delta(previous: &Totals, next: &Totals) -> Option<Counts> {
    Some(Counts {
        admitted: next.admitted.checked_sub(previous.admitted)?,
        challenged: next.challenged.checked_sub(previous.challenged)?,
        denied: next.denied.checked_sub(previous.denied)?,
        banned: next.banned.checked_sub(previous.banned)?,
        rate_limited: next.rate_limited.checked_sub(previous.rate_limited)?,
        other: next.other.checked_sub(previous.other)?,
        origin_4xx: next.origin_4xx.checked_sub(previous.origin_4xx)?,
        origin_5xx: next.origin_5xx.checked_sub(previous.origin_5xx)?,
    })
}

/// Returns `a + b` per counter, saturating.
fn add(a: &Counts, b: &Counts) -> Counts {
    let mut values = a.values();
    for (value, more) in values.iter_mut().zip(b.values()) {
        *value = value.saturating_add(more);
    }
    Counts::from_values(values)
}

impl Timeline {
    /// Returns the current epoch.
    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Observes the counters `totals` at Unix second `utc` and monotonic `ms` (since the
    /// collector started) and returns the interval since the previous observation, if one
    /// was recorded. The first observation only sets the baseline; a zero-duration one is
    /// ignored, so the next timed interval owns its counts.
    pub(crate) fn observe(&mut self, utc: u64, ms: u64, totals: Totals) -> Option<Bucket> {
        let next = Observation { utc, ms, counts: totals };
        let previous = self.previous.replace(next)?;
        if ms == previous.ms && utc == previous.utc {
            self.previous = Some(previous);
            return None;
        }
        let Some(counts) = delta(&previous.counts, &totals) else {
            self.reset();
            return None;
        };
        if ms <= previous.ms || utc < previous.utc {
            self.reset();
            return None;
        }
        let elapsed = ms - previous.ms;
        let clock_gap = utc - previous.utc > elapsed / 1000 + 1;
        let gap = elapsed > 1000 || clock_gap;
        let sequence = ms / 1000;
        let interval = Bucket {
            sequence,
            utc_start: previous.utc,
            utc_end: utc,
            start_ms: previous.ms,
            end_ms: ms,
            observed_ms: elapsed,
            observations: 1,
            gap,
            partial: false,
            counts,
        };
        // The remainder is below `SLOTS`, the slice's length.
        if let Some(slot) = self.slots.get_mut((sequence % SLOTS) as usize) {
            match slot {
                Some(bucket) if bucket.sequence == sequence => {
                    bucket.utc_end = utc;
                    bucket.end_ms = ms;
                    bucket.observed_ms = bucket.observed_ms.saturating_add(elapsed);
                    bucket.observations = bucket.observations.saturating_add(1);
                    bucket.gap = bucket.gap || gap;
                    bucket.counts = add(&bucket.counts, &counts);
                }
                _ => *slot = Some(interval),
            }
        }
        Some(interval)
    }

    /// Forgets every bucket and starts a new epoch.
    fn reset(&mut self) {
        self.slots.fill(None);
        self.epoch = self.epoch.saturating_add(1);
        self.discarded = self.discarded.saturating_add(1);
    }

    /// Returns the bucket of `sequence`, if retained.
    fn bucket(&self, sequence: u64) -> Option<&Bucket> {
        let slot = self.slots.get((sequence % SLOTS) as usize)?.as_ref()?;
        (slot.sequence == sequence).then_some(slot)
    }

    /// Returns one page of retained buckets, newest first, of `node` with boot `boot` (hex),
    /// continuing before `query.before`. At most [`SLOTS`] slots are probed, whatever the
    /// cursor or clock.
    ///
    /// Fails with [`LiveError::InvalidQuery`] for a limit of 0 or above [`MAX_ROWS`], or a
    /// cursor without all of `before`, `epoch` and `boot`; with
    /// [`LiveError::HistoryChanged`] for a cursor of another epoch or boot.
    pub(crate) fn page(&self, query: &Query, node: u32, boot: &str) -> Result<Page, LiveError> {
        let limit = usize::from(query.limit);
        if limit == 0 || limit > MAX_ROWS {
            return Err(LiveError::InvalidQuery);
        }
        let cursor = query.before.is_some();
        if cursor != query.epoch.is_some() || cursor != query.boot.is_some() {
            return Err(LiveError::InvalidQuery);
        }
        if let Some(epoch) = query.epoch
            && (epoch != self.epoch || query.boot.as_deref() != Some(boot))
        {
            return Err(LiveError::HistoryChanged);
        }
        let ms = self.previous.map_or(0, |previous| previous.ms);
        let newest = ms / 1000;
        let floor = newest.saturating_sub(SLOTS - 1);
        let oldest = (floor..=newest).find(|&sequence| self.bucket(sequence).is_some());
        let mut sequence = query.before.unwrap_or(newest + 1).min(newest + 1);
        let mut rows: Vec<Bucket> = Vec::with_capacity(limit);
        let mut next_before = None;
        while sequence > floor {
            sequence -= 1;
            let Some(bucket) = self.bucket(sequence) else { continue };
            if rows.len() == limit {
                next_before = rows.last().map(|row| row.sequence);
                break;
            }
            rows.push(Bucket { partial: sequence == newest, ..*bucket });
        }
        Ok(Page {
            version: 1,
            node,
            boot: boot.to_owned(),
            epoch: self.epoch,
            retention_seconds: CAPACITY,
            as_of_ms: ms,
            discarded_intervals: self.discarded,
            oldest_sequence: oldest,
            next_before,
            rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::codec::to_json;

    use super::*;

    const BOOT: &str = "00000000000000000000000000000001";

    fn query(limit: u8) -> Query {
        Query { limit, ..Query::default() }
    }

    // timeline_test.zig: "four counter observations conserve outcomes and monotonic
    // duration within each bucket".
    #[test]
    fn observations_conserve_outcomes_and_duration_within_a_bucket() {
        let mut timeline = Timeline::default();
        timeline.observe(100, 0, Totals::default());
        let mut totals = Totals::default();
        for i in 1..5 {
            totals.admitted += 3;
            totals.banned += 1;
            totals.origin_4xx += 1;
            timeline.observe(100, i * 200, totals);
        }
        let page = timeline.page(&Query::default(), 7, BOOT).unwrap();
        assert_eq!(page.rows.len(), 1);
        let bucket = page.rows[0];
        assert_eq!((bucket.counts.admitted, bucket.counts.banned), (12, 4));
        assert_eq!(bucket.counts.origin_4xx, 4);
        assert_eq!((bucket.observed_ms, bucket.observations), (800, 4));
        assert!(!bucket.gap && bucket.partial);
        // Zero elapsed observations must not discard counts or divide by zero.
        totals.admitted += 2;
        timeline.observe(100, 800, totals);
        timeline.observe(101, 1000, totals);
        let next = timeline.page(&Query::default(), 7, BOOT).unwrap();
        assert_eq!(next.rows[0].counts.admitted, 2);
        assert_eq!(next.rows[0].observed_ms, 200);
        assert!(next.rows[0].partial && !next.rows[1].partial);
    }

    // timeline_test.zig: "retention and keyset pagination are bounded and cursors cannot
    // cross a reset".
    #[test]
    fn pages_are_bounded_and_cursors_cannot_cross_a_reset() {
        let mut timeline = Timeline::default();
        timeline.observe(100, 0, Totals::default());
        for i in 1..4001 {
            timeline.observe(100 + i, i * 1000, Totals { admitted: i, ..Totals::default() });
        }
        let first = timeline.page(&query(2), 1, BOOT).unwrap();
        assert_eq!(first.oldest_sequence, Some(401));
        assert_eq!((first.rows[0].sequence, first.rows[1].sequence), (4000, 3999));
        let cursor = Query {
            before: first.next_before,
            boot: Some(BOOT.into()),
            epoch: Some(first.epoch),
            limit: 2,
            node: None,
        };
        let second = timeline.page(&cursor, 1, BOOT).unwrap();
        assert_eq!(second.rows[0].sequence, 3998);
        timeline.observe(4101, 4_001_000, Totals::default());
        assert_eq!(timeline.page(&cursor, 1, BOOT), Err(LiveError::HistoryChanged));
        let reset = timeline.page(&Query::default(), 1, BOOT).unwrap();
        assert!(reset.rows.is_empty());
        assert_eq!(reset.discarded_intervals, 1);
        assert_eq!(timeline.page(&query(17), 1, BOOT), Err(LiveError::InvalidQuery));
        let partial = Query { before: Some(10), ..Query::default() };
        assert_eq!(timeline.page(&partial, 1, BOOT), Err(LiveError::InvalidQuery));
    }

    // timeline_test.zig: "delayed observations retain their actual interval and leave
    // missing seconds absent".
    #[test]
    fn delayed_observations_keep_their_interval_and_leave_seconds_absent() {
        let mut timeline = Timeline::default();
        let totals = |admitted| Totals { admitted, ..Totals::default() };
        timeline.observe(100, 0, totals(0));
        timeline.observe(101, 1000, totals(1));
        timeline.observe(111, 11_000, totals(101));
        let page = timeline.page(&Query::default(), 1, BOOT).unwrap();
        assert_eq!(page.rows.len(), 2);
        assert!(page.rows[0].gap);
        assert_eq!((page.rows[0].observed_ms, page.rows[0].counts.admitted), (10_000, 100));
        // A UTC jump that monotonic time does not explain also prevents second attribution.
        timeline.observe(1000, 11_250, totals(102));
        assert!(timeline.page(&Query::default(), 1, BOOT).unwrap().rows[0].gap);
        timeline.observe(112, 11_500, totals(103));
        assert_eq!(timeline.epoch(), 2);
        assert!(timeline.page(&Query::default(), 1, BOOT).unwrap().rows.is_empty());
    }

    // timeline_test.zig: "maximum timeline page fits HTTP and keeps u64 values exact
    // through JSON".
    #[test]
    fn the_largest_page_fits_a_reply_and_keeps_counters_exact() {
        let max = Counts::from_values([u64::MAX; 8]);
        let row = Bucket {
            sequence: u64::MAX,
            utc_start: u64::MAX,
            utc_end: u64::MAX,
            start_ms: u64::MAX,
            end_ms: u64::MAX,
            observed_ms: u64::MAX,
            observations: u32::MAX,
            gap: false,
            partial: false,
            counts: max,
        };
        let page = Page {
            version: 1,
            node: u32::MAX,
            boot: BOOT.into(),
            epoch: u32::MAX,
            retention_seconds: CAPACITY,
            as_of_ms: u64::MAX,
            discarded_intervals: u64::MAX,
            oldest_sequence: Some(u64::MAX),
            next_before: Some(u64::MAX),
            rows: vec![row; MAX_ROWS],
        };
        let text = to_json(&page);
        assert!(text.len() <= 16 * 1024 - 256, "{}", text.len());
        assert!(text.contains("\"18446744073709551615\""));
    }
}

//! Window summaries over minute history: one descending scan per node and window. Only
//! complete, non-overlapping intervals can support a deviation; missing pages, restarts
//! and retention never become zero traffic.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{Decode, DecodeError, Encode, Fields, Path, counter_field, field};
use crate::error::{InvalidResponse, ValidationError, limit, response, sum};
use crate::minutes::{self, Cursor, Record, Reply};
use crate::timeline::Counts;

/// The most records one summary part covers (one storage page).
pub const MAX_ROWS: u64 = 96;

/// Milliseconds a complete minute observed, at least and at most.
const COMPLETE_MS: std::ops::RangeInclusive<u64> = 59_000..=61_000;

/// The totals of one node over one window of minutes, accumulated page by page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Window {
    /// The node.
    pub node: u32,
    /// The first minute.
    pub from: u64,
    /// The last minute.
    pub until: u64,
    /// The summed counts.
    pub counts: Counts,
    /// Records folded in.
    pub rows: u64,
    /// Complete records folded in.
    pub complete_rows: u64,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// The oldest record folded in.
    pub last: Option<Cursor>,
    /// Where the scan continues.
    pub next: Option<Cursor>,
    /// The scan reached the start of the window.
    pub finished: bool,
    /// Several boots or epochs share a minute; the counts stay, coverage cannot be claimed.
    pub ambiguous: bool,
    /// The retention changed during the scan.
    pub retention_changed: bool,
    /// The retention in force, in days.
    pub retention_days: Option<u16>,
}

impl Window {
    /// Returns true when the window is finished, unambiguous, and every minute has exactly
    /// one complete record.
    pub fn covered(&self) -> bool {
        self.finished
            && !self.ambiguous
            && !self.retention_changed
            && self.until.checked_sub(self.from).and_then(|span| span.checked_add(1))
                == Some(self.rows)
            && self.complete_rows == self.rows
            && self.observed_ms != 0
    }

    /// Folds one page of records in; nothing changes unless the whole page is valid.
    ///
    /// # Errors
    ///
    /// [`InvalidResponse`] for a finished window, a page of another scope or version, an
    /// invalid record, an out-of-order record, a continuation cursor that is not the last
    /// record, or counter overflow.
    pub fn accept(&mut self, page: &Reply) -> Result<(), InvalidResponse> {
        response(
            self.finished
                || page.version != 1
                || page.rows.len() > minutes::MAX_ROWS
                || page.until_minute != self.until
                || page.from_minute < self.from
                || page.from_minute > self.until
                || page.observed_at / 60 <= self.until
                || page.retention_days == 0
                || page.retention_days > minutes::RETENTION_DAYS,
        )?;
        let mut next = *self;
        next.retention_changed = self.retention_changed
            || page.from_minute != self.from
            || self.retention_days.is_some_and(|days| days != page.retention_days);
        next.retention_days = Some(page.retention_days);
        for row in &page.rows {
            next.add(row)?;
        }
        if let Some(cursor) = page.next {
            response(page.rows.is_empty() || Some(cursor) != next.last)?;
        }
        next.next = page.next;
        next.finished = page.next.is_none();
        *self = next;
        Ok(())
    }

    /// Folds one record in; nothing changes unless it is valid.
    ///
    /// # Errors
    ///
    /// [`InvalidResponse`] for a record of another node or outside the window, inconsistent
    /// interval fields, a complete record that is not sealed and gap-free, a record not
    /// strictly older than the previous one, or counter overflow.
    pub fn add(&mut self, row: &Record) -> Result<(), InvalidResponse> {
        response(
            row.node != self.node
                || row.minute < self.from
                || row.minute > self.until
                || row.minute != row.utc_end / 60
                || row.utc_start > row.utc_end
                || row.end_ms <= row.start_ms
                || row.observed_ms != row.end_ms - row.start_ms
                || row.observations == 0
                || row.epoch == 0
                || row.boot == [0; 16]
                || (row.complete
                    && (!row.sealed || row.gap || !COMPLETE_MS.contains(&row.observed_ms))),
        )?;
        let mut next = *self;
        if let Some(cursor) = self.last {
            response(!precedes(&row.cursor(), &cursor))?;
            // Several boots or epochs may overlap one UTC minute. Keep the counts for
            // inspection, but never publish a comparison as complete in that case.
            next.ambiguous = self.ambiguous || row.minute == cursor.minute;
        }
        next.counts = self.counts.checked_add(&row.counts).ok_or(InvalidResponse)?;
        total(&next.counts)?;
        next.rows = sum(self.rows, 1)?;
        next.complete_rows = sum(self.complete_rows, u64::from(row.complete))?;
        next.observed_ms = sum(self.observed_ms, row.observed_ms)?;
        next.last = Some(row.cursor());
        *self = next;
        Ok(())
    }
}

impl Encode for Window {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        counter_field(json, "from", self.from)?;
        counter_field(json, "until", self.until)?;
        field(json, "counts", &self.counts)?;
        counter_field(json, "rows", self.rows)?;
        counter_field(json, "complete_rows", self.complete_rows)?;
        counter_field(json, "observed_ms", self.observed_ms)?;
        field(json, "last", &self.last)?;
        field(json, "next", &self.next)?;
        field(json, "finished", &self.finished)?;
        field(json, "ambiguous", &self.ambiguous)?;
        field(json, "retention_changed", &self.retention_changed)?;
        field(json, "retention_days", &self.retention_days)?;
        json.end_object()
    }
}

impl Decode for Window {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Window, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let window = Window {
            node: fields.or_default("node")?,
            from: fields.or_default("from")?,
            until: fields.or_default("until")?,
            counts: fields.or_default("counts")?,
            rows: fields.or_default("rows")?,
            complete_rows: fields.or_default("complete_rows")?,
            observed_ms: fields.or_default("observed_ms")?,
            last: fields.or_default("last")?,
            next: fields.or_default("next")?,
            finished: fields.or_default("finished")?,
            ambiguous: fields.or_default("ambiguous")?,
            retention_changed: fields.or_default("retention_changed")?,
            retention_days: fields.or_default("retention_days")?,
        };
        fields.finish()?;
        Ok(window)
    }
}

/// One bounded storage scan summarized by the producer. The consumer still owns ordering,
/// continuation and interval completeness; an interrupted scan never becomes a full day.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Part {
    /// The format version.
    pub version: u8,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The newest record of the scan.
    pub first: Option<Cursor>,
    /// The scan's totals.
    pub window: Window,
}

impl Encode for Part {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "observed_at", &self.observed_at)?;
        field(json, "first", &self.first)?;
        field(json, "window", &self.window)?;
        json.end_object()
    }
}

impl Decode for Part {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Part, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let part = Part {
            version: fields.or("version", 1)?,
            observed_at: fields.required("observed_at")?,
            first: fields.or_default("first")?,
            window: fields.required("window")?,
        };
        fields.finish()?;
        Ok(part)
    }
}

/// Checks a summary query: a node is required, the limit is at most [`MAX_ROWS`], the
/// range is closed (before the current minute), and a cursor belongs to the node.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] otherwise.
pub fn validate(query: &minutes::Query) -> Result<(), ValidationError> {
    let node = query.node.unwrap_or(0);
    limit(query.limit == 0 || u64::from(query.limit) > MAX_ROWS || node == 0)?;
    minutes::validate(&minutes::Query { limit: 1, ..*query })?;
    limit(query.until_minute >= query.observed_at / 60)?;
    limit(query.before.is_some_and(|cursor| cursor.node != node))
}

/// Returns true when `a` comes strictly before `b`: by minute, then node, boot bytes and
/// epoch.
pub fn precedes(a: &Cursor, b: &Cursor) -> bool {
    (a.minute, a.node, a.boot, a.epoch) < (b.minute, b.node, b.boot, b.epoch)
}

/// Continues `window` with the next part; nothing changes unless the part is valid.
///
/// # Errors
///
/// [`InvalidResponse`] for a finished window, a part of another scope or version, an
/// oversized or inconsistent part, a part that does not follow the previous one, or
/// counter overflow.
pub fn accept_part(window: &mut Window, part: &Part) -> Result<(), InvalidResponse> {
    let item = &part.window;
    response(
        window.finished
            || part.version != 1
            || item.node != window.node
            || item.from != window.from
            || item.until != window.until
            || item.rows > MAX_ROWS
            || item.complete_rows > item.rows
            || item.retention_days.is_none_or(|days| days == 0 || days > minutes::RETENTION_DAYS)
            || part.observed_at / 60 <= window.until
            || item.finished != item.next.is_none(),
    )?;
    validate_endpoints(part)?;
    let mut next = *window;
    if let (Some(first), Some(last)) = (part.first, window.last) {
        response(!precedes(&first, &last))?;
        next.ambiguous = next.ambiguous || first.minute == last.minute;
    }
    next.counts = next.counts.checked_add(&item.counts).ok_or(InvalidResponse)?;
    total(&next.counts)?;
    next.rows = sum(next.rows, item.rows)?;
    next.complete_rows = sum(next.complete_rows, item.complete_rows)?;
    next.observed_ms = sum(next.observed_ms, item.observed_ms)?;
    next.ambiguous = next.ambiguous || item.ambiguous;
    next.retention_changed = window.retention_changed
        || item.retention_changed
        || (window.retention_days.is_some() && window.retention_days != item.retention_days);
    next.retention_days = item.retention_days;
    next.last = item.last.or(window.last);
    next.next = item.next;
    next.finished = item.finished;
    *window = next;
    Ok(())
}

/// Checks that a part's first and last records describe its rows consistently.
fn validate_endpoints(part: &Part) -> Result<(), InvalidResponse> {
    let item = &part.window;
    if item.rows == 0 {
        return response(
            part.first.is_some()
                || item.last.is_some()
                || item.next.is_some()
                || item.observed_ms != 0
                || item.counts != Counts::default(),
        );
    }
    let first = part.first.ok_or(InvalidResponse)?;
    let last = item.last.ok_or(InvalidResponse)?;
    for cursor in [first, last] {
        response(
            cursor.node != item.node
                || cursor.minute < item.from
                || cursor.minute > item.until
                || cursor.epoch == 0
                || cursor.boot == [0; 16],
        )?;
    }
    response(first.minute < last.minute)?;
    // Wide products cannot overflow: rows are at most MAX_ROWS.
    let span = u128::from(first.minute - last.minute) + 1;
    response(
        item.observed_ms == 0
            || u128::from(item.observed_ms) < u128::from(item.complete_rows) * 59_000
            || (item.rows == item.complete_rows
                && u128::from(item.observed_ms) > u128::from(item.rows) * 61_000)
            || (!item.ambiguous && u128::from(item.rows) > span)
            || (item.rows == 1 && first != last)
            || (item.rows > 1 && !precedes(&last, &first)),
    )?;
    response(item.next.is_some_and(|cursor| cursor != last))
}

/// A comparison between two windows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Deviation {
    /// The windows cannot be compared.
    Unavailable,
    /// The earlier window had none; the later one has some.
    New,
    /// The change of the observed rate, in percent.
    Percent(f64),
}

/// A counter the dashboard compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Metric {
    /// All local outcomes.
    Requests,
    /// Admitted requests.
    Admitted,
    /// Challenged requests.
    Challenged,
    /// Denied requests.
    Denied,
    /// Banned requests.
    Banned,
    /// Rate-limited requests.
    RateLimited,
    /// Other outcomes.
    Other,
    /// Origin 4xx responses.
    Origin4xx,
    /// Origin 5xx responses.
    Origin5xx,
}

/// Compares `metric` between two covered windows of equal length.
pub fn deviation(current: &Window, previous: &Window, metric: Metric) -> Deviation {
    if !current.covered()
        || !previous.covered()
        || current.until - current.from != previous.until - previous.from
    {
        return Deviation::Unavailable;
    }
    let (Some(now), Some(before)) =
        (value(&current.counts, metric), value(&previous.counts, metric))
    else {
        return Deviation::Unavailable;
    };
    rate_deviation(
        RateObservation { value: now, elapsed_ms: current.observed_ms },
        RateObservation { value: before, elapsed_ms: previous.observed_ms },
    )
}

/// A count and the milliseconds it was observed over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RateObservation {
    /// The count.
    pub value: u64,
    /// Milliseconds observed.
    pub elapsed_ms: u64,
}

/// Compares two observed rates. Equal UTC windows still have millisecond sampler jitter,
/// so rates are compared, not counts; exact wide products keep small deltas above 2^53
/// before the floating-point display value is formed.
pub fn rate_deviation(current: RateObservation, previous: RateObservation) -> Deviation {
    if current.elapsed_ms == 0 || previous.elapsed_ms == 0 {
        return Deviation::Unavailable;
    }
    let (a, b) = (current.value, previous.value);
    if b == 0 {
        return if a == 0 { Deviation::Percent(0.0) } else { Deviation::New };
    }
    let left = u128::from(a) * u128::from(previous.elapsed_ms);
    let right = u128::from(b) * u128::from(current.elapsed_ms);
    let difference = left.abs_diff(right) as f64;
    let sign = if left >= right { 100.0 } else { -100.0 };
    Deviation::Percent(difference / right as f64 * sign)
}

/// Returns the count of `metric`; `None` if the request total overflows.
pub fn value(counts: &Counts, metric: Metric) -> Option<u64> {
    Some(match metric {
        Metric::Requests => return counts.requests(),
        Metric::Admitted => counts.admitted,
        Metric::Challenged => counts.challenged,
        Metric::Denied => counts.denied,
        Metric::Banned => counts.banned,
        Metric::RateLimited => counts.rate_limited,
        Metric::Other => counts.other,
        Metric::Origin4xx => counts.origin_4xx,
        Metric::Origin5xx => counts.origin_5xx,
    })
}

/// Returns the request total (the six local outcomes).
///
/// # Errors
///
/// [`InvalidResponse`] if it overflows.
pub fn total(counts: &Counts) -> Result<u64, InvalidResponse> {
    counts.requests().ok_or(InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered_window() -> Window {
        Window {
            from: 10,
            until: 10,
            rows: 1,
            complete_rows: 1,
            finished: true,
            observed_ms: 60_000,
            ..Window::default()
        }
    }

    // Port of minute_summary.zig "comparisons require complete equal coverage and preserve
    // small large-counter deviations".
    #[test]
    fn comparisons_require_complete_equal_coverage_and_preserve_small_large_counter_deviations() {
        let mut a = covered_window();
        let mut b = a;
        assert_eq!(deviation(&a, &b, Metric::Requests), Deviation::Percent(0.0));
        a.counts.admitted = 1;
        assert_eq!(deviation(&a, &b, Metric::Requests), Deviation::New);
        b.counts.admitted = 9_007_199_254_740_993;
        a.counts.admitted = b.counts.admitted + 1;
        assert!(matches!(deviation(&a, &b, Metric::Requests), Deviation::Percent(p) if p > 0.0));
        a.observed_ms += 1;
        assert!(matches!(deviation(&a, &b, Metric::Requests), Deviation::Percent(p) if p < 0.0));
        a = b;
        a.ambiguous = true;
        assert_eq!(deviation(&a, &b, Metric::Requests), Deviation::Unavailable);
        a = b;
        a.finished = false;
        assert_eq!(deviation(&a, &b, Metric::Requests), Deviation::Unavailable);
    }

    pub(crate) fn test_record(minute: u64, admitted: u64) -> Record {
        Record {
            node: 1,
            boot: [1; 16],
            epoch: 1,
            minute,
            utc_start: minute * 60 - 60,
            utc_end: minute * 60,
            start_ms: minute * 60_000 - 60_000,
            end_ms: minute * 60_000,
            observed_ms: 60_000,
            observations: 240,
            sealed: true,
            complete: true,
            counts: Counts { admitted, ..Counts::default() },
            ..Record::default()
        }
    }

    // Port of minute_summary.zig "minute comparison pages are owned ordered atomic and
    // conservative across boots".
    #[test]
    fn minute_comparison_pages_are_owned_ordered_atomic_and_conservative_across_boots() {
        let mut window = Window { node: 1, from: 10, until: 11, ..Window::default() };
        let mut row = test_record(11, 4);
        let mut page = Reply {
            from_minute: 10,
            until_minute: 11,
            observed_at: 720,
            rows: vec![row],
            next: Some(row.cursor()),
            ..Reply::default()
        };
        window.accept(&page).unwrap();
        assert!(!window.covered());
        let saved = window;
        // Replaying or widening a page must not add counters twice.
        assert_eq!(window.accept(&page), Err(InvalidResponse));
        assert_eq!(saved, window);
        row = test_record(10, 8);
        row.node = 2;
        page.rows = vec![row];
        assert_eq!(window.accept(&page), Err(InvalidResponse));
        assert_eq!(saved, window);
        row.node = 1;
        page.rows = vec![row];
        page.next = None;
        window.accept(&page).unwrap();
        assert!(window.covered());
        assert_eq!(window.counts.admitted, 12);
        let mut overlap = saved;
        let mut late = test_record(11, 2);
        late.boot = [0; 16];
        late.boot[15] = 1;
        page.rows = vec![late];
        overlap.accept(&page).unwrap();
        assert!(overlap.ambiguous && !overlap.covered());
        let mut missing = saved;
        page.rows = Vec::new();
        missing.accept(&page).unwrap();
        assert!(!missing.covered());
        let mut overflow = saved;
        page.rows = vec![test_record(10, u64::MAX)];
        assert_eq!(overflow.accept(&page), Err(InvalidResponse));
        assert_eq!(saved, overflow);
    }

    // Port of minute_summary.zig "compact pages retain exact counters and fence cross-page
    // duplicates and replays".
    #[test]
    fn compact_pages_retain_exact_counters_and_fence_cross_page_duplicates_and_replays() {
        let base =
            Window { node: 1, from: 10, until: 11, retention_days: Some(90), ..Window::default() };
        let mut item = Part { version: 1, observed_at: 720, first: None, window: base };
        let first = test_record(11, 9_007_199_254_740_993);
        item.first = Some(first.cursor());
        item.window.add(&first).unwrap();
        item.window.next = Some(first.cursor());
        let mut window = Window { node: 1, from: 10, until: 11, ..Window::default() };
        accept_part(&mut window, &item).unwrap();
        let saved = window;
        assert_eq!(accept_part(&mut window, &item), Err(InvalidResponse));
        assert_eq!(saved, window);
        let second = test_record(10, 1);
        item.window = base;
        item.first = Some(second.cursor());
        item.window.add(&second).unwrap();
        item.window.finished = true;
        accept_part(&mut window, &item).unwrap();
        assert!(window.covered());
        assert_eq!(window.counts.admitted, 9_007_199_254_740_994);
        window = saved;
        let mut last = item.window.last.unwrap();
        last.minute = 11;
        last.boot = [0; 16];
        last.boot[15] = 1;
        item.window.last = Some(last);
        item.first = item.window.last;
        accept_part(&mut window, &item).unwrap();
        assert!(window.ambiguous && !window.covered());
        window = saved;
        item.window.rows = MAX_ROWS + 1;
        assert_eq!(accept_part(&mut window, &item), Err(InvalidResponse));
        assert_eq!(saved, window);
    }

    #[test]
    fn summary_queries_need_a_node_and_a_closed_range() {
        let query = minutes::Query {
            observed_at: 720,
            from_minute: 10,
            until_minute: 11,
            node: Some(1),
            limit: 96,
            ..minutes::Query::default()
        };
        assert_eq!(validate(&query), Ok(()));
        assert!(validate(&minutes::Query { node: None, ..query }).is_err());
        assert!(validate(&minutes::Query { limit: 97, ..query }).is_err());
        assert!(validate(&minutes::Query { until_minute: 12, ..query }).is_err());
    }
}

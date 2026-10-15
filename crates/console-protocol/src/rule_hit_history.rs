//! Bounded historical rule-hit comparisons. The owner and the browser share this
//! arithmetic: a window freezes its rule, node, revision and UTC boundaries across
//! continuation, and a part is merged only after every scope, cursor and arithmetic check.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, byte_array, counter_field, decode_byte_array,
    field, optional_counter, optional_counter_field,
};
use crate::error::{InvalidResponse, MAX_I64, ValidationError, limit, response};
use crate::rule_hits::{Key, Span};

/// Observations per page.
pub const PAGE_ROWS: u32 = 48;
/// Display bins per window.
pub const BIN_COUNT: usize = 24;
/// The longest window, in minutes.
const MAX_WINDOW_MINUTES: u64 = 90 * 1440;

/// A position in the descending observation scan: minute, boot bytes, sequence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The UTC minute index.
    pub minute: u64,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The interval sequence within the boot.
    pub sequence: u64,
}

impl Encode for Cursor {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "minute", self.minute)?;
        json.key("boot")?;
        byte_array(json, &self.boot)?;
        counter_field(json, "sequence", self.sequence)?;
        json.end_object()
    }
}

impl Decode for Cursor {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Cursor, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let cursor = Cursor {
            minute: fields.required("minute")?,
            boot: fields.required_with("boot", decode_byte_array)?,
            sequence: fields.required("sequence")?,
        };
        fields.finish()?;
        Ok(cursor)
    }
}

/// The frozen scope of a comparison window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Request {
    /// The rule's key.
    pub key: Key,
    /// The node.
    pub node: u32,
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// One policy revision, or `None` for all.
    pub revision: Option<u64>,
    /// Continue before this position.
    pub before: Option<Cursor>,
}

impl Encode for Request {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "key", &self.key)?;
        field(json, "node", &self.node)?;
        counter_field(json, "from_minute", self.from_minute)?;
        counter_field(json, "until_minute", self.until_minute)?;
        optional_counter_field(json, "revision", self.revision)?;
        field(json, "before", &self.before)?;
        json.end_object()
    }
}

impl Decode for Request {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Request, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let request = Request {
            key: fields.required("key")?,
            node: fields.required("node")?,
            from_minute: fields.required("from_minute")?,
            until_minute: fields.required("until_minute")?,
            revision: fields.or_default("revision")?,
            before: fields.or_default("before")?,
        };
        fields.finish()?;
        Ok(request)
    }
}

/// A history query as storage receives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The scope.
    pub request: Request,
}

/// One stored observation: an interval and the rule's hits in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Row {
    /// The interval.
    pub span: Span,
    /// The hits; `None` when the counter was unavailable.
    pub hits: Option<u64>,
}

/// One display bin of a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bin {
    /// Hits; `None` once any contributing observation lacked a counter or the sum
    /// overflowed.
    pub hits: Option<u64>,
    /// Observations.
    pub rows: u32,
    /// Complete observations.
    pub complete: u32,
}

impl Default for Bin {
    fn default() -> Bin {
        Bin { hits: Some(0), rows: 0, complete: 0 }
    }
}

impl Encode for Bin {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        optional_counter_field(json, "hits", self.hits)?;
        field(json, "rows", &self.rows)?;
        field(json, "complete", &self.complete)?;
        json.end_object()
    }
}

impl Decode for Bin {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Bin, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let bin = Bin {
            hits: fields.or("hits", Some(0))?,
            rows: fields.or_default("rows")?,
            complete: fields.or_default("complete")?,
        };
        fields.finish()?;
        Ok(bin)
    }
}

/// A rule's hits over one frozen window, accumulated page by page.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Window {
    /// The frozen scope; `before` advances with each merged part.
    pub request: Request,
    /// Hits; `None` once any observation lacked a counter or the sum overflowed.
    pub hits: Option<u64>,
    /// Observations folded in.
    pub rows: u32,
    /// Complete observations folded in.
    pub complete: u32,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// The newest observation.
    pub first: Option<Cursor>,
    /// The oldest observation.
    pub last: Option<Cursor>,
    /// Where the scan continues.
    pub next: Option<Cursor>,
    /// The scan reached the start of the window.
    pub finished: bool,
    /// Several boots share a minute.
    pub ambiguous: bool,
    /// Retention removed part of the window.
    pub clipped: bool,
    /// The retention in force, in days.
    pub retention_days: Option<u16>,
    /// The largest unconfirmed-observation count seen.
    pub unconfirmed: u64,
    /// The smallest policy revision seen.
    pub min_revision: Option<u64>,
    /// The largest policy revision seen.
    pub max_revision: Option<u64>,
    /// Display bins over the window.
    pub bins: [Bin; BIN_COUNT],
}

impl Window {
    /// Returns an empty window over `request`.
    pub fn new(request: Request) -> Window {
        Window {
            request,
            hits: Some(0),
            rows: 0,
            complete: 0,
            observed_ms: 0,
            first: None,
            last: None,
            next: None,
            finished: false,
            ambiguous: false,
            clipped: false,
            retention_days: None,
            unconfirmed: 0,
            min_revision: None,
            max_revision: None,
            bins: [Bin::default(); BIN_COUNT],
        }
    }

    /// Returns true when the window is finished, unambiguous, unclipped, counted, and
    /// every minute has exactly one complete observation.
    pub fn covered(&self) -> bool {
        let minutes = self.request.until_minute.checked_sub(self.request.from_minute);
        self.finished
            && !self.ambiguous
            && !self.clipped
            && self.hits.is_some()
            && minutes.and_then(|span| span.checked_add(1)) == Some(u64::from(self.rows))
            && self.complete == self.rows
    }

    /// Folds one observation in; nothing changes unless it is valid.
    ///
    /// # Errors
    ///
    /// [`InvalidResponse`] for an invalid interval, an observation outside the scope, one
    /// not strictly older than the previous one (or the request's cursor), or overflow.
    pub fn add(&mut self, row: &Row) -> Result<(), InvalidResponse> {
        let span = &row.span;
        span.validate().map_err(|_| InvalidResponse)?;
        let request = &self.request;
        response(
            span.node != request.node
                || span.minute < request.from_minute
                || span.minute > request.until_minute
                || request.revision.is_some_and(|revision| span.revision != revision),
        )?;
        let index = bin_index(request, span.minute).ok_or(InvalidResponse)?;
        let cursor = Cursor { minute: span.minute, boot: span.boot, sequence: span.sequence };
        let mut next = self.clone();
        if let Some(last) = self.last.or(self.request.before) {
            response(!precedes(&cursor, &last))?;
            next.ambiguous = self.ambiguous || cursor.minute == last.minute;
        }
        next.first = self.first.or(Some(cursor));
        next.hits = sum(self.hits, row.hits);
        next.rows = self.rows.checked_add(1).ok_or(InvalidResponse)?;
        next.complete =
            self.complete.checked_add(u32::from(span.complete)).ok_or(InvalidResponse)?;
        next.observed_ms =
            self.observed_ms.checked_add(span.observed_ms).ok_or(InvalidResponse)?;
        next.unconfirmed = self.unconfirmed.max(span.unconfirmed);
        next.min_revision =
            Some(self.min_revision.map_or(span.revision, |r| r.min(span.revision)));
        next.max_revision =
            Some(self.max_revision.map_or(span.revision, |r| r.max(span.revision)));
        let bin = next.bins.get_mut(index).ok_or(InvalidResponse)?;
        bin.hits = sum(bin.hits, row.hits);
        bin.rows = bin.rows.checked_add(1).ok_or(InvalidResponse)?;
        bin.complete =
            bin.complete.checked_add(u32::from(span.complete)).ok_or(InvalidResponse)?;
        next.last = Some(cursor);
        *self = next;
        Ok(())
    }
}

/// The bin a minute falls in: the floor projection of the window onto [`BIN_COUNT`]
/// bins. `None` for a minute outside the window.
fn bin_index(request: &Request, minute: u64) -> Option<usize> {
    let offset = minute.checked_sub(request.from_minute)?;
    let duration = u128::from(request.until_minute.checked_sub(request.from_minute)?) + 1;
    usize::try_from(u128::from(offset) * BIN_COUNT as u128 / duration).ok()
}

impl Encode for Window {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "request", &self.request)?;
        optional_counter_field(json, "hits", self.hits)?;
        field(json, "rows", &self.rows)?;
        field(json, "complete", &self.complete)?;
        counter_field(json, "observed_ms", self.observed_ms)?;
        field(json, "first", &self.first)?;
        field(json, "last", &self.last)?;
        field(json, "next", &self.next)?;
        field(json, "finished", &self.finished)?;
        field(json, "ambiguous", &self.ambiguous)?;
        field(json, "clipped", &self.clipped)?;
        field(json, "retention_days", &self.retention_days)?;
        counter_field(json, "unconfirmed", self.unconfirmed)?;
        optional_counter_field(json, "min_revision", self.min_revision)?;
        optional_counter_field(json, "max_revision", self.max_revision)?;
        field(json, "bins", &self.bins)?;
        json.end_object()
    }
}

impl Decode for Window {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Window, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let window = Window {
            request: fields.required("request")?,
            hits: fields.or("hits", Some(0))?,
            rows: fields.or_default("rows")?,
            complete: fields.or_default("complete")?,
            observed_ms: fields.or_default("observed_ms")?,
            first: fields.or_default("first")?,
            last: fields.or_default("last")?,
            next: fields.or_default("next")?,
            finished: fields.or_default("finished")?,
            ambiguous: fields.or_default("ambiguous")?,
            clipped: fields.or_default("clipped")?,
            retention_days: fields.or_default("retention_days")?,
            unconfirmed: fields.or_default("unconfirmed")?,
            min_revision: fields.or_default("min_revision")?,
            max_revision: fields.or_default("max_revision")?,
            bins: fields.or("bins", [Bin::default(); BIN_COUNT])?,
        };
        fields.finish()?;
        Ok(window)
    }
}

/// One bounded storage scan of a window.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Part {
    /// The format version.
    pub version: u8,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The scan's totals.
    pub window: Window,
}

impl Encode for Part {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "observed_at", &self.observed_at)?;
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
            window: fields.required("window")?,
        };
        fields.finish()?;
        Ok(part)
    }
}

/// Checks a history query: a key, a node, a closed window of less than 90 days that has
/// ended, and a cursor inside it.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] otherwise.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    let request = &query.request;
    limit(
        request.key.is_empty()
            || request.node == 0
            || request.from_minute > request.until_minute
            || request.until_minute - request.from_minute >= MAX_WINDOW_MINUTES
            || query.observed_at > MAX_I64
            || request.until_minute >= query.observed_at / 60
            || request.revision.unwrap_or(0) > MAX_I64,
    )?;
    limit(request.before.is_some_and(|cursor| {
        cursor.minute < request.from_minute
            || cursor.minute > request.until_minute
            || cursor.sequence == 0
            || cursor.sequence > MAX_I64
            || cursor.boot == [0; 16]
    }))
}

/// The minutes one display bin covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BinRange {
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
}

/// Returns the minutes of bin `index`, the inverse of the floor projection [`Window::add`]
/// uses, so charts and accessible tables agree. Empty bins of short windows have no
/// minute; they are not gaps. `None` also for an index past [`BIN_COUNT`] or an inverted
/// window.
pub fn bin_range(request: &Request, index: usize) -> Option<BinRange> {
    if index >= BIN_COUNT {
        return None;
    }
    let duration = u128::from(request.until_minute.checked_sub(request.from_minute)?) + 1;
    let bins = BIN_COUNT as u128;
    let start = (index as u128 * duration).div_ceil(bins);
    let end = ((index as u128 + 1) * duration).div_ceil(bins);
    if start == end {
        return None;
    }
    // `start < end <= duration`, so both offsets fit the window.
    let from = request.from_minute + u64::try_from(start).ok()?;
    let until = request.from_minute + u64::try_from(end - 1).ok()?;
    Some(BinRange { from_minute: from, until_minute: until })
}

/// Returns true when `a` comes strictly before `b`: by minute, boot bytes, then sequence.
pub fn precedes(a: &Cursor, b: &Cursor) -> bool {
    (a.minute, a.boot, a.sequence) < (b.minute, b.boot, b.sequence)
}

/// Adds two hit counts; `None` when either is unknown or the sum overflows.
fn sum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a?.checked_add(b?)
}

/// Merges a part into `window`; nothing changes unless every scope, cursor and arithmetic
/// check succeeds.
///
/// # Errors
///
/// [`InvalidResponse`] for a part of another scope or version, a finished window, an
/// oversized or inconsistent part, inconsistent endpoints or revisions, bins that do not
/// sum to the part's totals, or overflow.
pub fn accept(window: &mut Window, part: &Part) -> Result<(), InvalidResponse> {
    let item = &part.window;
    let query =
        Query { observed_at: part.observed_at, request: item.request.clone(), ..Query::default() };
    validate(&query).map_err(|_| InvalidResponse)?;
    response(
        window.finished
            || part.version != 1
            || window.request != item.request
            || item.rows > PAGE_ROWS
            || item.complete > item.rows
            || item.retention_days.is_none_or(|days| days == 0 || days > 90)
            || item.finished != item.next.is_none()
            || (window.retention_days.is_some() && window.retention_days != item.retention_days),
    )?;
    endpoints(item)?;
    let mut candidate = window.clone();
    merge(&mut candidate, item)?;
    *window = candidate;
    Ok(())
}

/// Checks that a part's endpoints, revisions and continuation agree with its rows.
fn endpoints(item: &Window) -> Result<(), InvalidResponse> {
    response(
        (item.rows == 0) != item.first.is_none()
            || item.first.is_none() != item.last.is_none()
            || (item.rows == 0) != item.min_revision.is_none()
            || item.min_revision.is_none() != item.max_revision.is_none(),
    )?;
    if let (Some(minimum), Some(maximum)) = (item.min_revision, item.max_revision) {
        response(minimum > maximum || maximum > MAX_I64)?;
        if let Some(revision) = item.request.revision {
            response(minimum != revision || maximum != revision)?;
        }
    }
    if let Some(next) = item.next {
        response(item.last != Some(next))?;
    }
    let (Some(first), Some(last)) = (item.first, item.last) else { return Ok(()) };
    for cursor in [first, last] {
        response(cursor.sequence == 0 || cursor.sequence > MAX_I64 || cursor.boot == [0; 16])?;
    }
    if let Some(before) = item.request.before {
        response(!precedes(&first, &before))?;
    }
    response(
        (item.rows == 1 && first != last)
            || (item.rows > 1 && !precedes(&last, &first))
            || first.minute > item.request.until_minute
            || last.minute < item.request.from_minute,
    )
}

/// Adds a part's totals and bins to a window copy.
fn merge(window: &mut Window, item: &Window) -> Result<(), InvalidResponse> {
    window.hits = sum(window.hits, item.hits);
    window.rows = window.rows.checked_add(item.rows).ok_or(InvalidResponse)?;
    window.complete = window.complete.checked_add(item.complete).ok_or(InvalidResponse)?;
    window.observed_ms =
        window.observed_ms.checked_add(item.observed_ms).ok_or(InvalidResponse)?;
    window.ambiguous = window.ambiguous || item.ambiguous;
    window.clipped = window.clipped || item.clipped;
    window.unconfirmed = window.unconfirmed.max(item.unconfirmed);
    if let Some(revision) = item.min_revision {
        window.min_revision = Some(window.min_revision.map_or(revision, |r| r.min(revision)));
    }
    if let Some(revision) = item.max_revision {
        window.max_revision = Some(window.max_revision.map_or(revision, |r| r.max(revision)));
    }
    window.retention_days = item.retention_days;
    let (mut bin_rows, mut bin_complete, mut bin_hits) = (0u64, 0u64, Some(0u64));
    for (bin, added) in window.bins.iter_mut().zip(&item.bins) {
        response(added.complete > added.rows || (added.rows == 0 && added.hits != Some(0)))?;
        bin_hits = sum(bin_hits, added.hits);
        bin.hits = sum(bin.hits, added.hits);
        bin.rows = bin.rows.checked_add(added.rows).ok_or(InvalidResponse)?;
        bin.complete = bin.complete.checked_add(added.complete).ok_or(InvalidResponse)?;
        bin_rows += u64::from(added.rows);
        bin_complete += u64::from(added.complete);
    }
    response(
        bin_rows != u64::from(item.rows)
            || bin_complete != u64::from(item.complete)
            || bin_hits != item.hits,
    )?;
    window.first = window.first.or(item.first);
    window.last = item.last.or(window.last);
    window.next = item.next;
    window.request.before = item.next;
    window.finished = item.finished;
    Ok(())
}

/// A bounded read of today's hourly cohorts. `None` hours have no retained
/// observations; an incomplete scan cannot be presented as the day's total.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Today {
    /// Hits today; `None` when unknown.
    pub hits: Option<u64>,
    /// Hits per UTC hour.
    pub hours: [Option<u64>; 24],
    /// Observations read.
    pub rows: u32,
    /// Complete observations read.
    pub complete: u32,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The first minute of the day.
    pub from_minute: u64,
    /// The scan stopped early.
    pub partial: bool,
    /// The largest unconfirmed-observation count seen.
    pub unconfirmed: u64,
}

impl Encode for Today {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        optional_counter_field(json, "hits", self.hits)?;
        json.key("hours")?;
        json.begin_array()?;
        for &hour in &self.hours {
            optional_counter(json, hour)?;
        }
        json.end_array()?;
        field(json, "rows", &self.rows)?;
        field(json, "complete", &self.complete)?;
        counter_field(json, "observed_at", self.observed_at)?;
        counter_field(json, "from_minute", self.from_minute)?;
        field(json, "partial", &self.partial)?;
        counter_field(json, "unconfirmed", self.unconfirmed)?;
        json.end_object()
    }
}

impl Decode for Today {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Today, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let today = Today {
            hits: fields.or_default("hits")?,
            hours: fields.or_default("hours")?,
            rows: fields.or_default("rows")?,
            complete: fields.or_default("complete")?,
            observed_at: fields.or_default("observed_at")?,
            from_minute: fields.or_default("from_minute")?,
            partial: fields.or_default("partial")?,
            unconfirmed: fields.or_default("unconfirmed")?,
        };
        fields.finish()?;
        Ok(today)
    }
}

#[cfg(test)]
mod tests;

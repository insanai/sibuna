//! Per-address challenge records and adaptive-difficulty transitions. Records are bounded
//! observations drained from a data-plane queue (loss is counted, never hidden); client
//! timing stays untrusted telemetry. Difficulty rows record the console's once-per-second
//! observation of the effective adaptive bump, not every request's parameters.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::challenges::CAUSE_COUNT;
use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, decode_list, field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;

/// Records per storage write.
pub const MAX_BATCH: usize = 32;
/// Rows per record page.
pub const MAX_ROWS: u8 = 12;
/// Rows per difficulty page.
pub const MAX_TRANSITIONS: u8 = 32;
/// How long records are kept, in days.
pub const RETENTION_DAYS: u16 = 7;
/// The `cause` of a record that is not a rejection.
pub const NO_CAUSE: u8 = 255;

/// The longest range a query may span, in seconds.
const RETENTION_SECONDS: u64 = RETENTION_DAYS as u64 * 86_400;

/// What happened to a challenge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// It was issued.
    #[default]
    Issued,
    /// Its solution was accepted.
    Accepted,
    /// Its solution was rejected.
    Rejected,
}

impl WireEnum for Outcome {
    const ALL: &'static [Outcome] = &[Outcome::Issued, Outcome::Accepted, Outcome::Rejected];

    fn name(self) -> &'static str {
        match self {
            Outcome::Issued => "issued",
            Outcome::Accepted => "accepted",
            Outcome::Rejected => "rejected",
        }
    }
}

/// One challenge event drained from the data plane.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    /// When it happened, in Unix seconds.
    pub second: u64,
    /// The client address.
    pub ip: Text<48>,
    /// What happened.
    pub outcome: Outcome,
    /// A rejection cause ordinal for rejections, [`NO_CAUSE`] otherwise.
    pub cause: u8,
    /// The algorithm ordinal.
    pub algorithm: u8,
    /// The proof-of-work parameter.
    pub parameter: u8,
    /// Proof openings.
    pub openings: u8,
    /// The client-reported solve time; `None` when absent or invalid.
    pub duration_ms: Option<u32>,
}

impl Default for Record {
    fn default() -> Record {
        Record {
            second: 0,
            ip: Text::default(),
            outcome: Outcome::Issued,
            cause: NO_CAUSE,
            algorithm: 0,
            parameter: 0,
            openings: 0,
            duration_ms: None,
        }
    }
}

/// A batch of records from one boot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Batch {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// At most [`MAX_BATCH`] records.
    pub records: Vec<Record>,
    /// Queue losses since boot at the time of the batch, for coverage notes.
    pub dropped: u64,
    /// The writer's clock, in Unix seconds.
    pub now: u64,
}

/// A position in the descending record scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The record's second.
    pub second: u64,
    /// The record id.
    pub id: u64,
}

impl Encode for Cursor {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "second", self.second)?;
        counter_field(json, "id", self.id)?;
        json.end_object()
    }
}

impl Decode for Cursor {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Cursor, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let cursor = Cursor { second: fields.required("second")?, id: fields.required("id")? };
        fields.finish()?;
        Ok(cursor)
    }
}

/// A record page query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The first second.
    pub from: u64,
    /// The last second.
    pub until: u64,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// One outcome, or `None` for all.
    pub outcome: Option<Outcome>,
    /// One cause, or `None` for all.
    pub cause: Option<u8>,
    /// Exact address match; empty selects every address.
    pub address: Text<48>,
    /// Continue before this position.
    pub before: Option<Cursor>,
    /// Rows wanted.
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query {
            session_digest: [0; 32],
            require_totp: false,
            observed_at: 0,
            from: 0,
            until: 0,
            node: None,
            outcome: None,
            cause: None,
            address: Text::default(),
            before: None,
            limit: MAX_ROWS,
        }
    }
}

/// One stored record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Row {
    /// The record id.
    pub id: u64,
    /// The recording node.
    pub node: u32,
    /// When it happened, in Unix seconds.
    pub second: u64,
    /// The client address.
    pub ip: Text<48>,
    /// What happened.
    pub outcome: Outcome,
    /// A rejection cause ordinal, or [`NO_CAUSE`].
    pub cause: u8,
    /// The algorithm ordinal.
    pub algorithm: u8,
    /// The proof-of-work parameter.
    pub parameter: u8,
    /// Proof openings.
    pub openings: u8,
    /// The client-reported solve time.
    pub duration_ms: Option<u32>,
}

impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        field(json, "node", &self.node)?;
        counter_field(json, "second", self.second)?;
        field(json, "ip", &self.ip)?;
        field(json, "outcome", &self.outcome)?;
        field(json, "cause", &self.cause)?;
        field(json, "algorithm", &self.algorithm)?;
        field(json, "parameter", &self.parameter)?;
        field(json, "openings", &self.openings)?;
        field(json, "duration_ms", &self.duration_ms)?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = Row {
            id: fields.required("id")?,
            node: fields.required("node")?,
            second: fields.required("second")?,
            ip: fields.required("ip")?,
            outcome: fields.required("outcome")?,
            cause: fields.required("cause")?,
            algorithm: fields.required("algorithm")?,
            parameter: fields.required("parameter")?,
            openings: fields.required("openings")?,
            duration_ms: fields.required("duration_ms")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A page of records (version 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    /// The format version.
    pub version: u8,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The first second.
    pub from: u64,
    /// The last second.
    pub until: u64,
    /// Records the queue dropped since boot.
    pub dropped_since_boot: u64,
    /// Batches whose write was not acknowledged; their rows may be absent.
    pub unconfirmed_since_boot: u64,
    /// At most [`MAX_ROWS`] rows.
    pub rows: Vec<Row>,
    /// Where the next page continues.
    pub next: Option<Cursor>,
}

impl Default for Page {
    fn default() -> Page {
        Page {
            version: 1,
            retention_days: RETENTION_DAYS,
            observed_at: 0,
            from: 0,
            until: 0,
            dropped_since_boot: 0,
            unconfirmed_since_boot: 0,
            rows: Vec::new(),
            next: None,
        }
    }
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "retention_days", &self.retention_days)?;
        counter_field(json, "observed_at", self.observed_at)?;
        counter_field(json, "from", self.from)?;
        counter_field(json, "until", self.until)?;
        counter_field(json, "dropped_since_boot", self.dropped_since_boot)?;
        counter_field(json, "unconfirmed_since_boot", self.unconfirmed_since_boot)?;
        field(json, "rows", &self.rows)?;
        field(json, "next", &self.next)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = Page {
            version: fields.required("version")?,
            retention_days: fields.required("retention_days")?,
            observed_at: fields.required("observed_at")?,
            from: fields.required("from")?,
            until: fields.required("until")?,
            dropped_since_boot: fields.required("dropped_since_boot")?,
            unconfirmed_since_boot: fields.required("unconfirmed_since_boot")?,
            rows: fields.required_with("rows", |value, path| {
                decode_list(value, path, usize::from(MAX_ROWS))
            })?,
            next: fields.required("next")?,
        };
        fields.finish()?;
        Ok(page)
    }
}

/// One observed change of the adaptive difficulty bump.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Transition {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// When it changed, in Unix seconds.
    pub second: u64,
    /// The bump before, in bits.
    pub previous_bits: u8,
    /// The bump after, in bits.
    pub bits: u8,
    /// The smoothed issue rate in 1/256 challenges per second when the bump changed.
    pub rate_256: u64,
}

/// A difficulty history query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DifficultyQuery {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The first second.
    pub from: u64,
    /// The last second.
    pub until: u64,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// Rows wanted.
    pub limit: u8,
}

impl Default for DifficultyQuery {
    fn default() -> DifficultyQuery {
        DifficultyQuery {
            session_digest: [0; 32],
            require_totp: false,
            observed_at: 0,
            from: 0,
            until: 0,
            node: None,
            limit: MAX_TRANSITIONS,
        }
    }
}

/// One stored transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TransitionRow {
    /// The node.
    pub node: u32,
    /// When it changed, in Unix seconds.
    pub second: u64,
    /// The bump before, in bits.
    pub previous_bits: u8,
    /// The bump after, in bits.
    pub bits: u8,
    /// The smoothed issue rate in 1/256 challenges per second.
    pub rate_256: u64,
}

impl Encode for TransitionRow {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        counter_field(json, "second", self.second)?;
        field(json, "previous_bits", &self.previous_bits)?;
        field(json, "bits", &self.bits)?;
        counter_field(json, "rate_256", self.rate_256)?;
        json.end_object()
    }
}

impl Decode for TransitionRow {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<TransitionRow, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = TransitionRow {
            node: fields.required("node")?,
            second: fields.required("second")?,
            previous_bits: fields.required("previous_bits")?,
            bits: fields.required("bits")?,
            rate_256: fields.required("rate_256")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A page of difficulty transitions (version 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifficultyPage {
    /// The format version.
    pub version: u8,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The first second.
    pub from: u64,
    /// The last second.
    pub until: u64,
    /// The serving node's current bump, observed once per second.
    pub current_bits: Option<u8>,
    /// Changes this node observed but did not record: a previous transition was pending,
    /// or the write was not acknowledged. Coverage is boot-local, never zero loss.
    pub missed_since_boot: u64,
    /// At most [`MAX_TRANSITIONS`] rows.
    pub rows: Vec<TransitionRow>,
    /// More transitions exist in the range.
    pub truncated: bool,
}

impl Default for DifficultyPage {
    fn default() -> DifficultyPage {
        DifficultyPage {
            version: 1,
            retention_days: RETENTION_DAYS,
            observed_at: 0,
            from: 0,
            until: 0,
            current_bits: None,
            missed_since_boot: 0,
            rows: Vec::new(),
            truncated: false,
        }
    }
}

impl Encode for DifficultyPage {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "retention_days", &self.retention_days)?;
        counter_field(json, "observed_at", self.observed_at)?;
        counter_field(json, "from", self.from)?;
        counter_field(json, "until", self.until)?;
        field(json, "current_bits", &self.current_bits)?;
        counter_field(json, "missed_since_boot", self.missed_since_boot)?;
        field(json, "rows", &self.rows)?;
        field(json, "truncated", &self.truncated)?;
        json.end_object()
    }
}

impl Decode for DifficultyPage {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<DifficultyPage, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = DifficultyPage {
            version: fields.required("version")?,
            retention_days: fields.required("retention_days")?,
            observed_at: fields.required("observed_at")?,
            from: fields.required("from")?,
            until: fields.required("until")?,
            current_bits: fields.required("current_bits")?,
            missed_since_boot: fields.required("missed_since_boot")?,
            rows: fields.required_with("rows", |value, path| {
                decode_list(value, path, usize::from(MAX_TRANSITIONS))
            })?,
            truncated: fields.required("truncated")?,
        };
        fields.finish()?;
        Ok(page)
    }
}

/// Checks a record query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a limit outside 1 to [`MAX_ROWS`], an inverted,
/// future or over-retention range, an unknown cause, or an oversized cursor.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(
        query.limit == 0
            || query.limit > MAX_ROWS
            || query.observed_at > MAX_I64
            || query.from > query.until
            || query.until > query.observed_at
            || query.until - query.from > RETENTION_SECONDS,
    )?;
    limit(
        query.cause.is_some_and(|cause| usize::from(cause) >= CAUSE_COUNT && cause != NO_CAUSE),
    )?;
    limit(query.before.is_some_and(|cursor| cursor.second > MAX_I64 || cursor.id > MAX_I64))
}

/// Checks a difficulty query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a limit outside 1 to [`MAX_TRANSITIONS`] or an
/// inverted, future or over-retention range.
pub fn validate_difficulty(query: &DifficultyQuery) -> Result<(), ValidationError> {
    limit(
        query.limit == 0
            || query.limit > MAX_TRANSITIONS
            || query.observed_at > MAX_I64
            || query.from > query.until
            || query.until > query.observed_at
            || query.until - query.from > RETENTION_SECONDS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of challenge_records.zig "record queries stay within retention and page bounds".
    #[test]
    fn record_queries_stay_within_retention_and_page_bounds() {
        let base = Query {
            session_digest: [1; 32],
            observed_at: 1000,
            from: 0,
            until: 1000,
            ..Query::default()
        };
        assert_eq!(validate(&base), Ok(()));
        let wide = Query { from: 0, observed_at: 10 * 86_400, until: 10 * 86_400, ..base.clone() };
        assert_eq!(validate(&wide), Err(ValidationError::InvalidLimit));
        let mut cause = Query { cause: Some(13), ..base.clone() };
        assert_eq!(validate(&cause), Err(ValidationError::InvalidLimit));
        cause.cause = Some(NO_CAUSE);
        assert_eq!(validate(&cause), Ok(()));
        let over = Query { limit: MAX_ROWS + 1, ..base };
        assert_eq!(validate(&over), Err(ValidationError::InvalidLimit));
    }

    #[test]
    fn pages_round_trip() {
        let page = Page {
            observed_at: 9,
            rows: vec![Row {
                id: 1,
                ip: Text::new("::1").unwrap(),
                outcome: Outcome::Rejected,
                cause: 2,
                duration_ms: Some(40),
                ..Row::default()
            }],
            next: Some(Cursor { second: 5, id: u64::MAX }),
            ..Page::default()
        };
        let text = to_json(&page);
        assert!(text.ends_with("\"next\":{\"second\":5,\"id\":\"18446744073709551615\"}}"));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        let page = DifficultyPage {
            current_bits: Some(3),
            rows: vec![TransitionRow {
                node: 1,
                second: 2,
                previous_bits: 0,
                bits: 3,
                rate_256: 512,
            }],
            ..DifficultyPage::default()
        };
        let text = to_json(&page);
        assert_eq!(
            text,
            "{\"version\":1,\"retention_days\":7,\"observed_at\":0,\"from\":0,\"until\":0,\
             \"current_bits\":3,\"missed_since_boot\":0,\"rows\":[{\"node\":1,\"second\":2,\
             \"previous_bits\":0,\"bits\":3,\"rate_256\":512}],\"truncated\":false}"
        );
        assert_eq!(from_json::<DifficultyPage>(text.as_bytes()), Ok(page));
        let query = DifficultyQuery { observed_at: 10, until: 10, ..DifficultyQuery::default() };
        assert_eq!(validate_difficulty(&query), Ok(()));
        assert!(validate_difficulty(&DifficultyQuery { until: 11, ..query }).is_err());
    }
}

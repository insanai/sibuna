//! Internal owner-to-hub feeds of incidents and audit rows. These are not public HTTP
//! requests. Each issuer has an independent durable incident cursor; node bits are never
//! compared across issuers.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::audit;
use crate::codec::{Decode, DecodeError, Encode, Fields, Path, counter_field, field};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::events::country;
use crate::text::Text;

/// Rows per feed page.
pub const PAGE_ROWS: usize = 8;
/// Recent ids the hub remembers per feed.
pub const RECENT_IDS: usize = 64;

/// Which feed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// One node's incidents.
    #[default]
    Events,
    /// The cluster's audit rows.
    Audit,
}

/// Reads the next feed page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Request {
    /// Which feed.
    pub kind: Kind,
    /// The issuing node for incidents (ids carry it in their top bits); zero for audit.
    pub node: u32,
    /// Rows after this id.
    pub after: Option<u64>,
    /// Rows up to this id.
    pub through: Option<u64>,
}

/// An incident summary as the `events` topic carries it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Event {
    /// The persisted country attribution.
    pub geography: country::Mapping,
    /// The incident id.
    pub id: u64,
    /// The recording node.
    pub node: u32,
    /// The incident time, in Unix seconds.
    pub time: u64,
    /// The client address.
    pub ip: Text<48>,
    /// The request method.
    pub method: Text<8>,
    /// The request path (display-bounded).
    pub path: Text<128>,
    /// The finding category.
    pub category: Text<32>,
    /// A display field was truncated.
    pub display_truncated: bool,
    /// The query string was redacted.
    pub query_redacted: bool,
}

impl Encode for Event {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "geography", &self.geography)?;
        counter_field(json, "id", self.id)?;
        field(json, "node", &self.node)?;
        counter_field(json, "time", self.time)?;
        field(json, "ip", &self.ip)?;
        field(json, "method", &self.method)?;
        field(json, "path", &self.path)?;
        field(json, "category", &self.category)?;
        field(json, "display_truncated", &self.display_truncated)?;
        field(json, "query_redacted", &self.query_redacted)?;
        json.end_object()
    }
}

impl Decode for Event {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Event, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let event = Event {
            geography: fields.or_default("geography")?,
            id: fields.or_default("id")?,
            node: fields.or_default("node")?,
            time: fields.or_default("time")?,
            ip: fields.or_default("ip")?,
            method: fields.or_default("method")?,
            path: fields.or_default("path")?,
            category: fields.or_default("category")?,
            display_truncated: fields.or_default("display_truncated")?,
            query_redacted: fields.or_default("query_redacted")?,
        };
        fields.finish()?;
        Ok(event)
    }
}

/// One feed row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    /// An incident.
    Events(Event),
    /// An audit row.
    Audit(audit::Row),
}

/// A page of a feed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// Which feed.
    pub kind: Kind,
    /// The issuing node.
    pub node: u32,
    /// The newest id at the issuer.
    pub head: u64,
    /// The id the page reads through.
    pub through: u64,
    /// The id to continue after.
    pub next: u64,
    /// Ids skipped because their rows are gone.
    pub missing_ids: u64,
    /// When storage read the page, in Unix seconds.
    pub observed_at: u64,
    /// Rows the producer dropped, if known.
    pub producer_dropped: Option<u64>,
    /// The producer's boot id as hex.
    pub producer_boot: Text<32>,
    /// When the replica was last observed, in Unix seconds.
    pub replica_observed_at: u64,
    /// The replica had a quorum.
    pub replica_quorum: bool,
    /// More rows follow.
    pub more: bool,
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<Row>,
}

/// Checks a feed request: an incident feed names its issuer (below 2^23) and audit names
/// none, cursors fit a signed 64-bit column, incident cursors belong to the issuer (the
/// top 24 bits of an incident id), and `after` does not pass `through`.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] otherwise.
pub fn validate(input: &Request) -> Result<(), ValidationError> {
    limit(input.node >= 1 << 23 || (input.kind == Kind::Events) != (input.node != 0))?;
    for id in [input.after, input.through].into_iter().flatten() {
        limit(id > MAX_I64 || (input.kind == Kind::Events && id >> 40 != u64::from(input.node)))?;
    }
    limit(matches!((input.after, input.through), (Some(after), Some(through)) if after > through))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of subscription_feed.zig "feed cursor validation prevents cross-issuer
    // comparisons".
    #[test]
    fn feed_cursor_validation_prevents_cross_issuer_comparisons() {
        let request =
            Request { kind: Kind::Events, node: 2, after: Some((2 << 40) + 5), through: None };
        assert_eq!(validate(&request), Ok(()));
        let other = Request { node: 1, ..request };
        assert_eq!(validate(&other), Err(ValidationError::InvalidLimit));
        let audit = Request { kind: Kind::Audit, node: 1, ..Request::default() };
        assert_eq!(validate(&audit), Err(ValidationError::InvalidLimit));
        let crossed = Request { through: Some((2 << 40) + 4), ..request };
        assert_eq!(validate(&crossed), Err(ValidationError::InvalidLimit));
    }

    #[test]
    fn events_round_trip() {
        let event = Event {
            id: 9_007_199_254_740_993,
            node: 2,
            ip: Text::new("::1").unwrap(),
            ..Event::default()
        };
        let text = to_json(&event);
        assert_eq!(
            text,
            "{\"geography\":{\"code\":null,\"generation\":null,\"mixed\":false,\
             \"recorded\":false},\
             \"id\":\"9007199254740993\",\"node\":2,\"time\":0,\"ip\":\"::1\",\"method\":\"\",\
             \"path\":\"\",\"category\":\"\",\"display_truncated\":false,\"query_redacted\":false}"
        );
        assert_eq!(from_json::<Event>(text.as_bytes()), Ok(event));
    }
}

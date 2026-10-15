//! Recorded incidents. Keyset cursors use time and id; ids cross the browser boundary as
//! decimal strings.

pub mod country;

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, decimal_string, field,
    optional_str,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::security::Module;
use crate::text::Text;

/// The most rows one events page returns.
pub const MAX_LIMIT: u16 = 10;

/// A keyset position: rows strictly before `(time, id)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The incident time, in Unix seconds.
    pub time: u64,
    /// The incident id.
    pub id: u64,
}

/// A page of incidents, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// Group repeated requests from one address.
    pub grouped: bool,
    /// An audited export rather than a view.
    pub export_page: bool,
    /// Continue before this position.
    pub before: Option<Cursor>,
    /// Rows wanted, 1 to [`MAX_LIMIT`].
    pub limit: u16,
    /// The earliest time, in Unix seconds.
    pub from: u64,
    /// The latest time, in Unix seconds.
    pub until: u64,
    /// One node, or zero for all.
    pub node: u32,
    /// One campaign, or zero for all.
    pub campaign: u64,
    /// One incident, or zero for all.
    pub incident: u64,
    /// One category, or empty for all.
    pub category: Text<32>,
    /// A country filter ([`country::valid_filter`]).
    pub country: country::Filter,
    /// One finding source, or `None` for all.
    pub module: Option<Module>,
    /// One address, or empty for all.
    pub ip: Text<48>,
    /// A path prefix, or empty for all.
    pub path_prefix: Text<256>,
    /// Address presenting the credential; recorded on the export audit row only.
    pub client: Text<48>,
}

impl Default for Query {
    fn default() -> Query {
        Query {
            session_digest: [0; 32],
            require_totp: false,
            grouped: false,
            export_page: false,
            before: None,
            limit: MAX_LIMIT,
            from: 0,
            until: MAX_I64,
            node: 0,
            campaign: 0,
            incident: 0,
            category: Text::default(),
            country: Text::default(),
            module: None,
            ip: Text::default(),
            path_prefix: Text::default(),
            client: Text::default(),
        }
    }
}

/// Capture metadata recorded beside an incident (evidence version 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capture {
    /// The evidence format version.
    pub version: u8,
    /// The status the firewall selected; it does not establish delivery.
    pub selected_status: u16,
    /// Length of the query string.
    pub query_bytes: u32,
    /// Length of the body read.
    pub body_bytes: u32,
    /// The declared `Content-Length`.
    pub declared_body_bytes: u32,
    /// Truncation flags.
    pub truncated: u16,
}

impl Default for Capture {
    fn default() -> Capture {
        Capture {
            version: 1,
            selected_status: 0,
            query_bytes: 0,
            body_bytes: 0,
            declared_body_bytes: 0,
            truncated: 0,
        }
    }
}

impl Encode for Capture {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "selected_status", &self.selected_status)?;
        field(json, "query_bytes", &self.query_bytes)?;
        field(json, "body_bytes", &self.body_bytes)?;
        field(json, "declared_body_bytes", &self.declared_body_bytes)?;
        field(json, "truncated", &self.truncated)?;
        json.end_object()
    }
}

impl Decode for Capture {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Capture, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let capture = Capture {
            version: fields.or("version", 1)?,
            selected_status: fields.required("selected_status")?,
            query_bytes: fields.required("query_bytes")?,
            body_bytes: fields.required("body_bytes")?,
            declared_body_bytes: fields.required("declared_body_bytes")?,
            truncated: fields.required("truncated")?,
        };
        fields.finish()?;
        Ok(capture)
    }
}

/// One incident row, or a group of rows from one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The persisted country attribution.
    pub geography: country::Mapping,
    /// Capture metadata, when capture was enabled.
    pub capture: Option<Capture>,
    /// The incident id.
    pub id: u64,
    /// A group of rows.
    pub grouped: bool,
    /// Rows in the group; 1 for a single incident.
    pub count: u64,
    /// The group's first time, in Unix seconds.
    pub first_seen: u64,
    /// The recording node.
    pub node: u32,
    /// The incident time, in Unix seconds.
    pub time: u64,
    /// The client address.
    pub ip: Text<48>,
    /// The request method.
    pub method: Text<8>,
    /// The request path (display-bounded).
    pub path: Text<256>,
    /// The finding category.
    pub category: Text<32>,
    /// The User-Agent (display-bounded).
    pub user_agent: Text<128>,
    /// The campaign the incident belongs to, if any.
    pub campaign: Option<u64>,
    /// A display field was truncated.
    pub display_truncated: bool,
    /// The query string was redacted.
    pub query_redacted: bool,
}

impl Default for Row {
    fn default() -> Row {
        Row {
            geography: country::Mapping::default(),
            capture: None,
            id: 0,
            grouped: false,
            count: 1,
            first_seen: 0,
            node: 0,
            time: 0,
            ip: Text::default(),
            method: Text::default(),
            path: Text::default(),
            category: Text::default(),
            user_agent: Text::default(),
            campaign: None,
            display_truncated: false,
            query_redacted: false,
        }
    }
}

/// Writes the incident in the browser's shape: the id and campaign as decimal strings,
/// the evidence version and country beside the full objects, and two fields the format
/// reserves (`response_status`, `matched_rule`) as `null`.
impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        json.key("id")?;
        decimal_string(json, self.id)?;
        field(json, "grouped", &self.grouped)?;
        field(json, "count", &self.count)?;
        field(json, "first_seen", &self.first_seen)?;
        field(json, "node", &self.node)?;
        field(json, "time", &self.time)?;
        field(json, "ip", &self.ip)?;
        field(json, "method", &self.method)?;
        field(json, "path", &self.path)?;
        field(json, "category", &self.category)?;
        field(json, "user_agent", &self.user_agent)?;
        json.key("campaign")?;
        match self.campaign {
            Some(campaign) => decimal_string(json, campaign)?,
            None => json.null()?,
        }
        field(json, "display_truncated", &self.display_truncated)?;
        field(json, "query_redacted", &self.query_redacted)?;
        field(json, "evidence_version", &self.capture.map(|capture| capture.version))?;
        field(json, "capture", &self.capture)?;
        json.key("country")?;
        optional_str(json, self.geography.wire().code)?;
        field(json, "geography", &self.geography)?;
        json.key("response_status")?;
        json.null()?;
        json.key("matched_rule")?;
        json.null()?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let id: String = fields.required("id")?;
        let campaign: Option<String> = fields.required("campaign")?;
        let row = Row {
            id: decimal(&id, path.key("id"))?,
            grouped: fields.required("grouped")?,
            count: fields.required("count")?,
            first_seen: fields.required("first_seen")?,
            node: fields.required("node")?,
            time: fields.required("time")?,
            ip: fields.required("ip")?,
            method: fields.required("method")?,
            path: fields.required("path")?,
            category: fields.required("category")?,
            user_agent: fields.required("user_agent")?,
            campaign: campaign.map(|text| decimal(&text, path.key("campaign"))).transpose()?,
            display_truncated: fields.required("display_truncated")?,
            query_redacted: fields.required("query_redacted")?,
            capture: None,
            geography: country::Mapping::default(),
        };
        let evidence: Option<u8> = fields.required("evidence_version")?;
        let capture: Option<Capture> = fields.required("capture")?;
        let code: Option<String> = fields.required("country")?;
        let geography: country::Mapping = fields.required("geography")?;
        let status: Option<u16> = fields.required("response_status")?;
        let rule: Option<String> = fields.required("matched_rule")?;
        fields.finish()?;
        let consistent = evidence == capture.map(|capture| capture.version)
            && code.as_deref() == geography.wire().code
            && status.is_none()
            && rule.is_none();
        if !consistent {
            return Err(DecodeError::new(
                path,
                DecodeErrorKind::Invalid("the summary fields disagree with the row"),
            ));
        }
        Ok(Row { capture, geography, ..row })
    }
}

/// Reads an identifier written as a decimal string.
fn decimal(text: &str, path: Path<'_>) -> Result<u64, DecodeError> {
    let digits = !text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit());
    let value = if digits { text.parse::<u64>().ok() } else { None };
    value.ok_or_else(|| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
}

/// Checks an events query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an invalid country filter, a limit outside 1 to
/// [`MAX_LIMIT`], an inverted or oversized range, or an oversized identifier or cursor.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(!country::valid_filter(query.country.as_str()))?;
    limit(
        query.limit == 0
            || query.limit > MAX_LIMIT
            || query.from > query.until
            || query.until > MAX_I64
            || query.campaign > MAX_I64
            || query.incident > MAX_I64,
    )?;
    limit(query.before.is_some_and(|cursor| cursor.time > MAX_I64 || cursor.id > MAX_I64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn rows_write_ids_as_strings_and_round_trip() {
        let row = Row {
            id: 9_007_199_254_740_993,
            node: 2,
            time: 100,
            first_seen: 100,
            ip: Text::new("192.0.2.1").unwrap(),
            method: Text::new("GET").unwrap(),
            path: Text::new("/x").unwrap(),
            category: Text::new("waf:sqli").unwrap(),
            campaign: Some(7),
            capture: Some(Capture { selected_status: 403, ..Capture::default() }),
            ..Row::default()
        };
        let text = to_json(&row);
        assert!(text.starts_with("{\"id\":\"9007199254740993\",\"grouped\":false,\"count\":1,"));
        assert!(text.contains("\"campaign\":\"7\""));
        assert!(text.contains("\"evidence_version\":1,\"capture\":{\"version\":1,"));
        assert!(text.ends_with("\"response_status\":null,\"matched_rule\":null}"));
        assert_eq!(from_json::<Row>(text.as_bytes()), Ok(row));
    }

    #[test]
    fn queries_are_bounded() {
        assert_eq!(validate(&Query::default()), Ok(()));
        assert!(validate(&Query { limit: 11, ..Query::default() }).is_err());
        assert!(
            validate(&Query { country: Text::new("us").unwrap(), ..Query::default() }).is_err()
        );
        let before = Some(Cursor { time: u64::MAX, id: 1 });
        assert!(validate(&Query { before, ..Query::default() }).is_err());
    }
}

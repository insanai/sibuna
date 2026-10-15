//! Recorded findings by source module. Findings are a separate population from exact
//! external-request outcomes. Ranges are half-open, frozen by the caller, and limited to
//! incident retention.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, WireEnum, counter, counter_field,
    field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;

/// Trend buckets per window.
pub const BUCKETS: usize = 60;
/// The longest window, in seconds: the incident retention.
pub const MAX_WINDOW_SECONDS: u64 = 30 * 86_400;

/// The source of a finding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Module {
    /// Semantic inspection and its audit mode.
    #[default]
    Inspection,
    /// The honeypot.
    Honeypot,
    /// Everything else.
    Other,
}

impl WireEnum for Module {
    const ALL: &'static [Module] = &[Module::Inspection, Module::Honeypot, Module::Other];

    fn name(self) -> &'static str {
        match self {
            Module::Inspection => "inspection",
            Module::Honeypot => "honeypot",
            Module::Other => "other",
        }
    }
}

/// How a page ranks findings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum View {
    /// By module.
    #[default]
    Modules,
    /// By category.
    Categories,
    /// By path.
    Paths,
}

impl WireEnum for View {
    const ALL: &'static [View] = &[View::Modules, View::Categories, View::Paths];

    fn name(self) -> &'static str {
        match self {
            View::Modules => "modules",
            View::Categories => "categories",
            View::Paths => "paths",
        }
    }
}

/// Returns the module that recorded a finding of `category`.
pub fn classify(category: &str) -> Module {
    if category.starts_with("waf:") || category.starts_with("audit:") {
        Module::Inspection
    } else if category == "honeypot" {
        Module::Honeypot
    } else {
        Module::Other
    }
}

/// The window and view of a security page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Request {
    /// How to rank findings.
    pub view: View,
    /// One node, or zero for all.
    pub node: u32,
    /// The window's start, in Unix seconds (inclusive).
    pub from: u64,
    /// The window's end, in Unix seconds (exclusive).
    pub until: u64,
}

impl Encode for Request {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "view", &self.view)?;
        field(json, "node", &self.node)?;
        field(json, "from", &self.from)?;
        field(json, "until", &self.until)?;
        json.end_object()
    }
}

impl Decode for Request {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Request, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let request = Request {
            view: fields.or_default("view")?,
            node: fields.or_default("node")?,
            from: fields.required("from")?,
            until: fields.required("until")?,
        };
        fields.finish()?;
        Ok(request)
    }
}

/// A security page request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The window and view.
    pub request: Request,
    /// Chosen by the route, never by untrusted JSON. Statistics scope excludes evidence.
    pub aggregate_only: bool,
}

/// One ranked label.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rank {
    /// The module, category or path.
    pub label: Text<96>,
    /// Findings with this label.
    pub count: u64,
    /// The label was truncated.
    pub truncated: bool,
}

impl Encode for Rank {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "label", &self.label)?;
        counter_field(json, "count", self.count)?;
        field(json, "truncated", &self.truncated)?;
        json.end_object()
    }
}

impl Decode for Rank {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Rank, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let rank = Rank {
            label: fields.or_default("label")?,
            count: fields.or_default("count")?,
            truncated: fields.or_default("truncated")?,
        };
        fields.finish()?;
        Ok(rank)
    }
}

/// One module's findings over the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Findings {
    /// Findings in the window.
    pub total: u64,
    /// Findings per sixtieth of the window.
    pub trend: [u64; BUCKETS],
    /// The three largest sources.
    pub sources: [Option<Rank>; 3],
}

impl Default for Findings {
    fn default() -> Findings {
        Findings { total: 0, trend: [0; BUCKETS], sources: Default::default() }
    }
}

impl Encode for Findings {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "total", self.total)?;
        json.key("trend")?;
        json.begin_array()?;
        for &count in &self.trend {
            counter(json, count)?;
        }
        json.end_array()?;
        field(json, "sources", &self.sources)?;
        json.end_object()
    }
}

impl Decode for Findings {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Findings, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let findings = Findings {
            total: fields.or_default("total")?,
            trend: fields.or("trend", [0; BUCKETS])?,
            sources: fields.or_default("sources")?,
        };
        fields.finish()?;
        Ok(findings)
    }
}

/// The security overview (version 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    /// The format version.
    pub version: u8,
    /// The window and view served.
    pub request: Request,
    /// When storage read the page, in Unix seconds.
    pub observed_at: u64,
    /// Findings by [`Module`] ordinal.
    pub modules: [Findings; 3],
    /// The five largest labels of the view.
    pub rows: [Option<Rank>; 5],
    /// Total recorded findings, including categories outside the top five.
    pub total: u64,
}

impl Default for Page {
    fn default() -> Page {
        Page {
            version: 2,
            request: Request::default(),
            observed_at: 0,
            modules: Default::default(),
            rows: Default::default(),
            total: 0,
        }
    }
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "request", &self.request)?;
        field(json, "observed_at", &self.observed_at)?;
        counter_field(json, "total", self.total)?;
        field(json, "modules", &self.modules)?;
        field(json, "rows", &self.rows)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = Page {
            version: fields.or("version", 2)?,
            request: fields.required("request")?,
            observed_at: fields.required("observed_at")?,
            total: fields.or_default("total")?,
            modules: fields.or_default("modules")?,
            rows: fields.or_default("rows")?,
        };
        fields.finish()?;
        if page.version != 2 {
            let path = path.key("version");
            return Err(DecodeError::new(path, DecodeErrorKind::Invalid("the version must be 2")));
        }
        Ok(page)
    }
}

/// Checks a security query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a non-module view in aggregate-only scope, an
/// empty, inverted or oversized window, or a node id of 2^23 or more.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    let request = &query.request;
    limit(query.aggregate_only && request.view != View::Modules)?;
    limit(
        request.from >= request.until
            || request.until > MAX_I64
            || request.until - request.from > MAX_WINDOW_SECONDS
            || request.node >= 1 << 23,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    fn query(from: u64, until: u64) -> Query {
        Query { request: Request { from, until, ..Default::default() }, ..Default::default() }
    }

    // Port of security.zig "security windows cannot overflow buckets or exceed incident
    // retention".
    #[test]
    fn security_windows_cannot_overflow_buckets_or_exceed_incident_retention() {
        assert_eq!(validate(&query(1, 2)), Ok(()));
        assert_eq!(validate(&query(0, 30 * 86_400 + 1)), Err(ValidationError::InvalidLimit));
        assert_eq!(validate(&query(1, 1)), Err(ValidationError::InvalidLimit));
        let mut paths = query(1, 2);
        paths.request.view = View::Paths;
        paths.aggregate_only = true;
        assert_eq!(validate(&paths), Err(ValidationError::InvalidLimit));
    }

    #[test]
    fn pages_round_trip() {
        let mut page = Page { observed_at: 9, total: 3, ..Default::default() };
        page.request = Request { view: View::Categories, node: 1, from: 0, until: 60 };
        page.modules[1].total = 3;
        page.modules[1].trend[59] = u64::MAX;
        page.rows[0] =
            Some(Rank { label: Text::new("honeypot").unwrap(), count: 3, truncated: false });
        let text = to_json(&page);
        assert!(text.starts_with(
            "{\"version\":2,\"request\":{\"view\":\"categories\",\"node\":1,\"from\":0,\
             \"until\":60},\"observed_at\":9,\"total\":3,\"modules\":[{\"total\":0,\"trend\":[0,"
        ));
        assert!(text.ends_with(
            "\"rows\":[{\"label\":\"honeypot\",\"count\":3,\"truncated\":false},null,null,null,\
             null]}"
        ));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        assert_eq!(classify("waf:sqli"), Module::Inspection);
        assert_eq!(classify("audit:xss"), Module::Inspection);
        assert_eq!(classify("honeypot"), Module::Honeypot);
        assert_eq!(classify("rate"), Module::Other);
    }
}

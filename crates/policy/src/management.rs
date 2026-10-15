//! Strict management documents (one rule each), as the console writes them. Separate from
//! the startup file loader: action and algorithm names are exact lower case, and the rule
//! carries a stable id, a priority and an enabled flag.

use std::fmt;

use crate::json::{Int, JsonError, Reader};
use crate::limits::managed_identity;
use crate::loader::schema;
use crate::matchers::{self, MatcherError, valid_text};
use crate::rule::{Action, Algorithm, PolicyRule};

/// Longest management document, in bytes.
pub const MAX_DOCUMENT: usize = 4096;
/// Longest document id.
const MAX_ID: usize = 128;
/// Longest rule name.
const MAX_NAME: usize = 128;
/// Longest path or User-Agent pattern.
const MAX_PATTERN: usize = 512;

/// Why a management document was refused. The names are Zig's error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ManagementError {
    /// The document exceeds `MAX_DOCUMENT` bytes.
    TooLarge,
    /// The id is empty, longer than 128 bytes, or not letters, digits, `-` and `_`.
    InvalidId,
    /// The name is empty, longer than 128 bytes, or not printable text.
    InvalidName,
    /// A pattern longer than 512 bytes or not printable text.
    InvalidPattern,
    /// A difficulty above 64 or on a non-challenge rule, or an algorithm on one.
    InvalidChallenge,
    /// A non-zero weight on a non-WEIGH rule.
    InvalidWeight,
    /// Limits on a WEIGH rule, or out of range.
    InvalidRuleLimit,
    /// Header or CIDR matchers refused (see `MatcherError`).
    Matcher(MatcherError),
    /// The document is not JSON of the documented shape.
    Json(JsonError),
}

impl ManagementError {
    /// Returns the Zig error name.
    pub fn name(self) -> &'static str {
        match self {
            ManagementError::TooLarge => "TooLarge",
            ManagementError::InvalidId => "InvalidId",
            ManagementError::InvalidName => "InvalidName",
            ManagementError::InvalidPattern => "InvalidPattern",
            ManagementError::InvalidChallenge => "InvalidChallenge",
            ManagementError::InvalidWeight => "InvalidWeight",
            ManagementError::InvalidRuleLimit => "InvalidRuleLimit",
            ManagementError::Matcher(error) => error.name(),
            ManagementError::Json(error) => error.kind.name(),
        }
    }
}

impl fmt::Display for ManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManagementError::Json(error) => error.fmt(f),
            other => f.write_str(other.name()),
        }
    }
}

impl std::error::Error for ManagementError {}

impl From<JsonError> for ManagementError {
    fn from(error: JsonError) -> ManagementError {
        ManagementError::Json(error)
    }
}

impl From<MatcherError> for ManagementError {
    fn from(error: MatcherError) -> ManagementError {
        ManagementError::Matcher(error)
    }
}

/// A compiled management document. It owns every string; the source may be released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The stable id.
    pub id: String,
    /// Order among managed rules: lower first.
    pub priority: i32,
    /// Disabled documents are validated but not evaluated.
    pub enabled: bool,
    /// The rule, with its limit identity derived from the id.
    pub rule: PolicyRule,
    /// The CIDRs as written, retained for storage.
    pub cidrs: Vec<String>,
}

#[derive(Default)]
struct Wire {
    id: Vec<u8>,
    name: Vec<u8>,
    action: Option<Action>,
    priority: Option<i32>,
    enabled: Option<bool>,
    path: Option<Vec<u8>>,
    user_agent: Option<Vec<u8>>,
    headers: Option<crate::json::Members>,
    cidrs: Vec<Vec<u8>>,
    difficulty: Option<u32>,
    algorithm: Option<Algorithm>,
    weight: i32,
    limits: Option<crate::limits::Limits>,
}

const FIELDS: [&str; 13] = [
    "id",
    "name",
    "action",
    "priority",
    "enabled",
    "path",
    "user_agent",
    "headers",
    "cidrs",
    "difficulty",
    "algorithm",
    "weight",
    "limits",
];

fn wire(source: &[u8]) -> Result<Wire, JsonError> {
    let mut reader = Reader::new(source);
    let mut wire = Wire::default();
    let actions = ["allow", "deny", "challenge", "weigh"];
    let algorithms = ["hashcash", "posw"];
    let seen = reader.object(&FIELDS, |reader, field| {
        match field {
            0 => wire.id = reader.string()?,
            1 => wire.name = reader.string()?,
            2 => wire.action = Some(Action::ALL[reader.enumeration(&actions)?]),
            3 => wire.priority = Some(reader.int(Int::I32)? as i32),
            4 => wire.enabled = Some(reader.boolean()?),
            5 => wire.path = reader.optional(Reader::string)?,
            6 => wire.user_agent = reader.optional(Reader::string)?,
            7 => wire.headers = Some(reader.members()?),
            8 => wire.cidrs = reader.string_list()?,
            9 => wire.difficulty = reader.optional(|r| r.int(Int::U32).map(|v| v as u32))?,
            10 => {
                wire.algorithm =
                    reader.optional(|r| r.enumeration(&algorithms).map(|i| Algorithm::ALL[i]))?
            }
            11 => wire.weight = reader.int(Int::I32)? as i32,
            _ => wire.limits = reader.optional(schema::limits)?,
        }
        Ok(())
    })?;
    reader.require(&seen, &[0, 1, 2])?;
    reader.finish()?;
    Ok(wire)
}

/// Parses and validates one management document.
///
/// Fails with `TooLarge` (checked before parsing), `Json` (unknown or repeated keys, a
/// missing `id`, `name` or `action`, wrong types), `InvalidId`, `InvalidName`,
/// `InvalidPattern`, `InvalidChallenge`, `InvalidWeight`, `InvalidRuleLimit`, or
/// `Matcher`, checked in that order.
pub fn parse(source: &[u8]) -> Result<Document, ManagementError> {
    if source.len() > MAX_DOCUMENT {
        return Err(ManagementError::TooLarge);
    }
    let wire = wire(source)?;
    let id_ok = !wire.id.is_empty()
        && wire.id.len() <= MAX_ID
        && wire.id.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !id_ok {
        return Err(ManagementError::InvalidId);
    }
    if wire.name.is_empty() || wire.name.len() > MAX_NAME || !valid_text(&wire.name) {
        return Err(ManagementError::InvalidName);
    }
    for pattern in [&wire.path, &wire.user_agent].into_iter().flatten() {
        if pattern.len() > MAX_PATTERN || !valid_text(pattern) {
            return Err(ManagementError::InvalidPattern);
        }
    }
    // `require` guarantees the action is present.
    let action = wire.action.unwrap_or(Action::Allow);
    let challenge = action == Action::Challenge;
    if wire.difficulty.is_some_and(|d| !challenge || d > 64)
        || (wire.algorithm.is_some() && !challenge)
    {
        return Err(ManagementError::InvalidChallenge);
    }
    if wire.weight != 0 && action != Action::Weigh {
        return Err(ManagementError::InvalidWeight);
    }
    if let Some(limits) = wire.limits
        && (action == Action::Weigh || limits.validate().is_err())
    {
        return Err(ManagementError::InvalidRuleLimit);
    }
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let rule = PolicyRule {
        path_pattern: wire.path.as_deref().map(text),
        ua_pattern: wire.user_agent.as_deref().map(text),
        difficulty: wire.difficulty,
        algorithm: wire.algorithm,
        weight: wire.weight,
        limits: wire.limits,
        limit_identity: managed_identity(&wire.id),
        headers: matchers::headers(wire.headers.as_ref().unwrap_or(&crate::json::Members::Null))?,
        cidrs: matchers::cidrs(&wire.cidrs)?,
        ..PolicyRule::new(&text(&wire.name), action)
    };
    Ok(Document {
        id: text(&wire.id),
        priority: wire.priority.unwrap_or(100),
        enabled: wire.enabled.unwrap_or(true),
        rule,
        cidrs: wire.cidrs.iter().map(|c| text(c)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Header;

    #[test]
    fn management_compilation_owns_strings_and_preserves_matcher_semantics() {
        let mut source = b"{\"id\":\"checkout\",\"name\":\"Checkout\",\"action\":\"challenge\",\"\
            path\":\"/checkout/*\",\"headers\":{\"X-Api\":\"v2\"},\"cidrs\":[\"8.8.8.0/24\"],\"al\
            gorithm\":\"posw\",\"difficulty\":16}"
            .to_vec();
        let document = parse(&source).unwrap();
        source.fill(b'x');
        assert_eq!(document.id, "checkout");
        assert_eq!(document.rule.algorithm, Some(Algorithm::Posw));
        let headers = [Header { name: b"x-api", value: b"v2" }];
        assert!(document.rule.matches(b"/checkout/pay", b"8.8.8.8", b"", &headers));
        assert!(!document.rule.matches(b"/checkout/pay", b"8.8.4.4", b"", &headers));
        assert_eq!(document.rule.limit_identity, managed_identity(b"checkout"));
    }

    #[test]
    fn management_input_rejects_ambiguous_and_overflowing_matchers_without_truncation() {
        let base = r#"{"id":"test","name":"Test","action":"allow","#;
        let nine = format!("\"cidrs\":[{}\"8.8.4.0/24\"]}}", "\"8.8.8.0/24\",".repeat(8));
        let cases: [(&str, &str); 8] = [
            (r#""headers":{"A":"1","B":"2","C":"3","D":"4","E":"5"}}"#, "TooManyHeaders"),
            (&nine, "TooManyCidrs"),
            (r#""headers":{"X-Api":"1","x-api":"2"}}"#, "InvalidHeader"),
            (r#""cidrs":["not-a-network"]}"#, "InvalidCidr"),
            (r#""difficulty":16}"#, "InvalidChallenge"),
            (r#""weight":5}"#, "InvalidWeight"),
            (r#""unexpected":true}"#, "UnknownField"),
            (r#""path":"/a","path":"/b"}"#, "DuplicateField"),
        ];
        for (tail, error) in cases {
            let text = format!("{base}{tail}");
            assert_eq!(parse(text.as_bytes()).unwrap_err().name(), error, "{text}");
        }
    }

    #[test]
    fn management_document_bounds_reject_exhaustion_and_invalid_identifiers() {
        let oversized = vec![b' '; MAX_DOCUMENT + 1];
        assert_eq!(parse(&oversized), Err(ManagementError::TooLarge));
        let input = br#"{"id":"bad/id","name":"Test","action":"allow"}"#;
        assert_eq!(parse(input), Err(ManagementError::InvalidId));
        assert_eq!(parse(br#"{"id":"a","action":"allow"}"#).unwrap_err().name(), "MissingField");
        assert_eq!(
            parse(br#"{"id":"a","name":"A","action":"ALLOW"}"#).unwrap_err().name(),
            "InvalidEnumTag"
        );
        assert_eq!(
            parse(br#"{"id":"a","name":"A","action":3,"weight":2}"#).unwrap().rule.action,
            Action::Weigh
        );
    }

    #[test]
    fn terminal_quota_validation_rejects_weigh_partial_and_out_of_range_settings() {
        let prefix = r#"{"id":"a","name":"A","action":"allow","limits":"#;
        for limits in [
            r#"{"rate":0,"window_seconds":1}"#,
            r#"{"rate":1000001,"window_seconds":1}"#,
            r#"{"rate":1,"window_seconds":0}"#,
            r#"{"rate":1,"window_seconds":86401}"#,
            r#"{"rate":1,"window_seconds":1,"ban_seconds":86401}"#,
        ] {
            let text = format!("{prefix}{limits}}}");
            assert_eq!(parse(text.as_bytes()), Err(ManagementError::InvalidRuleLimit), "{text}");
        }
        let partial = format!("{prefix}{}}}", r#"{"rate":1}"#);
        assert_eq!(parse(partial.as_bytes()).unwrap_err().name(), "MissingField");
        let typo = format!("{prefix}{}}}", r#"{"rate":1,"window_seconds":1,"typo":0}"#);
        assert_eq!(parse(typo.as_bytes()).unwrap_err().name(), "UnknownField");
        let weigh =
            br#"{"id":"a","name":"A","action":"weigh","limits":{"rate":1,"window_seconds":1}}"#;
        assert_eq!(parse(weigh), Err(ManagementError::InvalidRuleLimit));
        let maximum = format!(
            "{prefix}{}}}",
            r#"{"rate":1000000,"window_seconds":86400,"ban_seconds":86400}"#
        );
        assert_eq!(
            parse(maximum.as_bytes()).unwrap().rule.limits.map(|l| l.rate),
            Some(1_000_000)
        );
    }
}

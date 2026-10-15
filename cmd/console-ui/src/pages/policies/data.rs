//! The applied-policy replies: a page of applied rules and a policy decision, decoded once
//! when they arrive (`policy_data.zig` and the decoding half of `inspection_form.zig`).
//!
//! Members are read the way the Zig module read its parsed tree: a required member must be
//! present with the right type, and numbers must be integer literals within the target
//! type. Members nobody reads are ignored.

use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::rule_hit_history::Today;
use sibuna_json::Value;

use super::limits::{self, Limits};
use crate::json;

/// A reply member is missing or has the wrong type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

/// What an inspection category does with a finding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The category is skipped.
    #[default]
    Disabled,
    /// Findings are recorded and evaluation continues.
    Audit,
    /// Findings deny the request.
    Enforce,
}

impl Mode {
    /// Every mode, in the order the form lists them.
    pub const ALL: [Mode; 3] = [Mode::Disabled, Mode::Audit, Mode::Enforce];

    /// Returns the wire name.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Disabled => "disabled",
            Mode::Audit => "audit",
            Mode::Enforce => "enforce",
        }
    }

    /// Returns the label the form shows.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Disabled => "Disabled",
            Mode::Audit => "Audit",
            Mode::Enforce => "Enforce",
        }
    }

    fn from_name(name: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|mode| mode.name() == name)
    }
}

/// The modes of the four inspection categories, in wire order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modes(pub [Mode; 4]);

impl Modes {
    /// The wire names of the categories.
    pub const NAMES: [&'static str; 4] = ["path_traversal", "sqli", "xss", "rce"];
    /// The labels of the categories.
    pub const LABELS: [&'static str; 4] =
        ["Path traversal", "SQL injection", "Cross-site scripting", "Command injection"];

    /// Reads the four modes from an object; other members are ignored.
    pub fn decode(value: &Value<'_>) -> Result<Modes, Invalid> {
        let mut modes = [Mode::Disabled; 4];
        for (mode, name) in modes.iter_mut().zip(Modes::NAMES) {
            let text = json::field(value, name).and_then(Value::as_str).ok_or(Invalid)?;
            *mode = Mode::from_name(text).ok_or(Invalid)?;
        }
        Ok(Modes(modes))
    }

    /// Writes the modes as the compact JSON object the inspection edit carries.
    pub fn document(&self) -> String {
        let mut text = String::new();
        let mut json = sibuna_json::Writer::new(&mut text);
        // Writing into a `String` cannot fail.
        let _ = (|| {
            json.begin_object()?;
            for (name, mode) in Modes::NAMES.iter().zip(self.0) {
                json.key(name)?;
                json.string(mode.name())?;
            }
            json.end_object()
        })();
        text
    }
}

/// The inspection member of an applied page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Inspection {
    /// The page has no `inspection` member: the form is not drawn.
    #[default]
    Absent,
    /// The member is not a valid set of modes.
    Invalid,
    /// The applied modes.
    Modes(Modes),
}

/// One applied rule, as the policy page lists it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    /// The rule's hit history key; empty when the rule has none.
    pub history_key: String,
    /// Today's recorded hits, when reported.
    pub today: Option<Today>,
    /// The rule's quota.
    pub limits: Option<Limits>,
    /// The position in the applied order, from 0.
    pub index: u8,
    /// The rule name.
    pub name: String,
    /// The action: `deny`, `allow`, `challenge` or `weigh`.
    pub action: String,
    /// The path pattern; empty matches any path.
    pub path: String,
    /// The user-agent pattern; empty matches any.
    pub user_agent: String,
    /// The displayed text was shortened or replaced.
    pub truncated: bool,
    /// Header matchers.
    pub header_count: u8,
    /// Address matchers.
    pub cidr_count: u8,
    /// The difficulty override.
    pub difficulty: Option<u32>,
    /// The algorithm override.
    pub algorithm: Option<String>,
    /// The WEIGH score.
    pub weight: i32,
}

/// A page of the applied rules.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppliedPage {
    /// The committed revision.
    pub committed: String,
    /// The applied revision.
    pub applied: String,
    /// Applied rules in total.
    pub total: u16,
    /// Inspection runs.
    pub waf: bool,
    /// The default challenge difficulty.
    pub default_difficulty: u32,
    /// The default challenge algorithm.
    pub default_algorithm: String,
    /// The protection surface, when reported.
    pub surface: Option<String>,
    /// The global limiter's requests, when reported.
    pub rate_limit: Option<u32>,
    /// The global limiter's window, when reported.
    pub rate_window_seconds: Option<u64>,
    /// The honeypot ban, when reported.
    pub ban_seconds: Option<u64>,
    /// At most eight rules.
    pub rows: Vec<Row>,
    /// The offset of the next page.
    pub next: Option<u8>,
    /// The applied inspection modes.
    pub inspection: Inspection,
}

/// A stored applied-policy reply: the revisions as text (the inspection form reads them
/// even from a page it cannot show) and the page, if it is valid.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    /// The `committed` member, or empty.
    pub committed: String,
    /// The `applied` member, or empty.
    pub applied: String,
    /// The decoded page; `None` when the page is invalid.
    pub page: Option<AppliedPage>,
}

impl Snapshot {
    /// Keeps a reply whose envelope (`applied` and `next`) was already checked.
    pub fn new(body: &Value<'_>) -> Snapshot {
        Snapshot {
            committed: json::string(body, "committed").to_owned(),
            applied: json::string(body, "applied").to_owned(),
            page: AppliedPage::decode(body).ok(),
        }
    }
}

/// The result of the private policy tester.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decision {
    /// The rule's quota.
    pub limits: Option<Limits>,
    /// The inspection categories audited, as a bit mask; `None` when not recorded.
    pub audited: Option<u8>,
    /// A draft was evaluated.
    pub preview: bool,
    /// The committed revision of a draft evaluation.
    pub committed: Option<String>,
    /// The applied revision.
    pub applied: String,
    /// The decided action.
    pub action: String,
    /// The deciding rule.
    pub rule: String,
    /// The configured difficulty.
    pub difficulty: u32,
    /// The algorithm.
    pub algorithm: String,
    /// The WEIGH score.
    pub score: i32,
}

/// Returns member `key`, which must exist.
fn member<'v, 'a>(value: &'v Value<'a>, key: &str) -> Result<&'v Value<'a>, Invalid> {
    json::field(value, key).ok_or(Invalid)
}

/// Returns the string member `key`.
fn text(value: &Value<'_>, key: &str) -> Result<String, Invalid> {
    member(value, key)?.as_str().map(str::to_owned).ok_or(Invalid)
}

/// Returns the integer member `key`, which must fit `T`.
fn integer<T: TryFrom<i64>>(value: &Value<'_>, key: &str) -> Result<T, Invalid> {
    json::integer(member(value, key)?).and_then(|number| T::try_from(number).ok()).ok_or(Invalid)
}

/// Returns the boolean member `key`.
fn flag(value: &Value<'_>, key: &str) -> Result<bool, Invalid> {
    member(value, key)?.as_bool().ok_or(Invalid)
}

/// Returns member `key` unless it is absent or null.
fn optional<'v, 'a>(value: &'v Value<'a>, key: &str) -> Option<&'v Value<'a>> {
    json::field(value, key).filter(|item| !item.is_null())
}

/// Returns a required member that may be null.
fn nullable<'v, 'a>(value: &'v Value<'a>, key: &str) -> Result<Option<&'v Value<'a>>, Invalid> {
    let item = member(value, key)?;
    Ok((!item.is_null()).then_some(item))
}

/// Reads an optional number below 2^32, which must be an integer literal.
fn optional_u32(value: &Value<'_>, key: &str) -> Result<Option<u32>, Invalid> {
    optional(value, key)
        .map(|item| json::integer(item).and_then(|number| u32::try_from(number).ok()))
        .map(|number| number.ok_or(Invalid))
        .transpose()
}

/// Reads an optional 64-bit number: an integer literal or a string of decimal digits.
fn optional_u64(value: &Value<'_>, key: &str) -> Result<Option<u64>, Invalid> {
    optional(value, key).map(|item| json::counter(item).ok_or(Invalid)).transpose()
}

/// Reads an optional string.
fn optional_text(value: &Value<'_>, key: &str) -> Result<Option<String>, Invalid> {
    optional(value, key).map(|item| item.as_str().map(str::to_owned).ok_or(Invalid)).transpose()
}

impl AppliedPage {
    /// Decodes a page of applied rules.
    pub fn decode(value: &Value<'_>) -> Result<AppliedPage, Invalid> {
        let items = member(value, "rows")?.as_array().ok_or(Invalid)?;
        if items.len() > 8 {
            return Err(Invalid);
        }
        let rows = items.iter().map(Row::decode).collect::<Result<Vec<Row>, Invalid>>()?;
        let next = nullable(value, "next")?.map(|_| integer(value, "next")).transpose()?;
        let inspection = match json::field(value, "inspection") {
            None => Inspection::Absent,
            Some(item) => Modes::decode(item).map_or(Inspection::Invalid, Inspection::Modes),
        };
        Ok(AppliedPage {
            committed: text(value, "committed")?,
            applied: text(value, "applied")?,
            total: integer(value, "total")?,
            waf: flag(value, "waf")?,
            default_difficulty: integer(value, "default_difficulty")?,
            default_algorithm: text(value, "default_algorithm")?,
            surface: optional_text(value, "surface")?,
            rate_limit: optional_u32(value, "rate_limit")?,
            rate_window_seconds: optional_u64(value, "rate_window_seconds")?,
            ban_seconds: optional_u64(value, "ban_seconds")?,
            rows,
            next,
            inspection,
        })
    }
}

impl Row {
    /// Decodes one applied rule.
    fn decode(value: &Value<'_>) -> Result<Row, Invalid> {
        let today = optional(value, "today")
            .map(|item| Today::decode(item, Path::Root).map_err(|_| Invalid))
            .transpose()?;
        Ok(Row {
            history_key: optional_text(value, "history_key")?.unwrap_or_default(),
            today,
            limits: limits::read(value)?,
            index: integer(value, "index")?,
            name: text(value, "name")?,
            action: text(value, "action")?,
            path: text(value, "path")?,
            user_agent: text(value, "user_agent")?,
            truncated: flag(value, "truncated")?,
            header_count: integer(value, "header_count")?,
            cidr_count: integer(value, "cidr_count")?,
            difficulty: nullable(value, "difficulty")?
                .map(|_| integer(value, "difficulty"))
                .transpose()?,
            algorithm: nullable(value, "algorithm")?
                .map(|_| text(value, "algorithm"))
                .transpose()?,
            weight: integer(value, "weight")?,
        })
    }
}

impl Decision {
    /// Decodes a tester result.
    pub fn decode(value: &Value<'_>) -> Result<Decision, Invalid> {
        let object = value.as_object().ok_or(Invalid)?;
        let preview = if object.contains_key("preview") { flag(value, "preview")? } else { false };
        let audited = if object.contains_key("audited_categories") {
            Some(integer::<u8>(value, "audited_categories")?)
        } else {
            None
        };
        if audited.is_some_and(|mask| mask > 15) {
            return Err(Invalid);
        }
        Ok(Decision {
            audited,
            limits: limits::read(value)?,
            preview,
            committed: if preview { Some(text(value, "committed")?) } else { None },
            applied: text(value, "applied")?,
            action: text(value, "action")?,
            rule: text(value, "rule")?,
            difficulty: integer(value, "difficulty")?,
            algorithm: text(value, "algorithm")?,
            score: integer(value, "score")?,
        })
    }
}

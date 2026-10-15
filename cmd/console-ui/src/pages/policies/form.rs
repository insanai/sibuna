//! The managed-rule editor's form (`policy_form.zig` and `policy_matchers.zig`): the
//! fields as the operator typed them, the rule document they make, and the form markup.
//!
//! Editable text survives a failed validation: capturing a form only checks lengths, and
//! the document is built (and refused) separately.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::policies::MAX_DOCUMENT;
use sibuna_html::write_value;
use sibuna_json::{Value, Writer};

use super::limits::{self, Limits};
use crate::json;
use crate::json::parse_integer;
use crate::render::Html;
use crate::snippets;

/// The most header matchers a rule has, and the rows the form shows.
pub const HEADER_ROWS: usize = 4;
/// The most client networks a rule has.
const MAX_NETWORKS: usize = 8;

/// Why a form or document is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormError {
    /// A field is longer than its capacity.
    TooLong,
    /// The document is not a rule document.
    InvalidDocument,
    /// The header matchers are invalid.
    InvalidHeaders,
    /// The client networks are invalid.
    InvalidNetworks,
    /// The quota is invalid.
    InvalidRuleLimit,
    /// A number field is not a number of its type.
    InvalidNumber,
}

impl From<sibuna_console_protocol::TooLarge> for FormError {
    fn from(_: sibuna_console_protocol::TooLarge) -> FormError {
        FormError::TooLong
    }
}

impl From<super::data::Invalid> for FormError {
    fn from(_: super::data::Invalid) -> FormError {
        FormError::InvalidRuleLimit
    }
}

/// One header matcher row: a header name and a pattern.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderRow {
    /// The header name.
    pub name: String,
    /// The pattern its value must match.
    pub pattern: String,
}

/// The editor's fields, as text.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Form {
    /// The rule id.
    pub id: Text<128>,
    /// The rule name.
    pub name: Text<128>,
    /// The path pattern.
    pub path: Text<512>,
    /// The user-agent pattern.
    pub user_agent: Text<512>,
    /// The priority.
    pub priority: Text<12>,
    /// The WEIGH score.
    pub weight: Text<12>,
    /// The challenge difficulty.
    pub difficulty: Text<3>,
    /// The action.
    pub action: Text<16>,
    /// The challenge algorithm.
    pub algorithm: Text<8>,
    /// `true` or `false`.
    pub enabled: Text<5>,
    /// The header matcher rows, at most [`HEADER_ROWS`]; rows may be blank or repeated
    /// until the document is built.
    pub headers: Vec<HeaderRow>,
    /// The client networks, one per line.
    pub cidrs: Text<512>,
    /// The quota's burst.
    pub limit_rate: Text<10>,
    /// The quota's window.
    pub limit_window: Text<10>,
    /// The quota's ban.
    pub limit_ban: Text<10>,
}

/// Returns `value`, or `default` when it is empty.
pub fn fallback<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() { default } else { value }
}

impl Form {
    /// Takes the submitted editor fields (`rule_<field>`), in the order Zig did; a field
    /// that is too long stops the capture and is reported.
    pub fn capture(&mut self, fields: &Value<'_>) -> Result<(), FormError> {
        self.id.set(json::string(fields, "rule_id"))?;
        self.name.set(json::string(fields, "rule_name"))?;
        self.path.set(json::string(fields, "rule_path"))?;
        self.user_agent.set(json::string(fields, "rule_user_agent"))?;
        self.priority.set(json::string(fields, "rule_priority"))?;
        self.weight.set(json::string(fields, "rule_weight"))?;
        self.difficulty.set(json::string(fields, "rule_difficulty"))?;
        self.action.set(json::string(fields, "rule_action"))?;
        self.algorithm.set(json::string(fields, "rule_algorithm"))?;
        self.enabled.set(json::string(fields, "rule_enabled"))?;
        self.cidrs.set(json::string(fields, "rule_cidrs"))?;
        self.limit_rate.set(json::string(fields, "rule_limit_rate"))?;
        self.limit_window.set(json::string(fields, "rule_limit_window"))?;
        self.limit_ban.set(json::string(fields, "rule_limit_ban"))?;
        let mut rows = Vec::with_capacity(HEADER_ROWS);
        for index in 0..HEADER_ROWS {
            let name = json::string(fields, &format!("rule_header_name_{index}"));
            let pattern = json::string(fields, &format!("rule_header_pattern_{index}"));
            if name.len() > 64 || pattern.len() > 256 {
                return Err(FormError::InvalidHeaders);
            }
            rows.push(HeaderRow { name: name.to_owned(), pattern: pattern.to_owned() });
        }
        self.headers = rows;
        Ok(())
    }

    /// Reads a rule document into a form.
    pub fn load(source: &str) -> Result<Form, FormError> {
        let limits = json::limits(source.len());
        let root = sibuna_json::parse_with_limits(source.as_bytes(), &limits)
            .map_err(|_| FormError::InvalidDocument)?;
        let object = root.as_object().ok_or(FormError::InvalidDocument)?;
        let enabled = match object.get("enabled") {
            None => true,
            Some(value) => value.as_bool().ok_or(FormError::InvalidDocument)?,
        };
        let mut form = Form {
            id: Text::new(json::string(&root, "id"))?,
            name: Text::new(json::string(&root, "name"))?,
            path: Text::new(json::string(&root, "path"))?,
            user_agent: Text::new(json::string(&root, "user_agent"))?,
            action: Text::new(json::string(&root, "action"))?,
            algorithm: Text::new(json::string(&root, "algorithm"))?,
            priority: numeric(&root, "priority", Some(100))?,
            weight: numeric(&root, "weight", Some(0))?,
            difficulty: numeric(&root, "difficulty", None)?,
            enabled: Text::new(if enabled { "true" } else { "false" })?,
            headers: load_headers(&root)?,
            cidrs: load_networks(&root)?,
            ..Form::default()
        };
        if let Some(limits) = limits::read(&root)? {
            form.limit_rate = Text::new(&limits.rate.to_string())?;
            form.limit_window = Text::new(&limits.window_seconds.to_string())?;
            form.limit_ban = Text::new(&limits.ban_seconds.to_string())?;
        }
        Ok(form)
    }

    /// Builds the rule document (compact JSON, at most 4 KiB). Settings that belong to
    /// another action are left out.
    pub fn document(&self) -> Result<String, FormError> {
        let action = fallback(self.action.as_str(), "deny");
        let challenge = action == "challenge";
        let weigh = action == "weigh";
        let priority = parse_integer::<i32>(fallback(self.priority.as_str(), "100"))
            .ok_or(FormError::InvalidNumber)?;
        let difficulty = if challenge && !self.difficulty.is_empty() {
            Some(parse_integer::<u32>(self.difficulty.as_str()).ok_or(FormError::InvalidNumber)?)
        } else {
            None
        };
        let weight = if weigh {
            parse_integer::<i32>(fallback(self.weight.as_str(), "0"))
                .ok_or(FormError::InvalidNumber)?
        } else {
            0
        };
        let headers = header_pairs(&self.headers)?;
        let networks = networks(self.cidrs.as_str())?;
        let limits = self.limits()?;
        let mut text = String::new();
        let mut json = Writer::new(&mut text);
        let document = Document {
            form: self,
            action,
            priority,
            difficulty,
            algorithm: if challenge { optional(self.algorithm.as_str()) } else { None },
            weight,
            headers: &headers,
            networks: &networks,
            limits,
        };
        document.write(&mut json).map_err(|_| FormError::InvalidDocument)?;
        if text.len() > MAX_DOCUMENT {
            return Err(FormError::InvalidDocument);
        }
        Ok(text)
    }

    /// Builds the quota from the three quota fields: all empty is no quota.
    fn limits(&self) -> Result<Option<Limits>, FormError> {
        if self.limit_rate.is_empty() && self.limit_window.is_empty() && self.limit_ban.is_empty()
        {
            return Ok(None);
        }
        if self.action.as_str() == "weigh" {
            return Err(FormError::InvalidRuleLimit);
        }
        let ban =
            if self.limit_ban.is_empty() { 0 } else { limits::number(self.limit_ban.as_str())? };
        let quota = Limits {
            rate: limits::number(self.limit_rate.as_str())?,
            window_seconds: limits::number(self.limit_window.as_str())?,
            ban_seconds: ban,
        };
        Ok(Some(quota.validate()?))
    }

    /// Returns the header rows as the JSON text the change review compares.
    pub fn headers_text(&self) -> String {
        let mut text = String::new();
        let mut json = Writer::new(&mut text);
        // Writing into a `String` cannot fail.
        let _ = write_rows(&mut json, &self.headers);
        text
    }

    /// Returns the text of review field `index` (see `changes`).
    pub fn field_text(&self, index: usize) -> std::borrow::Cow<'_, str> {
        let text = match index {
            0 => self.id.as_str(),
            1 => self.name.as_str(),
            2 => self.action.as_str(),
            3 => self.enabled.as_str(),
            4 => self.priority.as_str(),
            5 => self.path.as_str(),
            6 => self.user_agent.as_str(),
            7 => return self.headers_text().into(),
            8 => self.cidrs.as_str(),
            9 => self.algorithm.as_str(),
            10 => self.difficulty.as_str(),
            11 => self.weight.as_str(),
            12 => self.limit_rate.as_str(),
            13 => self.limit_window.as_str(),
            _ => self.limit_ban.as_str(),
        };
        text.into()
    }
}

/// The values of a rule document, in the member order of the Zig encoder.
struct Document<'a> {
    form: &'a Form,
    action: &'a str,
    priority: i32,
    difficulty: Option<u32>,
    algorithm: Option<&'a str>,
    weight: i32,
    headers: &'a [&'a HeaderRow],
    networks: &'a [&'a str],
    limits: Option<Limits>,
}

impl Document<'_> {
    fn write(&self, json: &mut Writer<&mut String>) -> fmt::Result {
        json.begin_object()?;
        json.key("id")?;
        json.string(self.form.id.as_str())?;
        json.key("name")?;
        json.string(self.form.name.as_str())?;
        json.key("action")?;
        json.string(self.action)?;
        json.key("priority")?;
        json.int(i64::from(self.priority))?;
        json.key("enabled")?;
        json.bool(self.form.enabled.as_str() != "false")?;
        optional_string(json, "path", optional(self.form.path.as_str()))?;
        optional_string(json, "user_agent", optional(self.form.user_agent.as_str()))?;
        json.key("difficulty")?;
        match self.difficulty {
            Some(difficulty) => json.uint(u64::from(difficulty))?,
            None => json.null()?,
        }
        optional_string(json, "algorithm", self.algorithm)?;
        json.key("weight")?;
        json.int(i64::from(self.weight))?;
        json.key("headers")?;
        json.begin_object()?;
        for row in self.headers {
            json.key(&row.name)?;
            json.string(&row.pattern)?;
        }
        json.end_object()?;
        json.key("cidrs")?;
        json.begin_array()?;
        for network in self.networks {
            json.string(network)?;
        }
        json.end_array()?;
        json.key("limits")?;
        match self.limits {
            Some(limits) => {
                json.begin_object()?;
                json.key("rate")?;
                json.uint(u64::from(limits.rate))?;
                json.key("window_seconds")?;
                json.uint(u64::from(limits.window_seconds))?;
                json.key("ban_seconds")?;
                json.uint(u64::from(limits.ban_seconds))?;
                json.end_object()
            }
            None => json.null(),
        }?;
        json.end_object()
    }
}

/// Writes `key` with a string value or null.
fn optional_string(json: &mut Writer<&mut String>, key: &str, value: Option<&str>) -> fmt::Result {
    json.key(key)?;
    match value {
        Some(text) => json.string(text),
        None => json.null(),
    }
}

/// Returns `None` for empty text.
fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// Writes header rows as `[{"name":..,"pattern":..}]`.
fn write_rows(json: &mut Writer<&mut String>, rows: &[HeaderRow]) -> fmt::Result {
    json.begin_array()?;
    for row in rows {
        json.begin_object()?;
        json.key("name")?;
        json.string(&row.name)?;
        json.key("pattern")?;
        json.string(&row.pattern)?;
        json.end_object()?;
    }
    json.end_array()
}

/// Reads a number member as text: an absent member takes `default`, null is empty, and
/// the integer's text must fit `N` bytes.
fn numeric<const N: usize>(
    root: &Value<'_>,
    key: &str,
    default: Option<i64>,
) -> Result<Text<N>, FormError> {
    let number = match json::field(root, key) {
        None => default,
        Some(Value::Null) => None,
        Some(value) => Some(json::integer(value).ok_or(FormError::InvalidDocument)?),
    };
    match number {
        Some(number) => Ok(Text::new(&number.to_string())?),
        None => Ok(Text::default()),
    }
}

/// Reads the `headers` object of a document: at most four string patterns.
fn load_headers(root: &Value<'_>) -> Result<Vec<HeaderRow>, FormError> {
    let Some(value) = json::field(root, "headers").filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let object = value.as_object().ok_or(FormError::InvalidHeaders)?;
    if object.len() > HEADER_ROWS {
        return Err(FormError::InvalidHeaders);
    }
    object
        .iter()
        .map(|(name, pattern)| {
            let pattern = pattern.as_str().ok_or(FormError::InvalidHeaders)?;
            Ok(HeaderRow { name: name.to_owned(), pattern: pattern.to_owned() })
        })
        .collect()
}

/// Reads the `cidrs` array of a document as one network per line.
fn load_networks(root: &Value<'_>) -> Result<Text<512>, FormError> {
    let Some(value) = json::field(root, "cidrs").filter(|value| !value.is_null()) else {
        return Ok(Text::default());
    };
    let items = value.as_array().ok_or(FormError::InvalidNetworks)?;
    if items.len() > MAX_NETWORKS {
        return Err(FormError::InvalidNetworks);
    }
    let mut lines = String::new();
    for (index, item) in items.iter().enumerate() {
        let network = item.as_str().ok_or(FormError::InvalidNetworks)?;
        if network.is_empty() || network.len() > 48 || network.contains(['\r', '\n']) {
            return Err(FormError::InvalidNetworks);
        }
        if index != 0 {
            lines.push('\n');
        }
        lines.push_str(network);
    }
    Ok(Text::from_string(lines)?)
}

/// Returns the configured header rows of a document: blank rows are skipped; a row needs
/// a name of at most 64 bytes and a pattern of at most 256, and names are unique ignoring
/// ASCII case.
fn header_pairs(rows: &[HeaderRow]) -> Result<Vec<&HeaderRow>, FormError> {
    let mut pairs: Vec<&HeaderRow> = Vec::with_capacity(rows.len());
    for row in rows {
        if row.name.is_empty() && row.pattern.is_empty() {
            continue;
        }
        if row.name.is_empty() || row.name.len() > 64 || row.pattern.len() > 256 {
            return Err(FormError::InvalidHeaders);
        }
        if pairs.iter().any(|previous| previous.name.eq_ignore_ascii_case(&row.name)) {
            return Err(FormError::InvalidHeaders);
        }
        pairs.push(row);
    }
    Ok(pairs)
}

/// Returns the client networks, one per non-blank line, at most eight of 48 bytes.
fn networks(source: &str) -> Result<Vec<&str>, FormError> {
    let mut result = Vec::new();
    for line in source.split('\n') {
        let line = line.trim_matches([' ', '\r', '\t']);
        if line.is_empty() {
            continue;
        }
        if line.len() > 48 || result.len() == MAX_NETWORKS {
            return Err(FormError::InvalidNetworks);
        }
        result.push(line);
    }
    Ok(result)
}

/// Draws the editor fields; an existing rule's id is read-only.
pub fn render(out: &mut Html<'_>, form: &Form, existing: bool) -> fmt::Result {
    out.write_str(
        "<div class=\"sb-rule-grid\"><div class=\"sb-rule-field\">\
         <label for=\"rule-id\">Rule ID</label>",
    )?;
    let id = &form.id.as_str();
    if existing {
        snippets::render_policy_id_existing(out, &snippets::PolicyIdExistingValues { id })?;
    } else {
        snippets::render_policy_id_new(out, &snippets::PolicyIdNewValues { id })?;
    }
    out.write_str("</div>")?;
    snippets::render_policy_name(out, &snippets::PolicyNameValues { name: &form.name.as_str() })?;
    let action = fallback(form.action.as_str(), "deny");
    select(out, "action", "Action", action, &["deny", "allow", "challenge", "weigh"])?;
    let enabled = fallback(form.enabled.as_str(), "true");
    select(out, "enabled", "Enabled", enabled, &["true", "false"])?;
    snippets::render_policy_form(
        out,
        &snippets::PolicyFormValues {
            path: &form.path.as_str(),
            user_agent: &form.user_agent.as_str(),
            priority: &fallback(form.priority.as_str(), "100"),
        },
    )?;
    let algorithm = form.algorithm.as_str();
    select(out, "algorithm", "Challenge algorithm", algorithm, &["", "hashcash", "posw"])?;
    snippets::render_policy_extra_fields(
        out,
        &snippets::PolicyExtraFieldsValues {
            weight: &fallback(form.weight.as_str(), "0"),
            difficulty: &form.difficulty.as_str(),
        },
    )?;
    matchers(out, &form.headers, form.cidrs.as_str())?;
    snippets::render_policy_limits(
        out,
        &snippets::PolicyLimitsValues {
            rate: &form.limit_rate.as_str(),
            window: &form.limit_window.as_str(),
            ban: &form.limit_ban.as_str(),
        },
    )?;
    out.write_str("</div>")
}

/// Draws a select of `values` with `selected` chosen.
fn select(
    out: &mut Html<'_>,
    name: &str,
    label: &str,
    selected: &str,
    values: &[&str],
) -> fmt::Result {
    snippets::render_policy_select(
        out,
        &snippets::PolicySelectValues { name: &name, label: &label },
    )?;
    for value in values {
        let text = match (name, *value) {
            ("enabled", "true") => "Enabled",
            ("enabled", _) => "Disabled",
            (_, "") => "Inherit",
            (_, value) => value,
        };
        out.write_str("<option value=\"")?;
        write_value(out, value)?;
        out.write_str("\"")?;
        if *value == selected {
            out.write_str(" selected")?;
        }
        out.write_str(">")?;
        write_value(out, &text)?;
        out.write_str("</option>")?;
    }
    out.write_str("</select></div>")
}

/// Draws the four header matcher rows and the client networks.
fn matchers(out: &mut Html<'_>, rows: &[HeaderRow], networks: &str) -> fmt::Result {
    out.write_str(
        "<fieldset class=\"sb-rule-wide\"><legend class=\"font-bold\">Header matchers</legend>\
         <p class=\"sb-note\">All configured headers must match. Leave unused rows blank.</p>\
         <div class=\"sb-rule-grid\">",
    )?;
    let blank = HeaderRow::default();
    for index in 0..HEADER_ROWS {
        let row = rows.get(index).unwrap_or(&blank);
        snippets::render_policy_header_fields(
            out,
            &snippets::PolicyHeaderFieldsValues {
                index: &index,
                number: &(index + 1),
                name: &row.name.as_str(),
                pattern: &row.pattern.as_str(),
            },
        )?;
    }
    out.write_str("</div></fieldset>")?;
    snippets::render_policy_network_fields(
        out,
        &snippets::PolicyNetworkFieldsValues { networks: &networks },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `policy_form.zig`.
    #[test]
    fn editor_round_trips_all_matchers_and_clears_settings_owned_by_another_action() {
        let source = "{\"id\":\"checkout\",\"name\":\"Checkout\",\"action\":\"challenge\",\
             \"path\":\"/checkout/*\",\"user_agent\":\"Browser*\",\"priority\":-5,\
             \"difficulty\":16,\"algorithm\":\"posw\",\"enabled\":false,\
             \"headers\":{\"X-Api\":\"v2\"},\"cidrs\":[\"8.8.8.0/24\"]}";
        let mut form = Form::load(source).unwrap();
        let document = form.document().unwrap();
        let restored = Form::load(&document).unwrap();
        assert_eq!(form.headers, restored.headers);
        assert_eq!(form.cidrs, restored.cidrs);
        assert_eq!(restored.priority.as_str(), "-5");
        assert_eq!(restored.enabled.as_str(), "false");
        form.action.set("allow").unwrap();
        let allowed = Form::load(&form.document().unwrap()).unwrap();
        assert!(allowed.difficulty.is_empty());
        assert!(allowed.algorithm.is_empty());
        // Zig kept the header rows as JSON text and tested an unparsable text; the rows
        // are typed here, so the refusal is tested with duplicate names instead.
        form.headers.push(HeaderRow { name: "x-api".into(), pattern: "v3".into() });
        assert_eq!(form.document(), Err(FormError::InvalidHeaders));
        assert_eq!(form.headers.len(), 2);
    }

    /// Ported from `policy_matchers.zig`.
    #[test]
    fn duplicate_header_rows_remain_editable_but_cannot_become_a_policy_document() {
        let rows = vec![
            HeaderRow { name: "X-Review".into(), pattern: "one".into() },
            HeaderRow { name: "x-review".into(), pattern: "two".into() },
        ];
        assert_eq!(header_pairs(&rows), Err(FormError::InvalidHeaders));
        assert_eq!(rows[1].pattern, "two");
        assert!(header_pairs(&[]).unwrap().is_empty());
        assert_eq!(networks("8.8.8.0/24\n2001:db8::/32").unwrap().len(), 2);
        let nine = "1.0.0.0/8\n".repeat(9);
        assert_eq!(networks(&nine), Err(FormError::InvalidNetworks));
    }

    /// Ported from `policy_limits.zig`.
    #[test]
    fn rate_limit_drafts_round_trip_and_reject_partial_unknown_and_weigh_settings() {
        let source = "{\"id\":\"a\",\"name\":\"A\",\"action\":\"allow\",\
             \"limits\":{\"rate\":2,\"window_seconds\":60,\"ban_seconds\":3}}";
        let mut form = Form::load(source).unwrap();
        let restored = Form::load(&form.document().unwrap()).unwrap();
        assert_eq!(restored.limit_rate.as_str(), "2");
        assert_eq!(restored.limit_window.as_str(), "60");
        assert_eq!(restored.limit_ban.as_str(), "3");
        form.action.set("weigh").unwrap();
        assert_eq!(form.document(), Err(FormError::InvalidRuleLimit));
        form.action.set("deny").unwrap();
        form.limit_rate = Text::default();
        assert_eq!(form.document(), Err(FormError::InvalidRuleLimit));
        assert_eq!(Form::load("{\"limits\":{\"rate\":1}}"), Err(FormError::InvalidRuleLimit));
        let typo = "{\"limits\":{\"rate\":1,\"window_seconds\":60,\"typo\":1}}";
        assert_eq!(Form::load(typo), Err(FormError::InvalidRuleLimit));
    }

    #[test]
    fn documents_keep_the_zig_member_order_and_number_rules() {
        let mut form = Form::default();
        form.id.set("a").unwrap();
        form.name.set("A").unwrap();
        form.action.set("weigh").unwrap();
        form.weight.set("-1_0").unwrap();
        form.cidrs.set(" 10.0.0.0/8 \r\n\n").unwrap();
        form.headers =
            vec![HeaderRow::default(), HeaderRow { name: "X".into(), pattern: "\"".into() }];
        assert_eq!(
            form.document().unwrap(),
            "{\"id\":\"a\",\"name\":\"A\",\"action\":\"weigh\",\"priority\":100,\
             \"enabled\":true,\"path\":null,\"user_agent\":null,\"difficulty\":null,\
             \"algorithm\":null,\"weight\":-10,\"headers\":{\"X\":\"\\\"\"},\
             \"cidrs\":[\"10.0.0.0/8\"],\"limits\":null}"
        );
        assert_eq!(
            form.headers_text(),
            "[{\"name\":\"\",\"pattern\":\"\"},{\"name\":\"X\",\"pattern\":\"\\\"\"}]"
        );
        form.priority.set("2147483648").unwrap();
        assert_eq!(form.document(), Err(FormError::InvalidNumber));
        let huge = format!("{{\"id\":\"{}\"}}", "a".repeat(129));
        assert_eq!(Form::load(&huge), Err(FormError::TooLong));
        assert_eq!(Form::load("{\"difficulty\":1000}"), Err(FormError::TooLong));
        assert_eq!(Form::load("{\"priority\":1.5}"), Err(FormError::InvalidDocument));
        assert_eq!(Form::load("[]"), Err(FormError::InvalidDocument));
    }
}

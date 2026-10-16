//! The JSON policy file loader.
//!
//! The loader fails closed: a value the engine does not understand rejects the whole file.
//! An unknown key, a misspelled action, a malformed CIDR or an out-of-range number is never
//! dropped or defaulted, because a dropped criterion widens a rule and a defaulted action
//! turns a denial into admission. Matchers compile through the same strict `matchers` module
//! as managed documents, so both inputs share one grammar.
//!
//! ```
//! use sibuna_policy::{Action, Engine, RequestView};
//!
//! let file = br#"{"default_action":"DENY",
//!     "rules":[{"name":"office","action":"ALLOW","cidrs":["10.0.0.0/8"]}]}"#;
//! let engine = Engine::load_json(file, 16).unwrap();
//! let office = RequestView::new(b"/", b"10.1.2.3", b"curl");
//! assert_eq!(engine.evaluate(&office).action, Action::Allow);
//! assert_eq!(engine.evaluate(&RequestView::new(b"/", b"8.8.8.8", b"curl")).action, Action::Deny);
//! ```

pub(crate) mod schema;

use std::fmt;

use crate::engine::{Engine, MAX_RULE_NAME, RuleError};
use crate::ja4::Pattern;
use crate::json::{ErrorKind, JsonError, Members};
use crate::matchers::{self, MatcherError, valid_text};
use crate::rule::{Action, Algorithm, PolicyRule};
use schema::{File, RuleEntry, Thresholds};

/// Longest path or User-Agent pattern.
const MAX_PATTERN: usize = 512;
/// Range of thresholds and weights.
const SCORE_RANGE: std::ops::RangeInclusive<i32> = -1000..=1000;

/// Why a policy file was rejected. The names are Zig's error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadError {
    /// The file is not JSON of the documented shape (unknown or repeated keys included).
    Json(JsonError),
    /// An action that is not ALLOW, DENY, CHALLENGE or WEIGH, or a WEIGH default.
    InvalidAction,
    /// A rule without an action.
    MissingAction,
    /// A rule name that is empty, longer than 128 bytes or not printable text.
    InvalidRuleName,
    /// A path or User-Agent pattern that is empty, too long, not printable, or given twice.
    InvalidPattern,
    /// Header matchers out of shape, or given as both `headers` and `headers_regex`.
    InvalidHeader,
    /// More than four header matchers.
    TooManyHeaders,
    /// A rule CIDR that does not parse, or CIDRs given under both spellings.
    InvalidCidr,
    /// More than eight rule CIDRs.
    TooManyCidrs,
    /// A challenge block on a non-challenge rule, or an out-of-range difficulty or unknown
    /// algorithm.
    InvalidChallenge,
    /// A missing or out-of-range WEIGH weight, or a weight on another action.
    InvalidWeight,
    /// Thresholds out of range or out of order.
    InvalidThreshold,
    /// A reputation prefix that does not parse, or an action other than ALLOW, DENY or
    /// CHALLENGE.
    InvalidIpRule,
    /// Limits on a WEIGH rule, or out of range.
    InvalidRuleLimit,
    /// More than 128 rules.
    TooManyRules,
    /// More reputation prefixes than the 8,192-node trie holds.
    TrieFull,
    /// A JA4 pattern that no fingerprint could match (SID 0014).
    InvalidJa4,
}

impl LoadError {
    /// Returns the Zig error name (`InvalidAction`, `UnknownField`, `SyntaxError`, ...).
    pub fn name(self) -> &'static str {
        match self {
            LoadError::Json(error) => error.kind.name(),
            LoadError::InvalidAction => "InvalidAction",
            LoadError::MissingAction => "MissingAction",
            LoadError::InvalidRuleName => "InvalidRuleName",
            LoadError::InvalidPattern => "InvalidPattern",
            LoadError::InvalidHeader => "InvalidHeader",
            LoadError::TooManyHeaders => "TooManyHeaders",
            LoadError::InvalidCidr => "InvalidCidr",
            LoadError::TooManyCidrs => "TooManyCidrs",
            LoadError::InvalidChallenge => "InvalidChallenge",
            LoadError::InvalidWeight => "InvalidWeight",
            LoadError::InvalidThreshold => "InvalidThreshold",
            LoadError::InvalidIpRule => "InvalidIpRule",
            LoadError::InvalidRuleLimit => "InvalidRuleLimit",
            LoadError::TooManyRules => "TooManyRules",
            LoadError::TrieFull => "TrieFull",
            LoadError::InvalidJa4 => "InvalidJa4",
        }
    }

    /// Returns the operator wording for this error; see `explain`.
    pub fn explain(self) -> Explanation {
        explain(self)
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Json(error) => error.fmt(f),
            other => f.write_str(other.name()),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<JsonError> for LoadError {
    fn from(error: JsonError) -> LoadError {
        LoadError::Json(error)
    }
}

impl From<MatcherError> for LoadError {
    fn from(error: MatcherError) -> LoadError {
        match error {
            MatcherError::InvalidHeader => LoadError::InvalidHeader,
            MatcherError::TooManyHeaders => LoadError::TooManyHeaders,
            MatcherError::TooManyCidrs => LoadError::TooManyCidrs,
            MatcherError::InvalidCidr | MatcherError::TooLarge => LoadError::InvalidCidr,
            MatcherError::Json(error) => LoadError::Json(error),
        }
    }
}

impl From<RuleError> for LoadError {
    fn from(error: RuleError) -> LoadError {
        match error {
            RuleError::TooManyRules => LoadError::TooManyRules,
            RuleError::InvalidRuleName => LoadError::InvalidRuleName,
            RuleError::InvalidRuleLimit => LoadError::InvalidRuleLimit,
            RuleError::TooManyHeaders => LoadError::TooManyHeaders,
            RuleError::TooManyCidrs => LoadError::TooManyCidrs,
        }
    }
}

/// Where a rejected file went wrong, for the operator's diagnostic: the rule (by name), the
/// field and the offending value; empty strings when not applicable. For a JSON-level error
/// the rule and field are empty and `offset` holds the byte offset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diagnostic {
    /// The rule's name.
    pub rule: String,
    /// The field, such as `action` or `challenge.difficulty`.
    pub field: &'static str,
    /// The offending value.
    pub value: String,
    /// Byte offset of a JSON-level error.
    pub offset: Option<usize>,
}

impl Diagnostic {
    fn at(rule: &[u8], field: &'static str, value: &[u8]) -> Diagnostic {
        Diagnostic { rule: text(rule), field, value: text(value), offset: None }
    }
}

/// JSON strings are UTF-8 (the scanner validates them), so this never replaces anything.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Operator wording for a rejected file: a title for the rule line, a message and a hint.
/// The caller adds the file name and the `Diagnostic`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Explanation {
    /// The diagnostic title.
    pub title: &'static str,
    /// What is wrong, in plain words.
    pub message: &'static str,
    /// How to fix it.
    pub hint: &'static str,
}

const GENERIC: Explanation = Explanation {
    title: "INVALID POLICY FILE",
    message: "The policy file is not a JSON object of the documented shape.",
    hint: "Validate the JSON and compare it with the policy reference.",
};

/// Returns the operator wording for `error`, word for word as the Zig loader gave it.
pub fn explain(error: LoadError) -> Explanation {
    match error {
        LoadError::InvalidAction | LoadError::MissingAction => Explanation {
            title: "INVALID POLICY ACTION",
            message: "Every rule and the default action must name ALLOW, DENY, CHALLENGE or \
                WEIGH; the default cannot be WEIGH.",
            hint: "Check the spelling of the action. The file is rejected rather than defaulted, \
                because a misspelled DENY must never admit traffic.",
        },
        LoadError::InvalidCidr | LoadError::TooManyCidrs | LoadError::InvalidIpRule => {
            Explanation {
                title: "INVALID POLICY ADDRESS",
                message: "An address must be an IPv4 or IPv6 literal with an optional /prefix, \
                    and a rule lists at most eight.",
                hint: "A rule with an unreadable address would match every client, so the file \
                    is rejected. Fix the address or move it to ip_rules.",
            }
        }
        LoadError::InvalidHeader | LoadError::TooManyHeaders => Explanation {
            title: "INVALID POLICY HEADER",
            message: "Header matchers are an object of at most four token names mapped to text \
                patterns, given as headers or headers_regex, not both.",
            hint: "Header names use the HTTP token characters; values are printable text.",
        },
        LoadError::InvalidPattern => Explanation {
            title: "INVALID POLICY PATTERN",
            message: "path and user_agent patterns are non-empty printable text of at most 512 \
                bytes, given once each (path or path_regex, not both).",
            hint: "See the pattern grammar: '*' or '.*' match anything, '^...$' anchors, a \
                trailing '*' is a prefix, anything else is a substring.",
        },
        LoadError::Json(JsonError {
            kind: ErrorKind::UnknownField | ErrorKind::DuplicateField,
            ..
        }) => Explanation {
            title: "UNKNOWN POLICY FIELD",
            message: "A key appears that the engine does not evaluate, or appears twice.",
            hint: "A key the engine ignores would leave an operator's intent unmet, so the file \
                is rejected. Remove or correct the key.",
        },
        other => explain_values(other),
    }
}

fn explain_values(error: LoadError) -> Explanation {
    match error {
        LoadError::InvalidChallenge => Explanation {
            title: "INVALID POLICY CHALLENGE",
            message: "A challenge block belongs only to CHALLENGE rules, with difficulty 1 to 64 \
                work bits and algorithm hashcash or posw.",
            hint: "Remove the block from non-challenge rules or correct its values.",
        },
        LoadError::InvalidWeight => Explanation {
            title: "INVALID POLICY WEIGHT",
            message: "WEIGH rules need a weight between -1000 and 1000; other actions cannot \
                carry one.",
            hint: "Give every WEIGH rule a weight and remove weights elsewhere.",
        },
        LoadError::InvalidThreshold => Explanation {
            title: "INVALID POLICY THRESHOLDS",
            message: "challenge_at and deny_at lie in -1000..1000 with deny_at at or above \
                challenge_at; bits_step lies in 1..1000.",
            hint: "Lower challenge_at or raise deny_at so the WEIGH ladder is ordered.",
        },
        LoadError::InvalidRuleLimit => Explanation {
            title: "INVALID POLICY LIMIT",
            message: "limits need rate 1..1000000, window_seconds 1..86400 and ban_seconds at \
                most 86400, and WEIGH rules cannot carry limits.",
            hint: "Attach limits to the terminal rule that should hold the quota.",
        },
        LoadError::InvalidJa4 => Explanation {
            title: "INVALID POLICY JA4",
            message: "A ja4 pattern is a whole JA4 fingerprint, such as \
                t13d1516h2_8daaf6152771_02713d6af862, or the start of one followed by '*', \
                such as t13d*.",
            hint: "A pattern no fingerprint can match would leave the rule dead, so the file \
                is rejected. Copy the value from the ingress's header or shorten it to a \
                prefix.",
        },
        LoadError::InvalidRuleName | LoadError::TooManyRules | LoadError::TrieFull => {
            Explanation {
                title: "POLICY CAPACITY OR NAME",
                message: "Rule names are printable text of 1 to 128 bytes; a file holds at most \
                    128 rules and 8192 reputation prefixes.",
                hint: "Shorten the file or move prefixes to replicated reputation.",
            }
        }
        _ => GENERIC,
    }
}

impl Engine {
    /// Builds an engine with `Engine::new(default_difficulty)` and applies the policy file
    /// `text` to it (see `apply_json`).
    ///
    /// Fails with the first `LoadError`; the partial engine is dropped.
    pub fn load_json(text: &[u8], default_difficulty: u32) -> Result<Engine, LoadError> {
        let mut engine = Engine::new(default_difficulty);
        engine.apply_json(text, &mut Diagnostic::default())?;
        Ok(engine)
    }

    /// Applies the policy file `text`: `default_action`, `waf`, `inspection`,
    /// `thresholds`, `ip_rules` and `rules`, in that order. An explicit `rules` list
    /// replaces the current rules, an empty list included. The file buffer may be released
    /// afterwards; the engine copies what it keeps.
    ///
    /// Fails with the first `LoadError` in Zig's order and fills `diagnostic` with the
    /// rule, field and value where it went wrong; on success `diagnostic` is cleared. After
    /// an error the engine may be partly changed and must be discarded.
    pub fn apply_json(
        &mut self,
        text: &[u8],
        diagnostic: &mut Diagnostic,
    ) -> Result<(), LoadError> {
        *diagnostic = Diagnostic::default();
        let file =
            schema::file(text).inspect_err(|error| diagnostic.offset = Some(error.offset))?;
        self.apply_file(file, diagnostic)?;
        *diagnostic = Diagnostic::default();
        Ok(())
    }

    fn apply_file(&mut self, file: File, diagnostic: &mut Diagnostic) -> Result<(), LoadError> {
        if let Some(text) = file.default_action {
            *diagnostic = Diagnostic::at(b"", "default_action", &text);
            match Action::parse(&text) {
                Some(Action::Weigh) | None => return Err(LoadError::InvalidAction),
                Some(action) => self.default_action = action,
            }
        }
        if let Some(enabled) = file.waf {
            self.waf_enabled = enabled;
        }
        if let Some(modes) = file.inspection {
            self.inspection_modes = modes;
        }
        if let Some(thresholds) = file.thresholds {
            self.apply_thresholds(&thresholds, diagnostic)?;
        }
        if let Some(entries) = file.ip_rules {
            self.apply_ip_rules(&entries, diagnostic)?;
        }
        if let Some(entries) = file.rules {
            // An explicit list replaces the built-in table, an empty one included.
            self.clear_rules();
            for entry in &entries {
                let rule = compile_rule(entry, diagnostic)?;
                self.add_rule(rule)?;
            }
        }
        Ok(())
    }

    fn apply_thresholds(
        &mut self,
        thresholds: &Thresholds,
        diagnostic: &mut Diagnostic,
    ) -> Result<(), LoadError> {
        let fields: [(Option<i32>, &'static str, std::ops::RangeInclusive<i32>); 3] = [
            (thresholds.challenge_at, "thresholds.challenge_at", SCORE_RANGE),
            (thresholds.deny_at, "thresholds.deny_at", SCORE_RANGE),
            (thresholds.bits_step, "thresholds.bits_step", 1..=1000),
        ];
        for (index, (value, field, range)) in fields.into_iter().enumerate() {
            let Some(value) = value else { continue };
            *diagnostic = Diagnostic::at(b"", field, b"");
            if !range.contains(&value) {
                return Err(LoadError::InvalidThreshold);
            }
            match index {
                0 => self.thresholds.challenge_at = value,
                1 => self.thresholds.deny_at = value,
                _ => self.thresholds.bits_step = value,
            }
        }
        *diagnostic = Diagnostic::at(b"", "thresholds", b"");
        if self.thresholds.deny_at < self.thresholds.challenge_at {
            return Err(LoadError::InvalidThreshold);
        }
        Ok(())
    }

    /// `"ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" }` feeds the
    /// reputation trie, which scales to thousands of prefixes.
    fn apply_ip_rules(
        &mut self,
        entries: &[(Vec<u8>, Vec<u8>)],
        diagnostic: &mut Diagnostic,
    ) -> Result<(), LoadError> {
        for (cidr, action) in entries {
            *diagnostic = Diagnostic::at(b"", "ip_rules", cidr);
            let action = match Action::parse(action) {
                Some(Action::Weigh) | None => return Err(LoadError::InvalidIpRule),
                Some(action) => action,
            };
            self.insert_reputation(cidr, action).map_err(|error| match error {
                sibuna_cidr::TrieError::Full => LoadError::TrieFull,
                sibuna_cidr::TrieError::InvalidCidr(_) => LoadError::InvalidIpRule,
            })?;
        }
        Ok(())
    }
}

/// Reads one optional pattern given under two spellings.
fn pattern(
    plain: &Option<Vec<u8>>,
    regex: &Option<Vec<u8>>,
    name: &[u8],
    field: &'static str,
    diagnostic: &mut Diagnostic,
) -> Result<Option<String>, LoadError> {
    let value = plain.as_ref().or(regex.as_ref());
    *diagnostic = Diagnostic::at(name, field, value.map_or(&[][..], Vec::as_slice));
    if plain.is_some() && regex.is_some() {
        return Err(LoadError::InvalidPattern);
    }
    let Some(value) = value else { return Ok(None) };
    if value.is_empty() || value.len() > MAX_PATTERN || !valid_text(value) {
        return Err(LoadError::InvalidPattern);
    }
    Ok(Some(text(value)))
}

/// True for header matchers that are present and not `null`.
fn given(members: &Option<Members>) -> bool {
    members.as_ref().is_some_and(|members| *members != Members::Null)
}

/// Compiles one rule as Zig's `compileRule` does, field by field, leaving the diagnostic
/// on the field that failed (or on `limits` after the last check).
fn compile_rule(entry: &RuleEntry, diagnostic: &mut Diagnostic) -> Result<PolicyRule, LoadError> {
    let name = entry.name.as_deref().unwrap_or_default();
    *diagnostic = Diagnostic::at(name, "name", name);
    if name.is_empty() || name.len() > MAX_RULE_NAME || !valid_text(name) {
        return Err(LoadError::InvalidRuleName);
    }
    *diagnostic = Diagnostic::at(name, "action", entry.action.as_deref().unwrap_or_default());
    let action_text = entry.action.as_deref().ok_or(LoadError::MissingAction)?;
    let action = Action::parse(action_text).ok_or(LoadError::InvalidAction)?;
    let mut rule = PolicyRule::new(&text(name), action);
    rule.path_pattern = pattern(&entry.path, &entry.path_regex, name, "path", diagnostic)?;
    rule.ua_pattern =
        pattern(&entry.user_agent, &entry.user_agent_regex, name, "user_agent", diagnostic)?;
    *diagnostic = Diagnostic::at(name, "headers", b"");
    if given(&entry.headers) && given(&entry.headers_regex) {
        return Err(LoadError::InvalidHeader);
    }
    let headers = if given(&entry.headers) { &entry.headers } else { &entry.headers_regex };
    rule.headers = matchers::headers(headers.as_ref().unwrap_or(&Members::Null))?;
    *diagnostic = Diagnostic::at(name, "cidrs", b"");
    if entry.cidrs.is_some() && entry.remote_addresses.is_some() {
        return Err(LoadError::InvalidCidr);
    }
    let cidrs = entry.cidrs.as_ref().or(entry.remote_addresses.as_ref());
    rule.cidrs = matchers::cidrs(cidrs.map_or(&[][..], Vec::as_slice))?;
    if let Some(text) = &entry.ja4 {
        *diagnostic = Diagnostic::at(name, "ja4", text);
        rule.ja4 = Some(Pattern::parse(text).ok_or(LoadError::InvalidJa4)?);
    }
    compile_challenge(entry, &mut rule, diagnostic)?;
    *diagnostic = Diagnostic::at(name, "weight", b"");
    match entry.weight {
        Some(weight) if action == Action::Weigh && SCORE_RANGE.contains(&weight) => {
            rule.weight = weight
        }
        Some(_) => return Err(LoadError::InvalidWeight),
        None if action == Action::Weigh => return Err(LoadError::InvalidWeight),
        None => {}
    }
    *diagnostic = Diagnostic::at(name, "limits", b"");
    if let Some(limits) = entry.limits {
        if action == Action::Weigh || limits.validate().is_err() {
            return Err(LoadError::InvalidRuleLimit);
        }
        rule.limits = Some(limits);
    }
    Ok(rule)
}

fn compile_challenge(
    entry: &RuleEntry,
    rule: &mut PolicyRule,
    diagnostic: &mut Diagnostic,
) -> Result<(), LoadError> {
    let Some(challenge) = &entry.challenge else { return Ok(()) };
    let name = rule.name.as_bytes();
    *diagnostic = Diagnostic::at(name, "challenge", b"");
    if rule.action != Action::Challenge {
        return Err(LoadError::InvalidChallenge);
    }
    if let Some(difficulty) = challenge.difficulty {
        diagnostic.field = "challenge.difficulty";
        if difficulty == 0 || difficulty > 64 {
            return Err(LoadError::InvalidChallenge);
        }
        rule.difficulty = Some(difficulty);
    }
    if let Some(text) = &challenge.algorithm {
        *diagnostic = Diagnostic::at(name, "challenge.algorithm", text);
        rule.algorithm = Some(Algorithm::parse(text).ok_or(LoadError::InvalidChallenge)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

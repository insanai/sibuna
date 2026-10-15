//! Audit summaries: the redacted JSON objects stored as `before_summary` and
//! `after_summary`, and the allowlisted view the Audit page shows of them.
//!
//! A summary never holds passwords, token values, TOTP seeds, recovery codes, cookies,
//! webhook secrets, page markup or policy selectors (SID 0007). Writers build summaries
//! only from the fields they name; [`copy`] shows only allowlisted fields of a stored
//! summary, so a field that a direct database write slipped in is not shown either.

use sibuna_console_protocol::Text;
use sibuna_json::{Value, Writer};

/// The largest stored summary, in bytes (the `CHECK` of `console_audit`).
pub const MAX_SUMMARY: usize = 2048;
/// The largest stored summary [`copy`] reads; Zig refused longer cells as corrupt.
const MAX_SOURCE: usize = 8192;
/// The most bytes of one text field [`copy`] shows.
const MAX_FIELD: usize = 64;

/// Builds one summary object, field by field, in the order written. Numbers and flags are
/// written as JSON integers, as SQLite's `json_object` wrote integer columns in Zig.
#[derive(Debug)]
pub struct Summary {
    json: Writer<String>,
}

impl Default for Summary {
    fn default() -> Summary {
        Summary::new()
    }
}

impl Summary {
    /// Starts an empty object.
    pub fn new() -> Summary {
        let mut json = Writer::new(String::with_capacity(128));
        // Writing into a `String` cannot fail.
        let _ = json.begin_object();
        Summary { json }
    }

    /// Adds a text field.
    #[must_use]
    pub fn text(mut self, key: &str, value: &str) -> Summary {
        let _ = self.json.key(key);
        let _ = self.json.string(value);
        self
    }

    /// Adds an integer field.
    #[must_use]
    pub fn int(mut self, key: &str, value: u64) -> Summary {
        let _ = self.json.key(key);
        let _ = self.json.uint(value);
        self
    }

    /// Adds an integer field, or `null` for `None`.
    #[must_use]
    pub fn optional_int(mut self, key: &str, value: Option<u64>) -> Summary {
        let _ = self.json.key(key);
        let _ = match value {
            Some(value) => self.json.uint(value),
            None => self.json.null(),
        };
        self
    }

    /// Adds a flag as the integer 0 or 1.
    #[must_use]
    pub fn flag(self, key: &str, value: bool) -> Summary {
        self.int(key, u64::from(value))
    }

    /// Returns the finished object text.
    pub fn finish(mut self) -> String {
        let _ = self.json.end_object();
        self.json.into_inner()
    }
}

/// The allowlisted view of one stored summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Copied {
    /// The shown object.
    pub text: Text<1024>,
    /// A text field was cut at 64 bytes.
    pub truncated: bool,
    /// A field was left out or a control character replaced, or the summary itself says
    /// that policy selectors were redacted.
    pub redacted: bool,
}

/// Why a stored summary could not be shown: it is not a JSON object of at most 8,192 bytes,
/// or its allowlisted view exceeds 1,024 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSummary;

/// Returns the allowlisted view of the stored summary `source` of a row whose action is
/// `action`: text fields cut to 64 bytes at a character boundary with control characters
/// replaced by `?`, integer, boolean and null fields as stored, everything else left out.
/// Fields keep their stored order (PostgreSQL's `JSONB` stores its own order).
///
/// Fails with [`InvalidSummary`] for a source that is not a JSON object of at most 8,192
/// bytes, or a view longer than 1,024 bytes.
pub fn copy(source: &str, action: &str) -> Result<Copied, InvalidSummary> {
    if source.len() > MAX_SOURCE {
        return Err(InvalidSummary);
    }
    let parsed = sibuna_json::parse(source.as_bytes()).map_err(|_| InvalidSummary)?;
    let object = parsed.as_object().ok_or(InvalidSummary)?;
    let mut json = Writer::new(String::with_capacity(source.len().min(1024)));
    let mut copied = Copied::default();
    let _ = json.begin_object();
    for (key, value) in object.iter() {
        let integer = integer(value);
        if key == "selectors_redacted" && integer.is_some_and(|number| number != 0) {
            copied.redacted = true;
        }
        let text = value.as_str().filter(|_| is_text_field(action, key));
        let scalar = (integer.is_some() || value.as_bool().is_some() || value.is_null())
            && is_number_field(action, key);
        if let Some(text) = text {
            let _ = json.key(key);
            let _ = json.string(&bounded(text, &mut copied));
        } else if scalar {
            let _ = json.key(key);
            let _ = match (integer, value.as_bool()) {
                (Some(number), _) => json.int(number),
                (None, Some(flag)) => json.bool(flag),
                (None, None) => json.null(),
            };
        } else {
            copied.redacted = true;
        }
    }
    let _ = json.end_object();
    copied.text = Text::from_string(json.into_inner()).map_err(|_| InvalidSummary)?;
    Ok(copied)
}

/// Returns the value as an integer when it is an integer literal that fits `i64`, as Zig's
/// `std.json` parsed `.integer`.
fn integer(value: &Value<'_>) -> Option<i64> {
    let number = value.as_number()?;
    if number.is_integer_literal() { number.as_i64().ok() } else { None }
}

fn is_text_field(action: &str, key: &str) -> bool {
    const TEXT: [&str; 15] = [
        "username",
        "label",
        "role",
        "command",
        "state",
        "action",
        "algorithm",
        "path_traversal",
        "sqli",
        "xss",
        "rce",
        "sha256",
        "kind",
        "host",
        "secret",
    ];
    const NOTIFICATION_TEXT: [&str; 4] = ["operation", "outcome", "detail", "transport"];
    TEXT.contains(&key)
        || (is_notification(action) && NOTIFICATION_TEXT.contains(&key))
        // A setting's value is a catalogue number written as text, never a secret; the
        // Audit page shows it before and after the change. Scoped like the delivery
        // fields, so a `value` elsewhere stays hidden.
        || (action == "setting.change" && key == "value")
}

fn is_number_field(action: &str, key: &str) -> bool {
    const NUMBER: [&str; 18] = [
        "disabled",
        "must_change",
        "revision",
        "scopes",
        "expires",
        "cleared_entries",
        "enabled",
        "priority",
        "difficulty",
        "weight",
        "rate",
        "window_seconds",
        "ban_seconds",
        "selectors_redacted",
        "algorithm",
        "bytes",
        "events",
        "cooldown_seconds",
    ];
    const NOTIFICATION_NUMBER: [&str; 4] = ["event", "destination", "attempt", "cooldown"];
    NUMBER.contains(&key) || (is_notification(action) && NOTIFICATION_NUMBER.contains(&key))
}

/// Delivery fields describe deliveries, never arbitrary user JSON; the extension is scoped
/// to notification rows so a similarly named field elsewhere does not become public.
fn is_notification(action: &str) -> bool {
    action.starts_with("notification.")
}

/// Returns at most [`MAX_FIELD`] bytes of `source`, cut at a character boundary, with
/// control characters replaced by `?`.
fn bounded(source: &str, copied: &mut Copied) -> String {
    let mut length = source.len().min(MAX_FIELD);
    // Index 0 is always a character boundary, so the loop stops before underflowing, and
    // the slice below ends at a boundary within the string.
    while !source.is_char_boundary(length) {
        length -= 1;
    }
    copied.truncated |= length != source.len();
    let mut text = String::with_capacity(length);
    for character in source[..length].chars() {
        if character < ' ' || character == '\u{7f}' {
            text.push('?');
            copied.redacted = true;
        } else {
            text.push(character);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    // From console_audit_summary.zig "audit summary redaction drops secrets and truncates
    // complete UTF-8 characters".
    #[test]
    fn redaction_drops_secrets_and_truncates_complete_characters() {
        let source = format!(
            "{{\"label\":\"{}\u{e9}\",\"revision\":2,\"password\":\"private\",\
             \"token\":\"private\",\"nested\":{{\"secret\":true}}}}",
            "a".repeat(63)
        );
        let copied = copy(&source, "").unwrap();
        assert!(copied.redacted && copied.truncated);
        assert!(!copied.text.as_str().contains("private"));
        assert!(copied.text.as_str().contains("\"revision\":2"));
        assert!(copied.text.as_str().contains(&format!("\"label\":\"{}\"", "a".repeat(63))));
    }

    // From console_audit_summary.zig "notification receipts expose correlation and outcome
    // without arbitrary secret fields".
    #[test]
    fn notification_receipts_show_outcomes_but_not_secrets() {
        let source = "{\"operation\":\"0123456789abcdef0123456789abcdef\",\
                      \"outcome\":\"delivered\",\"detail\":\"status 204\",\"revision\":1,\
                      \"secret_envelope\":\"private\"}";
        let copied = copy(source, "notification.test_result").unwrap();
        assert!(copied.redacted && !copied.truncated);
        assert!(copied.text.as_str().contains("0123456789abcdef"));
        assert!(copied.text.as_str().contains("status 204"));
        assert!(!copied.text.as_str().contains("private"));
        let copied = copy(source, "user.update").unwrap();
        assert_eq!(copied.text.as_str(), "{\"revision\":1}");
    }

    #[test]
    fn setting_changes_show_their_values() {
        let before = Summary::new().text("value", "30").finish();
        let copied = copy(&before, "setting.change").unwrap();
        assert_eq!(copied.text.as_str(), "{\"value\":\"30\"}");
        assert!(!copied.redacted);
        let elsewhere = copy(&before, "page.edit").unwrap();
        assert_eq!(elsewhere.text.as_str(), "{}");
        assert!(elsewhere.redacted);
    }

    #[test]
    fn writer_and_reader_agree() {
        let text = Summary::new()
            .text("username", "ops\u{1}")
            .text("role", "admin")
            .flag("disabled", true)
            .optional_int("expires", None)
            .int("revision", 3)
            .finish();
        assert_eq!(
            text,
            "{\"username\":\"ops\\u0001\",\"role\":\"admin\",\"disabled\":1,\"expires\":null,\
             \"revision\":3}"
        );
        let copied = copy(&text, "user.create").unwrap();
        assert_eq!(
            copied.text.as_str(),
            "{\"username\":\"ops?\",\"role\":\"admin\",\"disabled\":1,\"expires\":null,\
             \"revision\":3}"
        );
        assert!(copied.redacted);
        let marked = copy("{\"selectors_redacted\":1,\"weight\":1.5}", "policy.edit").unwrap();
        assert!(marked.redacted);
        assert_eq!(marked.text.as_str(), "{\"selectors_redacted\":1}");
    }

    #[test]
    fn invalid_sources_are_refused() {
        assert_eq!(copy("[]", ""), Err(InvalidSummary));
        assert_eq!(copy("{", ""), Err(InvalidSummary));
        assert_eq!(copy(&" ".repeat(MAX_SOURCE + 1), ""), Err(InvalidSummary));
    }

    /// A deterministic xorshift generator, so the fuzz test needs no dependency.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % bound as u64).unwrap()
        }
    }

    const SEEDS: [&str; 5] = [
        "{\"username\":\"ops\",\"role\":\"admin\",\"disabled\":0,\"revision\":2}",
        "{\"label\":\"automation\",\"scopes\":192,\"expires\":null,\"disabled\":true}",
        "{\"operation\":\"0123\",\"outcome\":\"failed\",\"detail\":\"status 500\"}",
        "{\"action\":\"deny\",\"selectors_redacted\":1,\"weight\":-3,\"rate\":1.5}",
        "{\"host\":\"h\\u00e9\\n\",\"nested\":{\"secret\":[1,2]},\"sha256\":\"ab\"}",
    ];

    /// Mutates `input` by a bit flip, a truncation, a duplication or a splice with another
    /// seed.
    fn mutate(random: &mut XorShift, input: &[u8]) -> Vec<u8> {
        let mut bytes = input.to_vec();
        if bytes.is_empty() {
            return bytes;
        }
        match random.below(4) {
            0 => {
                let at = random.below(bytes.len());
                bytes[at] ^= 1 << random.below(8);
            }
            1 => bytes.truncate(random.below(bytes.len())),
            2 => {
                let at = random.below(bytes.len());
                let tail = bytes[at..].to_vec();
                bytes.extend_from_slice(&tail);
            }
            _ => {
                let other = SEEDS[random.below(SEEDS.len())].as_bytes();
                let at = random.below(bytes.len());
                bytes.truncate(at);
                bytes.extend_from_slice(&other[random.below(other.len())..]);
            }
        }
        bytes
    }

    #[test]
    fn copy_never_panics_and_shows_only_allowlisted_fields() {
        let mut random = XorShift(0x5eed_0013);
        let actions = ["user.create", "notification.delivery", "policy.edit", ""];
        let mut shown = 0;
        for round in 0..100_000 {
            let seed = SEEDS[round % SEEDS.len()].as_bytes();
            let mut input = mutate(&mut random, seed);
            for _ in 0..random.below(3) {
                input = mutate(&mut random, &input);
            }
            let Ok(text) = std::str::from_utf8(&input) else { continue };
            let action = actions[random.below(actions.len())];
            let Ok(copied) = copy(text, action) else { continue };
            shown += 1;
            assert!(copied.text.len() <= 1024);
            let parsed = sibuna_json::parse(copied.text.as_bytes()).unwrap();
            let object = parsed.as_object().unwrap();
            for (key, value) in object.iter() {
                let shown = (is_text_field(action, key) && value.as_str().is_some())
                    || is_number_field(action, key);
                assert!(shown, "{key} shown for {action}: {text}");
                if let Some(text) = value.as_str() {
                    assert!(text.len() <= MAX_FIELD);
                    assert!(!text.chars().any(|c| c < ' ' || c == '\u{7f}'));
                }
            }
        }
        assert!(shown > 10_000, "only {shown} mutants were valid summaries");
    }
}

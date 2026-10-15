//! The allow-list: known, deliberate differences between the daemons, each with the reason
//! and the design record, crate documentation or maintainer decision that states it. Only
//! differences an entry matches may occur; any other difference fails the run.
//!
//! The file is JSON:
//!
//! ```json
//! { "allow": [ { "id": "...", "reason": "...", "config": "proxy-*", "field": "status",
//!                "request": [" http://", "CONNECT "], "rust_status": "400 " } ] }
//! ```
//!
//! `id` and `reason` are required. Every other key is an optional condition, given as one
//! string or as an array of strings of which any one may hold:
//!
//! - `config`, `category`, `field`: patterns over the configuration name, the category and
//!   the differing field, where `*` matches any text.
//! - `label`: text in the scenario's label.
//! - `request`: text in the scenario's requests so far (every request of the earlier
//!   connections and of this connection up to the differing one, escaped as in reports),
//!   so a difference that follows from an earlier request is matched by that request.
//!   Each request is preceded by two line breaks, so `"\nHEAD "` finds a `HEAD` request.
//! - `path`: text in the paths of those requests (each target without its query, and the
//!   `X-Forwarded-Uri` or `X-Original-URI` of forward authorization), each preceded by a
//!   line break.
//! - `repeated`: text that occurs at least twice in one of those requests, such as a
//!   header field sent twice.
//! - `zig`, `rust`: text in the respective (masked) values of the field.
//! - `zig_status`, `rust_status`: text in the respective final answers to the request: the
//!   status line, or `connection closed`, `timeout ...`, `non-response bytes ...`.
//!
//! An entry matches a difference when all of its conditions hold. A `note` key holds free
//! text for maintainers. Differences in the counters after the corpus need no entry when
//! every other difference of the configuration is allowed (see `runner.rs`).

use std::fmt;

use sibuna_json::Value;

/// One allowed difference. Every list is a condition of which any element may hold; an
/// empty list is no condition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// A short unique name.
    pub id: String,
    /// Why the daemons differ here, with the document that says so.
    pub reason: String,
    /// Patterns over the configuration name.
    pub config: Vec<String>,
    /// Patterns over the category name.
    pub category: Vec<String>,
    /// Patterns over the differing field.
    pub field: Vec<String>,
    /// Text in the scenario's label.
    pub label: Vec<String>,
    /// Text in the requests so far.
    pub request: Vec<String>,
    /// Text in the paths of the requests so far.
    pub path: Vec<String>,
    /// Text that occurs at least twice in the requests so far.
    pub repeated: Vec<String>,
    /// Text in the Zig value.
    pub zig: Vec<String>,
    /// Text in the Rust value.
    pub rust: Vec<String>,
    /// Text in the Zig daemon's final answer to the request.
    pub zig_status: Vec<String>,
    /// Text in the Rust daemon's final answer to the request.
    pub rust_status: Vec<String>,
}

/// Why an allow-list could not be loaded.
#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The file is not valid JSON.
    Json(String),
    /// The JSON does not have the expected shape.
    Shape(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Json(message) => write!(formatter, "the allow-list is not JSON: {message}"),
            LoadError::Shape(message) => {
                write!(formatter, "the allow-list is malformed: {message}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// What an entry is matched against.
#[derive(Clone, Copy, Debug, Default)]
pub struct Subject<'a> {
    /// The configuration name.
    pub config: &'a str,
    /// The category name.
    pub category: &'a str,
    /// The scenario's label.
    pub label: &'a str,
    /// The requests so far, escaped.
    pub requests: &'a str,
    /// The paths of the requests so far (targets without queries, forwarded URIs).
    pub paths: &'a str,
    /// The differing field.
    pub field: &'a str,
    /// The Zig daemon's value.
    pub zig: &'a str,
    /// The Rust daemon's value.
    pub rust: &'a str,
    /// The Zig daemon's final answer to the request.
    pub zig_status: &'a str,
    /// The Rust daemon's final answer to the request.
    pub rust_status: &'a str,
}

const KEYS: [&str; 14] = [
    "id",
    "reason",
    "config",
    "category",
    "field",
    "label",
    "request",
    "path",
    "repeated",
    "zig",
    "rust",
    "zig_status",
    "rust_status",
    "note",
];

/// The strings of a condition: one string or an array of strings.
fn strings(value: &Value<'_>, place: &str) -> Result<Vec<String>, LoadError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text.to_owned()]);
    }
    let not_text = || LoadError::Shape(format!("{place} is not a string or a list of strings"));
    let list = value.as_array().ok_or_else(not_text)?;
    list.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(not_text)).collect()
}

/// Parses one entry object.
fn parse_entry(index: usize, item: &Value<'_>) -> Result<Entry, LoadError> {
    let object = item
        .as_object()
        .ok_or_else(|| LoadError::Shape(format!("allow[{index}] is not an object")))?;
    let mut entry = Entry::default();
    for (key, value) in object.iter() {
        let list = strings(value, &format!("allow[{index}].{key}"))?;
        let slot = match key {
            "id" => {
                entry.id = list.concat();
                continue;
            }
            "reason" => {
                entry.reason = list.concat();
                continue;
            }
            // Free text for maintainers; not a condition.
            "note" => continue,
            "config" => &mut entry.config,
            "category" => &mut entry.category,
            "field" => &mut entry.field,
            "label" => &mut entry.label,
            "request" => &mut entry.request,
            "path" => &mut entry.path,
            "repeated" => &mut entry.repeated,
            "zig" => &mut entry.zig,
            "rust" => &mut entry.rust,
            "zig_status" => &mut entry.zig_status,
            "rust_status" => &mut entry.rust_status,
            _ => {
                let hint = KEYS.join(", ");
                return Err(LoadError::Shape(format!(
                    "allow[{index}] has the unknown key `{key}`; the keys are {hint}"
                )));
            }
        };
        *slot = list;
    }
    if entry.id.is_empty() || entry.reason.is_empty() {
        return Err(LoadError::Shape(format!("allow[{index}] needs an id and a reason")));
    }
    Ok(entry)
}

/// Parses an allow-list.
///
/// # Errors
///
/// Returns [`LoadError`] for invalid JSON, a missing `allow` array, an unknown key, a
/// value that is neither a string nor a list of strings, or an entry without `id` or
/// `reason`.
pub fn parse(text: &[u8]) -> Result<Vec<Entry>, LoadError> {
    let value = sibuna_json::parse(text).map_err(|error| LoadError::Json(error.to_string()))?;
    let list = value
        .as_object()
        .and_then(|object| object.get("allow"))
        .and_then(Value::as_array)
        .ok_or_else(|| LoadError::Shape("the top level needs an \"allow\" array".into()))?;
    list.iter().enumerate().map(|(index, item)| parse_entry(index, item)).collect()
}

impl Entry {
    /// True when every condition of the entry holds for `subject`.
    pub fn matches(&self, subject: &Subject<'_>) -> bool {
        let pattern = |condition: &[String], text: &str| {
            condition.is_empty() || condition.iter().any(|pattern| glob(pattern, text))
        };
        let contains = |condition: &[String], text: &str| {
            condition.is_empty() || condition.iter().any(|needle| text.contains(needle.as_str()))
        };
        // Requests are separated by two line breaks; the text must repeat within one.
        let repeated = |condition: &[String], text: &str| {
            condition.is_empty()
                || text.split("\n\n").any(|request| {
                    condition
                        .iter()
                        .any(|needle| request.matches(needle.as_str()).nth(1).is_some())
                })
        };
        pattern(&self.config, subject.config)
            && pattern(&self.category, subject.category)
            && pattern(&self.field, subject.field)
            && contains(&self.label, subject.label)
            && contains(&self.request, subject.requests)
            && contains(&self.path, subject.paths)
            && repeated(&self.repeated, subject.requests)
            && contains(&self.zig, subject.zig)
            && contains(&self.rust, subject.rust)
            && contains(&self.zig_status, subject.zig_status)
            && contains(&self.rust_status, subject.rust_status)
    }
}

/// Returns the first entry that matches `subject`.
pub fn explain<'e>(entries: &'e [Entry], subject: &Subject<'_>) -> Option<&'e Entry> {
    entries.iter().find(|entry| entry.matches(subject))
}

/// Matches `text` against `pattern`, where `*` stands for any text.
pub fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else { return false };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else { return rest.is_empty() };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_any_text_at_the_stars() {
        assert!(glob("proxy-*", "proxy-shield"));
        assert!(glob("*", ""));
        assert!(glob("a*c*e", "abcde"));
        assert!(glob("header:x-*", "header:x-sibuna-rule"));
        assert!(!glob("a*c", "ab"));
        assert!(!glob("abc", "abcd"));
        assert!(glob("abc", "abc"));
        assert!(!glob("a*a", "a"));
    }

    #[test]
    fn entries_parse_and_match() {
        let text = br#"{"allow":[{"id":"x","reason":"because","config":"*any-ipv4*",
            "field":"status","zig":"200","rust":["403","404"],"request":"GET /a",
            "note":"free text"}]}"#;
        let entries = parse(text).unwrap();
        assert_eq!(entries[0].rust, ["403", "404"]);
        let mut subject = Subject {
            config: "proxy-shield-any-ipv4-direct-hashcash",
            category: "navigation",
            requests: "GET /a HTTP/1.1",
            field: "status",
            zig: "HTTP/1.1 200 OK",
            rust: "HTTP/1.1 404 Not Found",
            ..Subject::default()
        };
        assert_eq!(explain(&entries, &subject).map(|entry| entry.id.as_str()), Some("x"));
        subject.rust = "HTTP/1.1 401 Unauthorized";
        assert!(explain(&entries, &subject).is_none());
        subject.rust = "HTTP/1.1 403 Forbidden";
        subject.requests = "GET /b HTTP/1.1";
        assert!(explain(&entries, &subject).is_none());
    }

    #[test]
    fn statuses_and_labels_are_conditions() {
        let text = br#"{"allow":[{"id":"h","reason":"r","label":"HEAD",
            "zig_status":"non-response","rust_status":["closed","200"]}]}"#;
        let entries = parse(text).unwrap();
        let subject = Subject {
            label: "method HEAD",
            zig_status: "non-response bytes x",
            rust_status: "connection closed",
            ..Subject::default()
        };
        assert!(explain(&entries, &subject).is_some());
        let other = Subject { label: "method GET", ..subject };
        assert!(explain(&entries, &other).is_none());
        let twice = parse(br#"{"allow":[{"id":"t","reason":"r","repeated":"X-A:"}]}"#).unwrap();
        let once = Subject { requests: "\n\nX-A: 1\n\nX-A: 2", ..Subject::default() };
        assert!(explain(&twice, &once).is_none());
        let two = Subject { requests: "X-A: 1\nX-A: 2", ..Subject::default() };
        assert!(explain(&twice, &two).is_some());
    }

    #[test]
    fn malformed_lists_are_refused() {
        assert!(matches!(parse(b"{"), Err(LoadError::Json(_))));
        assert!(matches!(parse(b"{\"allow\":1}"), Err(LoadError::Shape(_))));
        let unknown = parse(br#"{"allow":[{"id":"a","reason":"b","colour":"c"}]}"#);
        assert!(matches!(unknown, Err(LoadError::Shape(message)) if message.contains("colour")));
        let missing = parse(br#"{"allow":[{"id":"a"}]}"#);
        assert!(matches!(missing, Err(LoadError::Shape(_))));
        let number = parse(br#"{"allow":[{"id":"a","reason":"b","zig":[1]}]}"#);
        assert!(matches!(number, Err(LoadError::Shape(_))));
    }
}

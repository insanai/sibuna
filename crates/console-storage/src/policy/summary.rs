//! Audit summaries of the policy workflows: rule summaries without selectors, and a small
//! writer for the signed and optional values that [`crate::audit::summary::Summary`] does
//! not write (negative priorities and scores, absent algorithms).

use sibuna_json::Writer;
use sibuna_policy::Modes;
use sibuna_policy::management::Document;

/// Builds one summary object, field by field, in the order written. Writing into a
/// `String` cannot fail, so the writer's results are ignored.
#[derive(Debug)]
pub(crate) struct SummaryWriter {
    json: Writer<String>,
}

impl SummaryWriter {
    /// Starts an empty object.
    pub(crate) fn new() -> SummaryWriter {
        let mut json = Writer::new(String::with_capacity(128));
        let _ = json.begin_object();
        SummaryWriter { json }
    }

    /// Adds a text field.
    pub(crate) fn text(mut self, key: &str, value: &str) -> SummaryWriter {
        let _ = self.json.key(key);
        let _ = self.json.string(value);
        self
    }

    /// Adds a text field, or `null` for `None`.
    pub(crate) fn optional_text(mut self, key: &str, value: Option<&str>) -> SummaryWriter {
        let _ = self.json.key(key);
        let _ = match value {
            Some(value) => self.json.string(value),
            None => self.json.null(),
        };
        self
    }

    /// Adds a signed integer field.
    pub(crate) fn int(mut self, key: &str, value: i64) -> SummaryWriter {
        let _ = self.json.key(key);
        let _ = self.json.int(value);
        self
    }

    /// Adds a signed integer field, or `null` for `None`.
    pub(crate) fn optional_int(mut self, key: &str, value: Option<i64>) -> SummaryWriter {
        let _ = self.json.key(key);
        let _ = match value {
            Some(value) => self.json.int(value),
            None => self.json.null(),
        };
        self
    }

    /// Returns the finished object text.
    pub(crate) fn finish(mut self) -> String {
        let _ = self.json.end_object();
        self.json.into_inner()
    }
}

/// Returns the redacted summary of a rule as Zig's `console_policy_commit` trigger wrote it:
/// the decision fields only, with `selectors_redacted` set when the rule has a path,
/// User-Agent, header or CIDR selector. Names, patterns and matchers never appear.
pub(crate) fn rule_summary(document: &Document) -> String {
    let rule = &document.rule;
    let limits = rule.limits;
    let selectors = rule.path_pattern.is_some()
        || rule.ua_pattern.is_some()
        || !rule.headers.is_empty()
        || !document.cidrs.is_empty();
    SummaryWriter::new()
        .text("action", rule.action.name())
        .int("enabled", i64::from(document.enabled))
        .int("priority", i64::from(document.priority))
        .optional_int("difficulty", rule.difficulty.map(i64::from))
        .optional_text("algorithm", rule.algorithm.map(|algorithm| algorithm.name()))
        .int("weight", i64::from(rule.weight))
        .optional_int("rate", limits.map(|limits| i64::from(limits.rate)))
        .optional_int("window_seconds", limits.map(|limits| i64::from(limits.window_seconds)))
        .optional_int("ban_seconds", limits.map(|limits| i64::from(limits.ban_seconds)))
        .int("selectors_redacted", i64::from(selectors))
        .finish()
}

/// Returns the inspection modes as the object Zig's `std.json` wrote for `Modes`, which is
/// also the shape the inspection editor submits.
pub(crate) fn modes_summary(modes: Modes) -> String {
    SummaryWriter::new()
        .text("path_traversal", modes.path_traversal.name())
        .text("sqli", modes.sqli.name())
        .text("xss", modes.xss.name())
        .text("rce", modes.rce.name())
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_summaries_redact_selectors_and_keep_decisions() {
        let source = br#"{"id":"a","name":"private-name","action":"challenge","enabled":false,
            "priority":-7,"algorithm":"posw","difficulty":16,"path":"/private",
            "limits":{"rate":2,"window_seconds":60,"ban_seconds":5}}"#;
        let document = sibuna_policy::management::parse(source).unwrap();
        let summary = rule_summary(&document);
        assert_eq!(
            summary,
            "{\"action\":\"challenge\",\"enabled\":0,\"priority\":-7,\"difficulty\":16,\
             \"algorithm\":\"posw\",\"weight\":0,\"rate\":2,\"window_seconds\":60,\
             \"ban_seconds\":5,\"selectors_redacted\":1}"
        );
        assert!(!summary.contains("private"));
        let plain =
            sibuna_policy::management::parse(br#"{"id":"b","name":"B","action":"deny"}"#).unwrap();
        assert_eq!(
            rule_summary(&plain),
            "{\"action\":\"deny\",\"enabled\":1,\"priority\":100,\"difficulty\":null,\
             \"algorithm\":null,\"weight\":0,\"rate\":null,\"window_seconds\":null,\
             \"ban_seconds\":null,\"selectors_redacted\":0}"
        );
    }

    #[test]
    fn modes_are_written_in_field_order() {
        let modes = Modes { sqli: sibuna_policy::Mode::Audit, ..Modes::default() };
        assert_eq!(
            modes_summary(modes),
            "{\"path_traversal\":\"enforce\",\"sqli\":\"audit\",\"xss\":\"enforce\",\
             \"rce\":\"enforce\"}"
        );
    }
}

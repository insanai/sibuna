//! Reading the fields of a JSON document with structured problems.
//!
//! Every versioned document (descriptors, protocol messages, plans) is read through a
//! [`Fields`] view, so a missing or mistyped field always produces the same kind of
//! problem, naming the document and the field.

use crate::{Problem, Value};

/// A JSON object being read, and what to call it in problems.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    json: &'a Value,
    what: &'a str,
}

impl<'a> Fields<'a> {
    /// A view of `json`, called `what` in problems, such as `the plugin descriptor`.
    pub fn of(json: &'a Value, what: &'a str) -> Fields<'a> {
        Fields { json, what }
    }

    /// The problem for a field that is missing or has the wrong kind.
    pub fn invalid(&self, key: &str, kind: &str) -> Problem {
        Problem::new(
            "jlv.document.invalid",
            "INVALID DOCUMENT",
            &format!("{} has no {kind} `{key}`.", capitalized(self.what)),
        )
        .consequence("The document was not used.")
        .status(422)
        .hint("Produce the document with the jlvd tools of a matching version.")
    }

    /// The field `key`, if present.
    pub fn get(&self, key: &str) -> Option<&'a Value> {
        self.json.get(key)
    }

    /// The text field `key`.
    pub fn text(&self, key: &str) -> Result<&'a str, Problem> {
        self.json.get(key).and_then(Value::as_str).ok_or_else(|| self.invalid(key, "text"))
    }

    /// The text field `key`, if present.
    pub fn opt_text(&self, key: &str) -> Option<&'a str> {
        self.json.get(key).and_then(Value::as_str)
    }

    /// The nonnegative integer field `key`.
    pub fn u64(&self, key: &str) -> Result<u64, Problem> {
        self.json
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| self.invalid(key, "nonnegative integer"))
    }

    /// The integer field `key`.
    pub fn i64(&self, key: &str) -> Result<i64, Problem> {
        self.json.get(key).and_then(Value::as_i64).ok_or_else(|| self.invalid(key, "integer"))
    }

    /// The boolean field `key`, or `false` when absent.
    pub fn flag(&self, key: &str) -> bool {
        self.json.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    /// The array field `key`.
    pub fn array(&self, key: &str) -> Result<&'a [Value], Problem> {
        self.json
            .get(key)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| self.invalid(key, "list"))
    }

    /// The object field `key`.
    pub fn object(&self, key: &str) -> Result<Fields<'a>, Problem> {
        match self.json.get(key) {
            Some(v) if v.is_object() => Ok(Fields { json: v, what: self.what }),
            _ => Err(self.invalid(key, "object")),
        }
    }

    /// The document itself.
    pub fn json(&self) -> &'a Value {
        self.json
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_name_the_document() {
        let json = gd_json::parse(r#"{"a":"x","n":3}"#).unwrap();
        let fields = Fields::of(&json, "the plan");
        assert_eq!(fields.text("a").unwrap(), "x");
        assert_eq!(fields.u64("n").unwrap(), 3);
        let problem = fields.text("b").unwrap_err();
        assert_eq!(problem.message, "The plan has no text `b`.");
    }
}

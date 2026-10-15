//! Result documents: a JSON value we build and write with two-space indentation, and helpers
//! for reading the JSON other programs print (the Zig benchmark, wrk, the daemon).
//!
//! Parsing uses `sibuna-json`; its writer is compact, and result files are read by people
//! and diffed in git, so we keep a small indented writer here.

use std::fmt::Write;

use sibuna_json::{Number, Value};

/// A JSON value to be written into a result file. Object members keep insertion order.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A number with a fraction; NaN and infinities are written as `null`.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, in insertion order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Returns an empty object.
    pub fn object() -> Json {
        Json::Object(Vec::new())
    }

    /// Returns this object with member `key` set to `value` (builder style).
    ///
    /// # Panics
    ///
    /// Panics when `self` is not an object: that is a programming error in the caller.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<Json>) -> Json {
        self.set(key, value);
        self
    }

    /// Sets member `key` of this object to `value`, replacing an earlier member of that name.
    ///
    /// # Panics
    ///
    /// Panics when `self` is not an object: that is a programming error in the caller.
    pub fn set(&mut self, key: &str, value: impl Into<Json>) {
        let Json::Object(members) = self else {
            panic!("Json::set on a value that is not an object");
        };
        let value = value.into();
        match members.iter_mut().find(|(name, _)| name == key) {
            Some(member) => member.1 = value,
            None => members.push((key.to_owned(), value)),
        }
    }

    /// Writes this value as indented JSON followed by a newline.
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Json::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Json::Float(value) if value.is_finite() => {
                let _ = write!(out, "{value}");
            }
            Json::Float(_) => out.push_str("null"),
            Json::Str(text) => {
                let _ = sibuna_json::write_string(out, text);
            }
            Json::Array(items) if items.is_empty() => out.push_str("[]"),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    out.push_str(if index == 0 { "\n" } else { ",\n" });
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push(']');
            }
            Json::Object(members) if members.is_empty() => out.push_str("{}"),
            Json::Object(members) => {
                out.push('{');
                for (index, (key, value)) in members.iter().enumerate() {
                    out.push_str(if index == 0 { "\n" } else { ",\n" });
                    indent(out, depth + 1);
                    let _ = sibuna_json::write_string(out, key);
                    out.push_str(": ");
                    value.write(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push('}');
            }
        }
    }

    /// Converts a parsed value into an owned one, keeping integers exact.
    pub fn from_value(value: &Value<'_>) -> Json {
        match value {
            Value::Null => Json::Null,
            Value::Bool(b) => Json::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Ok(int) if n.is_integer_literal() => Json::Int(int),
                _ => n.as_f64().map_or(Json::Null, Json::Float),
            },
            Value::String(text) => Json::Str(text.to_string()),
            Value::Array(items) => Json::Array(items.iter().map(Json::from_value).collect()),
            Value::Object(object) => Json::Object(
                object.iter().map(|(k, v)| (k.to_string(), Json::from_value(v))).collect(),
            ),
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Rounds `value` to two decimals, as the Zig benchmark prints nanoseconds.
pub fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

impl From<bool> for Json {
    fn from(value: bool) -> Json {
        Json::Bool(value)
    }
}

impl From<u64> for Json {
    fn from(value: u64) -> Json {
        i64::try_from(value).map_or(Json::Float(value as f64), Json::Int)
    }
}

impl From<u32> for Json {
    fn from(value: u32) -> Json {
        Json::Int(i64::from(value))
    }
}

impl From<u16> for Json {
    fn from(value: u16) -> Json {
        Json::Int(i64::from(value))
    }
}

impl From<usize> for Json {
    fn from(value: usize) -> Json {
        Json::from(value as u64)
    }
}

impl From<f64> for Json {
    fn from(value: f64) -> Json {
        Json::Float(value)
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Json {
        Json::Str(value.to_owned())
    }
}

impl From<String> for Json {
    fn from(value: String) -> Json {
        Json::Str(value)
    }
}

impl From<Vec<Json>> for Json {
    fn from(value: Vec<Json>) -> Json {
        Json::Array(value)
    }
}

impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(value: Option<T>) -> Json {
        value.map_or(Json::Null, Into::into)
    }
}

/// Returns member `key` of `value` when `value` is an object that has it.
pub fn member<'v, 'a>(value: &'v Value<'a>, key: &str) -> Option<&'v Value<'a>> {
    value.as_object().and_then(|object| object.get(key))
}

/// Returns member `key` of `value` as a float.
pub fn member_f64(value: &Value<'_>, key: &str) -> Option<f64> {
    member(value, key).and_then(Value::as_number).and_then(|n| Number::as_f64(&n).ok())
}

/// Returns member `key` of `value` as an unsigned integer.
pub fn member_u64(value: &Value<'_>, key: &str) -> Option<u64> {
    member(value, key).and_then(Value::as_number).and_then(|n| Number::as_u64(&n).ok())
}

/// Returns member `key` of `value` as a string.
pub fn member_str<'v>(value: &'v Value<'_>, key: &str) -> Option<&'v str> {
    member(value, key).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_indented_json_in_insertion_order() {
        let value = Json::object()
            .with("b", 1u64)
            .with("a", vec![Json::from(1.5), Json::Null, Json::from("x\"y")])
            .with("empty", Json::object())
            .with("nan", f64::NAN);
        let text = value.to_pretty();
        assert_eq!(
            text,
            "{\n  \"b\": 1,\n  \"a\": [\n    1.5,\n    null,\n    \"x\\\"y\"\n  ],\n  \
             \"empty\": {},\n  \"nan\": null\n}\n"
        );
    }

    #[test]
    fn round_trips_through_the_parser() {
        let value = Json::object().with("n", 12u64).with("f", 0.25).with("s", "t");
        let text = value.to_pretty();
        let parsed = sibuna_json::parse(text.as_bytes()).unwrap();
        assert_eq!(Json::from_value(&parsed), value);
        assert_eq!(member_u64(&parsed, "n"), Some(12));
        assert_eq!(member_f64(&parsed, "f"), Some(0.25));
        assert_eq!(member_str(&parsed, "s"), Some("t"));
    }

    #[test]
    fn set_replaces_an_existing_member() {
        let mut value = Json::object().with("a", 1u64);
        value.set("a", 2u64);
        assert_eq!(value, Json::object().with("a", 2u64));
        assert_eq!(round2(1.23456), 1.23);
    }
}

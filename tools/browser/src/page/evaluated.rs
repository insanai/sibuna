//! The value of an evaluated expression.

use sibuna_json::{Value, Writer};

use crate::cdp::{field, string_at};
use crate::error::Error;

/// The result of [`Page::evaluate`](crate::Page::evaluate), kept as JSON text.
///
/// `undefined` and functions become `null`. Numbers JSON cannot hold (`NaN`, `Infinity`,
/// `-0`, BigInts such as `5n`) become strings of their JavaScript spelling, and
/// [`Evaluated::is_truthy`] still treats `NaN`, `-0` and `0n` as false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluated {
    json: String,
    /// The JavaScript spelling of a value JSON cannot hold.
    unserializable: Option<String>,
}

impl Evaluated {
    /// Reads a `Runtime.RemoteObject` returned by value.
    pub(crate) fn from_remote_object(object: Option<&Value<'_>>) -> Evaluated {
        let Some(object) = object else { return Evaluated::from_json("null") };
        let special = string_at(object, &["unserializableValue"]);
        if !special.is_empty() {
            let mut json = String::new();
            // Writing into a String cannot fail.
            let _ = sibuna_json::write_string(&mut json, special);
            return Evaluated { json, unserializable: Some(special.to_owned()) };
        }
        match field(object, &["value"]) {
            Some(value) => {
                let mut writer = Writer::new(String::new());
                let _ = writer.value(value);
                Evaluated { json: writer.into_inner(), unserializable: None }
            }
            None => Evaluated::from_json("null"),
        }
    }

    fn from_json(json: &str) -> Evaluated {
        Evaluated { json: json.to_owned(), unserializable: None }
    }

    /// The value as compact JSON text.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// The value parsed, borrowing this result.
    ///
    /// # Errors
    ///
    /// None in practice: the text was written by the JSON writer.
    pub fn value(&self) -> Result<Value<'_>, Error> {
        Ok(sibuna_json::parse_with_limits(self.json.as_bytes(), &sibuna_json::Limits::UNBOUNDED)?)
    }

    /// The boolean, or `None` for any other value.
    pub fn as_bool(&self) -> Option<bool> {
        match self.json.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    /// The string, or `None` for any other value.
    pub fn as_string(&self) -> Option<String> {
        if self.unserializable.is_some() {
            return None;
        }
        self.value().ok()?.as_str().map(str::to_owned)
    }

    /// The number, or `None` for any other value.
    pub fn as_f64(&self) -> Option<f64> {
        self.value().ok()?.as_number()?.as_f64().ok()
    }

    /// JavaScript truthiness: `false`, `null`, `undefined`, `0`, `-0`, `0n`, `NaN` and
    /// `""` are false; everything else is true.
    pub fn is_truthy(&self) -> bool {
        if let Some(special) = &self.unserializable {
            return !matches!(special.as_str(), "NaN" | "-0" | "0n");
        }
        match self.value() {
            Ok(Value::Null) | Err(_) => false,
            Ok(Value::Bool(value)) => value,
            Ok(Value::Number(number)) => number.as_f64().is_ok_and(|n| n != 0.0),
            Ok(Value::String(text)) => !text.is_empty(),
            Ok(Value::Array(_) | Value::Object(_)) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(json: &str) -> Evaluated {
        let object = sibuna_json::parse(json.as_bytes()).unwrap();
        Evaluated::from_remote_object(Some(&object))
    }

    #[test]
    fn reads_values_and_follows_javascript_truthiness() {
        let cases = [
            (r#"{"type":"boolean","value":true}"#, "true", true),
            (r#"{"type":"boolean","value":false}"#, "false", false),
            (r#"{"type":"undefined"}"#, "null", false),
            (r#"{"type":"object","subtype":"null","value":null}"#, "null", false),
            (r#"{"type":"number","value":0}"#, "0", false),
            (r#"{"type":"number","value":2.5}"#, "2.5", true),
            (r#"{"type":"string","value":""}"#, "\"\"", false),
            (r#"{"type":"string","value":"x"}"#, "\"x\"", true),
            (r#"{"type":"object","value":[1,{"a":2}]}"#, "[1,{\"a\":2}]", true),
            (r#"{"type":"number","unserializableValue":"NaN"}"#, "\"NaN\"", false),
            (r#"{"type":"number","unserializableValue":"-0"}"#, "\"-0\"", false),
            (r#"{"type":"bigint","unserializableValue":"5n"}"#, "\"5n\"", true),
        ];
        for (object, json, truthy) in cases {
            let value = remote(object);
            assert_eq!(value.json(), json, "{object}");
            assert_eq!(value.is_truthy(), truthy, "{object}");
        }
        assert_eq!(Evaluated::from_remote_object(None).json(), "null");
    }

    #[test]
    fn converts_to_rust_types() {
        assert_eq!(remote(r#"{"value":true}"#).as_bool(), Some(true));
        assert_eq!(remote(r#"{"value":"a\"b"}"#).as_string().as_deref(), Some("a\"b"));
        assert_eq!(remote(r#"{"value":1.25}"#).as_f64(), Some(1.25));
        assert_eq!(remote(r#"{"unserializableValue":"NaN"}"#).as_string(), None);
        assert_eq!(remote(r#"{"value":1}"#).as_bool(), None);
    }
}

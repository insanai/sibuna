//! Typed extraction from parsed objects, with unknown-key rejection and field paths.
//!
//! Configuration that the engine does not understand must not be dropped silently: a
//! misspelled key would leave an operator's intent unmet. An [`ObjectReader`] records
//! which keys the caller took, and [`ObjectReader::finish`] names the first one it did not.

use std::fmt;

use crate::number::NumberError;
use crate::value::{Object, Value};

/// Why a field could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldErrorKind {
    /// The value is not an object where an object was required (only for the value given
    /// to [`ObjectReader::new`] or [`ObjectReader::with_path`]).
    NotAnObject,
    /// A required key is absent (see [`ObjectReader::missing`]).
    Missing,
    /// The object has a key the caller did not take.
    UnknownKey,
    /// The value has the wrong type.
    WrongType {
        /// What the caller asked for, such as "a string".
        expected: &'static str,
        /// What the document holds, such as "a number".
        found: &'static str,
    },
    /// The value is a number that does not fit the requested type.
    Number(NumberError),
}

/// A field that could not be read, and where it is.
///
/// The path names the field from the document root, with `.` between keys and `[i]` for
/// array elements, such as `rules[2].challenge.difficulty`. It is empty for the root.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldError {
    /// The field's path from the document root.
    pub path: String,
    /// What is wrong with it.
    pub kind: FieldErrorKind,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() { "the document" } else { self.path.as_str() };
        match self.kind {
            FieldErrorKind::NotAnObject => write!(f, "`{path}` is not an object"),
            FieldErrorKind::Missing => write!(f, "`{path}` is missing"),
            FieldErrorKind::UnknownKey => write!(f, "`{path}` is not a known key"),
            FieldErrorKind::WrongType { expected, found } => {
                write!(f, "`{path}` should be {expected}, not {found}")
            }
            FieldErrorKind::Number(error) => write!(f, "`{path}`: {error}"),
        }
    }
}

impl std::error::Error for FieldError {}

/// Reads the members of one object by key, remembering which keys were taken.
///
/// Absent keys and keys whose value is `null` both read as `None`, as optional fields do in
/// Zig's typed parsing; use [`ObjectReader::take`] to tell them apart. Call
/// [`ObjectReader::finish`] after taking every known key to reject the rest.
///
/// ```
/// use sibuna_json::{parse, FieldErrorKind, ObjectReader};
///
/// let value = parse(br#"{"name":"office","weight":3,"actoin":"DENY"}"#).unwrap();
/// let mut rule = ObjectReader::new(&value).unwrap();
/// assert_eq!(rule.take_str("name").unwrap(), Some("office"));
/// assert_eq!(rule.take_i64("weight").unwrap(), Some(3));
/// assert_eq!(rule.take_str("action").unwrap(), None);
/// let error = rule.finish().unwrap_err();
/// assert_eq!((error.path.as_str(), error.kind), ("actoin", FieldErrorKind::UnknownKey));
/// ```
#[derive(Debug)]
pub struct ObjectReader<'v, 'a> {
    object: &'v Object<'a>,
    taken: Vec<bool>,
    path: String,
}

impl<'v, 'a> ObjectReader<'v, 'a> {
    /// Starts reading the document root `value`.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::NotAnObject`] with an empty path if `value` is not an object.
    pub fn new(value: &'v Value<'a>) -> Result<ObjectReader<'v, 'a>, FieldError> {
        ObjectReader::with_path(value, String::new())
    }

    /// Starts reading `value`, an object found at `path` (used to name fields in errors).
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::NotAnObject`] at `path` if `value` is not an object.
    pub fn with_path(
        value: &'v Value<'a>,
        path: String,
    ) -> Result<ObjectReader<'v, 'a>, FieldError> {
        match value {
            Value::Object(object) => {
                Ok(ObjectReader { object, taken: vec![false; object.len()], path })
            }
            _ => Err(FieldError { path, kind: FieldErrorKind::NotAnObject }),
        }
    }

    /// Returns the path of this object from the document root.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the path of `key` in this object, for the caller's own error messages.
    pub fn field_path(&self, key: &str) -> String {
        if self.path.is_empty() { key.to_owned() } else { format!("{}.{key}", self.path) }
    }

    /// Returns the error for a required `key` that is absent or `null`.
    pub fn missing(&self, key: &str) -> FieldError {
        FieldError { path: self.field_path(key), kind: FieldErrorKind::Missing }
    }

    /// Takes `key` and returns its value as it is, including `null`; `None` if absent.
    pub fn take(&mut self, key: &str) -> Option<&'v Value<'a>> {
        let index = self.object.position(key)?;
        // `taken` has one flag per member, so `index` is always in range.
        if let Some(taken) = self.taken.get_mut(index) {
            *taken = true;
        }
        self.object.member(index).map(|(_, value)| value)
    }

    /// Takes `key` and returns its value unless it is absent or `null`.
    fn take_present(&mut self, key: &str) -> Option<&'v Value<'a>> {
        self.take(key).filter(|value| !value.is_null())
    }

    fn wrong_type(&self, key: &str, expected: &'static str, found: &Value<'_>) -> FieldError {
        let kind = FieldErrorKind::WrongType { expected, found: found.kind_name() };
        FieldError { path: self.field_path(key), kind }
    }

    /// Takes `key` as a string.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] if the value is present and not a string.
    pub fn take_str(&mut self, key: &str) -> Result<Option<&'v str>, FieldError> {
        match self.take_present(key) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(other) => Err(self.wrong_type(key, "a string", other)),
        }
    }

    /// Takes `key` as a boolean.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] if the value is present and not a boolean.
    pub fn take_bool(&mut self, key: &str) -> Result<Option<bool>, FieldError> {
        match self.take_present(key) {
            None => Ok(None),
            Some(Value::Bool(flag)) => Ok(Some(*flag)),
            Some(other) => Err(self.wrong_type(key, "a boolean", other)),
        }
    }

    /// Takes `key` as a number and converts it with `convert`.
    fn take_number<T>(
        &mut self,
        key: &str,
        expected: &'static str,
        convert: impl FnOnce(crate::Number<'a>) -> Result<T, NumberError>,
    ) -> Result<Option<T>, FieldError> {
        match self.take_present(key) {
            None => Ok(None),
            Some(Value::Number(number)) => convert(*number).map(Some).map_err(|error| {
                FieldError { path: self.field_path(key), kind: FieldErrorKind::Number(error) }
            }),
            Some(other) => Err(self.wrong_type(key, expected, other)),
        }
    }

    /// Takes `key` as an `i64`; see [`Number::as_i64`](crate::Number::as_i64).
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] for a value that is not a number, and
    /// [`FieldErrorKind::Number`] for a number that is not an `i64`.
    pub fn take_i64(&mut self, key: &str) -> Result<Option<i64>, FieldError> {
        self.take_number(key, "an integer", |number| number.as_i64())
    }

    /// Takes `key` as a `u64`; see [`Number::as_u64`](crate::Number::as_u64).
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] for a value that is not a number, and
    /// [`FieldErrorKind::Number`] for a number that is not a `u64`.
    pub fn take_u64(&mut self, key: &str) -> Result<Option<u64>, FieldError> {
        self.take_number(key, "an unsigned integer", |number| number.as_u64())
    }

    /// Takes `key` as an `f64`; see [`Number::as_f64`](crate::Number::as_f64).
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] for a value that is not a number, and
    /// [`FieldErrorKind::Number`] for one too large to be finite.
    pub fn take_f64(&mut self, key: &str) -> Result<Option<f64>, FieldError> {
        self.take_number(key, "a number", |number| number.as_f64())
    }

    /// Takes `key` as an array. Name its elements in errors with
    /// `format!("{}[{i}]", reader.field_path(key))`.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] if the value is present and not an array.
    pub fn take_array(&mut self, key: &str) -> Result<Option<&'v [Value<'a>]>, FieldError> {
        match self.take_present(key) {
            None => Ok(None),
            Some(Value::Array(items)) => Ok(Some(items)),
            Some(other) => Err(self.wrong_type(key, "an array", other)),
        }
    }

    /// Takes `key` as an object and returns a reader for it, whose errors name fields
    /// below this one.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::WrongType`] if the value is present and not an object.
    pub fn take_object(&mut self, key: &str) -> Result<Option<ObjectReader<'v, 'a>>, FieldError> {
        match self.take_present(key) {
            None => Ok(None),
            Some(value @ Value::Object(_)) => {
                ObjectReader::with_path(value, self.field_path(key)).map(Some)
            }
            Some(other) => Err(self.wrong_type(key, "an object", other)),
        }
    }

    /// Ends reading.
    ///
    /// # Errors
    ///
    /// [`FieldErrorKind::UnknownKey`] naming the first key, in input order, that was not
    /// taken.
    pub fn finish(self) -> Result<(), FieldError> {
        let Some(index) = self.taken.iter().position(|&taken| !taken) else {
            return Ok(());
        };
        let key = self.object.member(index).map_or("", |(key, _)| key);
        Err(FieldError { path: self.field_path(key), kind: FieldErrorKind::UnknownKey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    const POLICY: &[u8] = br#"{
        "default_action": "ALLOW",
        "waf": false,
        "thresholds": { "deny_at": 30, "challenge_at": -5 },
        "rules": [
            { "name": "block", "action": "DENY", "weight": null },
            { "name": "checkout", "action": "CHALLENGE", "challenge": { "difficulty": 99 } }
        ]
    }"#;

    #[test]
    fn reads_typed_fields_and_nested_objects() {
        let value = parse(POLICY).unwrap();
        let mut file = ObjectReader::new(&value).unwrap();
        assert_eq!(file.take_str("default_action").unwrap(), Some("ALLOW"));
        assert_eq!(file.take_bool("waf").unwrap(), Some(false));
        let mut thresholds = file.take_object("thresholds").unwrap().unwrap();
        assert_eq!(thresholds.path(), "thresholds");
        assert_eq!(thresholds.take_i64("deny_at").unwrap(), Some(30));
        assert_eq!(thresholds.take_i64("challenge_at").unwrap(), Some(-5));
        assert_eq!(thresholds.take_i64("bits_step").unwrap(), None);
        thresholds.finish().unwrap();
        let rules = file.take_array("rules").unwrap().unwrap();
        assert_eq!(rules.len(), 2);
        let path = format!("{}[1]", file.field_path("rules"));
        let mut rule = ObjectReader::with_path(&rules[1], path).unwrap();
        assert_eq!(rule.take_str("name").unwrap(), Some("checkout"));
        let mut challenge = rule.take_object("challenge").unwrap().unwrap();
        assert_eq!(challenge.field_path("difficulty"), "rules[1].challenge.difficulty");
        assert_eq!(challenge.take_u64("difficulty").unwrap(), Some(99));
        let error = rule.finish().unwrap_err();
        assert_eq!(error.path, "rules[1].action");
        assert_eq!(error.kind, FieldErrorKind::UnknownKey);
        file.finish().unwrap();
    }

    #[test]
    fn null_reads_as_absent_but_take_sees_it() {
        let value = parse(POLICY).unwrap();
        let mut file = ObjectReader::new(&value).unwrap();
        let rules = file.take_array("rules").unwrap().unwrap();
        let mut rule = ObjectReader::with_path(&rules[0], "rules[0]".into()).unwrap();
        assert_eq!(rule.take_i64("weight").unwrap(), None);
        assert_eq!(rule.take("weight"), Some(&Value::Null));
        assert_eq!(rule.take("absent"), None);
        assert_eq!(rule.missing("absent").to_string(), "`rules[0].absent` is missing");
    }

    #[test]
    fn reports_wrong_types_with_paths() {
        let value = parse(br#"{"a":{"b":"7","c":-1,"d":1.5,"e":[]}}"#).unwrap();
        let mut root = ObjectReader::new(&value).unwrap();
        let mut a = root.take_object("a").unwrap().unwrap();
        let error = a.take_u64("b").unwrap_err();
        assert_eq!(error.path, "a.b");
        assert_eq!(
            error.kind,
            FieldErrorKind::WrongType { expected: "an unsigned integer", found: "a string" }
        );
        assert_eq!(error.to_string(), "`a.b` should be an unsigned integer, not a string");
        let error = a.take_u64("c").unwrap_err();
        assert_eq!(error.kind, FieldErrorKind::Number(NumberError::OutOfRange));
        assert_eq!(error.to_string(), "`a.c`: the number is out of range");
        assert_eq!(
            a.take_i64("d").unwrap_err().kind,
            FieldErrorKind::Number(NumberError::NotAnInteger)
        );
        assert_eq!(a.take_f64("d").unwrap(), Some(1.5));
        assert!(a.take_str("e").is_err());
        assert!(a.take_bool("e").is_err());
        assert!(a.take_object("e").is_err());
        assert!(root.take_array("a").is_err());
    }

    #[test]
    fn root_must_be_an_object() {
        let value = parse(b"[]").unwrap();
        let error = ObjectReader::new(&value).unwrap_err();
        assert_eq!(error.kind, FieldErrorKind::NotAnObject);
        assert_eq!(error.to_string(), "`the document` is not an object");
    }
}

//! The parsed document tree.

use std::borrow::Cow;
use std::fmt;

use crate::number::Number;
use crate::write::Writer;

/// A JSON value. Strings and numbers borrow the input where they can.
///
/// A string without escapes is `Cow::Borrowed` from the input; one with escapes is decoded
/// into `Cow::Owned`. Numbers keep their source text (see [`Number`]).
///
/// Dropping, cloning, comparing and writing a value recurse once per level of nesting. The
/// parser bounds the nesting with [`Limits::max_depth`](crate::Limits::max_depth).
#[derive(Clone, Debug, PartialEq)]
pub enum Value<'a> {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as its source text.
    Number(Number<'a>),
    /// A string, decoded.
    String(Cow<'a, str>),
    /// An array.
    Array(Vec<Value<'a>>),
    /// An object, in input order, with unique keys.
    Object(Object<'a>),
}

impl<'a> Value<'a> {
    /// Returns true for `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns the boolean, or `None` for any other kind of value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the number, or `None` for any other kind of value.
    pub fn as_number(&self) -> Option<Number<'a>> {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
    }

    /// Returns the string, borrowed from this value, or `None` for any other kind of value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the elements of an array, or `None` for any other kind of value.
    pub fn as_array(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the object, or `None` for any other kind of value.
    pub fn as_object(&self) -> Option<&Object<'a>> {
        match self {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Returns the name of this kind of value, for messages: "null", "a boolean",
    /// "a number", "a string", "an array" or "an object".
    pub fn kind_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "a boolean",
            Value::Number(_) => "a number",
            Value::String(_) => "a string",
            Value::Array(_) => "an array",
            Value::Object(_) => "an object",
        }
    }
}

/// Writes the value as compact JSON, exactly as [`Writer::value`] does.
impl fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Writer::new(f).value(self)
    }
}

/// A JSON object: members in input order, each key at most once.
///
/// Lookups scan the members, which is the fastest choice for the small objects of
/// configuration files and protocol messages. Equality ignores member order, as JSON does.
#[derive(Clone, Debug, Default)]
pub struct Object<'a> {
    members: Vec<(Cow<'a, str>, Value<'a>)>,
}

impl<'a> Object<'a> {
    /// Returns an empty object.
    pub fn new() -> Object<'a> {
        Object { members: Vec::new() }
    }

    /// Wraps members the parser has already checked for duplicate keys.
    pub(crate) fn from_unique(members: Vec<(Cow<'a, str>, Value<'a>)>) -> Object<'a> {
        Object { members }
    }

    /// Returns the value of `key`, or `None` if the object has no such key.
    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        self.members.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// Returns true if the object has `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// Returns the index of `key` among the members.
    pub(crate) fn position(&self, key: &str) -> Option<usize> {
        self.members.iter().position(|(name, _)| name == key)
    }

    /// Returns the member at `index`, in input order.
    pub(crate) fn member(&self, index: usize) -> Option<(&str, &Value<'a>)> {
        self.members.get(index).map(|(key, value)| (key.as_ref(), value))
    }

    /// Returns the number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns true if the object has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Returns an iterator over the members in input order.
    pub fn iter(&self) -> ObjectIter<'_, 'a> {
        ObjectIter { inner: self.members.iter() }
    }

    /// Sets `key` to `value`. An existing member keeps its position and its old value is
    /// returned; a new member goes at the end.
    pub fn insert(&mut self, key: impl Into<Cow<'a, str>>, value: Value<'a>) -> Option<Value<'a>> {
        let key = key.into();
        match self.members.iter_mut().find(|(name, _)| *name == key) {
            Some((_, slot)) => Some(std::mem::replace(slot, value)),
            None => {
                self.members.push((key, value));
                None
            }
        }
    }

    /// Removes `key` and returns its value; the other members keep their order.
    pub fn remove(&mut self, key: &str) -> Option<Value<'a>> {
        self.position(key).map(|i| self.members.remove(i).1)
    }
}

/// Objects are equal when they have the same keys with equal values, in any order.
impl PartialEq for Object<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().all(|(key, value)| other.get(key) == Some(value))
    }
}

/// An iterator over the members of an [`Object`], as `(key, value)` pairs in input order.
#[derive(Clone, Debug)]
pub struct ObjectIter<'o, 'a> {
    inner: std::slice::Iter<'o, (Cow<'a, str>, Value<'a>)>,
}

impl<'o, 'a> Iterator for ObjectIter<'o, 'a> {
    type Item = (&'o str, &'o Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, value)| (key.as_ref(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for ObjectIter<'_, '_> {}

impl<'o, 'a> IntoIterator for &'o Object<'a> {
    type Item = (&'o str, &'o Value<'a>);
    type IntoIter = ObjectIter<'o, 'a>;

    fn into_iter(self) -> ObjectIter<'o, 'a> {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_keeps_order_and_unique_keys() {
        let mut object = Object::new();
        assert!(object.insert("b", Value::Bool(true)).is_none());
        assert!(object.insert("a", Value::Null).is_none());
        assert_eq!(object.insert("b", Value::Bool(false)), Some(Value::Bool(true)));
        let keys: Vec<&str> = object.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["b", "a"]);
        assert_eq!(object.get("b"), Some(&Value::Bool(false)));
        assert!(object.contains_key("a") && !object.contains_key("c"));
        assert_eq!(object.remove("b"), Some(Value::Bool(false)));
        assert_eq!(object.len(), 1);
        assert!(object.remove("b").is_none());
    }

    #[test]
    fn object_equality_ignores_order() {
        let mut first = Object::new();
        first.insert("x", Value::Null);
        first.insert("y", Value::Bool(true));
        let mut second = Object::new();
        second.insert("y", Value::Bool(true));
        second.insert("x", Value::Null);
        assert_eq!(first, second);
        second.insert("x", Value::Bool(false));
        assert_ne!(first, second);
    }

    #[test]
    fn accessors() {
        let number = Number::parse("5").unwrap();
        assert_eq!(Value::Number(number).as_number(), Some(number));
        assert_eq!(Value::String("s".into()).as_str(), Some("s"));
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert!(Value::Null.is_null());
        assert!(Value::Null.as_str().is_none());
        assert_eq!(Value::Array(Vec::new()).as_array(), Some(&[][..]));
        assert_eq!(Value::Object(Object::new()).kind_name(), "an object");
        assert!(Value::Array(Vec::new()).as_object().is_none());
    }
}

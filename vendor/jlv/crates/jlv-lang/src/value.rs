//! JLV values (JDD 0004, "Values and type system").
//!
//! Plain values are a disjoint union of null, booleans, checked 64-bit integers, UTF-8
//! texts, byte strings, ordered lists and maps with text keys. Maps keep their entries
//! sorted by the UTF-8 bytes of their keys, so no hash-table order can be observed.
//! Values are immutable; the shared buffers are reference counted and an update builds
//! a new value. Libraries also construct nominal [`Opaque`] values, such as resource
//! handles, which a plain map can never impersonate.
//!
//! Every list, map and opaque value knows how deeply it nests, which its constructor
//! computes from its parts in one step each. The functions that recurse over a value,
//! dropping, comparing, encoding and measuring it, recurse that deep and no deeper, and
//! the evaluator refuses a value deeper than `[limits] value_depth` (JDD 0013).

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

/// A map from text keys to values, sorted by key bytes.
pub type Entries = BTreeMap<Arc<str>, Value>;

/// The items of a list value and the depth they nest to; it reads as a `Vec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    items: Vec<Value>,
    depth: u32,
    plain: bool,
    size_units: u64,
}

impl Default for List {
    fn default() -> List {
        List::new(Vec::new())
    }
}

impl List {
    /// The list of `items`.
    pub fn new(items: Vec<Value>) -> List {
        let depth = 1u32.saturating_add(items.iter().map(Value::depth).max().unwrap_or(0));
        let plain = items.iter().all(Value::is_plain);
        let size_units = items.iter().fold(1u64, |acc, v| acc.saturating_add(v.size_units()));
        List { items, depth, plain, size_units }
    }

    /// The items, taken out of the list.
    pub fn into_items(self) -> Vec<Value> {
        self.items
    }

    /// Appends `value`, keeping the depth, plainness and size up to date, so that a
    /// comprehension builds its list in time proportional to its length.
    pub fn push(&mut self, value: Value) {
        self.depth = self.depth.max(1u32.saturating_add(value.depth()));
        self.plain &= value.is_plain();
        self.size_units = self.size_units.saturating_add(value.size_units());
        self.items.push(value);
    }
}

impl Deref for List {
    type Target = Vec<Value>;

    fn deref(&self) -> &Vec<Value> {
        &self.items
    }
}

impl FromIterator<Value> for List {
    fn from_iter<I: IntoIterator<Item = Value>>(items: I) -> List {
        List::new(items.into_iter().collect())
    }
}

/// The entries of a map value and the depth they nest to; it reads as its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Map {
    entries: Entries,
    depth: u32,
    plain: bool,
    size_units: u64,
}

impl Default for Map {
    fn default() -> Map {
        Map::new(Entries::new())
    }
}

impl Map {
    /// The map of `entries`.
    pub fn new(entries: Entries) -> Map {
        let depth = 1u32.saturating_add(entries.values().map(Value::depth).max().unwrap_or(0));
        let plain = entries.values().all(Value::is_plain);
        let size_units = entries.iter().fold(1u64, |acc, (k, v)| {
            acc.saturating_add(blocks(k.len())).saturating_add(v.size_units())
        });
        Map { entries, depth, plain, size_units }
    }

    /// The entries, taken out of the map.
    pub fn into_entries(self) -> Entries {
        self.entries
    }
}

impl Deref for Map {
    type Target = Entries;

    fn deref(&self) -> &Entries {
        &self.entries
    }
}

impl FromIterator<(Arc<str>, Value)> for Map {
    fn from_iter<I: IntoIterator<Item = (Arc<str>, Value)>>(entries: I) -> Map {
        Map::new(entries.into_iter().collect())
    }
}

/// One JLV value.
#[derive(Debug, Clone, Eq)]
pub enum Value {
    /// The null value; distinct from omission and from absence.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A signed 64-bit integer; arithmetic is checked.
    Int(i64),
    /// Exact UTF-8 text without implicit normalization.
    Text(Arc<str>),
    /// A byte string.
    Bytes(Arc<[u8]>),
    /// An ordered list.
    List(Arc<List>),
    /// A map with unique text keys.
    Map(Arc<Map>),
    /// A nominal library value, such as a resource reference.
    Opaque(Arc<Opaque>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Text(a), Value::Text(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Bytes(a), Value::Bytes(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::List(a), Value::List(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Map(a), Value::Map(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Opaque(a), Value::Opaque(b)) => Arc::ptr_eq(a, b) || a == b,
            _ => false,
        }
    }
}

/// A nominal value constructed by a library: its type, schema version and a plain
/// payload. Persisted opaque values hold no pointer, live connection or hidden state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opaque {
    /// The nominal type, such as `ResourceRef`.
    pub type_id: Arc<str>,
    /// The schema version of the payload.
    pub version: u32,
    /// The canonical payload.
    pub payload: Value,
}

impl Value {
    /// A text value.
    pub fn text(text: &str) -> Value {
        Value::Text(Arc::from(text))
    }

    /// A list value.
    pub fn list(items: Vec<Value>) -> Value {
        Value::List(Arc::new(List::new(items)))
    }

    /// A map value of `entries`.
    pub fn of_entries(entries: Entries) -> Value {
        Value::Map(Arc::new(Map::new(entries)))
    }

    /// A map value from `(key, value)` pairs; a later duplicate key replaces an earlier.
    pub fn map<'a>(pairs: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
        Value::of_entries(pairs.into_iter().map(|(k, v)| (Arc::from(k), v)).collect())
    }

    /// An opaque value of `type_id` with `payload`.
    pub fn opaque(type_id: &str, version: u32, payload: Value) -> Value {
        Value::Opaque(Arc::new(Opaque { type_id: Arc::from(type_id), version, payload }))
    }

    /// How deeply the value nests: 0 for a scalar, and one more than its deepest part
    /// for a list, a map or an opaque value.
    pub fn depth(&self) -> u32 {
        match self {
            Value::List(list) => list.depth,
            Value::Map(map) => map.depth,
            Value::Opaque(o) => 1u32.saturating_add(o.payload.depth()),
            _ => 0,
        }
    }

    /// The lower-case name of the value's kind, for messages.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "a boolean",
            Value::Int(_) => "an integer",
            Value::Text(_) => "a text",
            Value::Bytes(_) => "bytes",
            Value::List(_) => "a list",
            Value::Map(_) => "a map",
            Value::Opaque(_) => "an opaque value",
        }
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// The text, if this is one.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The items, if this is a list.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// The entries, if this is a map.
    pub fn as_map(&self) -> Option<&Entries> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The opaque value, if this is one of type `type_id`.
    pub fn as_opaque(&self, type_id: &str) -> Option<&Opaque> {
        match self {
            Value::Opaque(o) if &*o.type_id == type_id => Some(o),
            _ => None,
        }
    }

    /// The map entry `key`, if this is a map that has it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map().and_then(|m| m.get(key))
    }

    /// Whether the value is plain data: it holds no opaque value at any depth.
    pub fn is_plain(&self) -> bool {
        match self {
            Value::List(list) => list.plain,
            Value::Map(map) => map.plain,
            Value::Opaque(_) => false,
            _ => true,
        }
    }

    /// The value's size in the budget's units: started 64-byte blocks for texts and bytes,
    /// one unit per element of a container plus the elements' own sizes (JDD 0004).
    pub fn size_units(&self) -> u64 {
        match self {
            Value::Text(t) => blocks(t.len()),
            Value::Bytes(b) => blocks(b.len()),
            Value::List(list) => list.size_units,
            Value::Map(map) => map.size_units,
            Value::Opaque(o) => 1u64.saturating_add(o.payload.size_units()),
            _ => 1,
        }
    }
}

/// The number of started 64-byte blocks of `len` bytes, at least one.
fn blocks(len: usize) -> u64 {
    (len as u64).div_ceil(64).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_sort_their_keys_by_bytes() {
        let map = Value::map([("b", Value::Int(2)), ("a", Value::Bool(true)), ("B", Value::Null)]);
        let keys: Vec<&str> = map.as_map().unwrap().keys().map(|k| &**k).collect();
        assert_eq!(keys, ["B", "a", "b"]);
    }

    #[test]
    fn equality_is_tag_sensitive() {
        assert_ne!(Value::Bool(true), Value::Int(1));
        assert_eq!(Value::list(vec![Value::Int(1)]), Value::list(vec![Value::Int(1)]));
    }

    #[test]
    fn opaque_values_are_not_plain() {
        let handle = Value::opaque("ResourceRef", 1, Value::text("incus.instance.web"));
        assert!(!Value::list(vec![handle]).is_plain());
        assert!(Value::map([("a", Value::list(vec![]))]).is_plain());
    }

    #[test]
    fn sizes_count_started_blocks() {
        assert_eq!(Value::text("").size_units(), 1);
        assert_eq!(Value::text(&"x".repeat(65)).size_units(), 2);
        assert_eq!(Value::list(vec![Value::Int(1), Value::Int(2)]).size_units(), 3);
    }
}

//! Top-level set and remove deltas between two JSON objects. Arrays are replaced as a
//! field, never merged by position.
//!
//! A delta is `{"set":{...},"remove":[...]}`: the members of the current object that are
//! new or changed, then the keys of the previous object that are gone. The hub writes one
//! per topic and second; the subscription client applies it to its last good view.
//!
//! Values are compared and rewritten as Zig's dynamic `std.json.Value` did, so views stay
//! byte-identical to the Zig console's: a number written like an integer that fits `i64`
//! is an integer, one that does not is kept as its text, and any other finite number is an
//! `f64` (so `1.50` equals `1.5` and is rewritten as `1.5`). Applying a delta removes keys
//! as Zig's `swapRemove` did (the last member moves into the gap) and appends new keys.

use std::collections::BTreeMap;
use std::fmt::{self, Write};

use sibuna_json::{Error as JsonError, Number, Object, Value, Writer};

/// Why a delta could not be written or applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaError {
    /// An input is not valid JSON.
    Json(JsonError),
    /// An input is not a JSON object.
    NotAnObject,
    /// The delta is not `{"set":{...},"remove":[...]}` with string keys that `set` does
    /// not also name.
    InvalidDelta,
    /// The output sink failed.
    Write,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeltaError::Json(error) => write!(f, "invalid JSON: {error}"),
            DeltaError::NotAnObject => f.write_str("a delta needs two JSON objects"),
            DeltaError::InvalidDelta => f.write_str("the delta is malformed"),
            DeltaError::Write => f.write_str("the output is full"),
        }
    }
}

impl std::error::Error for DeltaError {}

impl From<fmt::Error> for DeltaError {
    fn from(_: fmt::Error) -> DeltaError {
        DeltaError::Write
    }
}

/// How Zig's dynamic parser classified a number.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ZigNumber<'a> {
    /// Written like an integer and within `i64`.
    Integer(i64),
    /// Written like a number Zig kept as text: an integer outside `i64` or a float out of
    /// range.
    Text(&'a str),
    /// Any other number.
    Float(f64),
}

fn classify(number: Number<'_>) -> ZigNumber<'_> {
    let text = number.as_str();
    if text == "-0" || text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return match text.parse::<f64>() {
            Ok(value) if value.is_finite() => ZigNumber::Float(value),
            _ => ZigNumber::Text(text),
        };
    }
    match text.parse::<i64>() {
        Ok(value) => ZigNumber::Integer(value),
        Err(_) => ZigNumber::Text(text),
    }
}

/// Writes `value` as Zig's `std.json.Value` serialized it: floats in their shortest form,
/// everything else as parsed. Recursion is bounded by the parser's depth limit.
///
/// # Errors
///
/// Returns the sink's error.
pub(crate) fn write_value<W: Write>(json: &mut Writer<W>, value: &Value<'_>) -> fmt::Result {
    match value {
        Value::Number(number) => match classify(*number) {
            ZigNumber::Float(float) => json.float(float),
            ZigNumber::Integer(_) | ZigNumber::Text(_) => json.number(*number),
        },
        Value::Array(items) => {
            json.begin_array()?;
            for item in items {
                write_value(json, item)?;
            }
            json.end_array()
        }
        Value::Object(object) => {
            json.begin_object()?;
            for (key, item) in object {
                json.key(key)?;
                write_value(json, item)?;
            }
            json.end_object()
        }
        other => json.value(other),
    }
}

/// Returns the value of `key`, trying member `hint` first: objects being compared usually
/// list their keys in the same order.
fn lookup<'o, 'a>(object: &'o Object<'a>, key: &str, hint: usize) -> Option<&'o Value<'a>> {
    match object.iter().nth(hint) {
        Some((name, value)) if name == key => Some(value),
        _ => object.get(key),
    }
}

/// Returns true when two values are equal as Zig's dynamic values were.
fn equal(a: &Value<'_>, b: &Value<'_>) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => classify(*x) == classify(*y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| equal(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter().enumerate().all(|(index, (key, value))| {
                    lookup(y, key, index).is_some_and(|other| equal(value, other))
                })
        }
        _ => false,
    }
}

/// Writes the delta from `previous` to `current` into `out` and returns whether anything
/// changed.
///
/// # Errors
///
/// [`DeltaError::Json`] or [`DeltaError::NotAnObject`] for bad inputs, and
/// [`DeltaError::Write`] when `out` fails; `out` may then hold a partial delta.
pub fn write<W: Write>(previous: &[u8], current: &[u8], out: &mut W) -> Result<bool, DeltaError> {
    let old = sibuna_json::parse(previous).map_err(DeltaError::Json)?;
    let new = sibuna_json::parse(current).map_err(DeltaError::Json)?;
    let (Value::Object(old), Value::Object(new)) = (&old, &new) else {
        return Err(DeltaError::NotAnObject);
    };
    write_objects(old, new, out)
}

/// Writes the delta between two parsed objects; see [`write()`].
///
/// # Errors
///
/// [`DeltaError::Write`] when `out` fails.
pub fn write_objects<W: Write>(
    previous: &Object<'_>,
    current: &Object<'_>,
    out: &mut W,
) -> Result<bool, DeltaError> {
    let mut json = Writer::new(out);
    let mut changed = false;
    json.begin_object()?;
    json.key("set")?;
    json.begin_object()?;
    for (index, (key, value)) in current.iter().enumerate() {
        if lookup(previous, key, index).is_some_and(|before| equal(before, value)) {
            continue;
        }
        json.key(key)?;
        write_value(&mut json, value)?;
        changed = true;
    }
    json.end_object()?;
    json.key("remove")?;
    json.begin_array()?;
    for (index, (key, _)) in previous.iter().enumerate() {
        if lookup(current, key, index).is_some() {
            continue;
        }
        json.string(key)?;
        changed = true;
    }
    json.end_array()?;
    json.end_object()?;
    Ok(changed)
}

/// The members of a patched object, in Zig's order, borrowing the state and the delta.
pub(crate) struct Patched<'v, 'a> {
    members: Vec<(&'v str, &'v Value<'a>)>,
}

impl<'v, 'a> Patched<'v, 'a> {
    /// Writes the patched object as Zig serialized it.
    pub(crate) fn write<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        for (key, value) in &self.members {
            json.key(key)?;
            write_value(json, value)?;
        }
        json.end_object()
    }
}

/// Splits a delta into its `set` object and `remove` keys after checking its shape: an
/// object of exactly `set` and `remove`, string keys, and no key both set and removed.
fn split_delta<'v, 'a>(
    delta: &'v Value<'a>,
) -> Result<(&'v Object<'a>, Vec<&'v str>), DeltaError> {
    let object =
        delta.as_object().filter(|object| object.len() == 2).ok_or(DeltaError::InvalidDelta)?;
    let set = object.get("set").and_then(Value::as_object).ok_or(DeltaError::InvalidDelta)?;
    let remove = object.get("remove").and_then(Value::as_array).ok_or(DeltaError::InvalidDelta)?;
    let keys = remove
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<&str>>>()
        .ok_or(DeltaError::InvalidDelta)?;
    if keys.iter().any(|key| set.contains_key(key)) {
        return Err(DeltaError::InvalidDelta);
    }
    Ok((set, keys))
}

/// Applies a delta to a parsed state object. Callers apply a delta only after checking
/// its topic, epoch and contiguous sequence.
///
/// # Errors
///
/// [`DeltaError::NotAnObject`] if `state` is not an object, and
/// [`DeltaError::InvalidDelta`] for a malformed delta; nothing is applied then.
pub(crate) fn patch<'v, 'a>(
    state: &'v Value<'a>,
    delta: &'v Value<'a>,
) -> Result<Patched<'v, 'a>, DeltaError> {
    let state = state.as_object().ok_or(DeltaError::NotAnObject)?;
    let (set, remove) = split_delta(delta)?;
    let mut members: Vec<(&str, &Value<'a>)> = state.iter().collect();
    let mut index: BTreeMap<&str, usize> =
        members.iter().enumerate().map(|(i, (key, _))| (*key, i)).collect();
    for key in remove {
        let Some(position) = index.remove(key) else { continue };
        members.swap_remove(position);
        if let Some((moved, _)) = members.get(position) {
            index.insert(moved, position);
        }
    }
    for (key, value) in set {
        match index.get(key) {
            Some(&position) => {
                if let Some(member) = members.get_mut(position) {
                    member.1 = value;
                }
            }
            None => {
                index.insert(key, members.len());
                members.push((key, value));
            }
        }
    }
    Ok(Patched { members })
}

/// Applies a delta to `state` and writes the patched object into `out`, as the Zig client
/// serialized its view.
///
/// # Errors
///
/// As the internal patch: [`DeltaError::NotAnObject`] or [`DeltaError::InvalidDelta`],
/// and [`DeltaError::Write`] when `out` fails.
pub fn apply<W: Write>(
    state: &Value<'_>,
    delta: &Value<'_>,
    out: &mut W,
) -> Result<(), DeltaError> {
    let patched = patch(state, delta)?;
    patched.write(&mut Writer::new(out))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(previous: &str, current: &str) -> (bool, String) {
        let mut out = String::new();
        let changed = write(previous.as_bytes(), current.as_bytes(), &mut out).unwrap();
        (changed, out)
    }

    fn applied(state: &str, delta: &str) -> Result<String, DeltaError> {
        let state = sibuna_json::parse(state.as_bytes()).unwrap();
        let delta = sibuna_json::parse(delta.as_bytes()).unwrap();
        let mut out = String::new();
        apply(&state, &delta, &mut out)?;
        Ok(out)
    }

    // Port of json_delta.zig "deltas preserve unchanged fields, large counters and
    // explicit nulls".
    #[test]
    fn deltas_preserve_unchanged_fields_large_counters_and_explicit_nulls() {
        let previous = "{\"count\":\"9007199254740993\",\"rows\":[1],\"old\":true}";
        let current = "{\"count\":\"9007199254740994\",\"rows\":[1],\"empty\":null}";
        let (changed, text) = delta(previous, current);
        assert!(changed);
        assert_eq!(
            text,
            "{\"set\":{\"count\":\"9007199254740994\",\"empty\":null},\"remove\":[\"old\"]}"
        );
        let state = applied(previous, &text).unwrap();
        assert_eq!(state, "{\"count\":\"9007199254740994\",\"rows\":[1],\"empty\":null}");
        let expected = sibuna_json::parse(current.as_bytes()).unwrap();
        assert!(equal(&sibuna_json::parse(state.as_bytes()).unwrap(), &expected));
        assert!(!delta(current, current).0);
    }

    #[test]
    fn numbers_compare_and_print_as_zig_values() {
        assert!(!delta("{\"a\":1.50}", "{\"a\":1.5}").0);
        assert!(delta("{\"a\":1}", "{\"a\":1.0}").0);
        assert!(delta("{\"a\":1e400}", "{\"a\":1E400}").0);
        assert!(!delta("{\"a\":-0}", "{\"a\":-0.0}").0);
        assert_eq!(
            delta("{}", "{\"a\":1.50,\"b\":1e2,\"c\":9223372036854775808}").1,
            "{\"set\":{\"a\":1.5,\"b\":100,\"c\":9223372036854775808},\"remove\":[]}"
        );
    }

    #[test]
    fn removals_swap_the_last_member_into_the_gap() {
        let state = "{\"a\":1,\"b\":2,\"c\":3,\"d\":4}";
        let out = applied(state, "{\"set\":{\"e\":5,\"c\":30},\"remove\":[\"a\"]}").unwrap();
        assert_eq!(out, "{\"d\":4,\"b\":2,\"c\":30,\"e\":5}");
        assert_eq!(applied(state, "{\"set\":{},\"remove\":[\"z\"]}").unwrap(), state);
    }

    #[test]
    fn malformed_deltas_change_nothing() {
        let state = "{\"a\":1}";
        for bad in [
            "{\"set\":{}}",
            "{\"set\":{},\"remove\":[],\"x\":1}",
            "{\"set\":[],\"remove\":[]}",
            "{\"set\":{},\"remove\":[1]}",
            "{\"set\":{\"a\":2},\"remove\":[\"a\"]}",
            "[]",
        ] {
            assert_eq!(applied(state, bad), Err(DeltaError::InvalidDelta), "{bad}");
        }
        assert_eq!(applied("[]", "{\"set\":{},\"remove\":[]}"), Err(DeltaError::NotAnObject));
        let mut out = String::new();
        assert_eq!(write(b"[]", b"{}", &mut out), Err(DeltaError::NotAnObject));
    }
}

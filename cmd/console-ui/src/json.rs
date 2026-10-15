//! Reading the JSON events the browser bridge sends.
//!
//! Every event is one JSON object that `glue.js` built with `JSON.stringify`. These helpers
//! read members the way the Zig module read its dynamic `std.json.Value`: a missing member
//! or a member of the wrong type reads as absent, and only integer literals (no fraction,
//! no exponent) that fit `i64` count as integers.

use sibuna_json::{Limits, Value};

/// The deepest nesting accepted in an event. Server replies nest a few levels; the bound
/// keeps dropping and walking a hostile reply cheap.
pub const MAX_DEPTH: usize = 64;

/// Returns the parser limits for an event of at most `input_limit` bytes: every value,
/// string and nesting level costs at least one input byte, so the input bound bounds the
/// tree as well.
pub fn limits(input_limit: usize) -> Limits {
    Limits {
        max_input_bytes: input_limit,
        max_depth: MAX_DEPTH,
        max_values: input_limit,
        max_string_bytes: input_limit,
    }
}

/// Returns member `key` of `value`, or `None` when `value` is not an object or has no
/// such member.
pub fn field<'v, 'a>(value: &'v Value<'a>, key: &str) -> Option<&'v Value<'a>> {
    value.as_object()?.get(key)
}

/// Returns member `key` as text; absent or non-string members read as the empty string.
pub fn string<'v>(value: &'v Value<'_>, key: &str) -> &'v str {
    field(value, key).and_then(Value::as_str).unwrap_or("")
}

/// Returns `value` as an integer if it is an integer literal that fits `i64`.
pub fn integer(value: &Value<'_>) -> Option<i64> {
    let number = value.as_number()?;
    if !number.is_integer_literal() {
        return None;
    }
    number.as_i64().ok()
}

/// Returns member `key` as a non-negative integer, or zero when it is absent, not an
/// integer, negative or beyond `i64` (Zig's `unsignedOrZero`).
pub fn unsigned_or_zero(value: &Value<'_>, key: &str) -> u64 {
    field(value, key).and_then(integer).and_then(|number| u64::try_from(number).ok()).unwrap_or(0)
}

/// Reads a counter the way Zig's typed decoding of `u64` did: a non-negative integer
/// literal, or a string of 1 to 20 decimal digits (counters above 2^53 travel as strings).
pub fn counter(value: &Value<'_>) -> Option<u64> {
    if let Some(number) = value.as_number() {
        if !number.is_integer_literal() {
            return None;
        }
        return number.as_u64().ok();
    }
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parses `text` as Zig's `std.fmt.parseInt(T, text, 10)` does: an optional sign, then
/// decimal digits with underscores between them (not at either end). Returns `None` for
/// anything else and for values outside `T`. Action names, form fields and request ids
/// carry such numbers.
pub fn parse_integer<T: TryFrom<i128>>(text: &str) -> Option<T> {
    T::try_from(parse_wide(text)?).ok()
}

/// The type-independent part of [`parse_integer`], so the module keeps one copy of it.
fn parse_wide(text: &str) -> Option<i128> {
    let (negative, digits) = match text.as_bytes().split_first()? {
        (b'+', rest) => (false, rest),
        (b'-', rest) => (true, rest),
        _ => (false, text.as_bytes()),
    };
    if digits.first().is_none_or(|&byte| byte == b'_') || digits.last() == Some(&b'_') {
        return None;
    }
    let mut value: i128 = 0;
    for &byte in digits {
        if byte == b'_' {
            continue;
        }
        let digit = i128::from(byte.checked_sub(b'0').filter(|digit| *digit < 10)?);
        value = value.checked_mul(10)?;
        value = if negative { value.checked_sub(digit)? } else { value.checked_add(digit)? };
    }
    Some(value)
}

/// Returns member `key` as a boolean, or `None` when it is absent or not a boolean.
pub fn boolean(value: &Value<'_>, key: &str) -> Option<bool> {
    field(value, key).and_then(Value::as_bool)
}

/// Returns true when member `key` is the boolean `true`.
pub fn is_true(value: &Value<'_>, key: &str) -> bool {
    boolean(value, key) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_of_the_wrong_type_read_as_absent() {
        let value = sibuna_json::parse(
            br#"{"a":"text","n":7,"f":7.0,"e":1e3,"neg":-1,"big":9223372036854775808,"t":true}"#,
        )
        .unwrap();
        assert_eq!(string(&value, "a"), "text");
        assert_eq!(string(&value, "n"), "");
        assert_eq!(unsigned_or_zero(&value, "n"), 7);
        assert_eq!(unsigned_or_zero(&value, "f"), 0);
        assert_eq!(unsigned_or_zero(&value, "e"), 0);
        assert_eq!(unsigned_or_zero(&value, "neg"), 0);
        assert_eq!(unsigned_or_zero(&value, "big"), 0);
        assert_eq!(unsigned_or_zero(&value, "missing"), 0);
        assert!(is_true(&value, "t"));
        assert_eq!(boolean(&value, "a"), None);
        assert_eq!(field(&Value::Null, "a"), None);
        let counters =
            sibuna_json::parse(br#"["18446744073709551615",4,"+1","1e3",1.5,-2]"#).unwrap();
        let read: Vec<Option<u64>> = counters.as_array().unwrap().iter().map(counter).collect();
        assert_eq!(read, [Some(u64::MAX), Some(4), None, None, None, None]);
    }

    #[test]
    fn integers_follow_zig_parse_int() {
        assert_eq!(parse_integer::<u64>("9007199254740993"), Some(9_007_199_254_740_993));
        assert_eq!(parse_integer::<u64>("+7"), Some(7));
        assert_eq!(parse_integer::<u64>("1_000"), Some(1000));
        assert_eq!(parse_integer::<u64>("1__0"), Some(10));
        assert_eq!(parse_integer::<u64>("-0"), Some(0));
        assert_eq!(parse_integer::<u64>("-1"), None);
        assert_eq!(parse_integer::<i32>("-17"), Some(-17));
        assert_eq!(parse_integer::<u64>("_1"), None);
        assert_eq!(parse_integer::<u64>("1_"), None);
        assert_eq!(parse_integer::<u64>(""), None);
        assert_eq!(parse_integer::<u64>("+"), None);
        assert_eq!(parse_integer::<u64>("-"), None);
        assert_eq!(parse_integer::<u64>("1a"), None);
        assert_eq!(parse_integer::<u64>("\u{b2}"), None);
        assert_eq!(parse_integer::<u64>("18446744073709551616"), None);
        assert_eq!(parse_integer::<u8>("256"), None);
        assert_eq!(parse_integer::<u32>(" 1"), None);
    }

    #[test]
    fn limits_follow_the_input_bound() {
        let limits = limits(16);
        assert!(sibuna_json::parse_with_limits(b"[1,2,3]", &limits).is_ok());
        assert!(sibuna_json::parse_with_limits(&[b' '; 17], &limits).is_err());
    }
}

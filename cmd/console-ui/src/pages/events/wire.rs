//! Reading server replies the way the Zig module's `json_value.zig` read its wire structs,
//! for the investigation pages (events, similarity, challenges).
//!
//! Members are read by name and unknown members are ignored. An absent member takes its
//! default, or fails when it has none. Integers are integer literals in the field's range;
//! 64-bit counters may also travel as decimal strings ([`json::counter`]). Identifiers
//! inside action names and form fields are parsed with Zig's `std.fmt.parseInt` rules
//! ([`parse_integer`]), so the same texts are accepted.

use sibuna_json::Value;

use crate::error::UiError;
use crate::json;

/// Returns `value` if it is an object, which every wire struct is.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] for any other value.
pub(crate) fn object<'v, 'a>(value: &'v Value<'a>) -> Result<&'v Value<'a>, UiError> {
    value.as_object().map(|_| value).ok_or(UiError::InvalidResponse)
}

/// Reads the required member `key` of the object `value` with `read`.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] if the member is absent or `read` refuses it.
pub(crate) fn required<'v, 'a, T>(
    value: &'v Value<'a>,
    key: &str,
    read: impl FnOnce(&'v Value<'a>) -> Option<T>,
) -> Result<T, UiError> {
    json::field(value, key).and_then(read).ok_or(UiError::InvalidResponse)
}

/// Reads member `key` of the object `value` with `read`, or returns `default` when it is
/// absent.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] if `read` refuses a present member.
pub(crate) fn or<'v, 'a, T>(
    value: &'v Value<'a>,
    key: &str,
    default: T,
    read: impl FnOnce(&'v Value<'a>) -> Option<T>,
) -> Result<T, UiError> {
    match json::field(value, key) {
        None => Ok(default),
        Some(item) => read(item).ok_or(UiError::InvalidResponse),
    }
}

/// Reads a 64-bit counter: an integer literal or a string of decimal digits.
pub(crate) fn counter(value: &Value<'_>) -> Option<u64> {
    json::counter(value)
}

/// Reads an integer literal that fits `T`.
pub(crate) fn number<T: TryFrom<i64>>(value: &Value<'_>) -> Option<T> {
    json::integer(value).and_then(|number| T::try_from(number).ok())
}

/// Reads a boolean.
pub(crate) fn boolean(value: &Value<'_>) -> Option<bool> {
    value.as_bool()
}

/// Reads a string.
pub(crate) fn text<'v>(value: &'v Value<'_>) -> Option<&'v str> {
    value.as_str()
}

/// Reads `null` as `None` and anything else with `read`.
pub(crate) fn nullable<'v, 'a: 'v, T>(
    read: impl FnOnce(&'v Value<'a>) -> Option<T>,
) -> impl FnOnce(&'v Value<'a>) -> Option<Option<T>> {
    move |value| if value.is_null() { Some(None) } else { read(value).map(Some) }
}

/// Reads an array of at most `max` elements.
pub(crate) fn list<'v, 'a>(value: &'v Value<'a>, max: usize) -> Option<&'v [Value<'a>]> {
    value.as_array().filter(|items| items.len() <= max)
}

/// Parses `text` as Zig's `std.fmt.parseInt(T, text, 10)` does: an optional sign, then
/// decimal digits with underscores between them (not at either end). Returns `None` for
/// anything else and for values outside `T`.
pub(crate) fn parse_integer<T: TryFrom<i128>>(text: &str) -> Option<T> {
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
    T::try_from(value).ok()
}

/// Parses an identifier, as [`parse_integer`] does for `u64`.
///
/// # Errors
///
/// [`UiError::InvalidRequest`] when `text` is not one; action names carry identifiers, so
/// a bad one is a malformed request.
pub(crate) fn identifier(text: &str) -> Result<u64, UiError> {
    parse_integer(text).ok_or(UiError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_follow_zig_parse_int() {
        assert_eq!(parse_integer::<u64>("9007199254740993"), Some(9_007_199_254_740_993));
        assert_eq!(parse_integer::<u64>("+7"), Some(7));
        assert_eq!(parse_integer::<u64>("1_000"), Some(1000));
        assert_eq!(parse_integer::<u64>("1__0"), Some(10));
        assert_eq!(parse_integer::<u64>("-0"), Some(0));
        assert_eq!(parse_integer::<u64>("-1"), None);
        assert_eq!(parse_integer::<u64>("_1"), None);
        assert_eq!(parse_integer::<u64>("1_"), None);
        assert_eq!(parse_integer::<u64>(""), None);
        assert_eq!(parse_integer::<u64>("+"), None);
        assert_eq!(parse_integer::<u64>("1a"), None);
        assert_eq!(parse_integer::<u64>("18446744073709551616"), None);
        assert_eq!(parse_integer::<u8>("256"), None);
        assert_eq!(parse_integer::<u32>(" 1"), None);
    }

    #[test]
    fn members_take_defaults_and_ignore_unknown_keys() {
        let value = sibuna_json::parse(br#"{"a":1,"b":"2","c":null,"x":true}"#).unwrap();
        assert_eq!(required(&value, "a", number::<u32>), Ok(1));
        assert_eq!(required(&value, "b", counter), Ok(2));
        assert_eq!(required(&value, "b", number::<u32>), Err(UiError::InvalidResponse));
        assert_eq!(or(&value, "z", 5, number::<u32>), Ok(5));
        assert_eq!(or(&value, "c", Some(1), nullable(number::<u32>)), Ok(None));
        assert_eq!(required(&value, "z", boolean), Err(UiError::InvalidResponse));
        assert!(object(&Value::Null).is_err());
    }
}

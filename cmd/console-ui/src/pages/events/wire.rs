//! Reading server replies the way the Zig module's `json_value.zig` read its wire structs,
//! for the investigation pages (events, similarity, challenges).
//!
//! Members are read by name and unknown members are ignored. An absent member takes its
//! default, or fails when it has none. Integers are integer literals in the field's range;
//! 64-bit counters may also travel as decimal strings ([`json::counter`]). Identifiers
//! inside action names and form fields are parsed with Zig's `std.fmt.parseInt` rules
//! ([`json::parse_integer`]), so the same texts are accepted.

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

/// Parses an identifier, as [`json::parse_integer`] does for `u64`.
///
/// # Errors
///
/// [`UiError::InvalidRequest`] when `text` is not one; action names carry identifiers, so
/// a bad one is a malformed request.
pub(crate) fn identifier(text: &str) -> Result<u64, UiError> {
    json::parse_integer(text).ok_or(UiError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

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

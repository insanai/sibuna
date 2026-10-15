//! JSON encoding and decoding of the wire contracts.
//!
//! Zig serialized these records with `std.json.Stringify` (often through hand-written
//! `jsonStringify` methods) and parsed them with `std.json.parseFromSlice`. The bytes are a
//! contract: browsers and stored rows depend on them. Every [`Encode`] implementation in this
//! crate writes exactly the bytes Zig wrote for the same value, and every [`Decode`]
//! implementation reads them back with the rules of Zig's typed parse:
//!
//! - unknown keys are rejected, duplicate keys are rejected (by the parser);
//! - a field Zig declared with a default may be absent; any other field is required, and a
//!   required optional field may be `null`;
//! - an integer may be a JSON number or a string holding one (Zig's `sliceToInt`), so the
//!   decimal strings that [`counter`] writes above 2^53 read back exactly;
//! - an enumeration may be its name or its ordinal (Zig's `sliceToEnum`);
//! - a byte array may be a string of exactly its length or an array of byte values;
//! - bounded text and lists longer than their capacity are rejected, never truncated.
//!
//! Whether a number is whole is decided exactly, where Zig rounded through `f128`, and a
//! numeric string that Zig's `parseFloat` would read as a hexadecimal float is rejected.

use std::fmt::{self, Write};

use sibuna_json::{Limits, Number, Object, ObjectIter, Value, Writer};

use crate::text::Text;

/// Integers at or above this value are written as decimal strings by [`counter`], because
/// JavaScript's `JSON.parse` rounds larger numbers.
pub const EXACT_INTEGER_LIMIT: u64 = 1 << 53;

/// Writes a value as one JSON value, byte for byte as the Zig console did.
pub trait Encode {
    /// Writes `self` into `json`.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result;
}

/// Reads a value from a parsed JSON document with the rules of Zig's typed parse.
pub trait Decode: Sized {
    /// Reads a value from `value`, found at `path` in the document (used in errors).
    ///
    /// # Errors
    ///
    /// A [`DecodeError`] naming the offending field.
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Self, DecodeError>;
}

/// An enumeration that crosses the wire by name, as Zig's `@tagName`.
pub trait WireEnum: Copy + PartialEq + 'static {
    /// Every value, in declaration order; the index of a value is its ordinal.
    const ALL: &'static [Self];

    /// Returns the wire name.
    fn name(self) -> &'static str;

    /// Returns the value named `name`, if any.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.name() == name)
    }

    /// Returns the value whose ordinal is `ordinal`, if any.
    fn from_ordinal(ordinal: u64) -> Option<Self> {
        usize::try_from(ordinal).ok().and_then(|index| Self::ALL.get(index)).copied()
    }

    /// Returns the ordinal: the position in [`WireEnum::ALL`].
    fn ordinal(self) -> usize {
        Self::ALL.iter().position(|value| *value == self).unwrap_or_default()
    }
}

/// The location of a value in a document, built on the stack while decoding and rendered
/// only when an error needs it.
#[derive(Clone, Copy, Debug)]
pub enum Path<'p> {
    /// The document root.
    Root,
    /// A member of the object at the inner path.
    Key(&'p Path<'p>, &'p str),
    /// An element of the array at the inner path.
    Index(&'p Path<'p>, usize),
}

impl<'p> Path<'p> {
    /// Returns the path of member `key` of this object.
    pub fn key<'q>(&'q self, key: &'q str) -> Path<'q> {
        Path::Key(self, key)
    }

    /// Returns the path of element `index` of this array.
    pub fn index<'q>(&'q self, index: usize) -> Path<'q> {
        Path::Index(self, index)
    }

    /// Renders the path as `rows[2].id`; the root is the empty string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) {
        match self {
            Path::Root => {}
            Path::Key(parent, key) => {
                parent.render_into(out);
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(key);
            }
            Path::Index(parent, index) => {
                parent.render_into(out);
                // Writing into a String cannot fail.
                let _ = write!(out, "[{index}]");
            }
        }
    }
}

/// Why a document could not be decoded.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodeErrorKind {
    /// The bytes are not one valid JSON document.
    Syntax(sibuna_json::Error),
    /// A required member is absent.
    Missing,
    /// The object has a member no field takes.
    UnknownKey,
    /// The value has the wrong JSON type.
    WrongType {
        /// What the field needs, such as "a string".
        expected: &'static str,
        /// What the document holds, such as "a number".
        found: &'static str,
    },
    /// A number (or numeric string) is not an integer, or outside the field's range.
    InvalidNumber,
    /// A name that is not one of the enumeration's values.
    UnknownName,
    /// Text longer than the field's capacity in bytes.
    TooLong {
        /// The capacity.
        max: usize,
    },
    /// An array with more elements than the field holds.
    TooMany {
        /// The largest element count.
        max: usize,
    },
    /// An array or byte string whose length must be exact.
    WrongLength {
        /// The required length.
        expected: usize,
    },
    /// A value the contract forbids, with the rule it breaks.
    Invalid(&'static str),
}

/// A document that could not be decoded, and where.
///
/// The details are boxed so that every decoder's `Result` stays two words wide: decoding
/// returns through many small calls, and only the failing path pays for the error.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodeError(Box<Detail>);

#[derive(Clone, Debug, PartialEq)]
struct Detail {
    path: String,
    kind: DecodeErrorKind,
}

impl DecodeError {
    /// Returns an error of `kind` at `path`.
    #[cold]
    pub fn new(path: Path<'_>, kind: DecodeErrorKind) -> DecodeError {
        DecodeError(Box::new(Detail { path: path.render(), kind }))
    }

    /// Returns the field's path from the document root, such as `rows[2].id`; empty for
    /// the root and for syntax errors, which carry their own location.
    pub fn path(&self) -> &str {
        &self.0.path
    }

    /// Returns what is wrong.
    pub fn kind(&self) -> &DecodeErrorKind {
        &self.0.kind
    }

    fn wrong_type(path: Path<'_>, expected: &'static str, value: &Value<'_>) -> DecodeError {
        DecodeError::new(path, DecodeErrorKind::WrongType { expected, found: value.kind_name() })
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.0.path.is_empty() { "the document" } else { self.0.path.as_str() };
        match &self.0.kind {
            DecodeErrorKind::Syntax(error) => write!(f, "invalid JSON: {error}"),
            DecodeErrorKind::Missing => write!(f, "`{path}` is missing"),
            DecodeErrorKind::UnknownKey => write!(f, "`{path}` is not a known key"),
            DecodeErrorKind::WrongType { expected, found } => {
                write!(f, "`{path}` should be {expected}, not {found}")
            }
            DecodeErrorKind::InvalidNumber => write!(f, "`{path}` is not an integer in range"),
            DecodeErrorKind::UnknownName => write!(f, "`{path}` is not a known name"),
            DecodeErrorKind::TooLong { max } => write!(f, "`{path}` is longer than {max} bytes"),
            DecodeErrorKind::TooMany { max } => {
                write!(f, "`{path}` has more than {max} elements")
            }
            DecodeErrorKind::WrongLength { expected } => {
                write!(f, "`{path}` must have exactly {expected} elements")
            }
            DecodeErrorKind::Invalid(rule) => write!(f, "`{path}` is invalid: {rule}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Returns the compact JSON text of `value`.
pub fn to_json<T: Encode + ?Sized>(value: &T) -> String {
    let mut out = String::new();
    // Writing into a String cannot fail.
    let _ = value.encode(&mut Writer::new(&mut out));
    out
}

/// Writes the compact JSON text of `value` into `sink`.
///
/// # Errors
///
/// Returns the sink's error, for example when a fixed buffer is full.
pub fn write_json<T: Encode + ?Sized, W: Write>(value: &T, sink: W) -> fmt::Result {
    value.encode(&mut Writer::new(sink))
}

/// Parses `input` and decodes a `T` from it, with the parser's default limits.
///
/// # Errors
///
/// [`DecodeErrorKind::Syntax`] for invalid JSON; otherwise the first field that breaks
/// the contract.
pub fn from_json<T: Decode>(input: &[u8]) -> Result<T, DecodeError> {
    from_json_with_limits(input, &Limits::default())
}

/// Parses `input` with `limits` and decodes a `T` from it; see [`from_json`].
///
/// # Errors
///
/// As [`from_json`].
pub fn from_json_with_limits<T: Decode>(input: &[u8], limits: &Limits) -> Result<T, DecodeError> {
    let value = sibuna_json::parse_with_limits(input, limits)
        .map_err(|error| DecodeError::new(Path::Root, DecodeErrorKind::Syntax(error)))?;
    T::decode(&value, Path::Root)
}

/// Writes `value` as a JSON number below 2^53 and as a decimal string from there on, so
/// browsers keep every digit (Zig's `writeCounter`).
///
/// # Errors
///
/// Returns the sink's error.
pub fn counter<W: Write>(json: &mut Writer<W>, value: u64) -> fmt::Result {
    if value < EXACT_INTEGER_LIMIT {
        return json.uint(value);
    }
    let mut buffer = [0u8; 20];
    json.string(decimal(value, &mut buffer))
}

/// Writes `value` with [`counter`], or `null`.
///
/// # Errors
///
/// Returns the sink's error.
pub fn optional_counter<W: Write>(json: &mut Writer<W>, value: Option<u64>) -> fmt::Result {
    match value {
        Some(value) => counter(json, value),
        None => json.null(),
    }
}

/// Writes `value` as a decimal string, whatever its size (for identifiers the browser
/// treats as opaque text).
///
/// # Errors
///
/// Returns the sink's error.
pub fn decimal_string<W: Write>(json: &mut Writer<W>, value: u64) -> fmt::Result {
    let mut buffer = [0u8; 20];
    json.string(decimal(value, &mut buffer))
}

/// Formats `value` in decimal into `buffer` and returns the text.
fn decimal(mut value: u64, buffer: &mut [u8; 20]) -> &str {
    let mut start = buffer.len();
    loop {
        start -= 1;
        // `value % 10` is a digit; `start` stays in bounds because u64 has at most 20 digits.
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    std::str::from_utf8(&buffer[start..]).unwrap_or_default()
}

/// Writes `key` and then `value`.
///
/// # Errors
///
/// Returns the sink's error.
pub fn field<W: Write, T: Encode + ?Sized>(
    json: &mut Writer<W>,
    key: &str,
    value: &T,
) -> fmt::Result {
    json.key(key)?;
    value.encode(json)
}

/// Writes `value` as a string, or `null`.
///
/// # Errors
///
/// Returns the sink's error.
pub fn optional_str<W: Write>(json: &mut Writer<W>, value: Option<&str>) -> fmt::Result {
    match value {
        Some(text) => json.string(text),
        None => json.null(),
    }
}

/// Writes `key` and then `value` with [`counter`].
///
/// # Errors
///
/// Returns the sink's error.
pub fn counter_field<W: Write>(json: &mut Writer<W>, key: &str, value: u64) -> fmt::Result {
    json.key(key)?;
    counter(json, value)
}

/// Writes `key` and then `value` with [`optional_counter`].
///
/// # Errors
///
/// Returns the sink's error.
pub fn optional_counter_field<W: Write>(
    json: &mut Writer<W>,
    key: &str,
    value: Option<u64>,
) -> fmt::Result {
    json.key(key)?;
    optional_counter(json, value)
}

/// Writes bytes as an array of numbers. Random identifiers such as boot ids are always
/// written this way, never as an accidental string.
///
/// # Errors
///
/// Returns the sink's error.
pub fn byte_array<W: Write>(json: &mut Writer<W>, bytes: &[u8]) -> fmt::Result {
    json.begin_array()?;
    for &byte in bytes {
        json.uint(u64::from(byte))?;
    }
    json.end_array()
}

/// Writes bytes as Zig's default `Stringify` writes a `[N]u8`: a string when they are valid
/// UTF-8, an array of numbers otherwise.
///
/// # Errors
///
/// Returns the sink's error.
pub fn zig_byte_string<W: Write>(json: &mut Writer<W>, bytes: &[u8]) -> fmt::Result {
    match std::str::from_utf8(bytes) {
        Ok(text) => json.string(text),
        Err(_) => byte_array(json, bytes),
    }
}

/// Reads a byte array written by [`byte_array`] or [`zig_byte_string`]: an array of `N`
/// byte values or a string of exactly `N` bytes.
///
/// # Errors
///
/// [`DecodeErrorKind::WrongLength`] for another length, and the element's error otherwise.
pub fn decode_byte_array<const N: usize>(
    value: &Value<'_>,
    path: Path<'_>,
) -> Result<[u8; N], DecodeError> {
    let mut bytes = [0u8; N];
    match value {
        Value::String(text) => {
            if text.len() != N {
                return Err(DecodeError::new(path, DecodeErrorKind::WrongLength { expected: N }));
            }
            bytes.copy_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            if items.len() != N {
                return Err(DecodeError::new(path, DecodeErrorKind::WrongLength { expected: N }));
            }
            for (index, (slot, item)) in bytes.iter_mut().zip(items).enumerate() {
                *slot = u8::decode(item, path.index(index))?;
            }
        }
        _ => return Err(DecodeError::wrong_type(path, "an array of bytes", value)),
    }
    Ok(bytes)
}

/// Reads text as Zig's typed parse reads a `[]const u8`: a string, or an array of byte
/// values that must form UTF-8.
///
/// # Errors
///
/// [`DecodeErrorKind::Invalid`] for bytes that are not UTF-8, and the element's error
/// otherwise.
pub fn zig_byte_string_value(value: &Value<'_>, path: Path<'_>) -> Result<String, DecodeError> {
    match value {
        Value::String(text) => Ok(text.to_string()),
        Value::Array(items) => {
            let bytes = items
                .iter()
                .enumerate()
                .map(|(index, item)| u8::decode(item, path.index(index)))
                .collect::<Result<Vec<u8>, _>>()?;
            String::from_utf8(bytes).map_err(|_| {
                DecodeError::new(path, DecodeErrorKind::Invalid("the bytes are not UTF-8"))
            })
        }
        _ => Err(DecodeError::wrong_type(path, "a string", value)),
    }
}

/// Reads an optional text field as Zig's typed parse reads a `?[]const u8`: `null`, or as
/// [`zig_byte_string_value`].
///
/// # Errors
///
/// As [`zig_byte_string_value`].
pub fn zig_optional_string(
    value: &Value<'_>,
    path: Path<'_>,
) -> Result<Option<String>, DecodeError> {
    match value {
        Value::Null => Ok(None),
        _ => zig_byte_string_value(value, path).map(Some),
    }
}

/// Reads an array of at most `max` elements.
///
/// # Errors
///
/// [`DecodeErrorKind::TooMany`] for a longer array, and the element's error otherwise.
pub fn decode_list<T: Decode>(
    value: &Value<'_>,
    path: Path<'_>,
    max: usize,
) -> Result<Vec<T>, DecodeError> {
    let items =
        value.as_array().ok_or_else(|| DecodeError::wrong_type(path, "an array", value))?;
    if items.len() > max {
        return Err(DecodeError::new(path, DecodeErrorKind::TooMany { max }));
    }
    // A plain loop: the module keeps one small copy per element type instead of the
    // iterator adapters a fallible `collect` instantiates.
    let mut list = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        list.push(T::decode(item, path.index(index))?);
    }
    Ok(list)
}

/// Reads a string of any length (bounded only by the document).
fn decode_str<'v>(value: &'v Value<'_>, path: Path<'_>) -> Result<&'v str, DecodeError> {
    value.as_str().ok_or_else(|| DecodeError::wrong_type(path, "a string", value))
}

/// Reads the members of one object by name and rejects members nobody read.
///
/// Members are usually in the order the encoder wrote them, so each lookup first tries the
/// member after the previous one (kept as an iterator, so the guess costs one step) and
/// scans only when that guess fails.
#[derive(Debug)]
pub struct Fields<'v, 'a, 'p> {
    object: &'v Object<'a>,
    taken: u128,
    /// The members after the last one taken, and the index of the first of them.
    cursor: ObjectIter<'v, 'a>,
    next: usize,
    path: Path<'p>,
}

impl<'v, 'a, 'p> Fields<'v, 'a, 'p> {
    /// Starts reading the object `value`, found at `path`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::WrongType`] if `value` is not an object, and
    /// [`DecodeErrorKind::TooMany`] for more than 128 members, which no record has.
    pub fn new(value: &'v Value<'a>, path: Path<'p>) -> Result<Fields<'v, 'a, 'p>, DecodeError> {
        let object =
            value.as_object().ok_or_else(|| DecodeError::wrong_type(path, "an object", value))?;
        if object.len() > 128 {
            return Err(DecodeError::new(path, DecodeErrorKind::TooMany { max: 128 }));
        }
        Ok(Fields { object, taken: 0, cursor: object.iter(), next: 0, path })
    }

    /// Returns the member `key` and marks it read.
    pub fn take(&mut self, key: &str) -> Option<&'v Value<'a>> {
        let mut probe = self.cursor.clone();
        if let Some((name, value)) = probe.next().filter(|(name, _)| *name == key) {
            let _ = name;
            self.taken |= 1 << self.next;
            self.cursor = probe;
            self.next += 1;
            return Some(value);
        }
        let mut members = self.object.iter();
        let index = members.position(|(name, _)| name == key)?;
        let (_, value) = self.object.iter().nth(index)?;
        self.taken |= 1 << index;
        self.cursor = members;
        self.next = index + 1;
        Some(value)
    }

    /// Reads the required member `key`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::Missing`] if it is absent, and the value's error otherwise.
    pub fn required<T: Decode>(&mut self, key: &str) -> Result<T, DecodeError> {
        match self.take(key) {
            Some(value) => T::decode(value, self.path.key(key)),
            None => Err(DecodeError::new(self.path.key(key), DecodeErrorKind::Missing)),
        }
    }

    /// Reads member `key`, or returns `default` if it is absent.
    ///
    /// # Errors
    ///
    /// The value's error.
    pub fn or<T: Decode>(&mut self, key: &str, default: T) -> Result<T, DecodeError> {
        match self.take(key) {
            Some(value) => T::decode(value, self.path.key(key)),
            None => Ok(default),
        }
    }

    /// Reads member `key`, or returns `T::default()` if it is absent.
    ///
    /// # Errors
    ///
    /// The value's error.
    pub fn or_default<T: Decode + Default>(&mut self, key: &str) -> Result<T, DecodeError> {
        self.or(key, T::default())
    }

    /// Reads the required member `key` with a custom reader, such as [`decode_list`].
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::Missing`] if it is absent, and the reader's error otherwise.
    pub fn required_with<T>(
        &mut self,
        key: &str,
        read: impl FnOnce(&Value<'_>, Path<'_>) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        match self.take(key) {
            Some(value) => read(value, self.path.key(key)),
            None => Err(DecodeError::new(self.path.key(key), DecodeErrorKind::Missing)),
        }
    }

    /// Reads member `key` with a custom reader, or returns `default` if it is absent.
    ///
    /// # Errors
    ///
    /// The reader's error.
    pub fn or_with<T>(
        &mut self,
        key: &str,
        default: T,
        read: impl FnOnce(&Value<'_>, Path<'_>) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        match self.take(key) {
            Some(value) => read(value, self.path.key(key)),
            None => Ok(default),
        }
    }

    /// Returns the number of members not read yet.
    pub fn remaining(&self) -> usize {
        self.object.len() - self.taken.count_ones() as usize
    }

    /// Returns the path of this object.
    pub fn path(&self) -> Path<'p> {
        self.path
    }

    /// Rejects the first member that was not read.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnknownKey`] naming it.
    pub fn finish(self) -> Result<(), DecodeError> {
        for (index, (name, _)) in self.object.iter().enumerate() {
            if self.taken & (1 << index) == 0 {
                return Err(DecodeError::new(self.path.key(name), DecodeErrorKind::UnknownKey));
            }
        }
        Ok(())
    }
}

/// Returns true for a number text Zig treats as an integer (`isNumberFormattedLikeAnInteger`).
fn integer_like(text: &str) -> bool {
    text != "-0" && !text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'))
}

/// Zig's `std.fmt.parseInt(T, text, 10)` over `i128`: an optional sign, then decimal
/// digits with single or repeated underscores between them (not at either end).
fn zig_parse_int(text: &str) -> Option<i128> {
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

/// Zig's `std.fmt.parseInt(u64, text, 10)`.
pub(crate) fn zig_parse_u64(text: &str) -> Option<u64> {
    zig_parse_int(text).and_then(|value| u64::try_from(value).ok())
}

/// Rewrites a number as Zig's `parseFloat` reads it into JSON number syntax: an optional
/// sign (`+` dropped), digits with single underscores between them (dropped), an optional
/// fraction (`1.` and `.5` completed), leading zeros trimmed and an optional exponent.
/// `None` for anything else, including infinities, NaN and hexadecimal floats.
fn zig_float_syntax(text: &str) -> Option<String> {
    let (negative, body) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let bytes = body.as_bytes();
    let digit_at = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    let underscores_valid = bytes.iter().enumerate().all(|(index, &byte)| {
        byte != b'_' || (index > 0 && digit_at(index - 1) && digit_at(index + 1))
    });
    if !underscores_valid {
        return None;
    }
    let body: String = body.chars().filter(|&c| c != '_').collect();
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body.as_str(), None),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (mantissa, None),
    };
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(integer)
        || !fraction.is_none_or(digits)
        || (integer.is_empty() && fraction.is_none_or(str::is_empty))
    {
        return None;
    }
    let mut out = String::from(if negative { "-" } else { "" });
    let trimmed = integer.trim_start_matches('0');
    out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
    if let Some(fraction) = fraction {
        out.push('.');
        out.push_str(if fraction.is_empty() { "0" } else { fraction });
    }
    if let Some(exponent) = exponent {
        let unsigned = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if unsigned.is_empty() || !digits(unsigned) {
            return None;
        }
        out.push('e');
        out.push_str(exponent);
    }
    Some(out)
}

/// Zig's `parseFloat(f64, text)` for finite results.
pub(crate) fn zig_parse_f64(text: &str) -> Option<f64> {
    let syntax = zig_float_syntax(text)?;
    Number::parse(&syntax)?.as_f64().ok()
}

/// Zig's `sliceToInt`: an integer-formatted text through `parseInt`, any other number
/// through a float that must be integral. Returns the value as `i128` for range checks.
pub(crate) fn zig_slice_to_int(text: &str) -> Option<i128> {
    // The common case first: plain decimal digits that cannot overflow.
    if (1..=19).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit()) {
        let value = text.bytes().fold(0u64, |value, byte| value * 10 + u64::from(byte - b'0'));
        return Some(i128::from(value));
    }
    if integer_like(text) {
        return zig_parse_int(text);
    }
    // Decide exactly, on the number's text, whether it is whole.
    let syntax = zig_float_syntax(text)?;
    let number = Number::parse(&syntax)?;
    match number.as_i64() {
        Ok(value) => Some(i128::from(value)),
        Err(_) => number.as_u64().ok().map(i128::from),
    }
}

/// Reads an integer as Zig's typed parse does: a number or a string holding one.
fn decode_integer(value: &Value<'_>, path: Path<'_>) -> Result<i128, DecodeError> {
    let text = match value {
        Value::Number(number) => number.as_str(),
        Value::String(text) => text,
        _ => return Err(DecodeError::wrong_type(path, "an integer", value)),
    };
    zig_slice_to_int(text).ok_or_else(|| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
}

fn decode_int_as<T: TryFrom<i128>>(value: &Value<'_>, path: Path<'_>) -> Result<T, DecodeError> {
    T::try_from(decode_integer(value, path)?)
        .map_err(|_| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
}

impl Decode for u8 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<u8, DecodeError> {
        decode_int_as(value, path)
    }
}

impl Decode for u16 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<u16, DecodeError> {
        decode_int_as(value, path)
    }
}

impl Decode for u32 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<u32, DecodeError> {
        decode_int_as(value, path)
    }
}

impl Decode for u64 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<u64, DecodeError> {
        decode_int_as(value, path)
    }
}

impl Decode for i32 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<i32, DecodeError> {
        decode_int_as(value, path)
    }
}

impl Decode for f64 {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<f64, DecodeError> {
        let parsed = match value {
            Value::Number(number) => number.as_f64().ok(),
            Value::String(text) => zig_parse_f64(text),
            _ => return Err(DecodeError::wrong_type(path, "a number", value)),
        };
        parsed.ok_or_else(|| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
    }
}

impl Decode for bool {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<bool, DecodeError> {
        value.as_bool().ok_or_else(|| DecodeError::wrong_type(path, "a boolean", value))
    }
}

impl Decode for String {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<String, DecodeError> {
        decode_str(value, path).map(str::to_owned)
    }
}

impl<const N: usize> Decode for Text<N> {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Text<N>, DecodeError> {
        let text = decode_str(value, path)?;
        Text::new(text).map_err(|_| DecodeError::new(path, DecodeErrorKind::TooLong { max: N }))
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Option<T>, DecodeError> {
        match value {
            Value::Null => Ok(None),
            _ => T::decode(value, path).map(Some),
        }
    }
}

impl<T: Decode + Default, const N: usize> Decode for [T; N] {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<[T; N], DecodeError> {
        let items =
            value.as_array().ok_or_else(|| DecodeError::wrong_type(path, "an array", value))?;
        if items.len() != N {
            return Err(DecodeError::new(path, DecodeErrorKind::WrongLength { expected: N }));
        }
        let mut result: [T; N] = std::array::from_fn(|_| T::default());
        for (index, (slot, item)) in result.iter_mut().zip(items).enumerate() {
            *slot = T::decode(item, path.index(index))?;
        }
        Ok(result)
    }
}

/// Reads an enumeration from its name or ordinal (Zig's `sliceToEnum`).
pub(crate) fn enum_from_text<T: WireEnum>(text: &str) -> Option<T> {
    if let Some(found) = T::from_name(text) {
        return Some(found);
    }
    if !integer_like(text) {
        return None;
    }
    zig_parse_int(text).and_then(|value| u64::try_from(value).ok()).and_then(T::from_ordinal)
}

impl<T: WireEnum> Decode for T {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<T, DecodeError> {
        let text = match value {
            Value::Number(number) => number.as_str(),
            Value::String(text) => text,
            _ => return Err(DecodeError::wrong_type(path, "a name", value)),
        };
        enum_from_text(text).ok_or_else(|| DecodeError::new(path, DecodeErrorKind::UnknownName))
    }
}

impl Encode for bool {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.bool(*self)
    }
}

impl Encode for u8 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.uint(u64::from(*self))
    }
}

impl Encode for u16 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.uint(u64::from(*self))
    }
}

impl Encode for u32 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.uint(u64::from(*self))
    }
}

/// A plain JSON number, as Zig's default `Stringify` writes a `u64`; use [`counter`] for
/// fields the browser must read exactly.
impl Encode for u64 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.uint(*self)
    }
}

impl Encode for i32 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.int(i64::from(*self))
    }
}

impl Encode for f64 {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.float(*self)
    }
}

impl Encode for str {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.string(self)
    }
}

impl Encode for String {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.string(self)
    }
}

impl<const N: usize> Encode for Text<N> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.string(self.as_str())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        match self {
            Some(value) => value.encode(json),
            None => json.null(),
        }
    }
}

impl<T: Encode> Encode for [T] {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_array()?;
        for item in self {
            item.encode(json)?;
        }
        json.end_array()
    }
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        self.as_slice().encode(json)
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        self.as_slice().encode(json)
    }
}

impl<T: WireEnum> Encode for T {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.string(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded<T: Decode>(text: &str) -> Result<T, DecodeError> {
        from_json(text.as_bytes())
    }

    // Port of root.zig "session account identifiers retain their complete range across
    // browser JSON".
    #[test]
    fn counters_switch_to_strings_at_two_to_the_53() {
        let mut out = String::new();
        let mut json = Writer::new(&mut out);
        json.begin_object().unwrap();
        counter_field(&mut json, "small", 1).unwrap();
        counter_field(&mut json, "large", 9_007_199_254_740_993).unwrap();
        json.end_object().unwrap();
        assert_eq!(out, "{\"small\":1,\"large\":\"9007199254740993\"}");
        let mut out = String::new();
        counter(&mut Writer::new(&mut out), u64::MAX).unwrap();
        assert_eq!(out, "\"18446744073709551615\"");
        let mut out = String::new();
        counter(&mut Writer::new(&mut out), EXACT_INTEGER_LIMIT - 1).unwrap();
        assert_eq!(out, "9007199254740991");
    }

    #[test]
    fn integers_follow_zig_slice_to_int() {
        assert_eq!(decoded::<u64>("\"18446744073709551615\""), Ok(u64::MAX));
        assert_eq!(decoded::<u64>("8.0"), Ok(8));
        assert_eq!(decoded::<u64>("1e3"), Ok(1000));
        assert_eq!(decoded::<u64>("\"+1_000\""), Ok(1000));
        assert_eq!(decoded::<u64>("\"-0\""), Ok(0));
        assert_eq!(decoded::<u8>("\"2.\""), Ok(2));
        assert_eq!(decoded::<u64>("\"1_0.0e1\""), Ok(100));
        assert_eq!(decoded::<u64>("\"+9007199254740993.\""), Ok(9_007_199_254_740_993));
        assert_eq!(decoded::<f64>("\"+1_0\""), Ok(10.0));
        assert_eq!(decoded::<f64>("\".5\""), Ok(0.5));
        for bad in ["\"1__0.0\"", "\"_1.0\"", "\"1.0_\"", "\"0x1p3\"", "\"inf\"", "1e400"] {
            assert!(decoded::<f64>(bad).is_err(), "{bad}");
        }
        for bad in ["\"_1\"", "\"1_\"", "\"\"", "\"+\"", "1.5", "-1", "256", "\" 1\"", "true"] {
            assert!(decoded::<u8>(bad).is_err(), "{bad}");
        }
        assert!(decoded::<u64>("\"18446744073709551616\"").is_err());
        assert_eq!(decoded::<i32>("-5"), Ok(-5));
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Colour {
        Red,
        Green,
    }

    impl WireEnum for Colour {
        const ALL: &'static [Colour] = &[Colour::Red, Colour::Green];
        fn name(self) -> &'static str {
            match self {
                Colour::Red => "red",
                Colour::Green => "green",
            }
        }
    }

    #[test]
    fn enums_read_names_and_ordinals() {
        assert_eq!(decoded::<Colour>("\"green\""), Ok(Colour::Green));
        assert_eq!(decoded::<Colour>("1"), Ok(Colour::Green));
        assert_eq!(decoded::<Colour>("\"0\""), Ok(Colour::Red));
        assert!(decoded::<Colour>("2").is_err());
        assert!(decoded::<Colour>("1.0").is_err());
        assert!(decoded::<Colour>("\"Green\"").is_err());
        assert_eq!(to_json(&Colour::Red), "\"red\"");
        assert_eq!(Colour::Green.ordinal(), 1);
    }

    #[test]
    fn byte_arrays_accept_strings_of_exact_length() {
        let bytes: [u8; 3] =
            decode_byte_array(&sibuna_json::parse(b"\"abc\"").unwrap(), Path::Root).unwrap();
        assert_eq!(&bytes, b"abc");
        let bytes: [u8; 3] =
            decode_byte_array(&sibuna_json::parse(b"[1,2,255]").unwrap(), Path::Root).unwrap();
        assert_eq!(bytes, [1, 2, 255]);
        assert!(
            decode_byte_array::<3>(&sibuna_json::parse(b"\"ab\"").unwrap(), Path::Root).is_err()
        );
        assert!(
            decode_byte_array::<3>(&sibuna_json::parse(b"[1,2,256]").unwrap(), Path::Root)
                .is_err()
        );
        let mut out = String::new();
        zig_byte_string(&mut Writer::new(&mut out), &[0xff, 1]).unwrap();
        assert_eq!(out, "[255,1]");
        let mut out = String::new();
        zig_byte_string(&mut Writer::new(&mut out), b"\x01a").unwrap();
        assert_eq!(out, "\"\\u0001a\"");
    }

    #[test]
    fn fields_reject_unknown_and_missing_members_with_paths() {
        let value = sibuna_json::parse(br#"{"a":1,"rows":[{"b":true,"c":2}]}"#).unwrap();
        let mut fields = Fields::new(&value, Path::Root).unwrap();
        assert_eq!(fields.required::<u8>("a"), Ok(1));
        let rows = fields.take("rows").unwrap().as_array().unwrap();
        let outer = Path::Root;
        let rows_path = outer.key("rows");
        let mut row = Fields::new(&rows[0], rows_path.index(0)).unwrap();
        assert_eq!(row.required::<bool>("b"), Ok(true));
        let missing = row.required::<bool>("d").unwrap_err();
        assert_eq!(missing.path(), "rows[0].d");
        assert_eq!(*missing.kind(), DecodeErrorKind::Missing);
        let unknown = row.finish().unwrap_err();
        assert_eq!(
            (unknown.path(), unknown.kind().clone()),
            ("rows[0].c", DecodeErrorKind::UnknownKey)
        );
        assert!(fields.finish().is_ok());
        assert_eq!(unknown_display(), "`rows[0].c` is not a known key");
    }

    fn unknown_display() -> String {
        let root = Path::Root;
        let rows = root.key("rows");
        let row = rows.index(0);
        DecodeError::new(row.key("c"), DecodeErrorKind::UnknownKey).to_string()
    }

    #[test]
    fn text_and_lists_are_bounded() {
        assert!(decoded::<Text<3>>("\"abc\"").is_ok());
        assert_eq!(
            *decoded::<Text<3>>("\"abcd\"").unwrap_err().kind(),
            DecodeErrorKind::TooLong { max: 3 }
        );
        let value = sibuna_json::parse(b"[1,2,3]").unwrap();
        assert_eq!(decode_list::<u8>(&value, Path::Root, 3), Ok(vec![1, 2, 3]));
        assert_eq!(
            *decode_list::<u8>(&value, Path::Root, 2).unwrap_err().kind(),
            DecodeErrorKind::TooMany { max: 2 }
        );
        assert!(decoded::<[u8; 2]>("[1,2,3]").is_err());
        assert_eq!(decoded::<Option<u8>>("null"), Ok(None));
        assert!(matches!(decoded::<u8>("{").unwrap_err().kind(), DecodeErrorKind::Syntax(_)));
    }
}

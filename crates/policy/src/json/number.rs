//! Integer and enum fields read the way Zig 0.16's typed JSON parsing reads them.
//!
//! Zig accepts an integer field written as a JSON number or as a JSON string. A text with
//! no `.`, `e` or `E` (and not `-0`) goes through `std.fmt.parseInt` in base 10: an
//! optional sign, digits, and `_` between digits. Any other text goes through
//! `std.fmt.parseFloat`, and the value must be integral and in range. Enum fields accept a
//! tag name, or an integer text that names a tag by number.
//!
//! One deliberate difference: Zig rounded such floats through binary128 before testing
//! integrality, so a text with more than about 34 significant digits could round to an
//! integer (`1.0000000000000000000000000000000000001` read as 1). We decide integrality
//! exactly and refuse such texts.

use super::ErrorKind;

/// True when `text` has no fraction or exponent and is not `-0` (Zig's
/// `isNumberFormattedLikeAnInteger`).
pub(crate) fn integer_formatted(text: &[u8]) -> bool {
    text != b"-0" && !text.iter().any(|b| matches!(b, b'.' | b'e' | b'E'))
}

/// Zig's `std.fmt.parseInt(T, text, 10)` for a type with range `min..=max`, with the same
/// error at the same position: `InvalidCharacter` or `Overflow`.
pub(crate) fn parse_int(text: &[u8], min: i64, max: i64) -> Result<i64, ErrorKind> {
    let (negative, digits) = match text {
        [b'+', rest @ ..] => (false, rest),
        [b'-', rest @ ..] => (true, rest),
        _ => (false, text),
    };
    if digits.is_empty() || digits[0] == b'_' || digits[digits.len() - 1] == b'_' {
        return Err(ErrorKind::InvalidCharacter);
    }
    let mut value: i64 = 0;
    let in_range = |value: i64| (min..=max).contains(&value);
    for &byte in digits {
        if byte == b'_' {
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(ErrorKind::InvalidCharacter);
        }
        let digit = i64::from(byte - b'0');
        if value != 0 {
            value *= 10;
            if !in_range(value) {
                return Err(ErrorKind::Overflow);
            }
        } else if negative {
            // The first digit of a negative number.
            value = -digit;
            if !in_range(value) {
                return Err(ErrorKind::Overflow);
            }
            continue;
        }
        value = if negative { value - digit } else { value + digit };
        if !in_range(value) {
            return Err(ErrorKind::Overflow);
        }
    }
    Ok(value)
}

/// Zig's `sliceToInt`: integer texts through `parse_int`, others through a float parse
/// that must give an integral value within `min..=max`.
pub(crate) fn slice_to_int(text: &[u8], min: i64, max: i64) -> Result<i64, ErrorKind> {
    if integer_formatted(text) {
        return parse_int(text, min, max);
    }
    let exact = parse_float(text).ok_or(ErrorKind::InvalidCharacter)?;
    exact.to_integer(min, max)
}

/// Zig's `sliceToEnum`: a tag name, or an integer text naming a tag by its number.
pub(crate) fn slice_to_enum(text: &[u8], names: &[&str]) -> Result<usize, ErrorKind> {
    if let Some(index) = names.iter().position(|name| name.as_bytes() == text) {
        return Ok(index);
    }
    if !integer_formatted(text) {
        return Err(ErrorKind::InvalidEnumTag);
    }
    // The tag types are at most 8 bits wide; any parse error is an invalid tag.
    match parse_int(text, 0, 255) {
        Ok(number) if (number as usize) < names.len() => Ok(number as usize),
        _ => Err(ErrorKind::InvalidEnumTag),
    }
}

/// A number parsed exactly: `digits` (significant, no leading or trailing zeros) times
/// `base` raised to `exponent`, where the base is 10 or 2.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Exact {
    negative: bool,
    /// Decimal or hexadecimal digit values, most significant first.
    digits: Vec<u8>,
    /// Power of ten (decimal) or of two (hexadecimal) applied to the digits.
    exponent: i64,
    hex: bool,
    /// `inf`, `infinity` or `nan`.
    special: Option<Special>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Special {
    Infinity,
    NotANumber,
}

impl Exact {
    /// Zig's checks in order: a non-integral value is `InvalidNumber`, an out-of-range one
    /// `Overflow`. Values of 2^113 and above count as integral, as binary128 makes them.
    fn to_integer(&self, min: i64, max: i64) -> Result<i64, ErrorKind> {
        match self.special {
            Some(Special::NotANumber) => return Err(ErrorKind::InvalidNumber),
            Some(Special::Infinity) => return Err(ErrorKind::Overflow),
            None => {}
        }
        if self.digits.is_empty() {
            return Ok(0);
        }
        // Digits carry no trailing zero digit, so a decimal value is integral exactly when
        // its exponent is not negative; a hexadecimal one may also absorb the trailing zero
        // bits of its last digit.
        let last = self.digits[self.digits.len() - 1];
        let spare_bits = if self.hex { i64::from(last.trailing_zeros().min(3) as u8) } else { 0 };
        let huge = if self.hex {
            (self.digits.len() as i64 - 1) * 4 + bit_length(self.digits[0]) + self.exponent > 113
        } else {
            self.digits.len() as i64 + self.exponent > 34
        };
        if huge {
            return Err(ErrorKind::Overflow);
        }
        if self.exponent + spare_bits < 0 {
            return Err(ErrorKind::InvalidNumber);
        }
        // Not huge: at most 34 decimal digits or 113 bits, so the arithmetic fits an i128.
        let base: i128 = if self.hex { 16 } else { 10 };
        let mut value: i128 = 0;
        for &digit in &self.digits {
            value = value.checked_mul(base).ok_or(ErrorKind::Overflow)? + i128::from(digit);
        }
        let value = match (self.hex, self.exponent) {
            (true, exponent) if exponent < 0 => value >> (-exponent),
            (true, exponent) => value.checked_shl(exponent as u32).ok_or(ErrorKind::Overflow)?,
            (false, exponent) => {
                let scale = 10i128.checked_pow(exponent as u32).ok_or(ErrorKind::Overflow)?;
                value.checked_mul(scale).ok_or(ErrorKind::Overflow)?
            }
        };
        let value = if self.negative { -value } else { value };
        if value < i128::from(min) || value > i128::from(max) {
            return Err(ErrorKind::Overflow);
        }
        Ok(value as i64)
    }
}

fn bit_length(digit: u8) -> i64 {
    i64::from(8 - digit.leading_zeros() as u8)
}

fn digit_value(byte: u8, hex: bool) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' if hex => Some(byte - b'a' + 10),
        b'A'..=b'F' if hex => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Zig's `validUnderscores`: each `_` sits between two digits of the base.
fn valid_underscores(text: &[u8], hex: bool) -> bool {
    let mut index = 0;
    while index < text.len() {
        if text[index] == b'_' {
            let before = index.checked_sub(1).and_then(|i| text.get(i));
            let after = text.get(index + 1);
            match (before, after) {
                (Some(&b), Some(&a))
                    if digit_value(b, hex).is_some() && digit_value(a, hex).is_some() => {}
                _ => return false,
            }
            index += 1;
        }
        index += 1;
    }
    true
}

/// Reads the next digit of `text` at `*index`, skipping and counting underscores as Zig's
/// `FloatStream.scanDigit` does.
fn scan_digit(text: &[u8], index: &mut usize, hex: bool, underscores: &mut usize) -> Option<u8> {
    loop {
        let &byte = text.get(*index)?;
        if let Some(value) = digit_value(byte, hex) {
            *index += 1;
            return Some(value);
        }
        if byte != b'_' {
            return None;
        }
        *index += 1;
        *underscores += 1;
    }
}

/// Zig's `parseScientific`: an optional sign, then at least one decimal digit. The
/// accumulation stops growing at 2^28, as Zig's does.
fn scientific(text: &[u8], index: &mut usize, underscores: &mut usize) -> Option<i64> {
    let negative = text.get(*index) == Some(&b'-');
    if matches!(text.get(*index), Some(b'-' | b'+')) {
        *index += 1;
    }
    if !text.get(*index).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut exponent: i64 = 0;
    while let Some(digit) = scan_digit(text, index, false, underscores) {
        if exponent < 0x1000_0000 {
            exponent = 10 * exponent + i64::from(digit);
        }
    }
    Some(if negative { -exponent } else { exponent })
}

/// Parses the digits, point and exponent of `text` (after any sign and `0x`).
fn mantissa(text: &[u8], hex: bool) -> Option<Exact> {
    let (mut index, mut underscores) = (0, 0);
    let mut digits = Vec::new();
    while let Some(digit) = scan_digit(text, &mut index, hex, &mut underscores) {
        digits.push(digit);
    }
    let mut fraction: i64 = 0;
    if text.get(index) == Some(&b'.') {
        index += 1;
        while let Some(digit) = scan_digit(text, &mut index, hex, &mut underscores) {
            digits.push(digit);
            fraction += 1;
        }
    }
    if digits.is_empty() {
        return None;
    }
    let marker = if hex { b'p' } else { b'e' };
    let mut exponent = if hex { -4 * fraction } else { -fraction };
    if text.get(index).is_some_and(|&b| b | 0x20 == marker) {
        index += 1;
        exponent += scientific(text, &mut index, &mut underscores)?;
    }
    if index != text.len() || (underscores > 0 && !valid_underscores(text, hex)) {
        return None;
    }
    let leading = digits.iter().take_while(|&&d| d == 0).count();
    digits.drain(..leading);
    while digits.last() == Some(&0) {
        digits.pop();
        exponent += if hex { 4 } else { 1 };
    }
    Some(Exact { negative: false, digits, exponent, hex, special: None })
}

/// Zig's `std.fmt.parseFloat` grammar, kept exact: an optional sign, then decimal digits
/// with an optional point and `e` exponent, or `0x` hexadecimal digits with an optional
/// point and `p` exponent, or `inf`, `infinity` or `nan` in any case. `_` may separate
/// digits. Returns `None` where Zig fails with `InvalidCharacter`.
pub(crate) fn parse_float(text: &[u8]) -> Option<Exact> {
    let &first = text.first()?;
    let negative = first == b'-';
    let body = if matches!(first, b'-' | b'+') { &text[1..] } else { text };
    if body.is_empty() {
        return None;
    }
    let hex = body.len() >= 2 && body[0] == b'0' && body[1] | 0x20 == b'x';
    let parsed = if hex { mantissa(&body[2..], true) } else { mantissa(body, false) };
    if let Some(exact) = parsed {
        return Some(Exact { negative, ..exact });
    }
    let special = if body.eq_ignore_ascii_case(b"inf") || body.eq_ignore_ascii_case(b"infinity") {
        Special::Infinity
    } else if body.eq_ignore_ascii_case(b"nan") {
        Special::NotANumber
    } else {
        return None;
    };
    Some(Exact { negative, digits: Vec::new(), exponent: 0, hex: false, special: Some(special) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ErrorKind::{
        InvalidCharacter as C, InvalidEnumTag as T, InvalidNumber as N, Overflow as O,
    };

    type Case = (&'static [u8], (i64, i64), Result<i64, ErrorKind>);

    const U32: (i64, i64) = (0, u32::MAX as i64);
    const I32: (i64, i64) = (i32::MIN as i64, i32::MAX as i64);

    #[test]
    fn integers_follow_zig_parse_int() {
        let cases: [Case; 14] = [
            (b"12", U32, Ok(12)),
            (b"+10", U32, Ok(10)),
            (b"-0", U32, Ok(0)),
            (b"-10", U32, Err(O)),
            (b"1_000", U32, Ok(1000)),
            (b"1__0", U32, Ok(10)),
            (b"_1", U32, Err(C)),
            (b"1_", U32, Err(C)),
            (b" 1", U32, Err(C)),
            (b"", U32, Err(C)),
            (b"-", I32, Err(C)),
            (b"-2147483648", I32, Ok(i64::from(i32::MIN))),
            (b"4294967296", U32, Err(O)),
            (b"99999999999x", U32, Err(O)),
        ];
        for (text, (min, max), expected) in cases {
            assert_eq!(
                slice_to_int(text, min, max),
                expected,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn floats_must_be_integral_and_in_range() {
        let cases: [(&[u8], Result<i64, ErrorKind>); 15] = [
            (b"12.0", Ok(12)),
            (b"1e3", Ok(1000)),
            (b"1.5e1", Ok(15)),
            (b"12.5", Err(N)),
            (b"-0", Ok(0)),
            (b"5.", Ok(5)),
            (b".5", Err(N)),
            (b".", Err(C)),
            (b"1e", Err(C)),
            (b"0x10.0", Ok(16)),
            (b"0x1e", Ok(30)),
            (b"0x1.8p1", Ok(3)),
            (b"0x1.4p1", Err(N)),
            (b"1_0.5e1", Ok(105)),
            (b"1._5", Err(C)),
        ];
        for (text, expected) in cases {
            assert_eq!(
                slice_to_int(text, 0, i64::from(u32::MAX)),
                expected,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
        assert_eq!(slice_to_int(b"1e400", 0, 10), Err(O));
        assert_eq!(slice_to_int(b"-1e1", -100, 100), Ok(-10));
        assert_eq!(slice_to_int(b"1.0e-1", 0, 10), Err(N));
    }

    #[test]
    fn enums_accept_names_and_tag_numbers() {
        let names = ["disabled", "audit", "enforce"];
        assert_eq!(slice_to_enum(b"audit", &names), Ok(1));
        assert_eq!(slice_to_enum(b"1", &names), Ok(1));
        assert_eq!(slice_to_enum(b"+2", &names), Ok(2));
        assert_eq!(slice_to_enum(b"3", &names), Err(T));
        assert_eq!(slice_to_enum(b"1.0", &names), Err(T));
        assert_eq!(slice_to_enum(b"Audit", &names), Err(T));
        assert_eq!(slice_to_enum(b"999", &names), Err(T));
    }
}

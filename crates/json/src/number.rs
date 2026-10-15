//! JSON numbers: grammar and exact conversion.

use std::fmt;

/// A JSON number, kept as its source text so that no precision is lost before the caller
/// chooses a type.
///
/// A `Number` always holds text that follows the JSON number grammar: an optional minus,
/// an integer part without leading zeros, an optional fraction and an optional exponent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Number<'a> {
    text: &'a str,
}

/// Why a number could not be converted to the requested type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NumberError {
    /// The value has a non-zero fractional part, so it is not an integer.
    NotAnInteger,
    /// The value lies outside the range of the requested type (or, for `f64`, is too large
    /// to be finite).
    OutOfRange,
}

impl fmt::Display for NumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NumberError::NotAnInteger => "the number is not an integer",
            NumberError::OutOfRange => "the number is out of range",
        })
    }
}

impl std::error::Error for NumberError {}

/// Returns the end of the digit run that starts at `start`.
fn skip_digits(bytes: &[u8], start: usize) -> usize {
    start + bytes[start.min(bytes.len())..].iter().take_while(|b| b.is_ascii_digit()).count()
}

/// Scans the number that starts at `start` and returns the offset just past it, or the
/// offset of the first byte that breaks the grammar (which may be `bytes.len()` when the
/// input ends early).
pub(crate) fn scan(bytes: &[u8], start: usize) -> Result<usize, usize> {
    let mut i = start;
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    match bytes.get(i) {
        // A leading zero is the whole integer part: "01" and "-00" are not numbers.
        Some(b'0') if bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => return Err(i + 1),
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i = skip_digits(bytes, i),
        _ => return Err(i),
    }
    if bytes.get(i) == Some(&b'.') {
        let end = skip_digits(bytes, i + 1);
        if end == i + 1 {
            return Err(end);
        }
        i = end;
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let end = skip_digits(bytes, i);
        if end == i {
            return Err(end);
        }
        i = end;
    }
    Ok(i)
}

/// The parts of a number's text: sign, digits before and after the point, and exponent.
struct Parts<'a> {
    negative: bool,
    integer: &'a [u8],
    fraction: &'a [u8],
    /// The exponent, saturated to the `i64` range; beyond it the outcome no longer depends
    /// on the exact value.
    exponent: i64,
}

impl<'a> Parts<'a> {
    fn split(text: &'a str) -> Parts<'a> {
        let unsigned = text.strip_prefix('-');
        let negative = unsigned.is_some();
        let unsigned = unsigned.unwrap_or(text);
        let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, parse_exponent(exponent.as_bytes())),
            None => (unsigned, 0),
        };
        let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let (integer, fraction) = (integer.as_bytes(), fraction.as_bytes());
        Parts { negative, integer, fraction, exponent }
    }

    /// Returns the digit at `index` of the integer and fraction digits read as one string,
    /// or 0 past their end. A `Number` holds scanned text, so every byte here is a digit.
    fn digit(&self, index: usize) -> u8 {
        let byte = match index.checked_sub(self.integer.len()) {
            None => self.integer.get(index),
            Some(i) => self.fraction.get(i),
        };
        byte.map_or(0, |b| b.wrapping_sub(b'0'))
    }

    /// Returns the magnitude of the value if it is an integer below 10^20.
    fn integer_magnitude(&self) -> Result<u128, NumberError> {
        let count = self.integer.len() + self.fraction.len();
        let leading = (0..count).take_while(|&i| self.digit(i) == 0).count();
        if leading == count {
            return Ok(0);
        }
        let trailing = (0..count).rev().take_while(|&i| self.digit(i) == 0).count();
        // value = significant digits * 10^scale
        let fraction_len = i64::try_from(self.fraction.len()).unwrap_or(i64::MAX);
        let trailing_len = i64::try_from(trailing).unwrap_or(i64::MAX);
        let scale = self.exponent.saturating_sub(fraction_len).saturating_add(trailing_len);
        if scale < 0 {
            return Err(NumberError::NotAnInteger);
        }
        let significant = count - leading - trailing;
        // u64::MAX has 20 digits; anything with more cannot fit either integer type.
        if scale > 20 || significant > 20 || significant + scale as usize > 20 {
            return Err(NumberError::OutOfRange);
        }
        let digits = (leading..count - trailing)
            .fold(0u128, |value, i| value * 10 + u128::from(self.digit(i)));
        Ok(digits * 10u128.pow(scale as u32))
    }
}

/// Parses exponent digits with an optional sign, saturating at the `i64` bounds.
fn parse_exponent(text: &[u8]) -> i64 {
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let magnitude = digits.iter().fold(0i64, |value, &d| {
        value.saturating_mul(10).saturating_add(i64::from(d.wrapping_sub(b'0')))
    });
    if negative { -magnitude } else { magnitude }
}

impl<'a> Number<'a> {
    /// Returns the number spelled by `text`, or `None` unless all of `text` follows the
    /// JSON number grammar.
    pub fn parse(text: &'a str) -> Option<Number<'a>> {
        match scan(text.as_bytes(), 0) {
            Ok(end) if end == text.len() => Some(Number { text }),
            _ => None,
        }
    }

    /// Wraps text the parser has already scanned.
    pub(crate) fn from_scanned(text: &'a str) -> Number<'a> {
        Number { text }
    }

    /// Returns the source text, borrowed from the input.
    pub fn as_str(&self) -> &'a str {
        self.text
    }

    /// Returns true when the text has no fraction or exponent and is not `-0`; this is
    /// Zig's `isNumberFormattedLikeAnInteger`.
    pub fn is_integer_literal(&self) -> bool {
        self.text != "-0" && !self.text.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
    }

    /// Returns the value as an `i64` if it is an integer in range.
    ///
    /// The conversion is exact: `1e3`, `8.0` and `-0` are the integers 1000, 8 and 0, as in
    /// Zig's typed parsing, while `1.5` and `1e-1` are not integers.
    ///
    /// # Errors
    ///
    /// [`NumberError::NotAnInteger`] for a fractional value and
    /// [`NumberError::OutOfRange`] outside `i64::MIN..=i64::MAX`.
    pub fn as_i64(&self) -> Result<i64, NumberError> {
        let parts = Parts::split(self.text);
        let magnitude =
            i128::try_from(parts.integer_magnitude()?).map_err(|_| NumberError::OutOfRange)?;
        let value = if parts.negative { -magnitude } else { magnitude };
        i64::try_from(value).map_err(|_| NumberError::OutOfRange)
    }

    /// Returns the value as a `u64` if it is a non-negative integer in range; see
    /// [`Number::as_i64`] for the exact conversion.
    ///
    /// # Errors
    ///
    /// [`NumberError::NotAnInteger`] for a fractional value and
    /// [`NumberError::OutOfRange`] for a negative value or one above `u64::MAX`.
    pub fn as_u64(&self) -> Result<u64, NumberError> {
        let parts = Parts::split(self.text);
        let magnitude = parts.integer_magnitude()?;
        if parts.negative && magnitude != 0 {
            return Err(NumberError::OutOfRange);
        }
        u64::try_from(magnitude).map_err(|_| NumberError::OutOfRange)
    }

    /// Returns the nearest `f64`, rounding correctly.
    ///
    /// # Errors
    ///
    /// [`NumberError::OutOfRange`] if the value is too large to be a finite `f64`.
    /// Values too small to represent round to zero.
    pub fn as_f64(&self) -> Result<f64, NumberError> {
        match self.text.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(value),
            _ => Err(NumberError::OutOfRange),
        }
    }
}

impl fmt::Display for Number<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(text: &str) -> Number<'_> {
        Number::parse(text).unwrap_or_else(|| panic!("{text:?} is a JSON number"))
    }

    #[test]
    fn grammar() {
        for text in ["0", "-0", "1", "-1", "10", "0.5", "1.25e3", "1E+3", "1e-3", "-0.0e0"] {
            assert!(Number::parse(text).is_some(), "{text}");
        }
        for text in ["", "-", "01", "-01", "00", "1.", ".5", "1e", "1e+", "+1", "1.5.", "0x1"] {
            assert!(Number::parse(text).is_none(), "{text}");
        }
        assert_eq!(scan(b"01", 0), Err(1));
        assert_eq!(scan(b"1.e5", 0), Err(2));
        assert_eq!(scan(b"-", 0), Err(1));
        assert_eq!(scan(b"12,", 0), Ok(2));
    }

    #[test]
    fn exact_integers() {
        assert_eq!(number("0").as_i64(), Ok(0));
        assert_eq!(number("-0").as_u64(), Ok(0));
        assert_eq!(number("9223372036854775807").as_i64(), Ok(i64::MAX));
        assert_eq!(number("-9223372036854775808").as_i64(), Ok(i64::MIN));
        assert_eq!(number("9223372036854775808").as_i64(), Err(NumberError::OutOfRange));
        assert_eq!(number("-9223372036854775809").as_i64(), Err(NumberError::OutOfRange));
        assert_eq!(number("18446744073709551615").as_u64(), Ok(u64::MAX));
        assert_eq!(number("18446744073709551616").as_u64(), Err(NumberError::OutOfRange));
        assert_eq!(number("-1").as_u64(), Err(NumberError::OutOfRange));
        assert_eq!(number("1e3").as_u64(), Ok(1000));
        assert_eq!(number("8.0").as_u64(), Ok(8));
        assert_eq!(number("100e-2").as_i64(), Ok(1));
        assert_eq!(number("0.1e1").as_i64(), Ok(1));
        assert_eq!(number("-1.5e1").as_i64(), Ok(-15));
        assert_eq!(number("1.8446744073709551615e19").as_u64(), Ok(u64::MAX));
    }

    #[test]
    fn integer_rejections() {
        assert_eq!(number("1.5").as_i64(), Err(NumberError::NotAnInteger));
        assert_eq!(number("1e-1").as_i64(), Err(NumberError::NotAnInteger));
        assert_eq!(number("1e-99999999999999999999").as_i64(), Err(NumberError::NotAnInteger));
        assert_eq!(number("1e20").as_u64(), Err(NumberError::OutOfRange));
        assert_eq!(number("1e400").as_u64(), Err(NumberError::OutOfRange));
        assert_eq!(number("1e99999999999999999999").as_u64(), Err(NumberError::OutOfRange));
        assert_eq!(
            number("123456789012345678901234567890").as_u64(),
            Err(NumberError::OutOfRange)
        );
        // Zero stays zero whatever its exponent.
        assert_eq!(number("0e99999999999999999999").as_u64(), Ok(0));
        assert_eq!(number("0.000e-5").as_i64(), Ok(0));
    }

    #[test]
    fn floats() {
        assert_eq!(number("0.1").as_f64(), Ok(0.1));
        assert_eq!(number("-2.5e-3").as_f64(), Ok(-0.0025));
        assert_eq!(number("9007199254740993").as_f64(), Ok(9007199254740992.0));
        assert_eq!(number("1e-400").as_f64(), Ok(0.0));
        assert_eq!(number("1e400").as_f64(), Err(NumberError::OutOfRange));
        assert_eq!(number("-1e400").as_f64(), Err(NumberError::OutOfRange));
    }

    #[test]
    fn integer_literal_matches_zig() {
        assert!(number("12").is_integer_literal());
        assert!(number("-12").is_integer_literal());
        assert!(number("0").is_integer_literal());
        assert!(!number("-0").is_integer_literal());
        assert!(!number("1.0").is_integer_literal());
        assert!(!number("1e2").is_integer_literal());
    }
}

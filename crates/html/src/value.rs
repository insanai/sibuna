//! The runtime: escaping, integer formatting and the `Value` trait.
//!
//! Generated snippet functions call `write_value` for every placeholder. Nothing here
//! allocates; output goes straight into the caller's `fmt::Write` sink.
//!
//! This file depends only on `core` (and on `alloc` behind the `alloc` feature), so a
//! test can compile it on its own to check the `HTML007` message rustc prints.

use core::fmt;

/// The five bytes HTML escaping replaces, indexed by byte value: `0` keeps the byte, and
/// any other value `n` selects `ENTITIES[n]`.
const ESCAPE_CLASS: [u8; 256] = escape_classes();

/// The replacement text for each escape class; class 0 is unused.
const ENTITIES: [&str; 6] = ["", "&amp;", "&lt;", "&gt;", "&quot;", "&#39;"];

const fn escape_classes() -> [u8; 256] {
    let mut table = [0u8; 256];
    table[b'&' as usize] = 1;
    table[b'<' as usize] = 2;
    table[b'>' as usize] = 3;
    table[b'"' as usize] = 4;
    table[b'\'' as usize] = 5;
    table
}

/// Writes `text` into `out` with `&`, `<`, `>`, `"` and `'` replaced by `&amp;`, `&lt;`,
/// `&gt;`, `&quot;` and `&#39;`.
///
/// It borrows `text` for the call and allocates nothing: runs without special bytes are
/// written in one `write_str` call each. The result is safe in HTML text and in quoted
/// attribute values; it does not make URLs, scripts or styles safe. It fails only when
/// `out` fails, and the output is then partial.
pub fn escape(out: &mut (impl fmt::Write + ?Sized), text: &str) -> fmt::Result {
    let bytes = text.as_bytes();
    let mut run_start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        let class = ESCAPE_CLASS[usize::from(byte)];
        if class == 0 {
            continue;
        }
        // `index` holds an ASCII byte and `run_start` follows one, so both are character
        // boundaries and `get` cannot fail; the error path exists only to avoid a panic.
        out.write_str(text.get(run_start..index).ok_or(fmt::Error)?)?;
        out.write_str(ENTITIES[usize::from(class)])?;
        run_start = index + 1;
    }
    out.write_str(text.get(run_start..).ok_or(fmt::Error)?)
}

/// Writes one placeholder value into `out`: text escaped, integers in decimal and
/// booleans as `true` or `false`.
///
/// It borrows `value` for the call and allocates nothing. It fails only when `out` fails.
/// Generated snippet functions call it once per placeholder.
pub fn write_value(out: &mut (impl fmt::Write + ?Sized), value: &dyn Value) -> fmt::Result {
    match value.scalar() {
        sealed::Scalar::Text(text) => escape(out, text),
        sealed::Scalar::Bool(true) => out.write_str("true"),
        sealed::Scalar::Bool(false) => out.write_str("false"),
        // Digits and the minus sign need no escaping.
        sealed::Scalar::Integer { negative, magnitude } => write_integer(out, negative, magnitude),
    }
}

/// Room for the 39 digits of `u128::MAX` and a minus sign.
const INTEGER_DIGITS: usize = 40;

/// Writes `magnitude` in decimal, preceded by `-` when `negative`, without allocating.
fn write_integer(
    out: &mut (impl fmt::Write + ?Sized),
    negative: bool,
    magnitude: u128,
) -> fmt::Result {
    let mut digits = [b'0'; INTEGER_DIGITS];
    let mut start = INTEGER_DIGITS;
    let mut wide = magnitude;
    // u128 division is slow, so only the digits above u64 use it.
    while wide > u128::from(u64::MAX) {
        start -= 1;
        digits[start] = b'0' + (wide % 10) as u8;
        wide /= 10;
    }
    let mut rest = u64::try_from(wide).map_err(|_| fmt::Error)?;
    loop {
        // At most 39 digits and one sign fit in 40 bytes, so `start` never underflows.
        start -= 1;
        digits[start] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if negative {
        start -= 1;
        digits[start] = b'-';
    }
    let text = digits.get(start..).ok_or(fmt::Error)?;
    out.write_str(core::str::from_utf8(text).map_err(|_| fmt::Error)?)
}

/// A value a snippet placeholder accepts: text (`str`, `String`, `Cow<str>` and
/// references to them), an integer of any built-in width, or a `bool`.
///
/// The trait is sealed, so these are the only values: there is no raw HTML value and no
/// way to skip escaping. Generated values structs hold `&dyn Value`, so a call site
/// writes `&"text"`, `&count` or `&true`. Any other type fails the build with `HTML007`:
///
/// ```compile_fail,E0277
/// let mut out = String::new();
/// sibuna_html::write_value(&mut out, &1.5_f64).unwrap();
/// ```
#[diagnostic::on_unimplemented(
    message = "HTML007: value must be text, an integer or a boolean",
    label = "`{Self}` is not text, an integer or a boolean",
    note = "HTML007: format this value as text before rendering"
)]
pub trait Value: sealed::Sealed {}

/// The sealing trait and the private view of a value. Code outside this crate can name
/// neither, so it cannot add value types.
mod sealed {
    /// A value reduced to what rendering needs.
    pub enum Scalar<'a> {
        /// Text, escaped on output.
        Text(&'a str),
        /// A boolean, written as `true` or `false`.
        Bool(bool),
        /// An integer as a sign and a magnitude, so every built-in width fits.
        Integer { negative: bool, magnitude: u128 },
    }

    /// Implemented exactly by the types that implement `Value`.
    pub trait Sealed {
        /// Borrows the value as a `Scalar`.
        fn scalar(&self) -> Scalar<'_>;
    }
}

impl sealed::Sealed for str {
    fn scalar(&self) -> sealed::Scalar<'_> {
        sealed::Scalar::Text(self)
    }
}
impl Value for str {}

impl sealed::Sealed for bool {
    fn scalar(&self) -> sealed::Scalar<'_> {
        sealed::Scalar::Bool(*self)
    }
}
impl Value for bool {}

impl<T: Value + ?Sized> sealed::Sealed for &T {
    fn scalar(&self) -> sealed::Scalar<'_> {
        (**self).scalar()
    }
}
impl<T: Value + ?Sized> Value for &T {}

#[cfg(feature = "alloc")]
impl sealed::Sealed for alloc::string::String {
    fn scalar(&self) -> sealed::Scalar<'_> {
        sealed::Scalar::Text(self)
    }
}
#[cfg(feature = "alloc")]
impl Value for alloc::string::String {}

#[cfg(feature = "alloc")]
impl sealed::Sealed for alloc::borrow::Cow<'_, str> {
    fn scalar(&self) -> sealed::Scalar<'_> {
        sealed::Scalar::Text(self)
    }
}
#[cfg(feature = "alloc")]
impl Value for alloc::borrow::Cow<'_, str> {}

/// Implements `Value` for unsigned integer types, which widen to `u128` losslessly.
macro_rules! unsigned_values {
    ($($kind:ty),*) => {$(
        impl sealed::Sealed for $kind {
            fn scalar(&self) -> sealed::Scalar<'_> {
                sealed::Scalar::Integer { negative: false, magnitude: *self as u128 }
            }
        }
        impl Value for $kind {}
    )*};
}

/// Implements `Value` for signed integer types; `unsigned_abs` keeps the minimum exact.
macro_rules! signed_values {
    ($($kind:ty),*) => {$(
        impl sealed::Sealed for $kind {
            fn scalar(&self) -> sealed::Scalar<'_> {
                sealed::Scalar::Integer {
                    negative: *self < 0,
                    magnitude: self.unsigned_abs() as u128,
                }
            }
        }
        impl Value for $kind {}
    )*};
}

unsigned_values!(u8, u16, u32, u64, u128, usize);
signed_values!(i8, i16, i32, i64, i128, isize);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::{String, ToString};
    use std::vec::Vec;

    /// The obvious escaper, one character at a time.
    fn naive_escape(text: &str) -> String {
        let mut out = String::new();
        for character in text.chars() {
            match character {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                other => out.push(other),
            }
        }
        out
    }

    fn escaped(text: &str) -> String {
        let mut out = String::new();
        escape(&mut out, text).unwrap();
        out
    }

    fn rendered(value: &dyn Value) -> String {
        let mut out = String::new();
        write_value(&mut out, value).unwrap();
        out
    }

    #[test]
    fn escape_replaces_the_five_special_bytes_and_keeps_everything_else() {
        assert_eq!(escaped(""), "");
        assert_eq!(escaped("plain"), "plain");
        assert_eq!(escaped("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(escaped("\" onclick='bad' &"), "&quot; onclick=&#39;bad&#39; &amp;");
        assert_eq!(escaped("\u{4e16}\u{754c}<&"), "\u{4e16}\u{754c}&lt;&amp;");
        assert_eq!(escaped("{{ id }}\0\x7f"), "{{ id }}\0\x7f");
    }

    #[test]
    fn integers_print_in_decimal_at_every_width_and_extreme() {
        assert_eq!(rendered(&0_u8), "0");
        assert_eq!(rendered(&i64::MIN), "-9223372036854775808");
        assert_eq!(rendered(&u64::MAX), "18446744073709551615");
        assert_eq!(rendered(&i128::MIN), "-170141183460469231731687303715884105728");
        assert_eq!(rendered(&u128::MAX), "340282366920938463463374607431768211455");
        assert_eq!(rendered(&(u128::from(u64::MAX) + 1)), "18446744073709551616");
        assert_eq!(rendered(&-7_i8), "-7");
        assert_eq!(rendered(&isize::MIN), isize::MIN.to_string());
        assert_eq!(rendered(&usize::MAX), usize::MAX.to_string());
    }

    #[test]
    fn booleans_and_text_references_render_like_their_values() {
        assert_eq!(rendered(&true), "true");
        assert_eq!(rendered(&false), "false");
        assert_eq!(rendered(&"a<b"), "a&lt;b");
        assert_eq!(rendered(&&&"a<b"), "a&lt;b");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_and_borrowed_strings_are_text() {
        let owned = String::from("a<b");
        assert_eq!(rendered(&owned), "a&lt;b");
        let cow = alloc::borrow::Cow::Borrowed("'");
        assert_eq!(rendered(&cow), "&#39;");
    }

    /// A fixed-capacity sink, like Zig's `Writer.fixed`: it fails once full.
    struct Fixed<const N: usize> {
        bytes: [u8; N],
        len: usize,
    }

    impl<const N: usize> fmt::Write for Fixed<N> {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
            let slot = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
            slot.copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    #[test]
    fn escaping_expansion_respects_a_fixed_output_capacity() {
        let mut out = Fixed::<8> { bytes: [0; 8], len: 0 };
        assert_eq!(escape(&mut out, "&&"), Err(fmt::Error));
        let mut out = Fixed::<10> { bytes: [0; 10], len: 0 };
        assert_eq!(escape(&mut out, "&&"), Ok(()));
        assert_eq!(&out.bytes, b"&amp;&amp;");
    }

    /// A xorshift64 generator: deterministic and dependency-free.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Characters weighted towards the special bytes and multi-byte UTF-8.
    const ALPHABET: [char; 14] =
        ['&', '<', '>', '"', '\'', 'a', ' ', '\0', '\u{7f}', '\u{e9}', '\u{4e16}', '{', ';', '#'];

    #[test]
    fn fuzz_escape_agrees_with_the_naive_escaper() {
        let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
        let mut text = String::new();
        let mut fast = String::new();
        for _ in 0..100_000 {
            text.clear();
            let length = random.next() % 40;
            for _ in 0..length {
                let pick = random.next();
                if pick.is_multiple_of(4) {
                    // Any scalar value, to reach every UTF-8 length.
                    let code = u32::try_from(pick >> 40).unwrap() % 0x11_0000;
                    text.push(char::from_u32(code).unwrap_or('x'));
                } else {
                    text.push(ALPHABET[usize::try_from(pick % 14).unwrap()]);
                }
            }
            fast.clear();
            escape(&mut fast, &text).unwrap();
            assert_eq!(fast, naive_escape(&text), "input {text:?}");
        }
    }

    #[test]
    fn fuzz_integers_agree_with_core_formatting() {
        let mut random = XorShift(0x1234_5678_9abc_def1);
        let mut samples: Vec<i128> = Vec::new();
        for _ in 0..100_000 {
            let high = random.next();
            let low = random.next();
            let shift = random.next() % 128;
            let wide = ((i128::from(high) << 64) | i128::from(low)) >> shift;
            samples.push(wide);
        }
        for sample in samples {
            assert_eq!(rendered(&sample), sample.to_string());
            assert_eq!(rendered(&sample.unsigned_abs()), sample.unsigned_abs().to_string());
            let narrow = sample as i64;
            assert_eq!(rendered(&narrow), narrow.to_string());
        }
    }
}

//! Base64 as specified by RFC 4648, identical to Zig 0.16 `std.base64`.
//!
//! The work happens in whole groups: three input bytes become four characters, and four
//! characters become three bytes. The inner loops take four groups at a time (12 bytes, 16
//! characters) and have no data-dependent branch.
//!
//! Encoding looks up twelve bits at a time in a table of character pairs, so a group costs
//! two lookups instead of four. Decoding looks each character up in one of four tables that
//! hold its six bits already shifted to their place in a little-endian word, so a group is
//! four lookups and three ORs. A character outside the alphabet sets the top byte of its
//! entry; the ORed entries of the whole input are checked once at the end. Only the final
//! group, which may carry padding or a partial byte, is handled one character at a time, as
//! Zig does. The tables of both alphabets take about 24 KiB and are built at compile time.

use core::fmt;

/// The decode-table entry for a byte outside the alphabet. Valid entries are below 64, so
/// the top bit tells them apart.
const INVALID: u8 = 0xFF;

/// The shifted-table entry for a byte outside the alphabet. Valid entries use only the low
/// 24 bits, so a non-zero top byte in the OR of many entries means one was invalid.
const INVALID_SHIFTED: u32 = 0xFF00_0000;

/// The padding character of the padded codecs.
const PAD: u8 = b'=';

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const STANDARD_PAIRS: &[[u8; 2]; 4096] = &pair_table(STANDARD_ALPHABET);
const URL_SAFE_PAIRS: &[[u8; 2]; 4096] = &pair_table(URL_SAFE_ALPHABET);

/// Builds the table that maps twelve bits to the two characters encoding them.
const fn pair_table(alphabet: &[u8; 64]) -> [[u8; 2]; 4096] {
    let mut table = [[0; 2]; 4096];
    let mut i = 0;
    while i < 4096 {
        table[i] = [alphabet[i >> 6], alphabet[i & 63]];
        i += 1;
    }
    table
}

const STANDARD_DECODE: &DecodeTables = &DecodeTables::new(STANDARD_ALPHABET);
const URL_SAFE_DECODE: &DecodeTables = &DecodeTables::new(URL_SAFE_ALPHABET);

/// The decode tables of one alphabet, built at compile time.
struct DecodeTables {
    /// The six-bit value of each character, or `INVALID`.
    value: [u8; 256],
    /// For the character at position `k` of a group, its value shifted to where its bits
    /// land in the three decoded bytes read as a little-endian `u32`, or `INVALID_SHIFTED`.
    /// These are the `fast_char_to_index` tables of Zig's decoder.
    shifted: [[u32; 256]; 4],
}

impl DecodeTables {
    const fn new(alphabet: &[u8; 64]) -> DecodeTables {
        let mut tables =
            DecodeTables { value: [INVALID; 256], shifted: [[INVALID_SHIFTED; 256]; 4] };
        let mut index = 0;
        while index < 64 {
            let c = alphabet[index] as usize;
            let v = index as u32;
            tables.value[c] = index as u8;
            // Byte 0 holds bits 2..8 of the first character and the top two bits of the
            // second; byte 1 the low four bits of the second and the top four of the third;
            // byte 2 the low two bits of the third and all six of the fourth.
            tables.shifted[0][c] = v << 2;
            tables.shifted[1][c] = (v >> 4) | (v & 0x0F) << 12;
            tables.shifted[2][c] = (v & 0x03) << 22 | (v & 0x3C) << 6;
            tables.shifted[3][c] = v << 16;
            index += 1;
        }
        tables
    }

    /// Decodes four characters into three bytes in the low 24 bits of a little-endian
    /// word; the top byte is non-zero if a character is outside the alphabet.
    #[inline(always)]
    fn group(&self, chars: [u8; 4]) -> u32 {
        let [t0, t1, t2, t3] = &self.shifted;
        t0[usize::from(chars[0])]
            | t1[usize::from(chars[1])]
            | t2[usize::from(chars[2])]
            | t3[usize::from(chars[3])]
    }
}

/// One of the four base64 codecs: an alphabet, and whether the encoded text is padded with
/// `=` to a multiple of four characters.
///
/// The fields are private so that the alphabet and its tables always agree; use the
/// constants [`STANDARD`], [`STANDARD_NO_PAD`], [`URL_SAFE`] and [`URL_SAFE_NO_PAD`].
#[derive(Clone, Copy)]
pub struct Config {
    alphabet: &'static [u8; 64],
    decode: &'static DecodeTables,
    pairs: &'static [[u8; 2]; 4096],
    padding: bool,
}

// The tables follow from the alphabet, so equality and debug output use only the alphabet
// and the padding flag instead of comparing or printing kilobytes of tables.
impl PartialEq for Config {
    fn eq(&self, other: &Config) -> bool {
        self.alphabet == other.alphabet && self.padding == other.padding
    }
}

impl Eq for Config {}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last_two = [char::from(self.alphabet[62]), char::from(self.alphabet[63])];
        f.debug_struct("Config")
            .field("last_two_characters", &last_two)
            .field("padding", &self.padding)
            .finish()
    }
}

impl Config {
    /// Returns true when this codec pads its output to a multiple of four characters and
    /// requires padding when decoding.
    pub const fn is_padded(self) -> bool {
        self.padding
    }

    /// Returns the 64 characters of this codec's alphabet, in value order.
    pub const fn alphabet(self) -> &'static [u8; 64] {
        self.alphabet
    }
}

/// The standard alphabet (`+` and `/`) with padding, RFC 4648 section 4.
pub const STANDARD: Config = Config {
    alphabet: STANDARD_ALPHABET,
    decode: STANDARD_DECODE,
    pairs: STANDARD_PAIRS,
    padding: true,
};

/// The standard alphabet without padding, RFC 4648 sections 3.2 and 4.
pub const STANDARD_NO_PAD: Config = Config {
    alphabet: STANDARD_ALPHABET,
    decode: STANDARD_DECODE,
    pairs: STANDARD_PAIRS,
    padding: false,
};

/// The URL- and filename-safe alphabet (`-` and `_`) with padding, RFC 4648 section 5.
pub const URL_SAFE: Config = Config {
    alphabet: URL_SAFE_ALPHABET,
    decode: URL_SAFE_DECODE,
    pairs: URL_SAFE_PAIRS,
    padding: true,
};

/// The URL- and filename-safe alphabet without padding. Sibuna's challenge identifiers,
/// tickets and session tokens use this codec.
pub const URL_SAFE_NO_PAD: Config = Config {
    alphabet: URL_SAFE_ALPHABET,
    decode: URL_SAFE_DECODE,
    pairs: URL_SAFE_PAIRS,
    padding: false,
};

/// Why base64 text could not be decoded, or why an output buffer could not hold the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input holds a byte outside the codec's alphabet, or a padding character where
    /// none may appear (anywhere in a codec without padding, or before the last group).
    InvalidCharacter,
    /// The input length is impossible for the codec, the padding is missing, misplaced or of
    /// the wrong length, or the bits after the last whole byte are not zero.
    InvalidPadding,
    /// The output slice is shorter than the encoded or decoded length.
    OutputTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidCharacter => "invalid base64 character",
            Error::InvalidPadding => "invalid base64 padding or length",
            Error::OutputTooSmall => "output buffer too small for base64 data",
        })
    }
}

impl core::error::Error for Error {}

/// Returns the length of the base64 text for `input_len` bytes.
///
/// Padded codecs round up to a multiple of four characters; the others emit two or three
/// characters for a final partial group. Lengths no slice can have (above
/// `usize::MAX / 4 * 3`) saturate at `usize::MAX`, so encoding them reports
/// [`Error::OutputTooSmall`] instead of overflowing.
pub const fn encoded_len(config: Config, input_len: usize) -> usize {
    let whole = (input_len / 3).saturating_mul(4);
    match (input_len % 3, config.padding) {
        (0, _) => whole,
        (_, true) => whole.saturating_add(4),
        (leftover, false) => whole.saturating_add(leftover + 1),
    }
}

/// Encodes `input` into the front of `output` and returns the number of bytes written,
/// which is [`encoded_len`]. Bytes of `output` past that length are left unchanged.
///
/// # Errors
///
/// [`Error::OutputTooSmall`] if `output` is shorter than [`encoded_len`]; nothing is
/// written then.
pub fn encode_to_slice(config: Config, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(config, input.len());
    let output = output.get_mut(..len).ok_or(Error::OutputTooSmall)?;
    let whole = input.len() - input.len() % 3;
    let (body, rest) = input.split_at(whole);
    let (out_body, out_rest) = output.split_at_mut(whole / 3 * 4);
    encode_body(config.pairs, body, out_body);
    encode_rest(config.alphabet, rest, out_rest);
    Ok(len)
}

/// Encodes whole groups of three bytes; `output` holds four characters per group.
fn encode_body(pairs: &[[u8; 2]; 4096], input: &[u8], output: &mut [u8]) {
    let pair_at = |bits: u64, shift: u32| pairs[(bits >> shift) as usize & 0xFFF];
    let (blocks, groups) = input.as_chunks::<12>();
    let (out_blocks, out_groups) = output.as_chunks_mut::<16>();
    for (src, dst) in blocks.iter().zip(out_blocks) {
        // Bytes 0..6 are the top 48 bits of `high`, bytes 6..12 the low 48 bits of `low`.
        let high = u64::from_be_bytes(core::array::from_fn(|i| src[i]));
        let low = u64::from_be_bytes(core::array::from_fn(|i| src[i + 4]));
        let p = [
            pair_at(high, 52),
            pair_at(high, 40),
            pair_at(high, 28),
            pair_at(high, 16),
            pair_at(low, 36),
            pair_at(low, 24),
            pair_at(low, 12),
            pair_at(low, 0),
        ];
        *dst = core::array::from_fn(|k| p[k / 2][k % 2]);
    }
    for (&[a, b, c], dst) in groups.as_chunks::<3>().0.iter().zip(out_groups.as_chunks_mut().0) {
        let group = u64::from(a) << 16 | u64::from(b) << 8 | u64::from(c);
        let ([c0, c1], [c2, c3]) = (pair_at(group, 12), pair_at(group, 0));
        *dst = [c0, c1, c2, c3];
    }
}

/// Encodes the final one or two bytes; `output` is exactly as long as their encoding, so the
/// characters after the data are padding.
fn encode_rest(alphabet: &[u8; 64], rest: &[u8], output: &mut [u8]) {
    let group = match *rest {
        [] => return,
        [a] => u32::from(a) << 16,
        [a, b, ..] => u32::from(a) << 16 | u32::from(b) << 8,
    };
    let data_chars = rest.len() + 1;
    // `index < data_chars <= 3` in the data branch, so `18 - 6 * index` does not underflow.
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = if index < data_chars {
            alphabet[(group >> (18 - 6 * index)) as usize & 63]
        } else {
            PAD
        };
    }
}

/// Returns the exact number of bytes that `input` decodes to.
///
/// Like Zig's `calcSizeForSlice`, this checks the length and counts trailing padding, but
/// does not look at the other characters: [`decode_to_slice`] may still reject the input.
///
/// # Errors
///
/// [`Error::InvalidPadding`] if a padded codec gets a length that is not a multiple of four,
/// or an unpadded codec gets a length of the form `4n + 1`.
pub fn decoded_len(config: Config, input: &[u8]) -> Result<usize, Error> {
    let whole = input.len() / 4 * 3;
    let leftover = input.len() % 4;
    if config.padding {
        if leftover != 0 {
            return Err(Error::InvalidPadding);
        }
        // Zig subtracts one for each of the last two characters that is padding, checking
        // them independently; "AA=A" therefore claims two bytes and fails in decoding.
        // A non-empty input here has at least four characters, so `whole` is at least 3
        // and at least `pads`; an empty one has no padding.
        let pads = input.iter().rev().take(2).filter(|&&c| c == PAD).count();
        Ok(whole.saturating_sub(pads))
    } else if leftover == 1 {
        Err(Error::InvalidPadding)
    } else {
        Ok(whole + leftover * 3 / 4)
    }
}

/// Decodes `input` into the front of `output` and returns the number of bytes written,
/// which is [`decoded_len`].
///
/// Decoding is strict, as in Zig: every character must be in the alphabet, padded codecs
/// require exactly the right padding in the last group, unpadded codecs reject `=`, and the
/// unused low bits of the last character must be zero, so every byte string has exactly one
/// accepted encoding.
///
/// # Errors
///
/// [`Error::InvalidPadding`] or [`Error::InvalidCharacter`] for malformed input, and
/// [`Error::OutputTooSmall`] if `output` is shorter than [`decoded_len`]. On error the
/// contents of `output` are unspecified.
pub fn decode_to_slice(config: Config, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let len = decoded_len(config, input)?;
    let output = output.get_mut(..len).ok_or(Error::OutputTooSmall)?;
    // The last group (up to four characters) may hold padding or a partial byte; every
    // group before it is four alphabet characters.
    let last_len = match input.len() % 4 {
        0 => input.len().min(4),
        leftover => leftover,
    };
    let (body, last) = input.split_at(input.len() - last_len);
    let (out_body, out_last) = output.split_at_mut(body.len() / 4 * 3);
    decode_body(config.decode, body, out_body)?;
    decode_last(config, last, out_last)?;
    Ok(len)
}

/// Decodes whole groups of four alphabet characters; `output` holds three bytes per group.
fn decode_body(tables: &DecodeTables, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let mut seen = 0u32;
    let (blocks, groups) = input.as_chunks::<16>();
    let (out_blocks, out_groups) = output.as_chunks_mut::<12>();
    for (src, dst) in blocks.iter().zip(out_blocks) {
        let words: [u32; 4] = core::array::from_fn(|g| {
            tables.group([src[4 * g], src[4 * g + 1], src[4 * g + 2], src[4 * g + 3]])
        });
        seen |= words[0] | words[1] | words[2] | words[3];
        let bits = u128::from(words[0])
            | u128::from(words[1]) << 24
            | u128::from(words[2]) << 48
            | u128::from(words[3]) << 72;
        let bytes = bits.to_le_bytes();
        *dst = core::array::from_fn(|i| bytes[i]);
    }
    for (&src, dst) in groups.as_chunks::<4>().0.iter().zip(out_groups.as_chunks_mut::<3>().0) {
        let word = tables.group(src);
        seen |= word;
        let bytes = word.to_le_bytes();
        *dst = [bytes[0], bytes[1], bytes[2]];
    }
    if seen & INVALID_SHIFTED != 0 {
        return Err(Error::InvalidCharacter);
    }
    Ok(())
}

/// Decodes the last group, following Zig's tail loop: characters are read up to the first
/// one outside the alphabet, which must be padding in a padded codec; then the unused bits
/// must be zero, and the padding must fill exactly the rest of the group.
fn decode_last(config: Config, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let mut bits = 0u32;
    let mut data_chars = 0;
    for &c in input {
        let value = config.decode.value[usize::from(c)];
        if value == INVALID {
            if config.padding && c == PAD {
                break;
            }
            return Err(Error::InvalidCharacter);
        }
        bits = bits << 6 | u32::from(value);
        data_chars += 1;
    }
    let byte_count = data_chars * 6 / 8;
    let spare_bits = data_chars * 6 % 8;
    if spare_bits > 4 || bits & ((1 << spare_bits) - 1) != 0 {
        return Err(Error::InvalidPadding);
    }
    // `data_chars` counts characters of `input`, so it is at most `input.len()`.
    let padding = input.get(data_chars..).unwrap_or_default();
    if !padding.is_empty()
        && (padding.len() != spare_bits / 2 || padding.iter().any(|&c| c != PAD))
    {
        return Err(Error::InvalidPadding);
    }
    // `decoded_len` sized `output` from the trailing padding; once the padding is valid the
    // two counts agree. Checking keeps a disagreement from writing a wrong length.
    if output.len() != byte_count {
        return Err(Error::InvalidPadding);
    }
    let data = bits >> spare_bits;
    // `index < output.len() == byte_count`, so the shift amount is in 0..24.
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = (data >> (8 * (byte_count - 1 - index))) as u8;
    }
    Ok(())
}

/// Encodes `input` into a new string.
#[cfg(feature = "alloc")]
pub fn encode(config: Config, input: &[u8]) -> alloc::string::String {
    let mut bytes = alloc::vec![0; encoded_len(config, input.len())];
    // The buffer has exactly the encoded length, so encoding cannot fail.
    let written = encode_to_slice(config, input, &mut bytes).unwrap_or(0);
    bytes.truncate(written);
    bytes.into_iter().map(char::from).collect()
}

/// Decodes `input` into a new vector.
///
/// # Errors
///
/// [`Error::InvalidPadding`] or [`Error::InvalidCharacter`] for malformed input; see
/// [`decode_to_slice`].
#[cfg(feature = "alloc")]
pub fn decode(config: Config, input: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut bytes = alloc::vec![0; decoded_len(config, input)?];
    decode_to_slice(config, input, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const ALL: [Config; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];

    fn encode_vec(config: Config, input: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0; encoded_len(config, input.len())];
        let written = encode_to_slice(config, input, &mut out).unwrap();
        assert_eq!(written, out.len());
        out
    }

    fn decode_vec(config: Config, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = std::vec![0; decoded_len(config, input)?];
        let written = decode_to_slice(config, input, &mut out)?;
        assert_eq!(written, out.len());
        Ok(out)
    }

    /// Zig's `testAllApis`: encoding gives `encoded` and decoding gives `decoded` back.
    fn check_all_apis(config: Config, decoded: &str, encoded: &str) {
        assert_eq!(encode_vec(config, decoded.as_bytes()), encoded.as_bytes(), "{decoded:?}");
        assert_eq!(decode_vec(config, encoded.as_bytes()).unwrap(), decoded.as_bytes());
    }

    fn check_error(config: Config, encoded: &str, expected: Error) {
        assert_eq!(decode_vec(config, encoded.as_bytes()), Err(expected), "{encoded:?}");
    }

    /// Zig's `testNoSpaceLeftError`: one byte less than the decoded size is refused.
    fn check_output_too_small(config: Config, encoded: &str) {
        let len = decoded_len(config, encoded.as_bytes()).unwrap();
        let mut out = std::vec![0; len - 1];
        assert_eq!(
            decode_to_slice(config, encoded.as_bytes(), &mut out),
            Err(Error::OutputTooSmall)
        );
    }

    // Port of Zig's `testBase64` (the ignore-space cases are not ported; see the crate
    // documentation).
    #[test]
    fn base64_standard() {
        let c = STANDARD;
        check_all_apis(c, "", "");
        check_all_apis(c, "f", "Zg==");
        check_all_apis(c, "fo", "Zm8=");
        check_all_apis(c, "foo", "Zm9v");
        check_all_apis(c, "foob", "Zm9vYg==");
        check_all_apis(c, "fooba", "Zm9vYmE=");
        check_all_apis(c, "foobar", "Zm9vYmFy");
        check_all_apis(c, "foobarfoobarfoo", "Zm9vYmFyZm9vYmFyZm9v");
        check_all_apis(c, "foobarfoobarfoob", "Zm9vYmFyZm9vYmFyZm9vYg==");
        check_all_apis(c, "foobarfoobarfooba", "Zm9vYmFyZm9vYmFyZm9vYmE=");
        check_all_apis(c, "foobarfoobarfoobar", "Zm9vYmFyZm9vYmFyZm9vYmFy");
        check_all_apis(c, "comptime", "Y29tcHRpbWU=");

        use Error::{InvalidCharacter, InvalidPadding};
        for (encoded, expected) in [
            ("A", InvalidPadding),
            ("AA", InvalidPadding),
            ("AAA", InvalidPadding),
            ("A..A", InvalidCharacter),
            ("AA=A", InvalidPadding),
            ("AA/=", InvalidPadding),
            ("A/==", InvalidPadding),
            ("A===", InvalidPadding),
            ("====", InvalidPadding),
            ("Zm9vYmFyZm9vYmFyA..A", InvalidCharacter),
            ("Zm9vYmFyZm9vYmFyAA=A", InvalidPadding),
            ("Zm9vYmFyZm9vYmFyAA/=", InvalidPadding),
            ("Zm9vYmFyZm9vYmFyA/==", InvalidPadding),
            ("Zm9vYmFyZm9vYmFyA===", InvalidPadding),
            ("A..AZm9vYmFyZm9vYmFy", InvalidCharacter),
            ("Zm9vYmFyZm9vAA=A", InvalidPadding),
            ("Zm9vYmFyZm9vAA/=", InvalidPadding),
            ("Zm9vYmFyZm9vA/==", InvalidPadding),
            ("Zm9vYmFyZm9vA===", InvalidPadding),
        ] {
            check_error(c, encoded, expected);
        }
        for encoded in ["AA==", "AAA=", "AAAA", "AAAAAA=="] {
            check_output_too_small(c, encoded);
        }
        let mut four = [0; 4];
        assert_eq!(decode_to_slice(c, b"AAAAAAAAAAAAAAAA", &mut four), Err(Error::OutputTooSmall));
    }

    // Port of Zig's `testBase64UrlSafeNoPad`.
    #[test]
    fn base64_url_safe_no_pad() {
        let c = URL_SAFE_NO_PAD;
        check_all_apis(c, "", "");
        check_all_apis(c, "f", "Zg");
        check_all_apis(c, "fo", "Zm8");
        check_all_apis(c, "foo", "Zm9v");
        check_all_apis(c, "foob", "Zm9vYg");
        check_all_apis(c, "fooba", "Zm9vYmE");
        check_all_apis(c, "foobar", "Zm9vYmFy");
        check_all_apis(c, "foobarfoobarfoobar", "Zm9vYmFyZm9vYmFyZm9vYmFy");
        check_all_apis(c, "comptime", "Y29tcHRpbWU");

        use Error::{InvalidCharacter, InvalidPadding};
        for (encoded, expected) in [
            ("A", InvalidPadding),
            ("AAA=", InvalidCharacter),
            ("A..A", InvalidCharacter),
            ("AA=A", InvalidCharacter),
            ("AA/=", InvalidCharacter),
            ("A/==", InvalidCharacter),
            ("A===", InvalidCharacter),
            ("====", InvalidCharacter),
            ("Zm9vYmFyZm9vYmFyA..A", InvalidCharacter),
            ("A..AZm9vYmFyZm9vYmFy", InvalidCharacter),
        ] {
            check_error(c, encoded, expected);
        }
        for encoded in ["AA", "AAA", "AAAA", "AAAAAA"] {
            check_output_too_small(c, encoded);
        }
        let mut four = [0; 4];
        assert_eq!(decode_to_slice(c, b"AAAAAAAAAAAAAAAA", &mut four), Err(Error::OutputTooSmall));
    }

    // Port of Zig's "base64 padding dest overflow": bytes past the encoding stay untouched.
    #[test]
    fn padding_does_not_overflow_output() {
        let mut got = [0u8; 128];
        let written = encode_to_slice(URL_SAFE, b"foo", &mut got).unwrap();
        assert_eq!(&got[..written], b"Zm9v");
        assert!(got[written..].iter().all(|&b| b == 0));
        let mut got = [0u8; 16];
        let written = encode_to_slice(URL_SAFE, b"f", &mut got).unwrap();
        assert_eq!(&got[..written], b"Zg==");
        assert!(got[written..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rfc4648_vectors() {
        let vectors = [
            ("", "", ""),
            ("f", "Zg==", "Zg"),
            ("fo", "Zm8=", "Zm8"),
            ("foo", "Zm9v", "Zm9v"),
            ("foob", "Zm9vYg==", "Zm9vYg"),
            ("fooba", "Zm9vYmE=", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy", "Zm9vYmFy"),
        ];
        for (plain, padded, unpadded) in vectors {
            check_all_apis(STANDARD, plain, padded);
            check_all_apis(URL_SAFE, plain, padded);
            check_all_apis(STANDARD_NO_PAD, plain, unpadded);
            check_all_apis(URL_SAFE_NO_PAD, plain, unpadded);
        }
    }

    #[test]
    fn alphabets_differ_only_in_the_last_two_characters() {
        let input = [0xfb, 0xff, 0xbf];
        assert_eq!(encode_vec(STANDARD, &input), b"+/+/");
        assert_eq!(encode_vec(URL_SAFE, &input), b"-_-_");
        check_error(STANDARD, "-_-_", Error::InvalidCharacter);
        check_error(URL_SAFE, "+/+/", Error::InvalidCharacter);
    }

    #[test]
    fn round_trips_every_length_up_to_300() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 13) as u8).collect();
        for config in ALL {
            for len in 0..=300 {
                let encoded = encode_vec(config, &data[..len]);
                assert_eq!(encoded.len(), encoded_len(config, len));
                assert_eq!(decode_vec(config, &encoded).unwrap(), &data[..len], "{len}");
            }
        }
    }

    #[test]
    fn rejects_non_zero_trailing_bits() {
        // "Zg==" is canonical for "f"; "Zh==" sets one of the four unused bits.
        check_error(STANDARD, "Zh==", Error::InvalidPadding);
        check_error(STANDARD_NO_PAD, "Zh", Error::InvalidPadding);
        check_error(STANDARD, "Zm9=", Error::InvalidPadding);
        check_error(URL_SAFE_NO_PAD, "Zm9", Error::InvalidPadding);
    }

    #[test]
    fn rejects_padding_in_the_wrong_place() {
        check_error(STANDARD, "Zg==Zg==", Error::InvalidCharacter);
        check_error(STANDARD, "Zg=", Error::InvalidPadding);
        check_error(STANDARD, "Zg===", Error::InvalidPadding);
        check_error(STANDARD, "Zm8=Zm8=", Error::InvalidCharacter);
        check_error(STANDARD_NO_PAD, "Zg==", Error::InvalidCharacter);
        check_error(URL_SAFE_NO_PAD, "Zm8=", Error::InvalidCharacter);
        check_error(STANDARD, "Zm9v\n", Error::InvalidPadding);
        check_error(STANDARD, "Zm9v Zm9v", Error::InvalidPadding);
        check_error(STANDARD, "Zm9v Zm9", Error::InvalidCharacter);
        check_error(STANDARD, "Zm 9", Error::InvalidCharacter);
        check_error(STANDARD, "Zm9\u{0}", Error::InvalidCharacter);
    }

    #[test]
    fn short_encode_output_is_refused() {
        let mut out = [0; 3];
        assert_eq!(encode_to_slice(STANDARD, b"foo", &mut out), Err(Error::OutputTooSmall));
        assert_eq!(
            encode_to_slice(STANDARD_NO_PAD, b"f", &mut out[..1]),
            Err(Error::OutputTooSmall)
        );
    }

    #[test]
    fn decoded_len_counts_padding_like_zig() {
        assert_eq!(decoded_len(STANDARD, b""), Ok(0));
        assert_eq!(decoded_len(STANDARD, b"AA=A"), Ok(2));
        assert_eq!(decoded_len(STANDARD, b"A=AA"), Ok(3));
        assert_eq!(decoded_len(STANDARD, b"AAA"), Err(Error::InvalidPadding));
        assert_eq!(decoded_len(URL_SAFE_NO_PAD, b"AAAAA"), Err(Error::InvalidPadding));
        assert_eq!(decoded_len(URL_SAFE_NO_PAD, b"AAAAAA"), Ok(4));
        assert_eq!(decoded_len(URL_SAFE_NO_PAD, b"AAAAAAA"), Ok(5));
    }

    /// FNV-1a, 64 bits: a compact digest of many decode outcomes.
    struct Fnv(u64);

    impl Fnv {
        fn bytes(&mut self, data: &[u8]) {
            for &b in data {
                self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x100000001b3);
            }
        }
    }

    fn record_outcome(config: Config, input: &[u8], fnv: &mut Fnv) {
        match decode_vec(config, input) {
            Ok(bytes) => {
                fnv.bytes(&[0]);
                fnv.bytes(&bytes);
            }
            Err(Error::InvalidCharacter) => fnv.bytes(&[1]),
            Err(Error::InvalidPadding) => fnv.bytes(&[2]),
            Err(Error::OutputTooSmall) => fnv.bytes(&[3]),
        }
    }

    // Every string over "ABQ/-=." up to length 7, and up to length 5 after four prefixes
    // (valid, invalid character, early padding, longer valid), decoded with each codec; the
    // outcome digests come from the same enumeration run against Zig 0.16 std.base64
    // (`calcSizeForSlice`, then `Decoder.decode`), so the accepted set, the decoded bytes
    // and the error kinds all agree.
    #[test]
    fn decoding_matches_zig_exhaustively() {
        let expected = [
            (STANDARD, 0x25419a15d67a1d7b_u64),
            (STANDARD_NO_PAD, 0x8e6b1829077130f4),
            (URL_SAFE, 0x23500f3c4461a263),
            (URL_SAFE_NO_PAD, 0xe77f155e3e892a96),
        ];
        let set = b"ABQ/-=.";
        let prefixes: [&[u8]; 5] =
            [b"", b"Zm9vYmFy", b"Zm9vYm.y", b"Zm9=YmFy", b"Zm9vYmFyZm9vYmFyZm9vYmFy"];
        for (config, digest) in expected {
            let mut fnv = Fnv(0xcbf29ce484222325);
            let mut input = Vec::new();
            for prefix in prefixes {
                let max_len = if prefix.is_empty() { 7 } else { 5 };
                for len in 0..=max_len {
                    for mut k in 0..set.len().pow(len) {
                        input.clear();
                        input.extend_from_slice(prefix);
                        for _ in 0..len {
                            input.push(set[k % set.len()]);
                            k /= set.len();
                        }
                        record_outcome(config, &input, &mut fnv);
                    }
                }
            }
            assert_eq!(fnv.0, digest, "{config:?}");
        }
    }

    // Digests of the encodings of bytes `i * 31 + 7` for every length 0..=300, each
    // followed by a newline, from Zig 0.16 std.base64 `Encoder.encode`.
    #[test]
    fn encoding_matches_zig() {
        let expected = [
            (STANDARD, 0x9821ef23e85208b1_u64),
            (STANDARD_NO_PAD, 0x43c9b4483897f0d1),
            (URL_SAFE, 0x3772b8b96c1aef0b),
            (URL_SAFE_NO_PAD, 0x48d61234e7bc544f),
        ];
        let data: Vec<u8> = (0..300usize).map(|i| (i * 31 + 7) as u8).collect();
        for (config, digest) in expected {
            let mut fnv = Fnv(0xcbf29ce484222325);
            for len in 0..=300 {
                fnv.bytes(&encode_vec(config, &data[..len]));
                fnv.bytes(b"\n");
            }
            assert_eq!(fnv.0, digest, "{config:?}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn allocating_helpers() {
        assert_eq!(encode(STANDARD, b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(URL_SAFE_NO_PAD, &[0xfb, 0xff]), "-_8");
        assert_eq!(decode(URL_SAFE_NO_PAD, b"-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(decode(STANDARD, b"Zg="), Err(Error::InvalidPadding));
    }
}

/// Deterministic fuzzing: random and mutated inputs against a naive reference decoder.
#[cfg(test)]
mod fuzz {
    use super::*;
    use std::vec::Vec;

    const ALL: [Config; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];

    /// Marsaglia's xorshift64: small, fast and reproducible from its seed.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound.max(1) as u64) as usize
        }

        /// Returns random bytes, fewer than `max` of them.
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let len = self.below(max);
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    /// Decodes the obvious way, one character at a time, under RFC 4648's strict rules:
    /// exact padding, characters from the alphabet only, and zero bits after the last byte.
    fn reference_decode(config: Config, input: &[u8]) -> Option<Vec<u8>> {
        let mut data = input;
        if config.is_padded() {
            if !input.len().is_multiple_of(4) {
                return None;
            }
            let pads = input.iter().rev().take_while(|&&c| c == PAD).count();
            data = &input[..input.len() - pads];
            let expected = match data.len() % 4 {
                0 => 0,
                2 => 2,
                3 => 1,
                _ => return None,
            };
            if pads != expected {
                return None;
            }
        } else if data.len() % 4 == 1 {
            return None;
        }
        let (mut bits, mut bit_count, mut out) = (0u32, 0, Vec::new());
        for &c in data {
            let value = config.alphabet().iter().position(|&a| a == c)?;
            bits = bits << 6 | value as u32;
            bit_count += 6;
            if bit_count >= 8 {
                bit_count -= 8;
                out.push((bits >> bit_count) as u8);
                bits &= (1 << bit_count) - 1;
            }
        }
        (bits == 0).then_some(out)
    }

    /// Applies one to three random edits: bit flips, characters that matter to the decoder,
    /// truncation, duplication of a range, and splicing with another encoding.
    fn mutate(rng: &mut XorShift, input: &mut Vec<u8>, other: &[u8]) {
        const INTERESTING: &[u8] = b"=AQgw+/-_. \n\xff\x00";
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(input.len() + 1);
            match rng.below(6) {
                0 if at < input.len() => input[at] ^= 1 << rng.below(8),
                1 if at < input.len() => input[at] = INTERESTING[rng.below(INTERESTING.len())],
                2 => input.truncate(at),
                3 => {
                    let end = at + rng.below(input.len() - at + 1);
                    let copy = input[at..end].to_vec();
                    input.splice(at..at, copy);
                }
                4 => {
                    let from = rng.below(other.len() + 1);
                    input.truncate(at);
                    input.extend_from_slice(&other[from..]);
                }
                _ => input.insert(at, INTERESTING[rng.below(INTERESTING.len())]),
            }
        }
    }

    /// Checks one input against every invariant: no panic, agreement with the reference,
    /// `decoded_len` equal to the bytes written, and no write past the decoded length.
    fn check(config: Config, input: &[u8]) {
        const SENTINEL: u8 = 0xA5;
        let expected = reference_decode(config, input);
        let mut out = std::vec![SENTINEL; input.len() + 8];
        let result = decode_to_slice(config, input, &mut out);
        match (&result, &expected) {
            (Ok(written), Some(bytes)) => {
                assert_eq!(&out[..*written], bytes.as_slice(), "{input:?}");
                assert_eq!(decoded_len(config, input), Ok(*written));
                assert_eq!(encode_vec(config, bytes), input, "not canonical: {input:?}");
            }
            (Err(_), None) => {}
            _ => panic!("{config:?} {input:?}: got {result:?}, reference {expected:?}"),
        }
        // Whatever the outcome, nothing past the decoded length (or the whole buffer when
        // the length is invalid) is touched.
        let limit = decoded_len(config, input).unwrap_or(0);
        assert!(out[limit..].iter().all(|&b| b == SENTINEL), "{input:?}");
    }

    fn encode_vec(config: Config, input: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0; encoded_len(config, input.len())];
        let written = encode_to_slice(config, input, &mut out).unwrap();
        assert_eq!(written, out.len());
        out
    }

    fn run(seed: u64, rounds: usize) {
        let mut rng = XorShift(seed);
        for round in 0..rounds {
            let config = ALL[round % 4];
            let data = rng.bytes(100);
            let encoded = encode_vec(config, &data);
            assert_eq!(reference_decode(config, &encoded).as_deref(), Some(&data[..]));
            check(config, &encoded);
            let other = encode_vec(config, &rng.bytes(40));
            let mut mutated = encoded;
            mutate(&mut rng, &mut mutated, &other);
            check(config, &mutated);
            let noise = rng.bytes(24);
            check(config, &noise);
        }
    }

    // 100,000 rounds of three inputs each: a valid encoding, a mutation of it, and noise.
    #[test]
    fn mutated_inputs_agree_with_reference() {
        run(0x9E37_79B9_7F4A_7C15, 100_000);
    }

    #[test]
    #[ignore = "heavy fuzz run; use `cargo test --release -- --ignored`"]
    fn mutated_inputs_agree_with_reference_long() {
        for seed in 1..=20 {
            run(seed * 0x2545_F491_4F6C_DD1D, 1_000_000);
        }
    }
}

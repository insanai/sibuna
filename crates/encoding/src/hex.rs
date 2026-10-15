//! Hexadecimal encoding, lowercase like Zig's `std.fmt.bytesToHex(.., .lower)`, and decoding
//! of either case like `std.fmt.hexToBytes`.

use core::fmt;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The decode-table entry for a byte that is not a hexadecimal digit.
const INVALID: u8 = 0xFF;

const DECODE: &[u8; 256] = &decode_table();

/// Why hexadecimal text could not be decoded, or why an output buffer has the wrong size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input has an odd length, or the output is not exactly the encoded or decoded
    /// length.
    InvalidLength,
    /// The input holds a byte that is not a hexadecimal digit.
    InvalidCharacter,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "invalid hexadecimal length",
            Error::InvalidCharacter => "invalid hexadecimal character",
        })
    }
}

impl core::error::Error for Error {}

const fn decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut value = 0;
    while value < 16 {
        table[DIGITS[value] as usize] = value as u8;
        table[DIGITS[value].to_ascii_uppercase() as usize] = value as u8;
        value += 1;
    }
    table
}

/// Writes the lowercase hexadecimal form of `input` into `output`, two digits per byte.
///
/// # Errors
///
/// [`Error::InvalidLength`] unless `output` is exactly twice as long as `input`; nothing is
/// written then.
pub fn encode_to_slice(input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let (pairs, []) = output.as_chunks_mut::<2>() else {
        return Err(Error::InvalidLength);
    };
    if pairs.len() != input.len() {
        return Err(Error::InvalidLength);
    }
    for (&byte, pair) in input.iter().zip(pairs) {
        *pair = [DIGITS[usize::from(byte >> 4)], DIGITS[usize::from(byte & 0x0F)]];
    }
    Ok(())
}

/// Decodes hexadecimal text of either case from `input` into `output`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `input` has an odd length or `output` is not exactly half as
/// long as `input` (nothing is written then), and [`Error::InvalidCharacter`] if a byte is
/// not a hexadecimal digit (the contents of `output` are then unspecified).
pub fn decode_to_slice(input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let (pairs, []) = input.as_chunks::<2>() else {
        return Err(Error::InvalidLength);
    };
    if pairs.len() != output.len() {
        return Err(Error::InvalidLength);
    }
    // Valid digits are below 16, so a set top bit in the OR of all lookups means at least
    // one byte was not a digit; one check after the loop replaces one branch per byte.
    let mut seen = 0u8;
    for (&[high, low], slot) in pairs.iter().zip(output.iter_mut()) {
        let high = DECODE[usize::from(high)];
        let low = DECODE[usize::from(low)];
        seen |= high | low;
        *slot = high << 4 | (low & 0x0F);
    }
    if seen & 0x80 != 0 {
        return Err(Error::InvalidCharacter);
    }
    Ok(())
}

/// Returns the lowercase hexadecimal form of `input`.
#[cfg(feature = "alloc")]
pub fn encode(input: &[u8]) -> alloc::string::String {
    let mut text = alloc::string::String::with_capacity(input.len().saturating_mul(2));
    for &byte in input {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    text
}

/// Decodes hexadecimal text of either case into a new vector.
///
/// # Errors
///
/// [`Error::InvalidLength`] for an odd length and [`Error::InvalidCharacter`] for a byte
/// that is not a hexadecimal digit.
#[cfg(feature = "alloc")]
pub fn decode(input: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    if !input.len().is_multiple_of(2) {
        return Err(Error::InvalidLength);
    }
    let mut bytes = alloc::vec![0; input.len() / 2];
    decode_to_slice(input, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lowercase() {
        let mut out = [0; 8];
        encode_to_slice(&[0x00, 0x9f, 0xa0, 0xff], &mut out).unwrap();
        assert_eq!(&out, b"009fa0ff");
        encode_to_slice(&[], &mut []).unwrap();
    }

    #[test]
    fn decodes_either_case() {
        let mut out = [0; 4];
        decode_to_slice(b"009FA0ff", &mut out).unwrap();
        assert_eq!(out, [0x00, 0x9f, 0xa0, 0xff]);
        decode_to_slice(b"", &mut []).unwrap();
    }

    #[test]
    fn round_trips_every_byte() {
        let input: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut text = [0; 512];
        encode_to_slice(&input, &mut text).unwrap();
        let mut back = [0; 256];
        decode_to_slice(&text, &mut back).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn rejects_bad_lengths_and_characters() {
        let mut out = [0; 2];
        assert_eq!(decode_to_slice(b"abc", &mut out), Err(Error::InvalidLength));
        assert_eq!(decode_to_slice(b"ab", &mut out), Err(Error::InvalidLength));
        assert_eq!(decode_to_slice(b"abcdef", &mut out), Err(Error::InvalidLength));
        assert_eq!(decode_to_slice(b"0g12", &mut out), Err(Error::InvalidCharacter));
        assert_eq!(decode_to_slice(b"12 3", &mut out), Err(Error::InvalidCharacter));
        assert_eq!(decode_to_slice(b"+123", &mut out), Err(Error::InvalidCharacter));
        assert_eq!(decode_to_slice(b"12\xff3", &mut out), Err(Error::InvalidCharacter));
        assert_eq!(encode_to_slice(&[1], &mut out[..1]), Err(Error::InvalidLength));
        assert_eq!(encode_to_slice(&[1], &mut [0; 3]), Err(Error::InvalidLength));
        // Every byte that is not a hexadecimal digit is rejected in either position.
        for byte in 0..=255u8 {
            let valid = byte.is_ascii_hexdigit();
            assert_eq!(decode_to_slice(&[byte, b'0'], &mut out[..1]).is_ok(), valid);
            assert_eq!(decode_to_slice(&[b'0', byte], &mut out[..1]).is_ok(), valid);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn allocating_helpers() {
        assert_eq!(encode(b"\x01\xab"), "01ab");
        assert_eq!(decode(b"01AB").unwrap(), [0x01, 0xab]);
        assert_eq!(decode(b"01A"), Err(Error::InvalidLength));
    }
}

/// Deterministic fuzzing against a naive reference decoder.
#[cfg(test)]
mod fuzz {
    use super::*;
    use std::vec::Vec;

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
    }

    /// Decodes pair by pair with `char::to_digit`, accepting only ASCII hex digits.
    fn reference_decode(input: &[u8]) -> Option<Vec<u8>> {
        if !input.len().is_multiple_of(2) {
            return None;
        }
        let digit = |b: u8| char::from(b).to_digit(16).filter(|_| b.is_ascii_hexdigit());
        input.chunks(2).map(|pair| Some((digit(pair[0])? << 4 | digit(pair[1])?) as u8)).collect()
    }

    fn check(input: &[u8]) {
        const SENTINEL: u8 = 0x5A;
        let expected = reference_decode(input);
        // One spare byte beyond the decoded length must never be written.
        let mut out = std::vec![SENTINEL; input.len() / 2 + 1];
        let (exact, spare) = out.split_at_mut(input.len() / 2);
        let result = decode_to_slice(input, exact);
        match (&result, &expected) {
            (Ok(()), Some(bytes)) => {
                assert_eq!(exact, bytes.as_slice());
                let mut text = std::vec![0; input.len()];
                encode_to_slice(bytes, &mut text).unwrap();
                assert_eq!(text, input.to_ascii_lowercase());
            }
            (Err(_), None) => {}
            _ => panic!("{input:?}: got {result:?}, reference {expected:?}"),
        }
        assert_eq!(spare, [SENTINEL]);
    }

    #[test]
    fn mutated_inputs_agree_with_reference() {
        const CHARS: &[u8] = b"0123456789abcdefABCDEFgG/:@`\xff\x00 ";
        let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
        for _ in 0..100_000 {
            let len = rng.below(40);
            let mut input: Vec<u8> = (0..len).map(|_| CHARS[rng.below(16)]).collect();
            check(&input);
            if !input.is_empty() {
                let at = rng.below(input.len());
                match rng.below(3) {
                    0 => input[at] ^= 1 << rng.below(8),
                    1 => input[at] = CHARS[rng.below(CHARS.len())],
                    _ => input.truncate(at),
                }
            }
            check(&input);
        }
    }
}

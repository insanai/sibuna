//! Canonical unpadded base64url (RFC 4648, section 5), as JDD 0004 requires.
//!
//! Decoding is strict: no padding, no whitespace, no characters outside the alphabet,
//! and no nonzero bits in the final partial group, so every byte string has exactly one
//! accepted spelling.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Appends the unpadded base64url spelling of `data` to `out`.
pub fn encode_into(out: &mut String, data: &[u8]) {
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let digits = chunk.len() + 1;
        for i in 0..digits {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
}

/// The unpadded base64url spelling of `data`.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    encode_into(&mut out, data);
    out
}

/// The bytes `text` spells, or `None` when it is not canonical unpadded base64url.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u32> = text.bytes().map(digit).collect::<Option<_>>()?;
    if digits.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    for group in digits.chunks(4) {
        let n = group.iter().enumerate().fold(0u32, |n, (i, d)| n | (d << (18 - 6 * i)));
        let bytes = group.len() - 1;
        let unused_bits = 24 - 8 * bytes as u32;
        if group.len() < 4 && n & ((1 << unused_bits) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

fn digit(c: u8) -> Option<u32> {
    let d = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_matches_the_report() {
        assert_eq!(encode(&[0, 255]), "AP8");
        assert_eq!(decode("AP8").unwrap(), [0, 255]);
        for len in 0..10 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 250) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn noncanonical_spellings_are_refused() {
        assert!(decode("AP8=").is_none());
        assert!(decode("AP9").is_none());
        assert!(decode("A").is_none());
        assert!(decode("AP 8").is_none());
        assert!(decode("+/8").is_none());
    }
}

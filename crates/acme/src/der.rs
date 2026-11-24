//! The few DER elements that a certificate request and a certificate need: a writer that
//! returns bytes, and a reader that never reads past its input.

/// `SEQUENCE`.
pub(crate) const SEQUENCE: u8 = 0x30;
/// `SET`.
pub(crate) const SET: u8 = 0x31;
/// `INTEGER`.
pub(crate) const INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub(crate) const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
pub(crate) const OID: u8 = 0x06;
/// `UTF8String`.
pub(crate) const UTF8_STRING: u8 = 0x0c;
/// `UTCTime`.
pub(crate) const UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub(crate) const GENERALIZED_TIME: u8 = 0x18;

/// Writes one element: the tag, the length in its shortest form, and the content.
pub(crate) fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(bytes.get(skip..).unwrap_or_default());
    }
    out.extend_from_slice(content);
    out
}

/// Writes a constructed element with the given parts as its content.
pub(crate) fn constructed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    element(tag, &parts.concat())
}

/// Writes a `SEQUENCE` of the given parts.
pub(crate) fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    constructed(SEQUENCE, parts)
}

/// Writes a non-negative `INTEGER` from big-endian bytes.
pub(crate) fn integer(bytes: &[u8]) -> Vec<u8> {
    let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
    let digits = bytes.get(skip..).unwrap_or_default();
    let mut content = Vec::with_capacity(digits.len() + 1);
    // A leading zero keeps a number with its top bit set positive.
    if digits.first().is_none_or(|&byte| byte & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(digits);
    element(INTEGER, &content)
}

/// Writes a `BIT STRING` of whole bytes.
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0);
    content.extend_from_slice(bytes);
    element(BIT_STRING, &content)
}

/// Reads one element: its tag, its content and the bytes after it. Returns `None` for a
/// truncated element, an indefinite length or a length of more than four bytes.
pub(crate) fn read(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (digits, rest) = rest.split_at(count);
        (digits.iter().fold(0usize, |n, &b| (n << 8) | usize::from(b)), rest)
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// Reads one element with its tag and length bytes: the whole element and the bytes
/// after it.
pub(crate) fn read_raw(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, rest) = read(der)?;
    Some(der.split_at(der.len() - rest.len()))
}

/// The elements inside the content of a constructed element. It ends at the first
/// element that cannot be read.
pub(crate) fn children(mut content: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, value, rest) = read(content)?;
        content = rest;
        Some((tag, value))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn lengths_take_their_shortest_form() {
        assert_eq!(element(0x04, &[7]), [0x04, 0x01, 7]);
        assert_eq!(element(0x04, &[0; 127])[..2], [0x04, 0x7f]);
        assert_eq!(element(0x04, &[0; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(element(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn integers_are_positive_and_minimal() {
        assert_eq!(integer(&[0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0, 0, 5]), [0x02, 0x01, 0x05]);
        assert_eq!(integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn the_reader_refuses_what_it_cannot_bound() {
        assert!(read(&[0x30]).is_none());
        assert!(read(&[0x30, 0x05, 1, 2]).is_none());
        assert!(read(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
        assert!(read(&[0x30, 0x80]).is_none());
        assert_eq!(read(&[0x04, 0x01, 7, 9]), Some((0x04, &[7][..], &[9][..])));
        let written = sequence(&[&integer(&[1]), &bit_string(&[2, 3])]);
        let (tag, content, rest) = read(&written).unwrap();
        assert_eq!((tag, rest.len()), (SEQUENCE, 0));
        let parts: Vec<_> = children(content).collect();
        assert_eq!(parts, [(INTEGER, &[1][..]), (BIT_STRING, &[0, 2, 3][..])]);
    }
}

//! Byte-level helpers shared by the request and response code: CRLF line splitting, header
//! lines, comma-separated token lists and Zig's integer syntax.

/// The pieces of `text` between CRLF sequences, as Zig's `splitSequence(text, "\r\n")`
/// yields them: `"a\r\n"` gives `"a"` and then `""`.
pub(crate) struct CrlfLines<'a> {
    rest: Option<&'a [u8]>,
}

/// Splits `text` at every CRLF.
pub(crate) fn crlf_lines(text: &[u8]) -> CrlfLines<'_> {
    CrlfLines { rest: Some(text) }
}

impl<'a> Iterator for CrlfLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.rest?;
        match find_crlf(rest) {
            Some(index) => {
                self.rest = rest.get(index + 2..);
                rest.get(..index)
            }
            None => {
                self.rest = None;
                Some(rest)
            }
        }
    }
}

/// The index of the first CRLF in `text`.
pub(crate) fn find_crlf(text: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(offset) = text.get(from..)?.iter().position(|&byte| byte == b'\r') {
        let index = from + offset;
        if text.get(index + 1) == Some(&b'\n') {
            return Some(index);
        }
        from = index + 1;
    }
    None
}

/// The index of the first blank line (`CRLF CRLF`) in `text`.
pub(crate) fn find_blank_line(text: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(offset) = text.get(from..).and_then(find_crlf) {
        let index = from + offset;
        if text.get(index + 2..index + 4) == Some(b"\r\n") {
            return Some(index);
        }
        from = index + 1;
    }
    None
}

/// The index of the first `byte` in `text`.
pub(crate) fn find_byte(text: &[u8], byte: u8) -> Option<usize> {
    text.iter().position(|&candidate| candidate == byte)
}

/// `text` without leading and trailing SP and HTAB.
pub(crate) fn trim_ws(text: &[u8]) -> &[u8] {
    let is_ws = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let start = text.iter().position(|byte| !is_ws(byte)).unwrap_or(text.len());
    let end = text.iter().rposition(|byte| !is_ws(byte)).map_or(start, |last| last + 1);
    text.get(start..end).unwrap_or_default()
}

/// The value of a header line whose name (trimmed of SP and HTAB) is `name` in any case,
/// itself trimmed of SP and HTAB. `None` for another name or a line without a colon.
pub(crate) fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = find_byte(line, b':')?;
    let (field, rest) = line.split_at_checked(colon)?;
    if !trim_ws(field).eq_ignore_ascii_case(name) {
        return None;
    }
    Some(trim_ws(rest.get(1..).unwrap_or_default()))
}

/// True when the comma-separated `list` holds `wanted` (any case, trimmed of SP and HTAB).
pub(crate) fn has_token(list: &[u8], wanted: &[u8]) -> bool {
    list.split(|&byte| byte == b',').any(|token| trim_ws(token).eq_ignore_ascii_case(wanted))
}

/// Parses an unsigned integer with the syntax of Zig's `std.fmt.parseInt(u64, text, radix)`
/// for a radix of 10 or 16: one optional `+` or `-` sign, digits of the radix in any case,
/// and `_` between digits but not first or last. A negative number parses only when it is
/// zero. Returns `None` for any other text or on overflow.
pub(crate) fn parse_zig_unsigned(text: &[u8], radix: u32) -> Option<u64> {
    let (negative, digits) = match text.split_first()? {
        (b'+', rest) => (false, rest),
        (b'-', rest) => (true, rest),
        _ => (false, text),
    };
    if digits.first()? == &b'_' || digits.last()? == &b'_' {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in digits.iter().filter(|&&byte| byte != b'_') {
        let digit = char::from(byte).to_digit(radix)?;
        if negative {
            // Zig accumulates a negative number by subtraction: only zeros stay in range.
            if digit != 0 {
                return None;
            }
            continue;
        }
        value = value.checked_mul(u64::from(radix))?.checked_add(u64::from(digit))?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_like_zig() {
        let pieces: Vec<&[u8]> = crlf_lines(b"a\r\nb\rc\r\n\r\n").collect();
        assert_eq!(pieces, [&b"a"[..], b"b\rc", b"", b""]);
        assert_eq!(crlf_lines(b"").collect::<Vec<_>>(), [&b""[..]]);
        assert_eq!(find_blank_line(b"x\r\n\r\r\n\r\n"), Some(4));
        assert_eq!(find_blank_line(b"x\r\n\r\n"), Some(1));
        assert_eq!(find_blank_line(b"x\r\n\r"), None);
    }

    #[test]
    fn header_lines_and_tokens() {
        assert_eq!(header_value(b" Content-Length \t: 5 ", b"content-length"), Some(&b"5"[..]));
        assert_eq!(header_value(b"Content-Type: x", b"content-length"), None);
        assert_eq!(header_value(b"no colon", b"no colon"), None);
        assert!(has_token(b"keep-alive, Upgrade", b"upgrade"));
        assert!(!has_token(b"keep-alive,upgrades", b"upgrade"));
    }

    /// Expected values follow Zig 0.16 `std.fmt.parseInt` and its own tests.
    #[test]
    fn integers_follow_zig_parse_int() {
        assert_eq!(parse_zig_unsigned(b"255", 10), Some(255));
        assert_eq!(parse_zig_unsigned(b"+10", 10), Some(10));
        assert_eq!(parse_zig_unsigned(b"-0", 10), Some(0));
        assert_eq!(parse_zig_unsigned(b"-0_0", 10), Some(0));
        assert_eq!(parse_zig_unsigned(b"-10", 10), None);
        assert_eq!(parse_zig_unsigned(b"1_0", 10), Some(10));
        assert_eq!(parse_zig_unsigned(b"1__0", 10), Some(10));
        assert_eq!(parse_zig_unsigned(b"_10", 10), None);
        assert_eq!(parse_zig_unsigned(b"10_", 10), None);
        assert_eq!(parse_zig_unsigned(b" 10", 10), None);
        assert_eq!(parse_zig_unsigned(b"", 10), None);
        assert_eq!(parse_zig_unsigned(b"+", 10), None);
        assert_eq!(parse_zig_unsigned(b"-", 10), None);
        assert_eq!(parse_zig_unsigned(b"aF", 16), Some(0xaf));
        assert_eq!(parse_zig_unsigned(b"ag", 16), None);
        assert_eq!(parse_zig_unsigned(b"ffffffffffffffff", 16), Some(u64::MAX));
        assert_eq!(parse_zig_unsigned(b"10000000000000000", 16), None);
        assert_eq!(parse_zig_unsigned(b"18446744073709551616", 10), None);
    }
}

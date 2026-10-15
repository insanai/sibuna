//! The content encodings of canonicalisation: JSON (and JavaScript) string escapes and HTML
//! character references. Both turn several input bytes into one, so they share the
//! pipeline's buffer like the other stages.
//!
//! Only escapes that denote ASCII are decoded, because every signature and detector is
//! ASCII; any other escape is copied as it stands. A malformed escape is copied too, one
//! byte at a time, so each input byte is examined a bounded number of times.

use super::{Buffers, hex_value};

/// A decoded escape: the byte it denotes and the input bytes it spans.
struct Escape {
    byte: u8,
    len: usize,
}

/// Runs a decoding stage: at each byte equal to `marker`, `decode` may recognise an escape
/// starting there; every other byte is copied. Returns the output length.
fn decode_escapes(
    io: &mut impl Buffers,
    marker: u8,
    decode: impl Fn(&dyn Buffers, usize) -> Option<Escape>,
) -> usize {
    let (mut input, mut output) = (0, 0);
    while input < io.input_len() && output < io.output_len() {
        let byte = io.input(input);
        if byte == marker
            && let Some(escape) = decode(&*io, input)
        {
            io.write(output, escape.byte);
            output += 1;
            input += escape.len;
            continue;
        }
        io.write(output, byte);
        output += 1;
        input += 1;
    }
    output
}

/// The JSON escape at `at` (a backslash): `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`,
/// `\uXXXX` below U+0080, and JavaScript's `\'`.
fn json_escape(io: &dyn Buffers, at: usize) -> Option<Escape> {
    let len = io.input_len();
    let next = (at + 1 < len).then(|| io.input(at + 1))?;
    let byte = match next {
        b'"' | b'\\' | b'/' | b'\'' => next,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'u' if at + 5 < len => {
            let mut value = 0u32;
            for index in at + 2..at + 6 {
                value = value << 4 | u32::from(hex_value(io.input(index))?);
            }
            return u8::try_from(value)
                .ok()
                .filter(u8::is_ascii)
                .map(|byte| Escape { byte, len: 6 });
        }
        _ => return None,
    };
    Some(Escape { byte, len: 2 })
}

/// Named character references that denote ASCII punctuation or white space, the ones an
/// injection can use. Names are matched without regard to case and need their `;`.
const NAMED: [(&[u8], u8); 26] = [
    (b"lt", b'<'),
    (b"gt", b'>'),
    (b"quot", b'"'),
    (b"apos", b'\''),
    (b"amp", b'&'),
    (b"tab", b'\t'),
    (b"newline", b'\n'),
    (b"colon", b':'),
    (b"sol", b'/'),
    (b"bsol", b'\\'),
    (b"lpar", b'('),
    (b"rpar", b')'),
    (b"semi", b';'),
    (b"equals", b'='),
    (b"grave", b'`'),
    (b"excl", b'!'),
    (b"num", b'#'),
    (b"percnt", b'%'),
    (b"period", b'.'),
    (b"comma", b','),
    (b"dollar", b'$'),
    (b"verbar", b'|'),
    (b"vert", b'|'),
    (b"ast", b'*'),
    (b"plus", b'+'),
    (b"lowbar", b'_'),
];

/// The longest name in [`NAMED`].
const MAX_NAME: usize = 7;

/// The character reference at `at` (an ampersand): `&#DDD;` or `&#xHH;` below U+0080 (the
/// `;` is optional, as browsers accept), or a name from [`NAMED`] with its `;`.
fn html_reference(io: &dyn Buffers, at: usize) -> Option<Escape> {
    let len = io.input_len();
    let mut index = at + 1;
    if index < len && io.input(index) == b'#' {
        index += 1;
        let hex = index < len && io.input(index) | 0x20 == b'x';
        index += usize::from(hex);
        let (start, mut value) = (index, 0u32);
        while index < len {
            let digit = match io.input(index) {
                byte if hex => hex_value(byte).map(u32::from),
                byte if byte.is_ascii_digit() => Some(u32::from(byte - b'0')),
                _ => None,
            };
            let Some(digit) = digit else { break };
            crate::steps::count(1);
            value = value.saturating_mul(if hex { 16 } else { 10 }).saturating_add(digit);
            index += 1;
        }
        index += usize::from(index < len && io.input(index) == b';');
        let byte = u8::try_from(value).ok().filter(|&byte| byte != 0 && byte.is_ascii())?;
        return (index > start).then_some(Escape { byte, len: index - at });
    }
    let mut name = [0u8; MAX_NAME];
    let mut name_len = 0;
    while index < len && name_len < MAX_NAME && io.input(index).is_ascii_alphabetic() {
        name[name_len] = io.input(index).to_ascii_lowercase();
        name_len += 1;
        index += 1;
    }
    if index >= len || io.input(index) != b';' {
        return None;
    }
    let name = &name[..name_len];
    let &(_, byte) = NAMED.iter().find(|(known, _)| *known == name)?;
    Some(Escape { byte, len: index + 1 - at })
}

/// Decodes JSON string escapes; see [`json_escape`].
pub(super) fn json_unescape_with(io: &mut impl Buffers) -> usize {
    decode_escapes(io, b'\\', json_escape)
}

/// Decodes HTML character references; see [`html_reference`].
pub(super) fn html_unescape_with(io: &mut impl Buffers) -> usize {
    decode_escapes(io, b'&', html_reference)
}

#[cfg(test)]
mod tests {
    use super::super::Split;
    use super::*;

    fn json(input: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; input.len()];
        let len = json_unescape_with(&mut Split { input, output: &mut out });
        out.truncate(len);
        out
    }

    fn html(input: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; input.len()];
        let len = html_unescape_with(&mut Split { input, output: &mut out });
        out.truncate(len);
        out
    }

    #[test]
    fn json_escapes_denoting_ascii_are_decoded() {
        assert_eq!(json(br#"1\u0027\u0020UNION"#), b"1' UNION");
        assert_eq!(json(br#"a\'b\"c\\d\/e\nf\tg"#), b"a'b\"c\\d/e\nf\tg");
        assert_eq!(json(br#"\u00e9\u12"#), br#"\u00e9\u12"#);
        assert_eq!(json(br#"\x41\"#), br#"\x41\"#);
        assert_eq!(json(br#"\\u0027"#), br#"\u0027"#);
    }

    #[test]
    fn html_references_denoting_ascii_are_decoded() {
        assert_eq!(html(b"&lt;script&gt;"), b"<script>");
        assert_eq!(html(b"&#x27;&#39;&#0000060&#X3C;"), b"''<<");
        assert_eq!(html(b"jav&#x09;ascript&colon;"), b"jav\tascript:");
        assert_eq!(html(b"a=1&b=2&lt=3&#;&#x;&#0;&#233;"), b"a=1&b=2&lt=3&#;&#x;&#0;&#233;");
        assert_eq!(html(b"&LT;&unknown;&amp;lt;"), b"<&unknown;&lt;");
        assert_eq!(html(b"&#99999999999999999999;"), b"&#99999999999999999999;");
    }
}

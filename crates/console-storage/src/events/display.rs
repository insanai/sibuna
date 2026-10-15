//! Display copies of captured bytes: what an incident row or a ranking label shows.
//!
//! Captured paths, user agents and addresses may hold any bytes. A display copy keeps each
//! valid UTF-8 character that is not an ASCII control, writes `?` for every other byte, and
//! stops at a byte bound without splitting a character, as Zig's `copy` did.

use sibuna_console_protocol::Text;

/// Returns the display copy of `source` in at most `N` bytes and whether it was cut.
pub fn copy<const N: usize>(source: &[u8]) -> (Text<N>, bool) {
    let mut out = String::with_capacity(source.len().min(N));
    let mut rest = source;
    while let Some(&lead) = rest.first() {
        let length = sequence_length(lead).min(rest.len());
        let piece = rest.get(..length).unwrap_or_default();
        let valid = lead >= 32 && lead != 127 && length == sequence_length(lead);
        let character = valid.then(|| std::str::from_utf8(piece).ok()).flatten();
        let needed = character.map_or(1, str::len);
        if out.len() + needed > N {
            break;
        }
        out.push_str(character.unwrap_or("?"));
        rest = rest.get(character.map_or(1, str::len)..).unwrap_or_default();
    }
    let cut = !rest.is_empty();
    // `out` holds at most N bytes by construction, so the conversion cannot fail.
    (Text::from_string(out).unwrap_or_default(), cut)
}

/// The length of the UTF-8 sequence `lead` starts; 1 for a byte that starts none.
fn sequence_length(lead: u8) -> usize {
    match lead {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Returns `path` without its query and fragment, and whether there was one: the part
/// before the first `?` or `#`.
pub fn without_query(path: &[u8]) -> (&[u8], bool) {
    match path.iter().position(|&byte| byte == b'?' || byte == b'#') {
        Some(end) => (path.get(..end).unwrap_or_default(), true),
        None => (path, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_replace_invalid_bytes_and_controls_and_never_split_characters() {
        let (text, cut) = copy::<16>(b"GET\x00/\xffcaf\xc3\xa9");
        assert_eq!((text.as_str(), cut), ("GET?/?caf\u{e9}", false));
        let (text, cut) = copy::<4>("ab\u{e9}\u{e9}".as_bytes());
        assert_eq!((text.as_str(), cut), ("ab\u{e9}", true));
        // A truncated sequence at the end becomes one `?` per byte.
        let (text, cut) = copy::<8>(b"a\xe2\x82");
        assert_eq!((text.as_str(), cut), ("a??", false));
        assert_eq!(copy::<3>(b"\x7f\x7f\x7f\x7f").0.as_str(), "???");
        assert_eq!(without_query(b"/a?b#c"), (&b"/a"[..], true));
        assert_eq!(without_query(b"/a#c?b"), (&b"/a"[..], true));
        assert_eq!(without_query(b"/a"), (&b"/a"[..], false));
    }
}

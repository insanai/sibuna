//! Edits of a message head that the caller prepared: field names to drop and field lines
//! to append (SID 0019).
//!
//! The proxy re-emits every head field by field. An edit joins that step. It is plain
//! borrowed data, so a request without an edit costs one comparison.

use crate::fields::{crlf_lines, find_byte};

/// A change to the fields of one message head.
///
/// `remove` holds field names. `append` holds blocks of complete field lines, each line
/// ending in CRLF. The caller validates both when it reads its configuration: a name is a
/// token, a line holds no other line break, and neither names a field that carries
/// framing.
#[derive(Clone, Copy, Debug, Default)]
pub struct HeadEdit<'a> {
    /// Names of fields to drop, compared without regard to case.
    pub remove: &'a [Box<str>],
    /// Blocks of field lines written after the fields that were kept.
    pub append: [&'a [u8]; 2],
}

impl HeadEdit<'_> {
    /// True when the edit changes nothing.
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.append.iter().all(|block| block.is_empty())
    }

    /// True when the field `name` is dropped.
    pub fn removes(&self, name: &[u8]) -> bool {
        self.remove.iter().any(|removed| name.eq_ignore_ascii_case(removed.as_bytes()))
    }

    /// Applies the edit to the head that begins at `start` in `out` and ends with the
    /// blank line at the end of `out`. The status or request line is kept. A text that
    /// does not end in a blank line is left unchanged.
    pub fn apply(&self, out: &mut Vec<u8>, start: usize) {
        if self.is_empty() {
            return;
        }
        let Some(head) = out.get(start..).and_then(|head| head.strip_suffix(b"\r\n\r\n")) else {
            return;
        };
        let mut edited = Vec::with_capacity(head.len() + self.added() + 4);
        for (index, line) in crlf_lines(head).enumerate() {
            let name = find_byte(line, b':').and_then(|colon| line.get(..colon));
            if index > 0 && name.is_some_and(|name| self.removes(name)) {
                continue;
            }
            edited.extend_from_slice(line);
            edited.extend_from_slice(b"\r\n");
        }
        for block in self.append {
            edited.extend_from_slice(block);
        }
        edited.extend_from_slice(b"\r\n");
        out.truncate(start);
        out.extend_from_slice(&edited);
    }

    fn added(&self) -> usize {
        self.append.iter().map(|block| block.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\
        set-cookie: a=1\r\nX-Powered-By: php\r\nConnection: keep-alive\r\n\r\n";

    #[test]
    fn an_edit_drops_names_in_any_case_and_appends_its_lines_before_the_blank_line() {
        let remove = ["server".into(), "X-POWERED-BY".into()];
        let edit = HeadEdit {
            remove: &remove,
            append: [b"X-Frame-Options: DENY\r\n", b"Set-Cookie: s=2; Path=/\r\n"],
        };
        let mut out = b"earlier bytes".to_vec();
        let start = out.len();
        out.extend_from_slice(HEAD);
        edit.apply(&mut out, start);
        let expected = b"earlier bytesHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
            set-cookie: a=1\r\nConnection: keep-alive\r\nX-Frame-Options: DENY\r\n\
            Set-Cookie: s=2; Path=/\r\n\r\n";
        assert_eq!(String::from_utf8_lossy(&out), String::from_utf8_lossy(expected));
    }

    #[test]
    fn an_empty_edit_and_a_text_without_a_blank_line_change_nothing() {
        let mut out = HEAD.to_vec();
        HeadEdit::default().apply(&mut out, 0);
        assert_eq!(out, HEAD);
        let remove = ["server".into()];
        let edit = HeadEdit { remove: &remove, append: [b"", b""] };
        assert!(!edit.is_empty() && HeadEdit::default().is_empty());
        let mut partial = b"HTTP/1.1 200 OK\r\nServer: x\r\n".to_vec();
        edit.apply(&mut partial, 0);
        assert_eq!(partial, b"HTTP/1.1 200 OK\r\nServer: x\r\n");
        // The first line is never a field, whatever it looks like.
        let odd = ["http/1.1 200 ok".into(), "get /a".into()];
        let edit = HeadEdit { remove: &odd, append: [b"", b""] };
        let mut request = b"GET /a:b HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        edit.apply(&mut request, 0);
        assert_eq!(request, b"GET /a:b HTTP/1.1\r\nHost: h\r\n\r\n");
    }
}

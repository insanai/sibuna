//! Selects the application text and upload metadata to inspect from a bounded body prefix.
//!
//! A multipart body yields each part's header block and the contents of each ordinary
//! field; file contents stay opaque (this is not a malware scanner, and the origin must
//! enforce its declared types). A part whose `filename` is empty is an ordinary field: a
//! browser sends it for a file input left empty, so its contents are not a file. A
//! declared binary type yields nothing when the prefix also looks binary (see
//! [`looks_binary`]), and is inspected as text otherwise. Anything unknown or ambiguous
//! (duplicate `Content-Type`, malformed parameters, a part that does not parse) falls back
//! to inspecting the remaining bytes as text: inspection is never skipped silently.
//!
//! Deliberate changes from Zig: Zig skipped every body of a declared binary type, so a form
//! labelled `image/png` went uninspected; it required CRLF right after a delimiter, where
//! RFC 2046 allows transport padding (spaces and tabs) before it, so `--b ` CRLF hid the
//! fields after it; and it kept the contents of a part with `filename=""` opaque.

use crate::bytes::{find, trim_spaces};
use crate::mime::{self, InvalidMime, Value};
use crate::rule::Header;

/// Bytes of a body that are inspected; attack payloads beyond this prefix can evade the
/// WAF. The bound limits cost; deployments must account for it.
pub const MAX_PREFIX: usize = 8 * 1024;
/// Longest multipart part header block that is parsed.
const MAX_PART_HEADERS: usize = 2048;
/// Most multipart parts that are parsed; the rest is inspected as text.
const MAX_PARTS: usize = 32;
/// Longest multipart boundary (RFC 2046).
const MAX_BOUNDARY: usize = 70;

/// The inspected fields of one body, in order. Every slice borrows the body.
#[derive(Clone, Debug)]
pub struct Fields<'a> {
    body: &'a [u8],
    boundary: &'a [u8],
    offset: usize,
    parts: usize,
    pending: Option<&'a [u8]>,
    finished: bool,
}

impl<'a> Fields<'a> {
    /// Prepares to read `body` (at most its first `MAX_PREFIX` bytes) as declared by the
    /// `Content-Type` among `headers`.
    pub fn new(headers: &[Header<'a>], body: &'a [u8]) -> Fields<'a> {
        let body = &body[..body.len().min(MAX_PREFIX)];
        let mut fields =
            Fields { body, boundary: &[], offset: 0, parts: 0, pending: None, finished: false };
        let Ok(Some(content_type)) = unique(headers, b"content-type") else { return fields };
        let Ok(mut value) = Value::new(content_type) else { return fields };
        if !mime::media_type(value.media) {
            return fields;
        }
        let multipart = value.media.eq_ignore_ascii_case(b"multipart/form-data");
        let mut boundary: Option<&[u8]> = None;
        loop {
            match value.next_parameter() {
                Ok(Some(parameter)) if parameter.name.eq_ignore_ascii_case(b"boundary") => {
                    if boundary.is_some() {
                        return fields;
                    }
                    boundary = Some(parameter.value);
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(InvalidMime) => return fields,
            }
        }
        if !multipart {
            fields.finished = mime::binary(value.media) && looks_binary(body);
            return fields;
        }
        let Some(delimiter) = boundary.filter(|delimiter| valid_boundary(delimiter)) else {
            return fields;
        };
        // The body must open with `--boundary`, transport padding and CRLF.
        let opening = body.strip_prefix(b"--").and_then(|rest| rest.strip_prefix(delimiter));
        if let Some(rest) = opening {
            let padding = transport_padding(rest);
            if rest[padding..].starts_with(b"\r\n") {
                fields.boundary = delimiter;
                fields.offset = 2 + delimiter.len() + padding + 2;
            }
        }
        fields
    }

    /// Ends the walk with the rest of the prefix as one text field.
    fn fallback(&mut self) -> &'a [u8] {
        self.finished = true;
        self.body.get(self.offset..).unwrap_or_default()
    }

    /// Finds the next delimiter line at or after `start`: CRLF `--boundary`, transport
    /// padding, then CRLF; or with `--` after the boundary, the closing delimiter, which may
    /// also end the prefix.
    fn find_boundary(&self, start: usize) -> Option<Boundary> {
        let mut delimiter = [0u8; 4 + MAX_BOUNDARY];
        let text = &mut delimiter[..4 + self.boundary.len()];
        text[..4].copy_from_slice(b"\r\n--");
        text[4..].copy_from_slice(self.boundary);
        let mut position = start;
        while let Some(at) = find(self.body, position, text) {
            let end = at + text.len();
            let rest = &self.body[end..];
            let closing = rest.starts_with(b"--");
            let dashes = if closing { 2 } else { 0 };
            let line_end = end + dashes + transport_padding(&rest[dashes..]);
            let tail = &self.body[line_end..];
            if tail.starts_with(b"\r\n") {
                return Some(Boundary { start: at, end: line_end + 2, closing });
            }
            if closing && tail.is_empty() {
                return Some(Boundary { start: at, end: line_end, closing });
            }
            // A boundary prefix inside a file is still file data.
            position = at + 1;
        }
        None
    }
}

struct Boundary {
    start: usize,
    end: usize,
    closing: bool,
}

impl<'a> Iterator for Fields<'a> {
    type Item = &'a [u8];

    /// Returns the next field: a part's header block (field names and filenames remain
    /// subject to inspection), then its contents unless it is a file, and so on; or the
    /// rest of the prefix as one field when the body is not multipart or stops parsing.
    fn next(&mut self) -> Option<&'a [u8]> {
        if let Some(text) = self.pending.take() {
            return Some(text);
        }
        if self.finished {
            return None;
        }
        if self.boundary.is_empty() || self.parts == MAX_PARTS {
            return Some(self.fallback());
        }
        let remaining = self.body.get(self.offset..).unwrap_or_default();
        let Some(end) = find(remaining, 0, b"\r\n\r\n").filter(|&end| end <= MAX_PART_HEADERS)
        else {
            return Some(self.fallback());
        };
        let header = &remaining[..end];
        let Ok(file) = file_part(header) else { return Some(self.fallback()) };
        self.parts += 1;
        let start = self.offset + end + 4;
        let marker = self.find_boundary(start);
        let body_end = marker.as_ref().map_or(self.body.len(), |found| found.start);
        if !file {
            self.pending = Some(&self.body[start..body_end]);
        }
        match marker {
            Some(found) => {
                self.offset = found.end;
                self.finished = found.closing;
            }
            // The inspection prefix can end inside a streamed part.
            None => self.finished = true,
        }
        Some(header)
    }
}

/// The length of the transport padding (RFC 2046: spaces and tabs) at the start of `text`.
fn transport_padding(text: &[u8]) -> usize {
    let padding = text.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    crate::steps::count(padding as u64);
    padding
}

/// True when `prefix` looks binary: at least one byte in sixteen is a control byte other
/// than tab, line feed, vertical tab, form feed or carriage return.
///
/// Compressed and encoded media (PNG, JPEG, gzip, protobuf) exceed this by far (random bytes
/// hold about one control byte in ten), while text in any ASCII-compatible encoding holds
/// almost none, so a text payload under a binary label is inspected. Binary bodies stay
/// uninspected because the detectors would misread their bytes (a NUL, `;id`). A client can
/// still hide text behind enough control bytes; an origin that parses a body of a declared
/// binary type as a form must enforce its own types.
fn looks_binary(prefix: &[u8]) -> bool {
    let control = prefix
        .iter()
        .filter(|&&b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r')) || b == 0x7f)
        .count();
    control > 0 && control * 16 >= prefix.len()
}

fn valid_boundary(text: &[u8]) -> bool {
    !text.is_empty()
        && text.len() <= MAX_BOUNDARY
        && text.last() != Some(&b' ')
        && text.iter().all(|&b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
}

/// Returns the value of the only header named `name`, `Ok(None)` when there is none.
///
/// Fails with `InvalidMime` when the header appears more than once.
fn unique<'h>(headers: &[Header<'h>], name: &[u8]) -> Result<Option<&'h [u8]>, InvalidMime> {
    let mut value = None;
    for header in headers.iter().filter(|header| header.name.eq_ignore_ascii_case(name)) {
        if value.is_some() {
            return Err(InvalidMime);
        }
        value = Some(header.value);
    }
    Ok(value)
}

/// Reads a part's header block: every line must be `token: value` without control bytes,
/// with exactly one `Content-Disposition: form-data` that names the field. Returns whether
/// the part is a file (has a non-empty `filename`).
///
/// Fails with `InvalidMime` otherwise.
fn file_part(head: &[u8]) -> Result<bool, InvalidMime> {
    let mut disposition = None;
    let mut rest = Some(head);
    while let Some(text) = rest {
        let (line, after) = match find(text, 0, b"\r\n") {
            Some(at) => (&text[..at], Some(&text[at + 2..])),
            None => (text, None),
        };
        rest = after;
        let colon = line.iter().position(|&b| b == b':').ok_or(InvalidMime)?;
        if colon == 0 || !line[..colon].iter().all(|&b| mime::token(b)) {
            return Err(InvalidMime);
        }
        if line.iter().any(|&b| (b < 32 && b != b'\t') || b == 127) {
            return Err(InvalidMime);
        }
        if !line[..colon].eq_ignore_ascii_case(b"content-disposition") {
            continue;
        }
        if disposition.is_some() {
            return Err(InvalidMime);
        }
        disposition = Some(trim_spaces(&line[colon + 1..]));
    }
    let mut value = Value::new(disposition.ok_or(InvalidMime)?)?;
    if !value.media.eq_ignore_ascii_case(b"form-data") {
        return Err(InvalidMime);
    }
    let (mut name, mut filename) = (false, None);
    while let Some(parameter) = value.next_parameter()? {
        if parameter.name.eq_ignore_ascii_case(b"name") {
            if name {
                return Err(InvalidMime);
            }
            name = true;
        } else if parameter.name.eq_ignore_ascii_case(b"filename") {
            if filename.is_some() {
                return Err(InvalidMime);
            }
            filename = Some(parameter.value);
        }
    }
    // An empty filename is a file input left empty, whose contents are no file.
    let file = filename.is_some_and(|filename| !filename.is_empty());
    if name { Ok(file) } else { Err(InvalidMime) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multipart(boundary: &str) -> Vec<u8> {
        format!("multipart/form-data; boundary={boundary}").into_bytes()
    }

    #[test]
    fn multipart_inspection_retains_metadata_and_ordinary_fields_while_skipping_file_bytes() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; \
            filename=\"a.bin\"\r\nContent-Type: \
            application/octet-stream\r\n\r\n\x00\r\n--b-fake\r\n\r\n--b\r\nContent-Disposition: \
            form-data; name=\"caption\"\r\n\r\nhello\r\n--b--\r\n";
        let headers =
            [Header { name: b"Content-Type", value: b"multipart/form-data; boundary=\"b\"" }];
        let mut fields = Fields::new(&headers, body);
        assert!(find(fields.next().unwrap(), 0, b"a.bin").is_some());
        assert!(find(fields.next().unwrap(), 0, b"caption").is_some());
        assert_eq!(fields.next().unwrap(), b"hello");
        assert_eq!(fields.next(), None);
    }

    #[test]
    fn ambiguous_mime_metadata_falls_back_to_text_and_declared_text_cannot_skip_inspection() {
        let binary_body = b"binary\x00bytes";
        let headers = [
            Header { name: b"Content-Type", value: b"application/octet-stream" },
            Header { name: b"Content-Type", value: b"application/json" },
        ];
        assert_eq!(Fields::new(&headers, binary_body).next().unwrap(), binary_body);
        let headers = [Header { name: b"Content-Type", value: b"image/png/invalid" }];
        assert_eq!(Fields::new(&headers, binary_body).next().unwrap(), binary_body);
        let doubled = b"multipart/form-data; boundary=b; boundary=other";
        let headers = [Header { name: b"Content-Type", value: doubled }];
        assert_eq!(Fields::new(&headers, binary_body).next().unwrap(), binary_body);
        let content_type = multipart("b");
        let headers = [Header { name: b"Content-Type", value: &content_type }];
        let disguised = b"--b\r\nContent-Disposition: form-data; name=\"field\"\r\nContent-Type: \
            application/octet-stream\r\n\r\ntext input\r\n--b--\r\n";
        let mut fields = Fields::new(&headers, disguised);
        fields.next().unwrap();
        assert_eq!(fields.next().unwrap(), b"text input");
        let duplicate = b"--b\r\nContent-Disposition: form-data; name=\"f\"; \
            filename=\"x\"\r\nContent-Disposition : form-data; name=\"field\"\r\n\r\ntext \
            input\r\n--b--\r\n";
        let mut fields = Fields::new(&headers, duplicate);
        assert!(find(fields.next().unwrap(), 0, b"text input").is_some());
    }

    #[test]
    fn partial_file_prefixes_are_opaque_and_parsing_stays_within_the_inspection_bound() {
        let header = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n";
        let mut body = vec![0u8; MAX_PREFIX + 1024];
        body[..header.len()].copy_from_slice(header);
        let content_type = multipart("b");
        let headers = [Header { name: b"Content-Type", value: &content_type }];
        let mut fields = Fields::new(&headers, &body);
        assert_eq!(fields.body.len(), MAX_PREFIX);
        assert!(find(fields.next().unwrap(), 0, b"filename").is_some());
        assert_eq!(fields.next(), None);
    }

    #[test]
    fn declared_binary_bodies_yield_nothing_and_plain_bodies_yield_themselves() {
        let headers = [Header { name: b"content-type", value: b"image/png" }];
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0\0\0\x01\0\x08\x06\0\0\0";
        assert_eq!(Fields::new(&headers, png).next(), None);
        assert_eq!(Fields::new(&[], b"a=1").collect::<Vec<_>>(), vec![&b"a=1"[..]]);
        assert_eq!(Fields::new(&[], b"").collect::<Vec<_>>(), vec![&b""[..]]);
    }

    #[test]
    fn a_text_body_under_a_binary_label_is_inspected() {
        let headers = [Header { name: b"Content-Type", value: b"image/png" }];
        let body = b"{\"q\":\"1' UNION SELECT password FROM users--\"}";
        assert_eq!(Fields::new(&headers, body).collect::<Vec<_>>(), vec![&body[..]]);
        let headers = [Header { name: b"Content-Type", value: b"application/octet-stream" }];
        let mut noise = vec![b'a'; 144];
        noise[..9].copy_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08\x0e");
        assert_eq!(Fields::new(&headers, &noise).next(), None);
        noise[..9].copy_from_slice(b"\t\n\r\x0c\x0b aaa");
        assert_eq!(Fields::new(&headers, &noise).next(), Some(&noise[..]));
    }

    #[test]
    fn transport_padding_after_a_delimiter_does_not_hide_the_next_fields() {
        let content_type = multipart("b");
        let headers = [Header { name: b"Content-Type", value: &content_type }];
        let body =
            b"--b \t\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n\
            hello\r\n--b \r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION \
            SELECT--\r\n--b-- \r\n";
        let fields: Vec<&[u8]> = Fields::new(&headers, body).collect();
        assert_eq!(fields.len(), 3, "{fields:?}");
        assert_eq!(fields[2], b"1' UNION SELECT--");
        let unclosed = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--b--  ";
        let fields: Vec<&[u8]> = Fields::new(&headers, unclosed).collect();
        assert_eq!(fields[1], b"v");
    }

    #[test]
    fn a_part_with_an_empty_filename_is_an_ordinary_field() {
        let content_type = multipart("b");
        let headers = [Header { name: b"Content-Type", value: &content_type }];
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"; filename=\"\"\r\n\r\n\
            1' UNION SELECT--\r\n--b--\r\n";
        let fields: Vec<&[u8]> = Fields::new(&headers, body).collect();
        assert_eq!(fields[1], b"1' UNION SELECT--");
        let duplicate = b"--b\r\nContent-Disposition: form-data; name=\"q\"; filename=\"\"; \
            filename=\"x\"\r\n\r\nv\r\n--b--\r\n";
        assert_eq!(Fields::new(&headers, duplicate).count(), 1, "falls back to text");
    }
}

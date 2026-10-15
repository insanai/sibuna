//! Selects the application text and upload metadata to inspect from a bounded body prefix.
//!
//! A multipart body yields each part's header block and the contents of each ordinary
//! field; file contents stay opaque (this is not a malware scanner, and the origin must
//! enforce its declared types). A declared binary type yields nothing. Anything unknown or
//! ambiguous (duplicate `Content-Type`, malformed parameters, a part that does not parse)
//! falls back to inspecting the remaining bytes as text: inspection is never skipped
//! silently.

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
            fields.finished = mime::binary(value.media);
            return fields;
        }
        let Some(delimiter) = boundary.filter(|delimiter| valid_boundary(delimiter)) else {
            return fields;
        };
        // The body must open with `--boundary` CRLF.
        let opening = body.strip_prefix(b"--").and_then(|rest| rest.strip_prefix(delimiter));
        if opening.is_some_and(|rest| rest.starts_with(b"\r\n")) {
            fields.boundary = delimiter;
            fields.offset = delimiter.len() + 4;
        }
        fields
    }

    /// Ends the walk with the rest of the prefix as one text field.
    fn fallback(&mut self) -> &'a [u8] {
        self.finished = true;
        self.body.get(self.offset..).unwrap_or_default()
    }

    /// Finds the next delimiter line at or after `start`: CRLF `--boundary` then CRLF, or
    /// `--` at the end of the prefix or before CRLF (the closing delimiter).
    fn find_boundary(&self, start: usize) -> Option<Boundary> {
        let mut delimiter = [0u8; 4 + MAX_BOUNDARY];
        let text = &mut delimiter[..4 + self.boundary.len()];
        text[..4].copy_from_slice(b"\r\n--");
        text[4..].copy_from_slice(self.boundary);
        let mut position = start;
        while let Some(at) = find(self.body, position, text) {
            let end = at + text.len();
            let suffix = self.body.get(end..end + 2)?;
            if suffix == b"\r\n" {
                return Some(Boundary { start: at, end: end + 2, closing: false });
            }
            let after = &self.body[end + 2..];
            if suffix == b"--" && (after.is_empty() || after.starts_with(b"\r\n")) {
                return Some(Boundary { start: at, end: end + 2, closing: true });
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
/// the part is a file (has a `filename`).
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
    let (mut name, mut file) = (false, false);
    while let Some(parameter) = value.next_parameter()? {
        let seen = if parameter.name.eq_ignore_ascii_case(b"name") {
            &mut name
        } else if parameter.name.eq_ignore_ascii_case(b"filename") {
            &mut file
        } else {
            continue;
        };
        if *seen {
            return Err(InvalidMime);
        }
        *seen = true;
    }
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
        assert_eq!(Fields::new(&headers, b"\x89PNG").next(), None);
        assert_eq!(Fields::new(&[], b"a=1").collect::<Vec<_>>(), vec![&b"a=1"[..]]);
        assert_eq!(Fields::new(&[], b"").collect::<Vec<_>>(), vec![&b""[..]]);
    }
}

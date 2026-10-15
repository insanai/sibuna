//! A slow, obviously correct transcription of the Zig parser, used only by tests.
//!
//! It follows `libs/net/src/http.zig` statement by statement with the plainest operations
//! available (splitting into vectors, naive substring search), so that it can be checked
//! against the Zig source by reading, and the fast parser can be checked against it by
//! fuzzing. The one rule the port adds, the target form, is checked last, as the fast
//! parser does.

use super::{Header, MAX_HEADERS, Method, ParseError, Request, Version};

fn token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn valid_token(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().all(|&c| token_char(c))
}

fn index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (0..=haystack.len().saturating_sub(needle.len()))
        .find(|&i| haystack.len() >= needle.len() && &haystack[i..i + needle.len()] == needle)
}

/// Zig's `std.mem.splitSequence(data, "\r\n")`.
fn split_crlf(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut rest = data;
    while let Some(i) = index_of(rest, b"\r\n") {
        lines.push(&rest[..i]);
        rest = &rest[i + 2..];
    }
    lines.push(rest);
    lines
}

fn trim<'a>(text: &'a [u8], set: &[u8]) -> &'a [u8] {
    let mut start = 0;
    let mut end = text.len();
    while start < end && set.contains(&text[start]) {
        start += 1;
    }
    while end > start && set.contains(&text[end - 1]) {
        end -= 1;
    }
    &text[start..end]
}

fn validate_content_length(value: &[u8]) -> Result<(), ParseError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::InvalidContentLength);
    }
    let text = std::str::from_utf8(value).map_err(|_| ParseError::InvalidContentLength)?;
    text.parse::<usize>().map(|_| ()).map_err(|_| ParseError::InvalidContentLength)
}

fn chunked_only(value: &[u8]) -> Result<(), ParseError> {
    let mut count = 0;
    let mut last: &[u8] = b"";
    for item in value.split(|&c| c == b',') {
        let coding = trim(item, b" \t");
        if !valid_token(coding) || last.eq_ignore_ascii_case(b"chunked") {
            return Err(ParseError::InvalidTransferEncoding);
        }
        last = coding;
        count += 1;
    }
    if !last.eq_ignore_ascii_case(b"chunked") {
        return Err(ParseError::InvalidTransferEncoding);
    }
    if count > 1 {
        return Err(ParseError::UnsupportedTransferEncoding);
    }
    Ok(())
}

/// The request line part of the Zig `parseRequest`, transcribed. Returns the target.
fn request_line<'a>(req_line: &'a [u8], req: &mut Request<'a>) -> Result<&'a [u8], ParseError> {
    if req_line.is_empty() {
        return Err(ParseError::EmptyRequest);
    }
    let tokens: Vec<&[u8]> = req_line.split(|&c| c == b' ').collect();
    if tokens.len() < 3 {
        return Err(ParseError::InvalidRequestLine);
    }
    let (method_str, uri_str, ver_str) = (tokens[0], tokens[1], tokens[2]);
    if !valid_token(method_str) || uri_str.is_empty() || tokens.len() > 3 {
        return Err(ParseError::InvalidRequestLine);
    }
    if uri_str.iter().any(|&c| c <= 32 || c == 127) {
        return Err(ParseError::InvalidRequestLine);
    }
    req.method_text = method_str;
    req.method = Method::from_bytes(method_str);
    req.version = match ver_str {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        _ => return Err(ParseError::UnsupportedVersion),
    };
    match uri_str.iter().position(|&c| c == b'?') {
        Some(mark) => {
            req.path = &uri_str[..mark];
            req.query = &uri_str[mark + 1..];
        }
        None => {
            req.path = uri_str;
            req.query = &uri_str[uri_str.len()..];
        }
    }
    Ok(uri_str)
}

/// One header line of the Zig `parseRequest` loop, transcribed.
fn header_line(line: &[u8]) -> Result<Header<'_>, ParseError> {
    if line.contains(&0) {
        return Err(ParseError::NullByteInHeader);
    }
    let colon = line.iter().position(|&c| c == b':').ok_or(ParseError::InvalidHeader)?;
    let name = &line[..colon];
    if !name.is_empty() && (name[name.len() - 1] == b' ' || name[name.len() - 1] == b'\t') {
        return Err(ParseError::InvalidHeaderWhitespace);
    }
    if !valid_token(name) {
        return Err(ParseError::InvalidHeader);
    }
    let value = trim(&line[colon + 1..], b" \t");
    if value.iter().any(|&c| (c < 32 && c != b'\t') || c == 127) {
        return Err(ParseError::InvalidHeader);
    }
    Ok(Header { name, value })
}

/// The Zig `parseRequest`, transcribed.
pub(crate) fn parse(data: &[u8]) -> Result<Request<'_>, ParseError> {
    let mut req = Request { body: &data[data.len()..], ..Request::default() };
    let lines = split_crlf(data);
    let target = request_line(lines[0], &mut req)?;
    let mut content_length: Option<&[u8]> = None;
    let mut transfer_encoding: Option<&[u8]> = None;
    let mut transfer_fields = 0;
    for &line in &lines[1..] {
        if line.is_empty() {
            break;
        }
        let Header { name, value } = header_line(line)?;
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some_and(|previous| previous != value) {
                return Err(ParseError::DuplicateContentLength);
            }
            content_length = Some(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encoding = Some(value);
            transfer_fields += 1;
        }
        if req.header_count >= MAX_HEADERS {
            return Err(ParseError::TooManyHeaders);
        }
        req.headers[req.header_count] = Header { name, value };
        req.header_count += 1;
    }
    if let Some(codings) = transfer_encoding {
        if content_length.is_some() {
            return Err(ParseError::RequestSmugglingAttempt);
        }
        if transfer_fields != 1 || req.version != Version::Http11 {
            return Err(ParseError::InvalidTransferEncoding);
        }
        chunked_only(codings)?;
        req.chunked = true;
    }
    if let Some(value) = content_length {
        validate_content_length(value)?;
    }
    let asterisk = target == b"*" && req.method == Method::Options;
    if !target.starts_with(b"/") && !asterisk {
        return Err(ParseError::UnsupportedTargetForm);
    }
    if let Some(end) = index_of(data, b"\r\n\r\n") {
        req.body = &data[end + 4..];
    }
    Ok(req)
}

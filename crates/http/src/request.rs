//! The zero-copy HTTP/1.1 request parser.
//!
//! [`parse_request`] reads a request head in one forward pass and returns a [`Request`] whose
//! slices borrow the input. The common shape of every line is checked by a fast scanner; a
//! line it does not recognise is handed to an exact, slower classifier that reproduces the
//! Zig parser's verdict, including which error a malformed line produces.

use std::fmt;

use crate::bytes::{
    FIELD, TARGET, TOKEN, contains, field_run, find_byte, find_crlf, is_token, run_length,
    trim_end_space, trim_space, trim_start_space,
};

/// The most header fields a request may carry. A 33rd field is [`ParseError::TooManyHeaders`].
pub const MAX_HEADERS: usize = 32;

/// The request method, with every method we do not route on folded into [`Method::Other`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`, the default of an empty [`Request`].
    #[default]
    Get,
    /// `POST`.
    Post,
    /// `HEAD`.
    Head,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
    /// `OPTIONS`.
    Options,
    /// `PATCH`.
    Patch,
    /// Any other token; [`Request::method_text`] keeps the spelling.
    Other,
}

impl Method {
    /// Classifies a method token. Matching is exact and case-sensitive, as RFC 9110 requires;
    /// never fails.
    pub fn from_bytes(text: &[u8]) -> Method {
        match text {
            b"GET" => Method::Get,
            b"POST" => Method::Post,
            b"HEAD" => Method::Head,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"OPTIONS" => Method::Options,
            b"PATCH" => Method::Patch,
            _ => Method::Other,
        }
    }
}

/// The protocol version. The parser accepts exactly these two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Version {
    /// `HTTP/1.0`.
    Http10,
    /// `HTTP/1.1`, the default of an empty [`Request`].
    #[default]
    Http11,
}

impl Version {
    /// The version as it appears on the request line.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Version::Http10 => b"HTTP/1.0",
            Version::Http11 => b"HTTP/1.1",
        }
    }
}

/// One header field. The value has its surrounding SP and HTAB removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header<'a> {
    /// The field name as sent (compare it with `eq_ignore_ascii_case`).
    pub name: &'a [u8],
    /// The field value without leading or trailing whitespace.
    pub value: &'a [u8],
}

/// A parsed request head. Every slice borrows the bytes given to [`parse_request`], so the
/// request cannot outlive the connection buffer that holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The method, classified.
    pub method: Method,
    /// The method token as sent.
    pub method_text: &'a [u8],
    /// The request-target up to its first `?`, as sent: `/` and a path, or `*` for
    /// `OPTIONS`. Decisions must read its normal form ([`crate::normalize_path`]).
    pub path: &'a [u8],
    /// The request-target after its first `?`, without the `?`; empty when there is none.
    pub query: &'a [u8],
    /// The protocol version.
    pub version: Version,
    /// The header fields in order; only the first `header_count` are meaningful.
    pub headers: [Header<'a>; MAX_HEADERS],
    /// The number of header fields in `headers`.
    pub header_count: usize,
    /// The bytes after the blank line that ends the head, or an empty slice at the end of the
    /// input when the head has no blank line.
    pub body: &'a [u8],
    /// The body follows in the chunked transfer coding, the only coding accepted (SID 0009).
    pub chunked: bool,
}

impl Default for Request<'_> {
    /// `GET / HTTP/1.1` with no header fields and no body, as in the Zig version.
    fn default() -> Self {
        Request {
            method: Method::Get,
            method_text: b"GET",
            path: b"/",
            query: b"",
            version: Version::Http11,
            headers: [Header::default(); MAX_HEADERS],
            header_count: 0,
            body: b"",
            chunked: false,
        }
    }
}

impl<'a> Request<'a> {
    /// The header fields that were parsed, in order.
    #[inline]
    pub fn headers(&self) -> &[Header<'a>] {
        // `header_count` is public; a value above the capacity shows every slot rather than
        // panicking.
        self.headers.get(..self.header_count).unwrap_or(&self.headers)
    }

    /// The value of the first field named `name` (ASCII case-insensitive), or `None`.
    #[inline]
    pub fn header(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.headers().iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
    }

    /// The value of the only field named `name`. `Ok(None)` when it is absent and `Err(())`
    /// when it appears more than once, for callers that must not pick one of several values.
    pub(crate) fn unique_header(&self, name: &[u8]) -> Result<Option<&'a [u8]>, ()> {
        let mut found = None;
        for header in self.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(name)) {
            if found.replace(header.value).is_some() {
                return Err(());
            }
        }
        Ok(found)
    }

    /// The declared body length, or `None` when `Content-Length` is absent or not a decimal
    /// number that fits a `usize`.
    pub fn content_length(&self) -> Option<usize> {
        let text = self.header(b"content-length")?;
        parse_decimal(trim_sp(text))
    }

    /// True when the connection may serve another request after this one. HTTP/1.1 defaults
    /// to persistent connections unless the client sends `Connection: close`; HTTP/1.0 must
    /// opt in with `Connection: keep-alive`.
    pub fn wants_keep_alive(&self) -> bool {
        let connection = self.header(b"connection").map(trim_sp);
        match self.version {
            Version::Http11 => !connection.is_some_and(|c| c.eq_ignore_ascii_case(b"close")),
            Version::Http10 => connection.is_some_and(|c| c.eq_ignore_ascii_case(b"keep-alive")),
        }
    }

    /// True for navigations that can render the challenge interstitial: the first `Accept`
    /// field mentions `text/html`.
    pub fn accepts_html(&self) -> bool {
        self.header(b"accept").is_some_and(|accept| contains(accept, b"text/html"))
    }

    /// The value of the cookie `name` in the first `Cookie` field, or `None`.
    ///
    /// Pairs are split at `;` and trimmed of SP and HTAB. The value is the text between the
    /// first and the second `=` of the pair, and empty when the pair has no `=`, as in Zig.
    pub fn cookie(&self, name: &[u8]) -> Option<&'a [u8]> {
        // A pair's name ends at its first `=`, so a name holding `=` never matches.
        if name.contains(&b'=') {
            return None;
        }
        let mut rest = self.header(b"cookie")?;
        loop {
            let (pair, next) = match find_byte(rest, b';') {
                Some(end) => (rest.get(..end)?, rest.get(end + 1..)),
                None => (rest, None),
            };
            if let Some(after) = trim_space(pair).strip_prefix(name) {
                match after.split_first() {
                    None => return after.get(..0),
                    Some((b'=', value)) => {
                        let end = find_byte(value, b'=').unwrap_or(value.len());
                        return value.get(..end);
                    }
                    Some(_) => {}
                }
            }
            rest = next?;
        }
    }

    fn push_header(&mut self, header: Header<'a>) -> Result<(), ParseError> {
        let slot = self.headers.get_mut(self.header_count).ok_or(ParseError::TooManyHeaders)?;
        *slot = header;
        self.header_count += 1;
        Ok(())
    }
}

/// `text` without leading and trailing SP (not HTAB), as Zig's `contentLength` and
/// `wantsKeepAlive` trimmed.
fn trim_sp(text: &[u8]) -> &[u8] {
    let start = text.iter().position(|&b| b != b' ').unwrap_or(text.len());
    let end = text.iter().rposition(|&b| b != b' ').map_or(start, |last| last + 1);
    text.get(start..end).unwrap_or_default()
}

/// Why a request head was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// The input is empty or starts with CRLF.
    EmptyRequest,
    /// The request line is not `method SP target SP version` with a token method and a
    /// target free of whitespace and control bytes.
    InvalidRequestLine,
    /// A header line holds a NUL byte.
    NullByteInHeader,
    /// A header line has no colon, an invalid name, or a control byte in its value.
    InvalidHeader,
    /// Whitespace separates a field name from its colon (RFC 9112 section 5.1).
    InvalidHeaderWhitespace,
    /// Two `Content-Length` fields disagree.
    DuplicateContentLength,
    /// The request carries both `Transfer-Encoding` and `Content-Length`.
    RequestSmugglingAttempt,
    /// The version is neither `HTTP/1.1` nor `HTTP/1.0`.
    UnsupportedVersion,
    /// The head has more than [`MAX_HEADERS`] fields.
    TooManyHeaders,
    /// A coding list ending in `chunked` after another coding: valid, but not decoded here.
    UnsupportedTransferEncoding,
    /// Framing no recipient can determine reliably (RFC 9112 sections 6.1 and 6.3).
    InvalidTransferEncoding,
    /// `Content-Length` is not a decimal number that fits a `usize`.
    InvalidContentLength,
    /// The request-target is neither origin-form (`/...`) nor `*` in an `OPTIONS` request.
    /// Sibuna is a reverse proxy: absolute-form and authority-form address a forward proxy.
    UnsupportedTargetForm,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::EmptyRequest => "empty request",
            ParseError::InvalidRequestLine => "invalid request line",
            ParseError::NullByteInHeader => "NUL byte in a header line",
            ParseError::InvalidHeader => "invalid header line",
            ParseError::InvalidHeaderWhitespace => "whitespace before a header colon",
            ParseError::DuplicateContentLength => "conflicting Content-Length fields",
            ParseError::RequestSmugglingAttempt => "both Transfer-Encoding and Content-Length",
            ParseError::UnsupportedVersion => "unsupported HTTP version",
            ParseError::TooManyHeaders => "too many header fields",
            ParseError::UnsupportedTransferEncoding => "unsupported transfer coding",
            ParseError::InvalidTransferEncoding => "invalid Transfer-Encoding",
            ParseError::InvalidContentLength => "invalid Content-Length",
            ParseError::UnsupportedTargetForm => "request target is not in origin form",
        })
    }
}

impl std::error::Error for ParseError {}

/// True when `byte` is an RFC 9110 token character (`tchar`).
#[inline]
pub fn is_token_char(byte: u8) -> bool {
    crate::bytes::is(byte, TOKEN)
}

/// True when `text` is a non-empty run of token characters.
#[inline]
pub fn is_valid_token(text: &[u8]) -> bool {
    is_token(text)
}

/// A request-target split into its path and query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Target<'a> {
    /// The target up to its first `?`.
    pub path: &'a [u8],
    /// The target after its first `?`, without the `?`; empty when there is none.
    pub query: &'a [u8],
}

/// Splits a request-target at its first `?`. This is the one split used everywhere a target
/// is read (the request line, forwarded metadata, the interstitial's reported URL): policy
/// matches the path alone, so a reader that kept the query attached would evaluate a
/// different request. Borrows `target`; never fails.
#[inline]
pub fn split_target(target: &[u8]) -> Target<'_> {
    match target.iter().position(|&byte| byte == b'?') {
        Some(mark) => {
            let (path, query) = target.split_at(mark);
            Target { path, query: query.get(1..).unwrap_or_default() }
        }
        // The empty query sits at the end of the target, so it still borrows the input.
        None => Target { path: target, query: target.get(target.len()..).unwrap_or_default() },
    }
}

/// Parses a request head, borrowing every slice of the result from `data`.
///
/// `data` is normally the head including its blank line, as found by the connection reader;
/// any bytes after the blank line become [`Request::body`]. A head without a blank line is
/// parsed up to its end. The parser never allocates and reads each byte once on the common
/// path.
///
/// # Errors
///
/// A [`ParseError`] names the first rule the head breaks, checked in the order of the Zig
/// parser: the request line, then each header line in turn (NUL byte, colon, whitespace
/// before the colon, name, value, conflicting `Content-Length`, field count), then the
/// framing rules of SID 0009 (`Transfer-Encoding` with `Content-Length`, repeated or
/// HTTP/1.0 `Transfer-Encoding`, the coding list), the `Content-Length` syntax, and finally
/// the target form: only origin-form, and `*` in an `OPTIONS` request, are accepted
/// ([`ParseError::UnsupportedTargetForm`]). The path is returned as sent; the daemon
/// normalises it with [`crate::normalize_path`] before any decision.
pub fn parse_request(data: &[u8]) -> Result<Request<'_>, ParseError> {
    let line = request_line(data)?;
    let mut request = Request {
        method: Method::from_bytes(line.method_text),
        method_text: line.method_text,
        path: line.target.path,
        query: line.target.query,
        version: line.version,
        headers: [Header::default(); MAX_HEADERS],
        header_count: 0,
        body: data.get(data.len()..).unwrap_or_default(),
        chunked: false,
    };
    let mut framing = Framing::default();
    let mut next = line.next;
    while let Some(at) = next {
        let rest = data.get(at..).unwrap_or_default();
        if rest.is_empty() {
            break;
        }
        if let Some(body) = rest.strip_prefix(b"\r\n") {
            request.body = body;
            break;
        }
        let field = header_line(rest)?;
        framing.observe(field.header)?;
        request.push_header(field.header)?;
        next = field.length.map(|length| at + length);
    }
    framing.finish(&mut request)?;
    if !line.form.is_accepted(request.method) {
        return Err(ParseError::UnsupportedTargetForm);
    }
    Ok(request)
}

/// The parts of a request line and where the next line starts (`None` without a CRLF).
struct RequestLine<'a> {
    method_text: &'a [u8],
    target: Target<'a>,
    form: TargetForm,
    version: Version,
    next: Option<usize>,
}

/// The form of a request-target (RFC 9112 section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetForm {
    /// `/` followed by the path and an optional query.
    Origin,
    /// Exactly `*`.
    Asterisk,
    /// Anything else: absolute-form (`http://host/path`), authority-form (`host:port`) or
    /// text that is no target at all.
    Other,
}

impl TargetForm {
    #[inline]
    fn of(target: &[u8]) -> TargetForm {
        match target {
            [b'/', ..] => TargetForm::Origin,
            b"*" => TargetForm::Asterisk,
            _ => TargetForm::Other,
        }
    }

    /// Origin-form always; asterisk-form only for `OPTIONS` (RFC 9112 section 3.2.4).
    #[inline]
    fn is_accepted(self, method: Method) -> bool {
        match self {
            TargetForm::Origin => true,
            TargetForm::Asterisk => method == Method::Options,
            TargetForm::Other => false,
        }
    }
}

fn request_line(data: &[u8]) -> Result<RequestLine<'_>, ParseError> {
    match request_line_fast(data) {
        Some(line) => Ok(line),
        None => request_line_exact(data),
    }
}

/// Recognises `token SP target SP HTTP/1.x` followed by CRLF or the end of the input, the
/// shape of every valid request line. Anything else returns `None`.
#[inline]
fn request_line_fast(data: &[u8]) -> Option<RequestLine<'_>> {
    let (method_text, rest) = data.split_at_checked(run_length(data, TOKEN))?;
    let rest = rest.strip_prefix(b" ").filter(|_| !method_text.is_empty())?;
    let (target, rest) = rest.split_at_checked(run_length(rest, TARGET))?;
    let rest = rest.strip_prefix(b" ").filter(|_| !target.is_empty())?;
    let (version, after) = rest.split_at_checked(8)?;
    let version = match version {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        _ => return None,
    };
    let next = match after {
        [] => None,
        [b'\r', b'\n', ..] => Some(data.len() - after.len() + 2),
        _ => return None,
    };
    let form = TargetForm::of(target);
    Some(RequestLine { method_text, target: split_target(target), form, version, next })
}

/// The Zig rules for a request line, applied literally: the line ends at the first CRLF and
/// splits at every single space.
#[cold]
fn request_line_exact(data: &[u8]) -> Result<RequestLine<'_>, ParseError> {
    let (line, next) = split_line(data);
    if line.is_empty() {
        return Err(ParseError::EmptyRequest);
    }
    let mut parts = line.split(|&byte| byte == b' ');
    let method_text = parts.next().unwrap_or_default();
    let target = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    let version = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    if !is_token(method_text) || target.is_empty() || parts.next().is_some() {
        return Err(ParseError::InvalidRequestLine);
    }
    if run_length(target, TARGET) != target.len() {
        return Err(ParseError::InvalidRequestLine);
    }
    let version = match version {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        _ => return Err(ParseError::UnsupportedVersion),
    };
    let form = TargetForm::of(target);
    Ok(RequestLine { method_text, target: split_target(target), form, version, next })
}

/// The line at the start of `bytes` and the length of the line with its CRLF, or the whole
/// input and `None` when there is no CRLF.
fn split_line(bytes: &[u8]) -> (&[u8], Option<usize>) {
    match find_crlf(bytes).and_then(|end| bytes.split_at_checked(end)) {
        Some((line, _)) => (line, Some(line.len() + 2)),
        None => (bytes, None),
    }
}

/// A parsed header line and its length including CRLF (`None` when it ends the input).
struct FieldLine<'a> {
    header: Header<'a>,
    length: Option<usize>,
}

#[inline]
fn header_line(rest: &[u8]) -> Result<FieldLine<'_>, ParseError> {
    match header_line_fast(rest) {
        Some(field) => Ok(field),
        None => header_line_exact(rest),
    }
}

/// Recognises `token ":" value` with a value free of control bytes but HTAB, followed by
/// CRLF or the end of the input. Anything else returns `None`.
#[inline]
fn header_line_fast(rest: &[u8]) -> Option<FieldLine<'_>> {
    let (name, after) = rest.split_at_checked(run_length(rest, TOKEN))?;
    let after = after.strip_prefix(b":").filter(|_| !name.is_empty())?;
    let (value, end) = after.split_at_checked(field_run(after))?;
    let length = match end {
        [] => None,
        [b'\r', b'\n', ..] => Some(rest.len() - end.len() + 2),
        _ => return None,
    };
    Some(FieldLine { header: Header { name, value: trim_space(value) }, length })
}

/// The Zig rules for a header line, applied literally, in the Zig order.
#[cold]
fn header_line_exact(rest: &[u8]) -> Result<FieldLine<'_>, ParseError> {
    let (line, length) = split_line(rest);
    if line.contains(&0) {
        return Err(ParseError::NullByteInHeader);
    }
    let colon = line.iter().position(|&byte| byte == b':').ok_or(ParseError::InvalidHeader)?;
    // `colon` indexes `line`, so the split is in bounds.
    let (name, value) = line.split_at_checked(colon).ok_or(ParseError::InvalidHeader)?;
    if matches!(name.last(), Some(b' ' | b'\t')) {
        return Err(ParseError::InvalidHeaderWhitespace);
    }
    if !is_token(name) {
        return Err(ParseError::InvalidHeader);
    }
    let value = trim_end_space(trim_start_space(value.get(1..).unwrap_or_default()));
    if run_length(value, FIELD) != value.len() {
        return Err(ParseError::InvalidHeader);
    }
    Ok(FieldLine { header: Header { name, value }, length })
}

/// The framing fields seen so far.
#[derive(Default)]
struct Framing<'a> {
    content_length: Option<&'a [u8]>,
    transfer_encoding: Option<&'a [u8]>,
    transfer_fields: usize,
}

impl<'a> Framing<'a> {
    #[inline]
    fn observe(&mut self, header: Header<'a>) -> Result<(), ParseError> {
        // The length test first: most names are neither, and differ in length.
        let name = header.name;
        if name.len() == 14 && name.eq_ignore_ascii_case(b"content-length") {
            if self.content_length.is_some_and(|previous| previous != header.value) {
                return Err(ParseError::DuplicateContentLength);
            }
            self.content_length = Some(header.value);
        } else if name.len() == 17 && name.eq_ignore_ascii_case(b"transfer-encoding") {
            self.transfer_encoding = Some(header.value);
            self.transfer_fields += 1;
        }
        Ok(())
    }

    /// Applies the framing rules R1 to R4 of SID 0009 and the `Content-Length` syntax.
    fn finish(&self, request: &mut Request<'a>) -> Result<(), ParseError> {
        if let Some(codings) = self.transfer_encoding {
            if self.content_length.is_some() {
                return Err(ParseError::RequestSmugglingAttempt);
            }
            if self.transfer_fields != 1 || request.version != Version::Http11 {
                return Err(ParseError::InvalidTransferEncoding);
            }
            chunked_only(codings)?;
            request.chunked = true;
        }
        if let Some(value) = self.content_length
            && parse_decimal(value).is_none()
        {
            return Err(ParseError::InvalidContentLength);
        }
        Ok(())
    }
}

/// Accepts exactly `chunked`. The final coding must be `chunked` and may appear once (RFC 9112
/// sections 6.3 and 7); a list that also names another coding is understood but not decoded,
/// because inspection would see encoded bytes.
fn chunked_only(value: &[u8]) -> Result<(), ParseError> {
    let mut count = 0usize;
    let mut last: &[u8] = b"";
    for item in value.split(|&byte| byte == b',') {
        let coding = trim_space(item);
        if !is_token(coding) || last.eq_ignore_ascii_case(b"chunked") {
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

/// A non-empty run of ASCII digits as a `usize`, or `None` on any other byte or overflow.
fn parse_decimal(text: &[u8]) -> Option<usize> {
    if text.is_empty() {
        return None;
    }
    text.iter().try_fold(0usize, |value, &byte| {
        let digit = byte.checked_sub(b'0').filter(|&digit| digit < 10)?;
        value.checked_mul(10)?.checked_add(usize::from(digit))
    })
}

#[cfg(test)]
mod fuzz;
#[cfg(test)]
pub(crate) mod reference;
#[cfg(test)]
mod tests;

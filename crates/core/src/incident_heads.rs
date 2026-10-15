//! Bounded, redacted request and response heads for incident evidence (SID 0007).
//!
//! Capture is opt-in. A header value is copied only when its name is on the kept list
//! (built in, or added by the operator); credential names always lose their value;
//! URL-bearing values lose userinfo, query values and fragments; and every query value is
//! masked before any byte is copied. Truncation is decided after redaction and flagged,
//! never silent: the head is a transcript of what was seen, not a rebuild.
//!
//! Capture runs on the request path, so it writes into a caller's fixed array and never
//! allocates. Its work is linear in the input, and its output never exceeds the array.

use std::fmt;

/// The capacity of a stored request head in bytes.
pub const REQUEST_BYTES: usize = 2048;
/// The capacity of a stored response head in bytes.
pub const RESPONSE_BYTES: usize = 1024;
/// What replaces a value that is not kept.
pub const REDACTED: &str = "[redacted]";
/// The most header names an operator may add to the kept list.
pub const MAX_EXTRA: usize = 16;
/// The longest header name an operator may add, in bytes.
pub const MAX_NAME: usize = 64;

/// The length of a captured head and whether it was cut at its capacity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Head {
    /// The bytes written at the start of the output array.
    pub len: usize,
    /// True when the redacted head did not fit and its end was dropped.
    pub truncated: bool,
}

/// How the response side of the evidence was observed. It is stored with the heads, so an
/// empty response never claims a local answer by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResponseState {
    /// Rows written before the state was recorded.
    #[default]
    Unknown = 0,
    /// The origin's head was captured.
    Captured = 1,
    /// Sibuna answered the client itself (denial, challenge, rate limit); no origin head.
    Local = 2,
    /// Forward-auth mode: the ingress relayed the origin; Sibuna never saw its response.
    Unobserved = 3,
    /// Reverse proxy: the relay ended before a response head arrived (client got 502).
    Unavailable = 4,
}

impl ResponseState {
    /// Returns the stored code of this state (0 to 4).
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Returns the state stored as `code`, or `None` for a code no state uses.
    pub fn from_code(code: u8) -> Option<ResponseState> {
        match code {
            0 => Some(ResponseState::Unknown),
            1 => Some(ResponseState::Captured),
            2 => Some(ResponseState::Local),
            3 => Some(ResponseState::Unobserved),
            4 => Some(ResponseState::Unavailable),
            _ => None,
        }
    }
}

/// Header names whose values are always redacted, compared without case. The matcher in
/// `is_secret_folded` spells the same list as a pattern; the tests check it against this.
#[cfg(test)]
const SECRET_HEADERS: [&[u8]; 9] = [
    b"cookie",
    b"set-cookie",
    b"authorization",
    b"proxy-authorization",
    b"x-api-key",
    b"x-auth-token",
    b"x-csrf-token",
    b"x-xsrf-token",
    b"x-amz-security-token",
];

/// A header name containing one of these, without case, is a credential name too.
const SECRET_MARKS: [&[u8]; 5] = [b"token", b"secret", b"password", b"session", b"apikey"];

/// Header names whose values are kept verbatim (URL-bearing ones after masking); every
/// other value is replaced unless the operator adds the name. `is_kept_folded` spells the
/// same list as a pattern; a test keeps them equal.
pub const KEPT_HEADERS: [&str; 19] = [
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "content-encoding",
    "cache-control",
    "origin",
    "referer",
    "location",
    "x-forwarded-proto",
    "connection",
    "upgrade",
    "sec-websocket-version",
    "server",
    "date",
    "retry-after",
];

/// RFC 9110 token punctuation, the characters besides letters and digits.
const TOKEN_PUNCTUATION: &[u8] = b"!#$%&'*+-.^_`|~";

/// Returns true when `name` is a credential header: one of the fixed credential names, or a
/// name containing `token`, `secret`, `password`, `session` or `apikey`, without case.
pub fn is_secret_header(name: &[u8]) -> bool {
    let mut buffer = [0; MAX_NAME];
    match fold(name, &mut buffer) {
        Some(folded) => is_secret_folded(folded),
        // Every fixed name is short, so only a mark can make a long name a credential.
        None => SECRET_MARKS.iter().any(|mark| contains_ignore_case(name, mark)),
    }
}

/// Returns true when `name` is 1 to [`MAX_NAME`] RFC 9110 token characters.
pub fn is_valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.iter().all(|byte| byte.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(byte))
}

/// Writes `name` in ASCII lower case into `buffer` and returns it, or returns `None` when
/// the name is longer than [`MAX_NAME`] bytes. Matching folded names against fixed
/// patterns is a length switch and short compares, several times faster than comparing
/// each list entry without case.
fn fold<'b>(name: &[u8], buffer: &'b mut [u8; MAX_NAME]) -> Option<&'b [u8]> {
    let folded = buffer.get_mut(..name.len())?;
    for (folded, byte) in folded.iter_mut().zip(name) {
        *folded = byte.to_ascii_lowercase();
    }
    Some(folded)
}

/// The credential rule for a name already in ASCII lower case.
fn is_secret_folded(name: &[u8]) -> bool {
    let fixed = matches!(
        name,
        b"cookie"
            | b"set-cookie"
            | b"authorization"
            | b"proxy-authorization"
            | b"x-api-key"
            | b"x-auth-token"
            | b"x-csrf-token"
            | b"x-xsrf-token"
            | b"x-amz-security-token"
    );
    fixed
        || (0..name.len()).any(|at| {
            // `at` is below `name.len()`, so the tail is never empty.
            let tail = &name[at..];
            match tail[0] {
                b't' => tail.starts_with(b"token"),
                b's' => tail.starts_with(b"secret") || tail.starts_with(b"session"),
                b'p' => tail.starts_with(b"password"),
                b'a' => tail.starts_with(b"apikey"),
                _ => false,
            }
        })
}

/// The kept list for a name already in ASCII lower case.
fn is_kept_folded(name: &[u8]) -> bool {
    matches!(
        name,
        b"host"
            | b"user-agent"
            | b"accept"
            | b"accept-encoding"
            | b"accept-language"
            | b"content-type"
            | b"content-length"
            | b"content-encoding"
            | b"cache-control"
            | b"origin"
            | b"referer"
            | b"location"
            | b"x-forwarded-proto"
            | b"connection"
            | b"upgrade"
            | b"sec-websocket-version"
            | b"server"
            | b"date"
            | b"retry-after"
    )
}

/// Kept headers whose values are URLs and are masked before they are copied, for a name
/// already in ASCII lower case.
fn is_url_folded(name: &[u8]) -> bool {
    matches!(name, b"origin" | b"referer" | b"location")
}

/// Returns true when `haystack` contains `needle`, ignoring ASCII case.
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// What capture does with a header's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Treatment {
    Redact,
    MaskUrl,
    Keep,
}

/// Applies the rules in order: credential names lose their value, kept and operator names
/// keep it (URL-bearing ones masked), and every other value is replaced.
fn treatment(name: &[u8], extra: &Extra) -> Treatment {
    let mut buffer = [0; MAX_NAME];
    // No kept or operator name is longer than MAX_NAME, so a longer name is never kept.
    let Some(folded) = fold(name, &mut buffer) else {
        return Treatment::Redact;
    };
    // The kept list holds no credential name (a test checks this), so the common kept
    // headers skip the credential scan.
    if is_url_folded(folded) {
        Treatment::MaskUrl
    } else if is_kept_folded(folded) || (!is_secret_folded(folded) && extra.contains(name)) {
        Treatment::Keep
    } else {
        Treatment::Redact
    }
}

/// Why [`Extra::add`] refused a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraError {
    /// The name is empty, longer than [`MAX_NAME`] bytes, or not an RFC 9110 token.
    InvalidHeaderName,
    /// The list already holds [`MAX_EXTRA`] names.
    TooManyHeaders,
}

impl fmt::Display for ExtraError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            ExtraError::InvalidHeaderName => "a header name must be 1-64 token characters",
            ExtraError::TooManyHeaders => "at most 16 capture headers may be added",
        })
    }
}

impl std::error::Error for ExtraError {}

/// Operator additions to the kept list (`--console-capture-header`), compared without case
/// and deduplicated. A credential name added here is still redacted.
///
/// The names live inline in fixed arrays, so the list is cheap to copy, never allocates,
/// and is compared on the request path without chasing pointers.
#[derive(Clone, PartialEq, Eq)]
pub struct Extra {
    names: [[u8; MAX_NAME]; MAX_EXTRA],
    lens: [u8; MAX_EXTRA],
    count: u8,
}

impl Default for Extra {
    fn default() -> Extra {
        Extra { names: [[0; MAX_NAME]; MAX_EXTRA], lens: [0; MAX_EXTRA], count: 0 }
    }
}

impl fmt::Debug for Extra {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_list().entries(self.names()).finish()
    }
}

impl Extra {
    /// Adds `name` (copied) to the list. Returns `Ok(false)` when the name was already
    /// present in any case.
    ///
    /// Fails with [`ExtraError::InvalidHeaderName`] when the name is not a valid header
    /// name, and with [`ExtraError::TooManyHeaders`] when the list is full.
    pub fn add(&mut self, name: &str) -> Result<bool, ExtraError> {
        if !is_valid_name(name.as_bytes()) {
            return Err(ExtraError::InvalidHeaderName);
        }
        if self.contains(name.as_bytes()) {
            return Ok(false);
        }
        let index = usize::from(self.count);
        let slot = self.names.get_mut(index).ok_or(ExtraError::TooManyHeaders)?;
        // A valid name has at most MAX_NAME bytes, the length of a slot.
        slot[..name.len()].copy_from_slice(name.as_bytes());
        self.lens[index] = name.len() as u8;
        self.count += 1;
        Ok(true)
    }

    /// Returns true when `name` is on the list, without case.
    pub fn contains(&self, name: &[u8]) -> bool {
        self.stored().any(|stored| stored.eq_ignore_ascii_case(name))
    }

    /// Returns the number of names on the list.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Returns true when the list holds no name.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the name at `index` in insertion order, or `None` past the end.
    pub fn name(&self, index: usize) -> Option<&str> {
        self.names().nth(index)
    }

    /// Iterates over the names in insertion order, borrowing the list.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        // Stored names passed `is_valid_name`, so they are ASCII and always valid UTF-8.
        self.stored().map(|bytes| std::str::from_utf8(bytes).unwrap_or_default())
    }

    fn stored(&self) -> impl Iterator<Item = &[u8]> {
        self.names
            .iter()
            .zip(self.lens)
            .take(self.len())
            .map(|(name, len)| &name[..usize::from(len)])
    }
}

/// A bounded writer that records overflow instead of failing the caller.
struct Sink<'a> {
    out: &'a mut [u8],
    len: usize,
    truncated: bool,
}

impl<'a> Sink<'a> {
    fn new(out: &'a mut [u8]) -> Sink<'a> {
        Sink { out, len: 0, truncated: false }
    }

    #[inline]
    fn put(&mut self, bytes: &[u8]) {
        // `len` never exceeds `out.len()`, so the tail always exists.
        let room = &mut self.out[self.len..];
        let count = room.len().min(bytes.len());
        room[..count].copy_from_slice(&bytes[..count]);
        self.len += count;
        if count < bytes.len() {
            self.truncated = true;
        }
    }

    fn head(&self) -> Head {
        Head { len: self.len, truncated: self.truncated }
    }
}

/// The request line of a request whose head is captured, borrowed from the parsed request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestLine<'a> {
    /// The method as received, such as `GET`.
    pub method: &'a [u8],
    /// The path without the query.
    pub path: &'a [u8],
    /// The query without its `?`; empty when there was none.
    pub query: &'a [u8],
    /// The protocol version, such as `HTTP/1.1`.
    pub version: &'a [u8],
}

/// Captures `METHOD path?query VERSION` and one `Name: value` line per header, CRLF
/// separated, into `out`, with every query value masked and header values kept or redacted
/// by the rules of this module.
///
/// It borrows `line`, the `(name, value)` pairs of `headers` and `extra` for the call and
/// returns how much of `out` it filled. It cannot fail: what does not fit is dropped and
/// flagged.
pub fn request_head<'h>(
    line: &RequestLine<'_>,
    headers: impl IntoIterator<Item = (&'h [u8], &'h [u8])>,
    extra: &Extra,
    out: &mut [u8; REQUEST_BYTES],
) -> Head {
    let mut sink = Sink::new(out);
    sink.put(line.method);
    sink.put(b" ");
    sink.put(line.path);
    if !line.query.is_empty() {
        sink.put(b"?");
        mask_query(&mut sink, line.query);
    }
    sink.put(b" ");
    sink.put(line.version);
    sink.put(b"\r\n");
    for (name, value) in headers {
        field(&mut sink, name, value, extra);
    }
    sink.head()
}

/// Captures the origin's status line and headers as relayed into `out`, values kept by the
/// same rules as [`request_head`]. `head` is the raw response head; capture stops at the
/// first empty line, and a line without a colon is copied as it is.
///
/// It borrows `head` and `extra` for the call and cannot fail: what does not fit is dropped
/// and flagged.
pub fn response_head(head: &[u8], extra: &Extra, out: &mut [u8; RESPONSE_BYTES]) -> Head {
    let mut sink = Sink::new(out);
    let mut lines = split_crlf(head);
    if let Some(status) = lines.next() {
        sink.put(status);
        sink.put(b"\r\n");
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        match line.iter().position(|&byte| byte == b':') {
            Some(colon) => {
                let (name, rest) = line.split_at(colon);
                field(&mut sink, name, trim_blanks(&rest[1..]), extra);
            }
            None => {
                sink.put(line);
                sink.put(b"\r\n");
            }
        }
    }
    sink.head()
}

/// Splits on the two-byte sequence CRLF, like Zig's `splitSequence`: an input without CRLF
/// is one line, and an empty input is one empty line.
fn split_crlf(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(bytes);
    std::iter::from_fn(move || {
        let current = rest?;
        match current.windows(2).position(|pair| pair == b"\r\n") {
            Some(at) => {
                rest = Some(&current[at + 2..]);
                Some(&current[..at])
            }
            None => {
                rest = None;
                Some(current)
            }
        }
    })
}

/// Removes spaces and tabs at both ends, like Zig's `std.mem.trim(u8, value, " \t")`.
fn trim_blanks(value: &[u8]) -> &[u8] {
    let blank = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let start = value.iter().position(|byte| !blank(byte)).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !blank(byte)).map_or(start, |last| last + 1);
    &value[start..end]
}

fn field(sink: &mut Sink<'_>, name: &[u8], value: &[u8], extra: &Extra) {
    sink.put(name);
    sink.put(b": ");
    match treatment(name, extra) {
        Treatment::Redact => sink.put(REDACTED.as_bytes()),
        Treatment::MaskUrl => mask_url(sink, value),
        Treatment::Keep => sink.put(value),
    }
    sink.put(b"\r\n");
}

fn mask_query(sink: &mut Sink<'_>, query: &[u8]) {
    for (index, part) in query.split(|&byte| byte == b'&').enumerate() {
        if index != 0 {
            sink.put(b"&");
        }
        match part.iter().position(|&byte| byte == b'=') {
            Some(equals) => {
                sink.put(&part[..=equals]);
                sink.put(REDACTED.as_bytes());
            }
            None => sink.put(part),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Replaces the userinfo, the query values and the fragment of a URL. A value that is
/// neither an absolute or protocol-relative URL nor a path is ambiguous and replaced whole.
fn mask_url(sink: &mut Sink<'_>, value: &[u8]) {
    let authority_start = match find(value, b"://") {
        Some(scheme_end) => Some(scheme_end + 3),
        None if value.starts_with(b"//") => Some(2),
        None => None,
    };
    let mut rest = value;
    if let Some(start) = authority_start {
        let end = value[start..]
            .iter()
            .position(|byte| b"/?#".contains(byte))
            .map_or(value.len(), |offset| start + offset);
        let authority = &value[start..end];
        sink.put(&value[..start]);
        match authority.iter().rposition(|&byte| byte == b'@') {
            Some(at) => {
                sink.put(REDACTED.as_bytes());
                sink.put(&authority[at..]);
            }
            None => sink.put(authority),
        }
        rest = &value[end..];
    } else if rest.first().is_some_and(|&byte| byte != b'/') {
        sink.put(REDACTED.as_bytes());
        return;
    }
    let query_start = rest.iter().position(|&byte| byte == b'?');
    let fragment_start = rest.iter().position(|&byte| byte == b'#');
    let path_end = query_start.unwrap_or(rest.len()).min(fragment_start.unwrap_or(rest.len()));
    sink.put(&rest[..path_end]);
    if let Some(query) = query_start.filter(|&q| fragment_start.is_none_or(|f| q < f)) {
        sink.put(b"?");
        mask_query(sink, &rest[query + 1..fragment_start.unwrap_or(rest.len())]);
    }
    if fragment_start.is_some() {
        sink.put(b"#");
        sink.put(REDACTED.as_bytes());
    }
}

#[cfg(test)]
mod tests;

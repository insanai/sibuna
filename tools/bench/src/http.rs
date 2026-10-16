//! A minimal HTTP/1.1 client for loopback benchmarks: one-shot requests to set a run up
//! (health, challenge, verification, status probes), and response framing for the
//! keep-alive connections of the latency generator.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::{Error, Result};

/// The largest response we read; anything larger is an error rather than a memory hazard.
const MAX_RESPONSE: usize = 16 << 20;

/// A complete response.
#[derive(Clone, Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The header fields in order, names as sent.
    pub headers: Vec<(String, String)>,
    /// The body, with any chunked coding removed.
    pub body: Vec<u8>,
}

impl Response {
    /// Returns the values of every header named `name` (ASCII case-insensitive).
    pub fn header_values<'r>(&'r self, name: &'r str) -> impl Iterator<Item = &'r str> + 'r {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| &**v)
    }

    /// Returns the `Cookie` header a browser would send back, as `compare.py` built it: the
    /// `name=value` pair of every `Set-Cookie` field with its attributes dropped, a later
    /// field replacing an earlier one of the same name, and pairs with an empty value (which
    /// delete a cookie) left out, joined by `; `. Returns an empty string when none is left.
    pub fn cookie_header(&self) -> String {
        let mut jar: Vec<(&str, &str)> = Vec::new();
        for field in self.header_values("set-cookie") {
            let pair = field.split(';').next().unwrap_or_default().trim();
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (name, value) = (name.trim(), value.trim());
            if name.is_empty() {
                continue;
            }
            match jar.iter_mut().find(|(known, _)| *known == name) {
                Some(entry) => entry.1 = value,
                None => jar.push((name, value)),
            }
        }
        let pairs: Vec<String> = jar
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        pairs.join("; ")
    }
}

/// Sends one request to `127.0.0.1:port` on a fresh connection and reads the whole response.
///
/// # Errors
///
/// Fails on connection or I/O errors, a ten-second timeout, or a malformed response.
pub fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Response> {
    let fail = |e: io::Error| Error::io(format!("{method} {target} on port {port}"), e);
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(fail)?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(fail)?;
    stream.set_write_timeout(Some(Duration::from_secs(10))).map_err(fail)?;
    let mut head = request_head(method, target, port, headers);
    if !body.is_empty() || method == "POST" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).map_err(fail)?;
    stream.write_all(body).map_err(fail)?;
    let mut data = Vec::new();
    stream.take(MAX_RESPONSE as u64).read_to_end(&mut data).map_err(fail)?;
    parse_response(&data).ok_or_else(|| {
        Error::new("BAD RESPONSE", format!("{method} {target}: the response is not HTTP/1.1."))
    })
}

/// Returns the request line and headers of a request, without the final blank line.
pub fn request_head(
    method: &str,
    target: &str,
    port: u16,
    headers: &[(String, String)],
) -> String {
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head
}

/// How far a buffer holds a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    /// More bytes are needed.
    Incomplete,
    /// The response ends at byte `length`; `close` when the server will close afterwards.
    Complete {
        /// The status code.
        status: u16,
        /// The length of the whole message.
        length: usize,
        /// The server announced `Connection: close`.
        close: bool,
    },
    /// The body has no length: it ends when the server closes the connection.
    UntilClose {
        /// The status code.
        status: u16,
    },
    /// The bytes are not an HTTP/1.1 response.
    Invalid,
}

/// The parsed head of a response.
struct Head {
    status: u16,
    head_len: usize,
    content_length: Option<usize>,
    chunked: bool,
    close: bool,
    headers: Vec<(String, String)>,
}

fn parse_head(data: &[u8]) -> Option<Option<Head>> {
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Some(None);
    };
    let text = std::str::from_utf8(&data[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut head = Head {
        status,
        head_len: end + 4,
        content_length: None,
        chunked: false,
        close: false,
        headers: Vec::new(),
    };
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            head.content_length = Some(value.parse().ok()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.to_ascii_lowercase().contains("chunked");
        } else if name.eq_ignore_ascii_case("connection") {
            head.close = value.eq_ignore_ascii_case("close");
        }
        head.headers.push((name.to_owned(), value.to_owned()));
    }
    Some(Some(head))
}

/// Decides how much of `data` is the first response in it.
pub fn frame(data: &[u8]) -> Frame {
    let head = match parse_head(data) {
        None => return Frame::Invalid,
        Some(None) => return Frame::Incomplete,
        Some(Some(head)) => head,
    };
    // Responses to our GET and POST requests: 1xx, 204 and 304 have no body.
    let no_body = head.status < 200 || head.status == 204 || head.status == 304;
    let length = if no_body {
        Some(head.head_len)
    } else if head.chunked {
        match chunked_end(&data[head.head_len..]) {
            Some(Some(body)) => Some(head.head_len + body),
            Some(None) => None,
            None => return Frame::Invalid,
        }
    } else if let Some(content) = head.content_length {
        let total = head.head_len + content;
        (data.len() >= total).then_some(total)
    } else {
        return Frame::UntilClose { status: head.status };
    };
    match length {
        Some(length) => Frame::Complete { status: head.status, length, close: head.close },
        None => Frame::Incomplete,
    }
}

/// Returns the length of a complete chunked body at the start of `data`, `Some(None)` when
/// more bytes are needed, or `None` when the coding is malformed. Trailers are not expected.
fn chunked_end(data: &[u8]) -> Option<Option<usize>> {
    let mut at = 0;
    loop {
        let Some(line_end) = data[at..].windows(2).position(|w| w == b"\r\n") else {
            return Some(None);
        };
        let line = std::str::from_utf8(&data[at..at + line_end]).ok()?;
        let size_text = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        at += line_end + 2;
        if size == 0 {
            return Some((data.len() >= at + 2).then_some(at + 2));
        }
        if data.len() < at + size + 2 {
            return Some(None);
        }
        at += size + 2;
    }
}

/// Returns the chunked body at the start of `data` with its coding removed.
fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut rest = data;
    while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&rest[..line_end]);
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        rest = &rest[line_end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        body.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    body
}

/// Parses a whole response read until the server closed the connection.
fn parse_response(data: &[u8]) -> Option<Response> {
    let head = parse_head(data)??;
    let rest = &data[head.head_len..];
    let body = if head.chunked {
        dechunk(rest)
    } else {
        let length = head.content_length.unwrap_or(rest.len()).min(rest.len());
        rest[..length].to_vec()
    };
    Some(Response { status: head.status, headers: head.headers, body })
}

/// Reads one response from a keep-alive `stream` into `buffer` (cleared first) and returns
/// its status and whether the connection must be reopened afterwards.
///
/// # Errors
///
/// Fails on I/O errors, a closed connection, a malformed response or one over 16 MiB.
pub fn read_response(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<(u16, bool)> {
    buffer.clear();
    let mut scratch = [0u8; 16 * 1024];
    loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return match frame(buffer) {
                Frame::UntilClose { status } => Ok((status, true)),
                _ => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")),
            };
        }
        buffer.extend_from_slice(&scratch[..read]);
        match frame(buffer) {
            Frame::Complete { status, length, close } => {
                // A pipelined response cannot arrive: we send one request at a time.
                return Ok((status, close || length != buffer.len()));
            }
            Frame::Invalid => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "not an HTTP response"));
            }
            Frame::Incomplete | Frame::UntilClose { .. } if buffer.len() > MAX_RESPONSE => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
            }
            Frame::Incomplete | Frame::UntilClose { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_content_length_and_no_body_responses() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(frame(ok), Frame::Complete { status: 200, length: ok.len(), close: false });
        assert_eq!(frame(&ok[..ok.len() - 1]), Frame::Incomplete);
        assert_eq!(frame(b"HTTP/1.1 200 OK\r\nContent"), Frame::Incomplete);
        let not_modified = b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
        assert_eq!(
            frame(not_modified),
            Frame::Complete { status: 304, length: not_modified.len(), close: true }
        );
        assert_eq!(frame(b"HTTP/1.1 200 OK\r\n\r\nabc"), Frame::UntilClose { status: 200 });
        assert_eq!(frame(b"SSH-2.0 hello\r\n\r\n"), Frame::Invalid);
    }

    #[test]
    fn frames_and_decodes_chunked_bodies() {
        let data = b"HTTP/1.1 401 X\r\nTransfer-Encoding: chunked\r\n\r\n\
            3;x=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(frame(data), Frame::Complete { status: 401, length: data.len(), close: false });
        assert_eq!(frame(&data[..data.len() - 2]), Frame::Incomplete);
        let response = parse_response(data).unwrap();
        assert_eq!(response.body, b"abcde");
        assert_eq!(response.header_values("transfer-encoding").next(), Some("chunked"));
        assert_eq!(
            frame(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"),
            Frame::Invalid
        );
    }

    #[test]
    fn parses_a_closed_response() {
        let data = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b; Path=/\r\nSet-Cookie: c=d\r\n\r\nhello";
        let response = parse_response(data).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        let cookies: Vec<&str> = response.header_values("set-cookie").collect();
        assert_eq!(cookies, ["a=b; Path=/", "c=d"]);
        assert_eq!(response.cookie_header(), "a=b; c=d");
    }

    #[test]
    fn cookie_header_keeps_the_last_value_and_drops_deletions() {
        let data = b"HTTP/1.1 200 OK\r\n\
            Set-Cookie: auth=; Path=/; Max-Age=0; SameSite=Lax; Partitioned\r\n\
            Set-Cookie: verify=01a1; Path=/; Partitioned\r\n\
            set-cookie: auth=jwt.token; Path=/\r\n\
            Set-Cookie: =orphan\r\n\
            Content-Length: 0\r\n\r\n";
        let response = parse_response(data).unwrap();
        assert_eq!(response.cookie_header(), "auth=jwt.token; verify=01a1");
        let none = parse_response(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=\r\n\r\n").unwrap();
        assert_eq!(none.cookie_header(), "");
    }
}

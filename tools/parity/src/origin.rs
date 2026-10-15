//! The stub origin both daemons proxy to. It reads each request as an origin would and
//! answers with an echo of what it received: the request line, a digest of the header
//! section, the body's framing, length and digest, and the header section itself, so a
//! difference in what a daemon forwarded shows up in the response the client compares.
//!
//! A few paths under `/__origin/` choose other answer framings (chunked, close-delimited,
//! large, empty, 304, a cookie, unusual header fields, an accepted upgrade whose tunnel
//! the origin measures) so the daemons' relaying of them is compared too.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use crate::configs::COOKIE_NAME;
use crate::response::find;

/// The largest request head or body the origin reads.
const MAX_READ: usize = 32 << 20;

/// Starts the origin on a loopback port and returns its address. Its threads live until
/// the process ends.
///
/// # Errors
///
/// Returns the error of binding the listener.
pub fn start() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve(stream));
        }
    });
    Ok(address)
}

/// FNV-1a over `bytes`, the digest the echo reports.
pub fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A connection's unread bytes.
struct Conn {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Conn {
    fn more(&mut self) -> bool {
        let mut chunk = [0u8; 32 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) | Err(_) => false,
            Ok(count) => {
                self.buffer.extend_from_slice(&chunk[..count]);
                self.buffer.len() <= MAX_READ
            }
        }
    }

    fn take(&mut self, count: usize) -> Option<Vec<u8>> {
        while self.buffer.len() < count {
            if !self.more() {
                return None;
            }
        }
        Some(self.buffer.drain(..count).collect())
    }

    fn line(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(at) = find(&self.buffer, b"\n") {
                return Some(self.buffer.drain(..=at).collect());
            }
            if !self.more() {
                return None;
            }
        }
    }
}

/// Serves requests on one connection until it ends.
fn serve(stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let mut conn = Conn { stream, buffer: Vec::new() };
    loop {
        let head = loop {
            if let Some(at) = find(&conn.buffer, b"\r\n\r\n") {
                break conn.buffer.drain(..at + 4).collect::<Vec<u8>>();
            }
            if !conn.more() {
                return;
            }
        };
        let Some((framing, body)) = read_body(&mut conn, &head) else { return };
        if is_upgrade(&head) {
            tunnel(conn, &head);
            return;
        }
        let reply = answer(&head, framing, &body);
        if conn.stream.write_all(&reply).is_err() || find(&head, b"/__origin/close").is_some() {
            return;
        }
    }
}

/// True for an upgrade request to `/__origin/upgrade`, which the origin accepts.
fn is_upgrade(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    find(head, b"/__origin/upgrade").is_some() && header(&text, "upgrade").is_some()
}

/// The key of the RFC 6455 example handshake, which the corpus sends.
const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
/// Its `Sec-WebSocket-Accept` (RFC 6455, section 1.3).
const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// Accepts the upgrade, then reads the tunnel until the client side ends or pauses for a
/// second, and answers with the length and digest of what came through. The accept key is
/// only right for the example key; other keys get none, which a daemon may refuse.
fn tunnel(mut conn: Conn, head: &[u8]) {
    let text = String::from_utf8_lossy(head);
    let mut accept = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n".to_owned();
    if let Some(protocol) = header(&text, "upgrade") {
        accept.push_str(&format!("Upgrade: {protocol}\r\n"));
    }
    if header(&text, "sec-websocket-key") == Some(SAMPLE_KEY) {
        accept.push_str(&format!("Sec-WebSocket-Accept: {SAMPLE_ACCEPT}\r\n"));
    }
    accept.push_str("\r\n");
    if conn.stream.write_all(accept.as_bytes()).is_err() {
        return;
    }
    let _ = conn.stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    while conn.more() {}
    let received = std::mem::take(&mut conn.buffer);
    let reply = format!("TUNNEL|{}|{:016x}", received.len(), digest(&received));
    let _ = conn.stream.write_all(reply.as_bytes());
}

/// The value of the first header field `name` in `head`.
fn header<'h>(head: &'h str, name: &str) -> Option<&'h str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Reads the request body by its framing: chunked, Content-Length or none.
fn read_body(conn: &mut Conn, head: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let text = String::from_utf8_lossy(head);
    let chunked =
        header(&text, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return Some(("chunked", read_chunked(conn)?));
    }
    match header(&text, "content-length").map(str::parse::<usize>) {
        Some(Ok(length)) if length <= MAX_READ => Some(("length", conn.take(length)?)),
        Some(_) => None,
        None => Some(("none", Vec::new())),
    }
}

/// Decodes a chunked body; the daemons send canonical chunks, so anything else ends the
/// connection.
fn read_chunked(conn: &mut Conn) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = conn.line()?;
        let digits = std::str::from_utf8(line.strip_suffix(b"\r\n")?).ok()?;
        let size = usize::from_str_radix(digits, 16).ok()?;
        if size == 0 {
            // Trailer fields up to the blank line.
            loop {
                if conn.line()? == b"\r\n" {
                    return Some(body);
                }
            }
        }
        if body.len() + size > MAX_READ {
            return None;
        }
        body.extend(conn.take(size)?);
        if conn.take(2)? != b"\r\n" {
            return None;
        }
    }
}

/// The head with the session cookie's value masked: its text is random per daemon, while
/// the rest of a forwarded head must be identical.
pub fn mask_head(head: &[u8]) -> Vec<u8> {
    let marker = format!("{COOKIE_NAME}=");
    let mut out = Vec::with_capacity(head.len());
    let mut rest = head;
    while let Some(at) = find(rest, marker.as_bytes()) {
        let start = at + marker.len();
        out.extend_from_slice(&rest[..start]);
        out.extend_from_slice(b"<token>");
        let tail = &rest[start..];
        let end =
            tail.iter().position(|&byte| byte == b';' || byte == b'\r').unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.extend_from_slice(rest);
    out
}

/// The echo body for a request.
pub fn echo(head: &[u8], framing: &str, body: &[u8]) -> Vec<u8> {
    let head = mask_head(head.strip_suffix(b"\r\n\r\n").unwrap_or(head));
    let line_end = find(&head, b"\r\n").unwrap_or(head.len());
    let fields = head.get(line_end..).unwrap_or_default();
    let mut out = format!(
        "ORIGIN\nline: {}\nheaders: {:016x}\nbody: {framing} {} {:016x}\n--\n",
        String::from_utf8_lossy(&head[..line_end]),
        digest(fields),
        body.len(),
        digest(body),
    )
    .into_bytes();
    out.extend_from_slice(&head);
    out
}

/// The whole answer to one request: the echo in the framing its path asks for.
fn answer(head: &[u8], framing: &str, body: &[u8]) -> Vec<u8> {
    let echo = echo(head, framing, body);
    let path = |name: &str| find(head, format!("/__origin/{name}").as_bytes()).is_some();
    let ok = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: stub\r\n";
    let (head_text, body): (String, Vec<u8>) = if path("chunked") {
        let mut chunks = Vec::new();
        for piece in echo.chunks(100) {
            chunks.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            chunks.extend_from_slice(piece);
            chunks.extend_from_slice(b"\r\n");
        }
        chunks.extend_from_slice(b"0\r\n\r\n");
        (format!("{ok}Transfer-Encoding: chunked\r\n\r\n"), chunks)
    } else if path("close") {
        (format!("{ok}Connection: close\r\n\r\n"), echo)
    } else if path("big") {
        let mut big = echo;
        big.resize(big.len() + 200_000, b'z');
        (format!("{ok}Content-Length: {}\r\n\r\n", big.len()), big)
    } else if path("empty") {
        ("HTTP/1.1 204 No Content\r\nX-Origin: stub\r\n\r\n".to_owned(), Vec::new())
    } else if path("not-modified") {
        ("HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n".to_owned(), Vec::new())
    } else if path("cookie") {
        let fields = "Set-Cookie: origin=1; Path=/\r\nSet-Cookie: other=2\r\nLocation: /next\r\n";
        (format!("HTTP/1.1 302 Found\r\n{fields}Content-Length: {}\r\n\r\n", echo.len()), echo)
    } else if path("headers") {
        let fields =
            "X-Dup: 1\r\nX-Dup: 2\r\nServer: stub/1\r\nKeep-Alive: timeout=5\r\nX-Empty:\r\n";
        (format!("{ok}{fields}Content-Length: {}\r\n\r\n", echo.len()), echo)
    } else {
        (format!("{ok}Content-Length: {}\r\n\r\n", echo.len()), echo)
    };
    let head_only = head.starts_with(b"HEAD ");
    let mut reply = head_text.into_bytes();
    if !head_only {
        reply.extend_from_slice(&body);
    }
    reply
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
        out
    }

    #[test]
    fn the_echo_describes_the_request() {
        let address = start().unwrap();
        let reply = exchange(
            address,
            b"POST /x?y HTTP/1.1\r\nHost: a\r\nCookie: __sibuna_token=secret; b=1\r\n\
              Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        );
        let text = String::from_utf8_lossy(&reply);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("line: POST /x?y HTTP/1.1\n"));
        assert!(text.contains(&format!("body: chunked 3 {:016x}\n", digest(b"abc"))));
        assert!(text.contains("__sibuna_token=<token>; b=1"));
        assert!(!text.contains("secret"));
    }

    #[test]
    fn origin_paths_choose_the_framing() {
        let address = start().unwrap();
        let chunked = exchange(address, b"GET /__origin/chunked HTTP/1.1\r\n\r\n");
        assert!(find(&chunked, b"Transfer-Encoding: chunked\r\n\r\n64\r\nORIGIN").is_some());
        let head = exchange(address, b"HEAD /p HTTP/1.1\r\n\r\n");
        assert!(head.ends_with(b"\r\n\r\n"));
        let empty = exchange(address, b"GET /__origin/empty HTTP/1.1\r\n\r\n");
        assert!(empty.starts_with(b"HTTP/1.1 204"));
    }

    #[test]
    fn an_upgrade_opens_a_tunnel() {
        let address = start().unwrap();
        let reply = exchange(
            address,
            b"GET /__origin/upgrade HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\nping",
        );
        let text = String::from_utf8_lossy(&reply);
        assert!(text.starts_with("HTTP/1.1 101 "), "{text}");
        assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(text.ends_with(&format!("TUNNEL|4|{:016x}", digest(b"ping"))), "{text}");
    }

    #[test]
    fn masking_replaces_only_the_token() {
        let masked = mask_head(b"Cookie: a=1; __sibuna_token=xyz\r\nX: __sibuna_token=q");
        assert_eq!(masked, b"Cookie: a=1; __sibuna_token=<token>\r\nX: __sibuna_token=<token>");
    }
}

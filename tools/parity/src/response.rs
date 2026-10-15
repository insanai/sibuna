//! Reads what a daemon sends on one connection as a sequence of events: framed responses,
//! the end of the connection, a timeout, or bytes that are not a response.

use std::io::{self, Read};
use std::net::TcpStream;

/// The largest head or chunk line we accept from a daemon before calling it garbage.
const MAX_HEAD: usize = 1 << 20;
/// The largest body we keep.
const MAX_BODY: usize = 16 << 20;

/// How a response body was delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body by definition (a `HEAD` answer, 1xx, 204 or 304).
    None,
    /// `Content-Length`, complete.
    Length,
    /// `Transfer-Encoding: chunked`, complete.
    Chunked,
    /// Delimited by the end of the connection.
    Close,
    /// The connection ended or stalled before the declared body was complete.
    Truncated,
}

impl Framing {
    /// The framing's name in reports.
    pub fn name(self) -> &'static str {
        match self {
            Framing::None => "none",
            Framing::Length => "length",
            Framing::Chunked => "chunked",
            Framing::Close => "close",
            Framing::Truncated => "truncated",
        }
    }
}

/// One response as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status line without its CRLF.
    pub status_line: String,
    /// The status code, 0 when the line has none.
    pub status: u16,
    /// Header fields in order, names as sent.
    pub headers: Vec<(String, String)>,
    /// The body, decoded from chunks when chunked.
    pub body: Vec<u8>,
    /// How the body was delimited.
    pub framing: Framing,
}

impl Response {
    /// The value of the first field named `name` (ignoring case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What reading the next response produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A response.
    Response(Response),
    /// The daemon closed the connection (a FIN or a reset) with nothing pending.
    Closed,
    /// Nothing arrived within the read timeout; holds what had arrived.
    Timeout(Vec<u8>),
    /// Bytes that do not form a response, up to the end of the connection.
    Garbage(Vec<u8>),
}

/// A buffered reader over a client connection.
pub struct Reader {
    stream: TcpStream,
    buffer: Vec<u8>,
}

/// The result of refilling the buffer.
enum Fill {
    More,
    End,
    Stalled,
}

impl Reader {
    /// Wraps `stream`; its read timeout decides when a silent daemon counts as stalled.
    pub fn new(stream: TcpStream) -> Reader {
        Reader { stream, buffer: Vec::with_capacity(16 * 1024) }
    }

    /// Borrows the stream, to write requests or shut it down.
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    fn fill(&mut self) -> Fill {
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) => Fill::End,
            Ok(count) => {
                self.buffer.extend_from_slice(&chunk[..count]);
                Fill::More
            }
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                Fill::Stalled
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Fill::More,
            // A reset ends the connection like a FIN; which one a daemon's close produces
            // depends on unread data in its buffer, which is timing, not behaviour.
            Err(_) => Fill::End,
        }
    }

    /// Reads the next event. `head_request` says whether the request was `HEAD`, whose
    /// answer has no body whatever its fields say.
    pub fn next_event(&mut self, head_request: bool) -> Event {
        let head_end = loop {
            if let Some(at) = find(&self.buffer, b"\r\n\r\n") {
                break at;
            }
            if self.buffer.len() > MAX_HEAD {
                return Event::Garbage(self.drain_rest());
            }
            match self.fill() {
                Fill::More => {}
                Fill::End if self.buffer.is_empty() => return Event::Closed,
                Fill::End => return Event::Garbage(std::mem::take(&mut self.buffer)),
                Fill::Stalled => return Event::Timeout(std::mem::take(&mut self.buffer)),
            }
        };
        let head: Vec<u8> = self.buffer.drain(..head_end + 4).collect();
        let Some(mut response) = parse_head(&head) else {
            let mut garbage = head;
            garbage.extend(self.drain_rest());
            return Event::Garbage(garbage);
        };
        let no_body = head_request
            || (100..200).contains(&response.status)
            || response.status == 204
            || response.status == 304;
        if no_body {
            response.framing = Framing::None;
        } else if response
            .header("transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            self.read_chunked(&mut response);
        } else if let Some(length) = response.header("content-length") {
            let length = length.trim().parse::<usize>().unwrap_or(0).min(MAX_BODY);
            self.read_length(&mut response, length);
        } else {
            response.body = self.drain_rest();
            response.framing = Framing::Close;
        }
        Event::Response(response)
    }

    /// Reads everything until the connection ends or stalls.
    pub fn drain_rest(&mut self) -> Vec<u8> {
        while self.buffer.len() < MAX_BODY {
            if !matches!(self.fill(), Fill::More) {
                break;
            }
        }
        std::mem::take(&mut self.buffer)
    }

    fn read_length(&mut self, response: &mut Response, length: usize) {
        while self.buffer.len() < length {
            if !matches!(self.fill(), Fill::More) {
                response.body = std::mem::take(&mut self.buffer);
                response.framing = Framing::Truncated;
                return;
            }
        }
        response.body = self.buffer.drain(..length).collect();
        response.framing = Framing::Length;
    }

    fn read_line(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(at) = find(&self.buffer, b"\r\n") {
                return Some(self.buffer.drain(..at + 2).collect());
            }
            if self.buffer.len() > MAX_HEAD || !matches!(self.fill(), Fill::More) {
                return None;
            }
        }
    }

    fn read_chunked(&mut self, response: &mut Response) {
        response.framing = Framing::Truncated;
        loop {
            let Some(line) = self.read_line() else { return };
            let text = String::from_utf8_lossy(&line);
            let digits = text.trim_end().split(';').next().unwrap_or_default().trim();
            let Ok(size) = usize::from_str_radix(digits, 16) else { return };
            if size == 0 {
                // Trailer fields up to the blank line.
                while let Some(line) = self.read_line() {
                    if line == b"\r\n" {
                        response.framing = Framing::Chunked;
                        return;
                    }
                }
                return;
            }
            if size > MAX_BODY || response.body.len() > MAX_BODY {
                return;
            }
            while self.buffer.len() < size + 2 {
                if !matches!(self.fill(), Fill::More) {
                    response.body.append(&mut self.buffer);
                    return;
                }
            }
            response.body.extend(self.buffer.drain(..size));
            if self.buffer.drain(..2).as_slice() != b"\r\n" {
                return;
            }
        }
    }
}

/// Parses a response head ending in CRLF CRLF; `None` when it is not an HTTP/1.x status
/// line.
pub fn parse_head(head: &[u8]) -> Option<Response> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?.to_owned();
    if !status_line.starts_with("HTTP/1.") {
        return None;
    }
    let status = status_line.get(9..12).and_then(|code| code.parse().ok()).unwrap_or(0);
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| match line.split_once(':') {
            Some((name, value)) => (name.to_owned(), value.trim_matches([' ', '\t']).to_owned()),
            None => (line.to_owned(), String::new()),
        })
        .collect();
    Some(Response { status_line, status, headers, body: Vec::new(), framing: Framing::None })
}

/// The offset of the first `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Shutdown, TcpListener};
    use std::time::Duration;

    use super::*;

    /// Serves `bytes` to one client and returns a reader of them.
    fn reader_of(bytes: &'static [u8]) -> Reader {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(bytes).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Reader::new(stream)
    }

    #[test]
    fn responses_are_split_by_their_framing() {
        let mut reader = reader_of(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc\
              HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              2;x\r\nhi\r\n1\r\n!\r\n0\r\nT: v\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nHTTP/1.0 200 OK\r\n\r\nrest",
        );
        let Event::Response(continued) = reader.next_event(false) else { panic!() };
        assert_eq!((continued.status, continued.framing), (100, Framing::None));
        let Event::Response(first) = reader.next_event(false) else { panic!() };
        assert_eq!((first.body.as_slice(), first.framing), (&b"abc"[..], Framing::Length));
        let Event::Response(second) = reader.next_event(false) else { panic!() };
        assert_eq!((second.body.as_slice(), second.framing), (&b"hi!"[..], Framing::Chunked));
        let Event::Response(head) = reader.next_event(true) else { panic!() };
        assert_eq!(head.framing, Framing::None);
        let Event::Response(last) = reader.next_event(false) else { panic!() };
        assert_eq!((last.body.as_slice(), last.framing), (&b"rest"[..], Framing::Close));
        assert_eq!(reader.next_event(false), Event::Closed);
    }

    #[test]
    fn short_bodies_and_non_responses_are_reported() {
        let mut reader = reader_of(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
        let Event::Response(short) = reader.next_event(false) else { panic!() };
        assert_eq!((short.body.as_slice(), short.framing), (&b"abc"[..], Framing::Truncated));
        let mut reader = reader_of(b"garbage\r\n\r\nmore");
        assert_eq!(reader.next_event(false), Event::Garbage(b"garbage\r\n\r\nmore".to_vec()));
        let mut reader = reader_of(b"partial head");
        assert_eq!(reader.next_event(false), Event::Garbage(b"partial head".to_vec()));
    }

    #[test]
    fn heads_parse_into_fields() {
        let response = parse_head(b"HTTP/1.1 403 Forbidden\r\nA: 1\r\nb:2 \r\n\r\n").unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(response.header("B"), Some("2"));
        assert!(parse_head(b"HTTP/2 200\r\n\r\n").is_none());
        assert_eq!(find(b"abc", b"c"), Some(2));
        assert_eq!(find(b"abc", b""), None);
    }
}

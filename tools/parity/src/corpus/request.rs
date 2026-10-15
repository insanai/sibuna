//! A small builder for raw HTTP/1.x requests. It writes exactly the bytes it is given, so
//! scenarios can also build malformed requests.

use super::{LEN, has_placeholder};

/// How the body is framed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Body {
    /// No body and no framing header.
    #[default]
    Empty,
    /// The bytes with a `Content-Length` header (`@@LEN@@` when they hold placeholders).
    Length(Vec<u8>),
    /// The bytes in canonical chunks of at most `chunk` bytes with `Transfer-Encoding:
    /// chunked`.
    Chunked {
        /// The decoded body.
        data: Vec<u8>,
        /// The largest chunk; zero means one chunk.
        chunk: usize,
    },
    /// Bytes written after the blank line as they are, with no framing header added.
    Raw(Vec<u8>),
}

/// One request: line, header fields and body.
#[derive(Clone, Debug)]
pub struct Request {
    /// The method token, written as is.
    pub method: String,
    /// The request target, written as is.
    pub target: Vec<u8>,
    /// The protocol version, such as `HTTP/1.1`.
    pub version: &'static str,
    /// Header fields in order.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body and its framing.
    pub body: Body,
}

impl Request {
    /// A request with `Host: app.test` and no body.
    pub fn new(method: &str, target: impl Into<Vec<u8>>) -> Request {
        Request {
            method: method.to_owned(),
            target: target.into(),
            version: "HTTP/1.1",
            headers: vec![("Host".to_owned(), b"app.test".to_vec())],
            body: Body::Empty,
        }
    }

    /// A `GET` of `target`.
    pub fn get(target: impl Into<Vec<u8>>) -> Request {
        Request::new("GET", target)
    }

    /// A `POST` of `body` with a `Content-Length` and `content_type`.
    pub fn post(
        target: impl Into<Vec<u8>>,
        content_type: &str,
        body: impl Into<Vec<u8>>,
    ) -> Request {
        Request { body: Body::Length(body.into()), ..Request::new("POST", target) }
            .header("Content-Type", content_type)
    }

    /// Appends a header field.
    pub fn header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Request {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Removes every header field named `name` (ignoring case).
    pub fn without(mut self, name: &str) -> Request {
        self.headers.retain(|(field, _)| !field.eq_ignore_ascii_case(name));
        self
    }

    /// Replaces the body.
    pub fn body(mut self, body: Body) -> Request {
        self.body = body;
        self
    }

    /// Writes the request as bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(&self.target);
        out.push(b' ');
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(b"\r\n");
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        match &self.body {
            Body::Empty => out.extend_from_slice(b"\r\n"),
            Body::Length(data) => {
                if has_placeholder(data) {
                    out.extend_from_slice(format!("Content-Length: {LEN}\r\n\r\n").as_bytes());
                } else {
                    out.extend_from_slice(
                        format!("Content-Length: {}\r\n\r\n", data.len()).as_bytes(),
                    );
                }
                out.extend_from_slice(data);
            }
            Body::Chunked { data, chunk } => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                out.extend_from_slice(&chunked(data, *chunk));
            }
            Body::Raw(data) => {
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(data);
            }
        }
        out
    }
}

/// Encodes `data` as canonical chunks of at most `chunk` bytes (one chunk when `chunk` is
/// zero) followed by the last chunk.
pub fn chunked(data: &[u8], chunk: usize) -> Vec<u8> {
    let size = if chunk == 0 { data.len().max(1) } else { chunk };
    let mut out = Vec::with_capacity(data.len() + 32);
    for piece in data.chunks(size) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// True when `needle` occurs in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_encode_with_their_framing() {
        let get = Request::get("/a?b").header("X-A", "1").encode();
        assert_eq!(get, b"GET /a?b HTTP/1.1\r\nHost: app.test\r\nX-A: 1\r\n\r\n");
        let post = Request::post("/p", "text/plain", "hello").encode();
        assert!(post.ends_with(b"Content-Length: 5\r\n\r\nhello"));
        let templated = Request::post("/v", "application/json", "{\"id\":\"@@ID@@\"}").encode();
        assert!(contains(&templated, b"Content-Length: @@LEN@@\r\n\r\n{"));
        let chunked = Request::new("PUT", "/u")
            .body(Body::Chunked { data: b"abcdef".to_vec(), chunk: 4 })
            .encode();
        assert!(chunked.ends_with(b"chunked\r\n\r\n4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n"));
        let raw = Request::get("/").without("host").body(Body::Raw(b"xyz".to_vec())).encode();
        assert_eq!(raw, b"GET / HTTP/1.1\r\n\r\nxyz");
    }

    #[test]
    fn an_empty_chunked_body_is_only_the_last_chunk() {
        assert_eq!(chunked(b"", 0), b"0\r\n\r\n");
        assert_eq!(chunked(b"abc", 0), b"3\r\nabc\r\n0\r\n\r\n");
    }
}

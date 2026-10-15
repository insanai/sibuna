//! The stub origin: a keep-alive HTTP/1.1 server on loopback that answers every request with
//! the same small page, so reverse-proxy runs measure the daemon rather than the origin.
//!
//! It serves each connection on a thread of its own with blocking I/O, the simplest design
//! that keeps up with a daemon's pooled origin connections on loopback. It runs as a
//! process of its own (`sibuna-bench origin --port N`) so that it can be pinned away from
//! the daemon and its CPU time is not counted as the daemon's.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};

/// The body every request receives, as `caddy respond --body` served it for `tools.py`.
pub const BODY: &str = "<!doctype html><title>origin</title><p>ok";

/// The largest request head and body we buffer before closing the connection.
const MAX_REQUEST: usize = 1 << 20;

/// Serves forever on `127.0.0.1:port`.
///
/// # Errors
///
/// Fails when the port cannot be bound.
pub fn serve(port: u16) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| Error::io(format!("binding the origin to port {port}"), e))?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\r\n{BODY}",
        BODY.len()
    );
    let response: &'static [u8] = response.into_bytes().leak();
    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || serve_connection(stream, response));
    }
    Ok(())
}

/// Answers every request on `stream` until the peer closes it, asks to close, or errs.
pub(crate) fn serve_connection(mut stream: TcpStream, response: &[u8]) {
    let _ = stream.set_nodelay(true);
    let mut buffer = Vec::with_capacity(8192);
    let mut scratch = [0u8; 8192];
    loop {
        // Answer every complete request already buffered (a client may pipeline).
        while let Some((length, close)) = request_length(&buffer) {
            buffer.drain(..length);
            if stream.write_all(response).is_err() || close {
                return;
            }
        }
        if buffer.len() > MAX_REQUEST {
            return;
        }
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&scratch[..read]),
        }
    }
}

/// Returns the length of the first complete request in `data` and whether it asked to
/// close the connection, or `None` when more bytes are needed. Bodies are framed by
/// `Content-Length`; a chunked request body is not expected from the daemons' proxies for
/// the benchmark's GET requests.
fn request_length(data: &[u8]) -> Option<(usize, bool)> {
    let end = data.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&data[..end]);
    let mut body = 0usize;
    let mut close = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            body = value.trim().parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("connection") {
            close = value.trim().eq_ignore_ascii_case("close");
        }
    }
    let total = end.checked_add(body)?;
    (data.len() >= total).then_some((total, close))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_requests_with_and_without_bodies() {
        let get = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(request_length(get), Some((get.len(), false)));
        assert_eq!(request_length(&get[..get.len() - 1]), None);
        let post = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc";
        assert_eq!(request_length(post), Some((post.len(), true)));
        assert_eq!(request_length(&post[..post.len() - 1]), None);
    }

    #[test]
    fn answers_keep_alive_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream, response);
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut buffer = Vec::new();
        for _ in 0..3 {
            client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let (status, close) = crate::http::read_response(&mut client, &mut buffer).unwrap();
            assert_eq!((status, close), (200, false));
        }
    }
}

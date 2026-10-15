//! `sibuna-browser origin`: a small origin server to put behind a daemon for the console
//! checks.
//!
//! It answers every request with a short HTML page naming the path (404 for paths under
//! `/missing`, 500 under `/broken`, so the origin tiles have something to count), keeps
//! connections alive as a reverse proxy expects, and reads and discards request bodies
//! with a `Content-Length`. It serves until killed, or for `--for` seconds.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use sibuna_browser::Error;

use crate::arguments::{Flag, Flags, UsageError};

/// The flags `origin` accepts.
pub const FLAGS: &[Flag] =
    &[Flag { name: "--listen", takes_value: true }, Flag { name: "--for", takes_value: true }];

/// The longest request head and body we read.
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: u64 = 1 << 20;

/// How long a kept-alive connection may stay idle.
const IDLE: Duration = Duration::from_secs(30);

/// The checked flags of `origin`.
#[derive(Debug)]
pub struct Settings {
    listen: SocketAddr,
    serve_for: Option<Duration>,
}

impl Settings {
    /// Reads and checks the flags.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a missing or invalid `--listen` or an invalid `--for`.
    pub fn read(flags: &Flags) -> Result<Settings, UsageError> {
        let text = flags.required("--listen")?;
        let listen = text.parse().map_err(|_| {
            UsageError::new(
                format!("`--listen {text}` is not an address and port."),
                "Write, for example, `--listen 127.0.0.1:3000`.",
            )
        })?;
        let serve_for = match flags.value("--for") {
            Some(_) => Some(flags.seconds("--for", 60)?),
            None => None,
        };
        Ok(Settings { listen, serve_for })
    }
}

/// Serves until killed or until `--for` passes. Returns true.
///
/// # Errors
///
/// [`Error::Io`] when the address cannot be bound.
pub fn run(settings: &Settings) -> Result<bool, Error> {
    let listener = TcpListener::bind(settings.listen).map_err(|error| Error::Io {
        context: format!("binding {}", settings.listen),
        source: error,
    })?;
    let _ = writeln!(io::stdout().lock(), "origin: serving http://{}/", settings.listen);
    let deadline = settings.serve_for.map(|duration| Instant::now() + duration);
    if deadline.is_some() {
        listener.set_nonblocking(true).map_err(|error| Error::Io {
            context: "configuring the listener".into(),
            source: error,
        })?;
    }
    loop {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(true);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                std::thread::spawn(move || serve(stream));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {}
        }
    }
}

/// Serves one connection until the client closes it or asks to.
fn serve(stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IDLE));
    let Ok(writer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(stream);
    let mut writer = writer;
    while let Some(request) = read_request(&mut reader) {
        let reply = response(&request.path);
        if writer.write_all(reply.as_bytes()).is_err() || request.close {
            return;
        }
    }
}

/// The parts of a request the origin uses.
struct Request {
    path: String,
    close: bool,
}

/// Reads one request head and discards its body; `None` at the end of the connection or
/// for a request we will not serve.
fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    let mut head_bytes = 0;
    reader.read_line(&mut line).ok().filter(|&count| count > 0)?;
    let path = line.split(' ').nth(1)?.to_owned();
    let close_by_default = line.trim_end().ends_with("HTTP/1.0");
    let mut close = close_by_default;
    let mut length = 0u64;
    loop {
        let mut field = String::new();
        let count = reader.read_line(&mut field).ok().filter(|&count| count > 0)?;
        head_bytes += count;
        if head_bytes > MAX_HEAD {
            return None;
        }
        let field = field.trim_end();
        if field.is_empty() {
            break;
        }
        let (name, value) = field.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok().filter(|&length| length <= MAX_BODY)?;
        } else if name.eq_ignore_ascii_case("connection") {
            close = value.eq_ignore_ascii_case("close")
                || (close_by_default && !value.eq_ignore_ascii_case("keep-alive"));
        }
    }
    io::copy(&mut reader.by_ref().take(length), &mut io::sink()).ok()?;
    Some(Request { path, close })
}

/// The reply to `path`.
fn response(path: &str) -> String {
    let status = if path.starts_with("/missing") {
        "404 Not Found"
    } else if path.starts_with("/broken") {
        "500 Internal Server Error"
    } else {
        "200 OK"
    };
    let escaped: String = path
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '&' => "&amp;".to_owned(),
            _ => c.to_string(),
        })
        .collect();
    let body = format!(
        "<!doctype html><html><head><title>Origin fixture</title></head><body>\
         <h1>Origin fixture</h1><p>{status} for {escaped}</p></body></html>\n"
    );
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_keep_alive_requests_and_discards_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                serve(stream);
            }
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(
                b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc\
                  GET /missing/<b> HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut replies = String::new();
        client.read_to_string(&mut replies).unwrap();
        assert!(replies.starts_with("HTTP/1.1 200 OK\r\n"), "{replies}");
        assert!(replies.contains("200 OK for /a</p>"));
        assert!(replies.contains("HTTP/1.1 404 Not Found\r\n"));
        assert!(replies.contains("for /missing/&lt;b&gt;</p>"));
    }

    #[test]
    fn statuses_follow_the_path() {
        assert!(response("/broken/x").starts_with("HTTP/1.1 500 "));
        assert!(response("/").starts_with("HTTP/1.1 200 "));
    }
}

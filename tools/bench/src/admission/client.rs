//! The two clients of `bench admission`, each with its own keep-alive connection, and the
//! timing of one batch, as `compare.py`'s `measure` and `batch_worker` did.
//!
//! A batch is a list of groups; a group is one operation, made of one or more exchanges
//! (the bootstrap of Sibuna is two). The first client sends the first half of the groups and
//! the second client the rest, both at once. Requests are rendered before the batch, so the
//! timer covers only the exchanges.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Barrier;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::http::{self, Response};

/// The number of clients, as in `compare.py`.
pub const CLIENTS: usize = 2;

/// One request, rendered, and the status it must answer with.
#[derive(Clone, Debug)]
pub struct Exchange {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    request: Vec<u8>,
    expected: u16,
    label: String,
}

impl Exchange {
    /// Renders `method target` for `127.0.0.1:port` with `headers` and `body`, kept alive,
    /// expecting `expected`.
    pub fn new(
        port: u16,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
        expected: u16,
    ) -> Exchange {
        let mut head = http::request_head(method, target, port, headers);
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        request.extend_from_slice(body);
        Exchange {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: headers.to_vec(),
            body: body.to_vec(),
            request,
            expected,
            label: format!("{method} {target}"),
        }
    }

    /// Sends this request once on a fresh connection, closed after the answer, and returns
    /// the whole answer, whatever its status.
    ///
    /// # Errors
    ///
    /// Fails like [`http::request`].
    pub fn send_once(&self, port: u16) -> Result<Response> {
        http::request(port, &self.method, &self.target, &self.headers, &self.body)
    }

    /// Returns the status this exchange expects.
    pub fn expected(&self) -> u16 {
        self.expected
    }

    /// Returns the method and target, for messages.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// A client with one keep-alive connection, reopened when the server closes it.
struct Client {
    port: u16,
    stream: Option<TcpStream>,
    buffer: Vec<u8>,
}

impl Client {
    /// Opens a connection to `127.0.0.1:port`.
    fn connect(port: u16) -> Result<Client> {
        let mut client = Client { port, stream: None, buffer: Vec::with_capacity(16 * 1024) };
        client.stream = Some(client.open()?);
        Ok(client)
    }

    fn open(&self) -> Result<TcpStream> {
        let fail = |e| Error::io(format!("connecting to port {}", self.port), e);
        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        let stream =
            TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(fail)?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(fail)?;
        stream.set_write_timeout(Some(Duration::from_secs(10))).map_err(fail)?;
        stream.set_nodelay(true).map_err(fail)?;
        Ok(stream)
    }

    /// Sends `exchange` and reads its answer, which must have the expected status.
    fn exchange(&mut self, exchange: &Exchange) -> Result<()> {
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => self.open()?,
        };
        let fail = |e| Error::io(exchange.label(), e);
        stream.write_all(&exchange.request).map_err(fail)?;
        let (status, close) = http::read_response(&mut stream, &mut self.buffer).map_err(fail)?;
        if status != exchange.expected {
            let start = self.buffer.len().min(200);
            let excerpt = String::from_utf8_lossy(&self.buffer[..start]).into_owned();
            return Err(Error::new(
                "UNEXPECTED STATUS",
                format!(
                    "{}: expected {}, got {status}:\n{excerpt}",
                    exchange.label(),
                    exchange.expected
                ),
            ));
        }
        if !close {
            self.stream = Some(stream);
        }
        Ok(())
    }
}

/// The timing of one batch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BatchTiming {
    /// Operations of the batch divided by the time from the start of the first client to the
    /// end of the last.
    pub operations_per_second: f64,
    /// The slower client's time divided by the operations of the first client, in
    /// nanoseconds, as `compare.py` reported it.
    pub slowest_client_ns_per_operation: f64,
}

/// The time span one client spent on its part of a batch.
type Span = (Instant, Instant);

/// Runs `groups` on two clients at once and times it.
///
/// # Errors
///
/// Fails when a client cannot connect, an exchange fails or answers an unexpected status.
pub fn run_batch(port: u16, groups: &[&[Exchange]]) -> Result<BatchTiming> {
    let half = groups.len() / CLIENTS;
    let (first, second) = groups.split_at(half);
    let barrier = Barrier::new(CLIENTS);
    let spans: Vec<Result<Span>> = std::thread::scope(|scope| {
        let handles = [first, second].map(|part| {
            let barrier = &barrier;
            scope.spawn(move || run_client(port, part, barrier))
        });
        handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap_or_else(|_| {
                    Err(Error::new("CLIENT FAILED", "An admission client thread panicked."))
                })
            })
            .collect()
    });
    let spans: Vec<Span> = spans.into_iter().collect::<Result<_>>()?;
    Ok(timing(groups.len(), half, &spans))
}

/// Returns the timing of a batch of `operations`, `half` of them on the first client, whose
/// clients spent `spans`.
fn timing(operations: usize, half: usize, spans: &[Span]) -> BatchTiming {
    let start = spans.iter().map(|span| span.0).min();
    let end = spans.iter().map(|span| span.1).max();
    let elapsed = match (start, end) {
        (Some(start), Some(end)) => end.duration_since(start).as_secs_f64(),
        _ => 0.0,
    };
    let slowest = spans.iter().map(|(s, e)| e.duration_since(*s)).max().unwrap_or_default();
    BatchTiming {
        operations_per_second: operations as f64 / elapsed.max(1e-9),
        slowest_client_ns_per_operation: slowest.as_nanos() as f64 / half.max(1) as f64,
    }
}

/// Connects, waits until the other client is connected too, and runs `groups` in order.
/// Both clients reach the barrier even when one cannot connect, so neither waits forever.
fn run_client(port: u16, groups: &[&[Exchange]], barrier: &Barrier) -> Result<Span> {
    let connected = Client::connect(port);
    barrier.wait();
    let mut client = connected?;
    let start = Instant::now();
    for group in groups {
        for exchange in *group {
            client.exchange(exchange)?;
        }
    }
    Ok((start, Instant::now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_keep_alive_requests() {
        let headers = vec![("User-Agent".to_owned(), "Mozilla/5.0".to_owned())];
        let get = Exchange::new(8080, "GET", "/private", &headers, b"", 401);
        let text = String::from_utf8(get.request.clone()).unwrap();
        assert_eq!(
            text,
            "GET /private HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        );
        assert_eq!((get.expected(), get.label()), (401, "GET /private"));
        let post = Exchange::new(80, "POST", "/v", &[], b"{}", 200);
        assert!(post.request.ends_with(b"Content-Length: 2\r\n\r\n{}"));
    }

    #[test]
    fn times_a_batch_from_the_first_start_to_the_last_end() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let spans = [(at(0), at(100)), (at(10), at(200))];
        let timing = timing(200, 100, &spans);
        assert!((timing.operations_per_second - 1000.0).abs() < 1e-6);
        assert!((timing.slowest_client_ns_per_operation - 1_900_000.0).abs() < 1e-3);
    }

    #[test]
    fn runs_a_batch_against_a_keep_alive_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || answer_forever(stream));
            }
        });
        let ok = [Exchange::new(port, "GET", "/", &[], b"", 200)];
        let groups: Vec<&[Exchange]> = vec![&ok; 10];
        let timing = run_batch(port, &groups).unwrap();
        assert!(timing.operations_per_second > 0.0);
        let wrong = [Exchange::new(port, "GET", "/", &[], b"", 401)];
        assert!(run_batch(port, &[&wrong, &wrong]).is_err());
    }

    /// Answers every request on `stream` with an empty `200`, keeping the connection.
    fn answer_forever(mut stream: TcpStream) {
        let mut buffer = [0u8; 4096];
        let mut pending = Vec::new();
        loop {
            let Ok(read) = std::io::Read::read(&mut stream, &mut buffer) else { return };
            if read == 0 {
                return;
            }
            pending.extend_from_slice(&buffer[..read]);
            while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                pending.drain(..end + 4);
                let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                if stream.write_all(reply).is_err() {
                    return;
                }
            }
        }
    }
}

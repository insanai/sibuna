//! The separate listener for health, readiness and metrics (SID 0020).
//!
//! One thread serves one request per connection. It reads a bounded head within a bounded
//! time, so a slow client delays the next one by at most two seconds. Its bind address is
//! its access control: it applies no allow-list of its own.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_http::response::{self, Extra, Status};
use sibuna_reactor::{Poller, READ, handle};

use crate::access::{self, Observe};
use crate::server::{Server, VERSION};

/// The longest request head read.
const MAX_HEAD: usize = 4096;
/// The longest wait for a request and for the client to take the response.
const PATIENCE: Duration = Duration::from_secs(2);
/// Connections served per wake, so that a stop is seen.
const BATCH: usize = 64;

/// What the listener reports on.
pub(super) struct Sources {
    /// The series of SID 0020 and the readiness flag.
    pub observe: Arc<Observe>,
    /// The HTTP server, for the process counters. A topology without HTTP has none.
    pub server: Option<Arc<Server>>,
}

/// The running listener. Dropping it stops the thread.
pub(super) struct Probe {
    stop: Arc<AtomicBool>,
    address: SocketAddr,
    thread: Option<JoinHandle<()>>,
}

impl Probe {
    /// Binds `address` and starts the thread.
    ///
    /// # Errors
    ///
    /// The error of the bind, with the address, or of starting the thread.
    pub fn start(address: SocketAddr, sources: Sources) -> io::Result<Self> {
        let listener = TcpListener::bind(address).map_err(|error| {
            io::Error::new(error.kind(), format!("observability.listen {address}: {error}"))
        })?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("edge-probe".into())
            .spawn(move || run(&listener, &sources, &flag))?;
        Ok(Self { stop, address, thread: Some(thread) })
    }

    /// The address the listener is bound to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(listener: &TcpListener, sources: &Sources, stop: &AtomicBool) {
    let mut poll = Poller::new().ok();
    if let Some(poll) = poll.as_mut()
        && poll.set(handle(listener), READ, ()).is_err()
    {
        return;
    }
    let mut ready = Vec::new();
    while !stop.load(Ordering::Acquire) {
        ready.clear();
        let waited = poll.as_mut().is_some_and(|poll| poll.wait(250, &mut ready).is_ok());
        if !waited {
            // Without readiness the thread looks at the listener at intervals.
            std::thread::sleep(Duration::from_millis(50));
        }
        for _ in 0..BATCH {
            let Ok((stream, _)) = listener.accept() else { break };
            // A failed exchange concerns that client only.
            let _ = serve(&stream, sources);
        }
    }
}

/// Reads one request head and answers it.
fn serve(mut stream: &TcpStream, sources: &Sources) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(PATIENCE))?;
    stream.set_write_timeout(Some(PATIENCE))?;
    let mut head = [0u8; MAX_HEAD];
    let mut held = 0;
    let complete = loop {
        if crate::connection::find_blank_line(&head[..held]).is_some() {
            break true;
        }
        if held == head.len() {
            break false;
        }
        match stream.read(&mut head[held..])? {
            0 => break false,
            count => held += count,
        }
    };
    let mut out = Vec::with_capacity(1024);
    if complete {
        answer(&head[..held], sources, &mut out)?;
    } else {
        response::write_400(&mut out, b"Malformed HTTP request")?;
    }
    stream.write_all(&out)?;
    // Closing over unread bytes resets the connection, and the reset can destroy the
    // response on its way. Take what has arrived first.
    stream.shutdown(std::net::Shutdown::Write)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    for _ in 0..4 {
        if !matches!(stream.read(&mut head), Ok(count) if count > 0) {
            break;
        }
    }
    Ok(())
}

/// Writes the response to the request whose head is `head`.
fn answer(head: &[u8], sources: &Sources, out: &mut Vec<u8>) -> io::Result<()> {
    let line = head.split(|&byte| byte == b'\r').next().unwrap_or_default();
    let mut words = line.split(|&byte| byte == b' ');
    let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let path = target.split(|&byte| byte == b'?').next().unwrap_or_default();
    let path = path.strip_prefix(b"/__sibuna").unwrap_or(path);
    let extra = Extra { keep_alive: false, ..Extra::default() };
    if method != b"GET" && method != b"HEAD" {
        let text = b"Not Implemented: the listener serves GET and HEAD";
        return response::write_text(out, Status::NotImplemented, text, false);
    }
    match path {
        b"/health" => {
            let body =
                format!("{{\"status\":\"ok\",\"engine\":\"sibuna\",\"version\":\"{VERSION}\"}}");
            response::write_response(out, Status::Ok, b"application/json", body.as_bytes(), extra)
        }
        b"/ready" => {
            let (status, body) = access::ready_answer(sources.observe.is_ready());
            response::write_response(out, status, b"application/json", body, extra)
        }
        b"/metrics" => {
            let text = access::metrics_text(sources.server.as_deref(), &sources.observe);
            let kind = b"text/plain; version=0.0.4";
            response::write_response(out, Status::Ok, kind, text.as_bytes(), extra)
        }
        _ => response::write_text(out, Status::NotFound, b"Not Found", false),
    }
}

#[cfg(test)]
mod tests {
    use sibuna_lb::{ObserveOptions, Stats};

    use super::*;

    fn probe() -> (Probe, Arc<Observe>) {
        let options = ObserveOptions::default();
        let observe = Arc::new(Observe::new(options, None, Arc::new(Stats::default())));
        let sources = Sources { observe: observe.clone(), server: None };
        let probe = Probe::start("127.0.0.1:0".parse().unwrap(), sources).unwrap();
        (probe, observe)
    }

    fn get(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut text = String::new();
        stream.read_to_string(&mut text).unwrap();
        text
    }

    #[test]
    fn the_listener_answers_health_readiness_and_metrics() {
        let (probe, observe) = probe();
        let address = probe.address();
        let health = get(address, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(health.starts_with("HTTP/1.1 200 ") && health.contains("\"status\":\"ok\""));
        let ready = get(address, "GET /ready HTTP/1.1\r\n\r\n");
        assert!(ready.starts_with("HTTP/1.1 200 ") && ready.ends_with("{\"status\":\"ready\"}"));
        let metrics = get(address, "GET /__sibuna/metrics?x=1 HTTP/1.1\r\n\r\n");
        assert!(metrics.starts_with("HTTP/1.1 200 "), "{metrics}");
        assert!(metrics.contains("sibuna_edge_ready 1\n"), "{metrics}");
        assert!(metrics.contains("sibuna_edge_flows_active 0\n"), "{metrics}");
        // A draining node is not ready, and says so in both places.
        observe.draining.store(true, Ordering::Release);
        let ready = get(address, "GET /ready HTTP/1.1\r\n\r\n");
        assert!(ready.starts_with("HTTP/1.1 503 "), "{ready}");
        assert!(ready.ends_with("{\"status\":\"draining\"}"), "{ready}");
        assert!(get(address, "GET /metrics HTTP/1.1\r\n\r\n").contains("sibuna_edge_ready 0\n"));
    }

    #[test]
    fn the_listener_refuses_what_it_does_not_serve() {
        let (probe, _observe) = probe();
        let address = probe.address();
        assert!(get(address, "GET /nothing HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404 "));
        assert!(get(address, "POST /metrics HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 501 "));
        // A head without an end is refused once it is as long as the bound.
        let endless = format!("GET /health HTTP/1.1\r\nx: {}", "a".repeat(MAX_HEAD));
        assert!(get(address, &endless).starts_with("HTTP/1.1 400 "));
        // A client that sends nothing is cut off, and the next client is served.
        let silent = TcpStream::connect(address).unwrap();
        let started = std::time::Instant::now();
        assert!(get(address, "GET /ready HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 200 "));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(silent);
    }
}

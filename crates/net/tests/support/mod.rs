//! A minimal daemon built on the crate's public API and a stub origin, for the end-to-end
//! tests. The daemon follows the Zig connection loop: register with the idle table, read a
//! head, buffer the body (decoding a chunked one in place), proxy, touch the lease.

#![allow(dead_code, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use sibuna_http::chunked::Decoder;
use sibuna_http::{Request, parse_request, response};
use sibuna_net::buffered::{ReadError, Reader, Writer};
use sibuna_net::connect::set_no_delay;
use sibuna_net::{Audit, Client, Exchange, IdleTable, Lease, Pool, ProxyError, Upload, Workspace};

const BUFFER: usize = 64 * 1024;
const MAX_HEAD: usize = 16 * 1024;

impl Daemon {
    /// The connections being served now.
    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

pub struct Daemon {
    pub port: u16,
    pub max_connections: AtomicUsize,
    connections: AtomicUsize,
    table: IdleTable,
    pool: Pool,
    origin_port: u16,
    websocket_idle_seconds: u32,
}

/// Starts a daemon with a one-second idle timeout in front of the shared stub origin.
pub fn start(websocket_idle_seconds: u32) -> Arc<Daemon> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let daemon = Arc::new(Daemon {
        port: listener.local_addr().unwrap().port(),
        max_connections: AtomicUsize::new(64),
        connections: AtomicUsize::new(0),
        table: IdleTable::with_capacity(128),
        pool: Pool::new(),
        origin_port: origin_port(),
        websocket_idle_seconds,
    });
    let reaper = Arc::clone(&daemon);
    thread::spawn(move || {
        let never = AtomicBool::new(false);
        reaper.table.run_reaper(1, reaper.websocket_idle_seconds, &never);
    });
    let accepting = Arc::clone(&daemon);
    thread::spawn(move || accept_loop(&accepting, &listener));
    daemon
}

fn accept_loop(daemon: &Arc<Daemon>, listener: &TcpListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let limit = daemon.max_connections.load(Ordering::SeqCst);
        if daemon.connections.fetch_add(1, Ordering::SeqCst) >= limit {
            daemon.connections.fetch_sub(1, Ordering::SeqCst);
            let _ = response::write_text(
                &mut &stream,
                response::Status::ServiceUnavailable,
                b"Service Unavailable: connection limit reached",
                false,
            );
            let _ = stream.shutdown(Shutdown::Write);
            continue;
        }
        set_no_delay(&stream);
        let daemon = Arc::clone(daemon);
        thread::spawn(move || {
            serve(&daemon, &stream);
            daemon.connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn serve(daemon: &Daemon, stream: &TcpStream) {
    let Some(lease) = daemon.table.register(stream) else { return };
    let mut read_buffer = vec![0u8; BUFFER];
    let mut write_buffer = vec![0u8; 16 * 1024];
    let mut reader = Reader::new(stream, &mut read_buffer);
    let mut writer = Writer::new(stream, &mut write_buffer);
    let mut workspace = Workspace::new();
    while let Some(true) = serve_one(daemon, &lease, &mut reader, &mut writer, &mut workspace) {
        lease.touch();
    }
    let _ = writer.flush();
}

/// Reads a head; `None` on a clean close or an error.
fn read_head(reader: &mut Reader<'_, &TcpStream>) -> Option<usize> {
    loop {
        let bytes = reader.buffered();
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(at + 4);
        }
        if bytes.len() >= MAX_HEAD {
            return None;
        }
        reader.fill_more().ok()?;
    }
}

/// Decodes a chunked body in place behind the head (SID 0009 admission).
fn buffer_chunked(
    reader: &mut Reader<'_, &TcpStream>,
    head_len: usize,
) -> Option<(usize, Upload)> {
    let mut decoder = Decoder::new();
    let mut decoded = 0;
    loop {
        let start = head_len + decoded;
        let step = decoder.decode(&mut reader.buffered_mut()[start..]).ok()?;
        reader.remove(start + step.output, start + step.consumed);
        decoded += step.output;
        if decoder.is_done() {
            return Some((decoded, Upload::Length(decoded as u64)));
        }
        if reader.buffered_len() == reader.capacity() {
            return Some((decoded, Upload::Chunked(decoder)));
        }
        reader.fill_more().ok()?;
    }
}

fn buffer_length(
    reader: &mut Reader<'_, &TcpStream>,
    head_len: usize,
    declared: usize,
) -> Option<usize> {
    let fits = declared.min(BUFFER - head_len);
    match reader.fill(head_len + fits) {
        Ok(()) => Some(fits),
        Err(ReadError::EndOfStream | ReadError::Io(_) | ReadError::BufferFull) => None,
    }
}

fn serve_one(
    daemon: &Daemon,
    lease: &Lease<'_>,
    reader: &mut Reader<'_, &TcpStream>,
    writer: &mut Writer<'_, &TcpStream>,
    workspace: &mut Workspace,
) -> Option<bool> {
    let head_len = read_head(reader)?;
    let chunked = parse_request(&reader.buffered()[..head_len]).ok()?.chunked;
    let (body_len, upload, declared) = if chunked {
        let Some((decoded, upload)) = buffer_chunked(reader, head_len) else {
            let _ = response::write_400(writer, b"Malformed chunked request body");
            return None;
        };
        let declared = if matches!(upload, Upload::Chunked(_)) { usize::MAX } else { decoded };
        (decoded, upload, declared)
    } else {
        let request = parse_request(&reader.buffered()[..head_len]).ok()?;
        let declared = request.content_length().unwrap_or(0);
        let upload = Upload::declared(&request);
        (buffer_length(reader, head_len, declared)?, upload, declared)
    };
    let bytes = reader.buffered();
    let mut request: Request<'_> = parse_request(&bytes[..head_len]).ok()?;
    request.body = &bytes[head_len..head_len + body_len];
    let keep_alive = request.wants_keep_alive() && declared <= body_len;
    let result = proxy(
        daemon,
        lease,
        stream_of(reader),
        &request,
        &bytes[head_len + body_len..],
        upload,
        keep_alive,
        writer,
        workspace,
    );
    reader.consume(head_len + body_len);
    answer(result, writer)
}

fn stream_of<'s>(reader: &Reader<'_, &'s TcpStream>) -> &'s TcpStream {
    reader.inner()
}

#[allow(clippy::too_many_arguments)]
fn proxy(
    daemon: &Daemon,
    lease: &Lease<'_>,
    stream: &TcpStream,
    request: &Request<'_>,
    pending: &[u8],
    upload: Upload,
    keep_alive: bool,
    writer: &mut Writer<'_, &TcpStream>,
    workspace: &mut Workspace,
) -> Result<bool, ProxyError> {
    let exchange = Exchange {
        client: Client {
            stream,
            pending,
            writer,
            activity: Some(lease.activity()),
            websocket_idle_timeout_seconds: daemon.websocket_idle_seconds,
        },
        upstream_host: "127.0.0.1",
        upstream_port: daemon.origin_port,
        request,
        upload,
        audit: Audit {
            client_ip: b"203.0.113.1",
            peer: b"203.0.113.1",
            status: b"PASS",
            rule: b"test",
            ..Audit::default()
        },
        keep_alive,
    };
    sibuna_net::stream_proxy(&daemon.pool, workspace, exchange)
}

fn answer(result: Result<bool, ProxyError>, writer: &mut Writer<'_, &TcpStream>) -> Option<bool> {
    match result {
        Ok(keep) => Some(keep),
        Err(ProxyError::InvalidUpgrade) => {
            let _ = response::write_400(writer, b"Invalid upgrade");
            None
        }
        Err(ProxyError::UpstreamUnreachable) => {
            let _ = response::write_502(writer, b"Bad Gateway: upstream unreachable");
            None
        }
        Err(ProxyError::UpstreamReadFailed) => {
            let _ = response::write_502(writer, b"Bad Gateway: malformed upstream response");
            None
        }
        Err(ProxyError::MalformedRequestBody) => {
            let _ = response::write_400(writer, b"Malformed chunked request body");
            None
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------------------
// The stub origin.

fn origin_port() -> u16 {
    static PORT: OnceLock<u16> = OnceLock::new();
    *PORT.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || origin_connection(stream));
            }
        });
        port
    })
}

/// FNV-1a, the digest the upload echo reports.
pub fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

struct Conn {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Conn {
    fn more(&mut self) -> bool {
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) | Err(_) => false,
            Ok(count) => {
                self.buffer.extend_from_slice(&chunk[..count]);
                true
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
            if let Some(at) = self.buffer.iter().position(|&b| b == b'\n') {
                return Some(self.buffer.drain(..=at).collect());
            }
            if !self.more() {
                return None;
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> bool {
        self.stream.write_all(bytes).is_ok()
    }
}

fn origin_connection(stream: TcpStream) {
    set_no_delay(&stream);
    let mut conn = Conn { stream, buffer: Vec::new() };
    let mut seq = 0;
    loop {
        let head = loop {
            if let Some(at) = conn.buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break conn.buffer.drain(..at + 4).collect::<Vec<u8>>();
            }
            if !conn.more() {
                return;
            }
        };
        seq += 1;
        if !route(&mut conn, &head, seq) {
            return;
        }
    }
}

fn request_line(head: &[u8]) -> String {
    let end = head.iter().position(|&b| b == b'\r').unwrap_or(head.len());
    String::from_utf8_lossy(&head[..end]).into_owned()
}

/// Serves one request; false closes the connection.
fn route(conn: &mut Conn, head: &[u8], seq: u32) -> bool {
    let line = request_line(head);
    let path = line.split(' ').nth(1).unwrap_or("");
    match path {
        "/silent" => {
            thread::sleep(Duration::from_secs(4));
            false
        }
        "/slow-stream" => slow_stream(conn),
        "/slow-length" => trickle(conn, "Content-Length: 15360\r\n"),
        "/slow-close" => {
            trickle(conn, "Connection: close\r\n");
            false
        }
        "/split" => {
            conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
            thread::sleep(Duration::from_millis(5));
            conn.send(b"body")
        }
        "/truncated" => {
            conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
            false
        }
        "/close-after" => {
            conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            false
        }
        "/headbody" => {
            // A faulty origin: the HEAD response is followed, late, by bytes shaped as a
            // second response (review reproduction `origin.py`).
            let evil = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-Poison: 1\r\n\r\nPOISONED!";
            conn.send(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", evil.len()).as_bytes(),
            );
            thread::sleep(Duration::from_millis(50));
            conn.send(evil)
        }
        "/trailing-junk" => conn.send(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\
              okHTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-Poison: 1\r\n\r\nPOISONED!",
        ),
        "/large" => {
            // 64 MiB as fast as the socket takes it.
            conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\n\r\n");
            let block = vec![b'L'; 1 << 20];
            (0..64).all(|_| conn.send(&block))
        }
        "/ws" => websocket(conn, head, true),
        "/ws-silent" => websocket(conn, head, false),
        _ if path.ends_with("?upload") => upload_echo(conn, head),
        _ => {
            let body = format!("ORIGIN|{}", String::from_utf8_lossy(head));
            let reply = format!(
                "HTTP/1.1 200 OK\r\nX-Origin: stub\r\nX-Origin-Seq: {seq}\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            conn.send(reply.as_bytes())
        }
    }
}

/// Twelve chunks a quarter second apart: three seconds of activity against a one-second
/// idle timeout.
fn slow_stream(conn: &mut Conn) -> bool {
    conn.send(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    for _ in 0..12 {
        thread::sleep(Duration::from_millis(250));
        if !conn.send(b"5\r\nchunk\r\n") {
            return false;
        }
    }
    conn.send(b"0\r\n\r\n")
}

/// Thirty 512-byte writes 100 ms apart: 15 KiB over three seconds.
fn trickle(conn: &mut Conn, framing: &str) -> bool {
    conn.send(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{framing}\r\n").as_bytes());
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        if !conn.send(&[b's'; 512]) {
            return false;
        }
    }
    true
}

fn header<'h>(head: &'h str, name: &str) -> Option<&'h str> {
    head.split("\r\n").find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Reads the upload as an origin would and answers with its framing, length and digest. The
/// chunked reader accepts only canonical framing.
fn upload_echo(conn: &mut Conn, head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head).into_owned();
    let (framing, body) = if header(&text, "transfer-encoding") == Some("chunked") {
        let Some(body) = canonical_chunked(conn) else { return false };
        ("chunked", body)
    } else if let Some(length) = header(&text, "content-length").and_then(|v| v.parse().ok()) {
        let Some(body) = conn.take(length) else { return false };
        ("length", body)
    } else {
        ("none", Vec::new())
    };
    let reply = format!("UPLOAD|{framing}|{}|{:x}", body.len(), digest(&body));
    conn.send(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply}", reply.len()).as_bytes(),
    )
}

fn canonical_chunked(conn: &mut Conn) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = conn.line()?;
        let hex = line.strip_suffix(b"\r\n")?;
        let canonical = !hex.is_empty()
            && hex.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && (hex.len() == 1 || hex[0] != b'0');
        if !canonical {
            return None;
        }
        let size = usize::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        if size == 0 {
            return (conn.take(2)? == b"\r\n").then_some(body);
        }
        body.extend(conn.take(size)?);
        if conn.take(2)? != b"\r\n" {
            return None;
        }
    }
}

fn websocket(conn: &mut Conn, head: &[u8], echo: bool) -> bool {
    let text = String::from_utf8_lossy(head).into_owned();
    let key = header(&text, "sec-websocket-key").unwrap_or("");
    let accept = sibuna_http::websocket::accept_key(key.as_bytes()).unwrap();
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        String::from_utf8_lossy(&accept)
    );
    conn.send(reply.as_bytes());
    if !echo {
        thread::sleep(Duration::from_secs(5));
        return false;
    }
    loop {
        if !conn.buffer.is_empty() {
            let bytes = std::mem::take(&mut conn.buffer);
            conn.send(&bytes);
        }
        if !conn.more() {
            return false;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Client helpers.

pub fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Sends one raw request, shuts down the sending side, and reads until the peer closes.
pub fn round_trip(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address(port)).unwrap();
    if !raw.is_empty() {
        stream.write_all(raw).unwrap();
        let _ = stream.shutdown(Shutdown::Write);
    }
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

pub fn status(response: &[u8]) -> u16 {
    std::str::from_utf8(response.get(9..12).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

pub fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| *window == needle).count()
}

pub fn body(response: &[u8]) -> &[u8] {
    let at =
        response.windows(4).position(|w| w == b"\r\n\r\n").map_or(response.len(), |at| at + 4);
    &response[at..]
}

pub struct Timed {
    pub first_body_ms: Option<u128>,
    pub total_ms: u128,
    pub body: usize,
    pub response: Vec<u8>,
}

/// Reads one response read by read, noting when the first body byte arrived, until the
/// peer closes or `want` body bytes are in.
pub fn timed_get(port: u16, path: &str, want: usize) -> Timed {
    let mut stream = TcpStream::connect(address(port)).unwrap();
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes()).unwrap();
    let started = Instant::now();
    let mut timed = Timed { first_body_ms: None, total_ms: 0, body: 0, response: Vec::new() };
    let mut chunk = [0u8; 4096];
    while timed.body < want {
        let Ok(count) = stream.read(&mut chunk) else { break };
        if count == 0 {
            break;
        }
        timed.response.extend_from_slice(&chunk[..count]);
        let Some(at) = timed.response.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        timed.body = timed.response.len() - at - 4;
        if timed.body != 0 && timed.first_body_ms.is_none() {
            timed.first_body_ms = Some(started.elapsed().as_millis());
        }
        timed.total_ms = started.elapsed().as_millis();
    }
    timed
}

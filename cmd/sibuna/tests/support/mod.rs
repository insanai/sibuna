//! Fixtures for the end-to-end tests: the real server booted in-process on loopback ports in
//! front of a stub origin, and raw HTTP/1.1 client helpers. Each scenario uses its own
//! forwarded client address so the per-client tables do not interfere, as in Zig.

#![allow(dead_code, clippy::unwrap_used)]

#[cfg(feature = "console")]
pub mod console;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use sibuna::{EngineSlot, Hooks, Options, Running, Server};
use sibuna_challenge::Seed;
use sibuna_core::{Config, Incident, Metrics, Mode, PowAlgorithm, TokenScheme};
use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};
use sibuna_policy::pages::{Kind, Template};
use sibuna_policy::{Action, Engine, HeaderMatcher, Limits, Mode as InspectionMode, PolicyRule};
use sibuna_pow::{hashcash, posw};

pub const BROWSER_UA: &str =
    "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/128.0 Safari/537.36";
pub const BROWSER_ACCEPT: &str =
    "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: en\r\n";

/// Which hand-built fixture a test runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKind {
    /// Reverse proxy, hashcash at 8 bits, with three extra challenge routes.
    Proxy,
    /// Forward authorization, PoSW at 9 bits with 4 openings, Ed25519 tokens.
    Auth,
    /// Reverse proxy with audited SQL injection, a banned address and a custom denial page.
    Audit,
    /// Reverse proxy with rule quotas only.
    Quota,
    /// Reverse proxy with a challenge budget of two.
    Budget,
    /// Reverse proxy for tests that change the connection bound.
    Bounded,
    /// Reverse proxy for the silent-origin test, which also changes the bound.
    Silent,
}

pub struct Fixture {
    pub running: Running,
    pub port: u16,
}

impl Fixture {
    pub fn server(&self) -> &Arc<Server> {
        self.running.server()
    }
}

/// Audit findings of category `audit:sqli` seen by the audit fixture's hook.
pub static AUDITED: AtomicU64 = AtomicU64::new(0);

/// Returns the fixture of `kind`, booting it (and the stub origin) on first use.
pub fn fixture(kind: FixtureKind) -> &'static Fixture {
    static FIXTURES: [OnceLock<Fixture>; 7] = [const { OnceLock::new() }; 7];
    FIXTURES[kind as usize].get_or_init(|| boot(kind))
}

/// The configuration every fixture shares (Zig's `bootFixture`).
pub fn base_config(kind: FixtureKind) -> Config {
    let mut config = Config::default();
    match kind {
        FixtureKind::Auth => {
            config.mode = Mode::ForwardAuth;
            config.default_difficulty = 9;
            config.algorithm = PowAlgorithm::Posw;
            config.posw_challenges = 4;
            config.token_scheme = TokenScheme::Ed25519;
        }
        _ => {
            config.default_difficulty = 8;
            config.algorithm = PowAlgorithm::Hashcash;
        }
    }
    if kind == FixtureKind::Budget {
        config.challenge_rate_limit = 2;
    }
    config.upstream_port = origin_port();
    config.trust_forwarded = Some(true);
    config.workers = 1;
    config.rate_limit = 8;
    config.rate_window_seconds = 10;
    config.idle_timeout_seconds = 1;
    config.ban_seconds = 60;
    config
}

fn boot(kind: FixtureKind) -> Fixture {
    let config = base_config(kind);
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    engine.waf_enabled = config.waf;
    let mut hooks = Hooks::default();
    match kind {
        FixtureKind::Quota => configure_quotas(&mut engine),
        FixtureKind::Proxy | FixtureKind::Budget | FixtureKind::Bounded | FixtureKind::Silent => {
            add_routes(&mut engine)
        }
        FixtureKind::Audit => {
            configure_audit(&mut engine);
            hooks.record_incident = Some(Box::new(capture_audit));
        }
        FixtureKind::Auth => {}
    }
    start_server(config, engine, hooks)
}

/// Starts a server on a loopback port with `engine` and the fixture seed.
pub fn start_server(config: Config, engine: Engine, hooks: Hooks) -> Fixture {
    let options = Options {
        config,
        slot: Arc::new(EngineSlot::new(engine)),
        seed: Seed::new([0x5a; 32]),
        metrics: Arc::new(Metrics::default()),
        hooks,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let running = Running::start(Arc::new(Server::new(options)), listener).unwrap();
    Fixture { running, port }
}

fn capture_audit(incident: &Incident<'_>) {
    if incident.category != "audit:sqli" {
        return;
    }
    assert!(incident.payload.is_empty() && incident.evidence.version == 0);
    AUDITED.fetch_add(1, Ordering::Relaxed);
}

fn challenge_rule(name: &str, path: &str, difficulty: u32) -> PolicyRule {
    PolicyRule {
        path_pattern: Some(path.into()),
        difficulty: Some(difficulty),
        ..PolicyRule::new(name, Action::Challenge)
    }
}

/// One route demands more work than the eight-bit default, for session-level checks; it
/// goes first because the built-in generic-browser rule would otherwise claim the path. An
/// exact path and a rule on a navigation header need the requirement carried.
fn add_routes(engine: &mut Engine) {
    engine.insert_rule(0, challenge_rule("strong-route", "/strong/*", 12)).unwrap();
    engine.insert_rule(0, challenge_rule("exact-route", "^/exact$", 12)).unwrap();
    let mut navigate = challenge_rule("navigate-route", "/navigate/*", 13);
    navigate
        .headers
        .push(HeaderMatcher { name: "Sec-Fetch-Mode".into(), pattern: "navigate".into() });
    engine.insert_rule(0, navigate).unwrap();
}

/// A controlled explicit policy replaces the defaults, as a startup rules array does.
fn configure_quotas(engine: &mut Engine) {
    engine.clear_rules();
    let rows = [
        ("/quota", Action::Challenge, 1, 0),
        ("/quota-other", Action::Challenge, 1, 0),
        ("/quota-ban", Action::Allow, 1, 60),
        ("/quota-global", Action::Allow, 1000, 0),
    ];
    for (path, action, rate, ban_seconds) in rows {
        let limits = Limits { rate, window_seconds: 60, ban_seconds };
        let rule = PolicyRule {
            path_pattern: Some(path.into()),
            limits: Some(limits),
            ..PolicyRule::new(path, action)
        };
        engine.add_rule(rule).unwrap();
    }
}

fn configure_audit(engine: &mut Engine) {
    engine.inspection_modes.sqli = InspectionMode::Audit;
    engine.inspection_modes.path_traversal = InspectionMode::Disabled;
    engine.insert_reputation(b"203.0.113.223/32", Action::Deny).unwrap();
    // A customised denial page: the request path renders it from the snapshot.
    let source = "<!doctype html><title>Custom</title><p>Custom denial: {{ reason }} \
                  ({{ status }}) ref {{ request_id }}</p>";
    let template = Template::compile(Kind::Denied, source.as_bytes()).unwrap();
    assert!(template.customized);
    engine.pages.set(Kind::Denied, template);
}

// ---------------------------------------------------------------------------------------
// The stub origin.

/// Starts the stub origin once and returns its port.
pub fn origin_port() -> u16 {
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

/// Serves one origin connection with keep-alive; `X-Origin-Seq` counts the requests seen on
/// the socket so tests can observe pooled reuse.
fn origin_connection(stream: TcpStream) {
    // The stub's own writes must not be held back, or it would hide the proxy's behaviour.
    let _ = stream.set_nodelay(true);
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

/// Serves one request; false closes the connection.
fn route(conn: &mut Conn, head: &[u8], seq: u32) -> bool {
    let end = head.iter().position(|&b| b == b'\r').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..end]).into_owned();
    if line.contains("/silent") {
        // An origin that never answers: the proxy must give up before this closes.
        thread::sleep(Duration::from_secs(4));
        return false;
    }
    if line.contains("/slow-stream") {
        return slow_stream(conn);
    }
    if line.contains("/slow-length") {
        return trickle(conn, "Content-Length: 15360\r\n");
    }
    if line.contains("/slow-close") {
        trickle(conn, "Connection: close\r\n");
        return false;
    }
    if line.contains("/split") {
        // An origin that flushes its head early (streaming rendering) and its body after.
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
        thread::sleep(Duration::from_millis(5));
        return conn.send(b"body");
    }
    if line.contains("?upload") {
        return upload_echo(conn, head);
    }
    if line.contains("/truncated") {
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
        return false;
    }
    if line.contains("/headbody") {
        // A faulty origin: a HEAD response followed, late, by bytes shaped as a response.
        let evil = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-Poison: 1\r\n\r\nPOISONED!";
        conn.send(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", evil.len()).as_bytes());
        thread::sleep(Duration::from_millis(50));
        return conn.send(evil);
    }
    if line.contains("/origin-error") {
        // An origin that fails: the console counts it as an origin 5xx.
        return conn.send(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror");
    }
    if line.starts_with("GET /ws") {
        return websocket_upgrade(conn, head);
    }
    if line.contains("/large-body") {
        // 64 MiB as fast as the socket takes it.
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\n\r\n");
        let block = vec![b'L'; 1 << 20];
        return (0..64).all(|_| conn.send(&block));
    }
    let head_text = &head[..head.len() - 4];
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: stub\r\nX-Origin-Seq: {seq}\r\n\
         Content-Length: {}\r\n\r\nORIGIN|",
        head_text.len() + 7
    )
    .into_bytes();
    reply.extend_from_slice(head_text);
    conn.send(&reply)
}

/// Accepts a WebSocket upgrade with a valid `Sec-WebSocket-Accept` and holds the socket
/// until the client closes it.
fn websocket_upgrade(conn: &mut Conn, head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head).into_owned();
    let Some(key) = header_of(&text, "sec-websocket-key") else { return false };
    let Ok(accept) = sibuna_http::websocket::accept_key(key.as_bytes()) else { return false };
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        String::from_utf8_lossy(&accept)
    );
    if !conn.send(reply.as_bytes()) {
        return false;
    }
    while conn.more() {
        conn.buffer.clear();
    }
    false
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

fn header_of<'h>(head: &'h str, name: &str) -> Option<&'h str> {
    head.split("\r\n").find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Reads the upload as an origin would and answers with its framing, length and digest. The
/// chunked reader accepts only canonical framing.
fn upload_echo(conn: &mut Conn, head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head).into_owned();
    let chunked = header_of(&text, "transfer-encoding") == Some("chunked");
    let length = header_of(&text, "content-length").and_then(|v| v.parse::<usize>().ok());
    let (framing, body) = if chunked && length.is_none() {
        let Some(body) = canonical_chunked(conn) else { return false };
        ("chunked", body)
    } else if let (false, Some(length)) = (chunked, length) {
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

/// The expected origin answer for an upload of `body` framed as `framing`.
pub fn upload_echo_text(framing: &str, body: &[u8]) -> String {
    format!("UPLOAD|{framing}|{}|{:x}", body.len(), digest(body))
}

// ---------------------------------------------------------------------------------------
// Client helpers.

pub fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// One response as received, until the peer closed.
#[derive(Debug, Default)]
pub struct Response {
    pub bytes: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    pub fn status(&self) -> u16 {
        std::str::from_utf8(self.bytes.get(9..12).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        let text = self.text();
        let head = text.split("\r\n\r\n").next()?;
        head.split("\r\n").skip(1).find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field.eq_ignore_ascii_case(name).then(|| value.trim_matches(' ').to_owned())
        })
    }

    pub fn body(&self) -> &[u8] {
        let at = self
            .bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(self.bytes.len(), |at| at + 4);
        &self.bytes[at..]
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(self.body()).into_owned()
    }

    pub fn contains(&self, needle: &str) -> bool {
        contains(&self.bytes, needle.as_bytes())
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

pub fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| *window == needle).count()
}

/// Sends one raw request, shuts down the sending side, and reads until the peer closes.
/// An empty request only reads (an admission rejection is sent before any request).
pub fn round_trip(port: u16, raw: &[u8]) -> Response {
    let mut stream = TcpStream::connect(address(port)).unwrap();
    if !raw.is_empty() {
        let _ = stream.write_all(raw);
        let _ = stream.shutdown(Shutdown::Write);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
        }
    }
    Response { bytes }
}

pub fn get(port: u16, path: &str, ip: &str, ua: &str, extra: &str) -> Response {
    let raw = format!(
        "GET {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\n\
         User-Agent: {ua}\r\n{extra}\r\n"
    );
    round_trip(port, raw.as_bytes())
}

pub fn post(port: u16, path: &str, ip: &str, ua: &str, body: &str) -> Response {
    let raw = format!(
        "POST {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\nUser-Agent: {ua}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    round_trip(port, raw.as_bytes())
}

/// An issued challenge as the client reads it.
#[derive(Clone, Debug)]
pub struct Challenge {
    pub id: String,
    pub algorithm: String,
    pub difficulty: u32,
    pub challenges: u8,
}

pub fn fetch_challenge(port: u16, ip: &str, ua: &str, path: &str) -> Challenge {
    issue(port, ip, ua, &format!("path={path}"))
}

/// Requests a challenge with an explicit issuance query (a reported path, a ticket or both).
pub fn issue(port: u16, ip: &str, ua: &str, query: &str) -> Challenge {
    let response = get(port, &format!("/__sibuna/challenge.json?{query}"), ip, ua, "");
    assert_eq!(response.status(), 200, "{}", response.text());
    let body = response.body();
    let field = |key: &str| {
        let value = sibuna::extract_json_string(body, key.as_bytes()).unwrap();
        String::from_utf8(value.to_vec()).unwrap()
    };
    Challenge {
        id: field("id"),
        algorithm: field("algorithm"),
        difficulty: field("difficulty").parse().unwrap(),
        challenges: field("challenges").parse().unwrap(),
    }
}

pub fn solve_hashcash(challenge: &Challenge) -> u64 {
    hashcash::solve_bits(challenge.id.as_bytes(), challenge.difficulty, 1 << 26).unwrap()
}

pub fn solve_posw(challenge: &Challenge) -> String {
    let mut workspace = Box::new(posw::Workspace::new());
    let params = posw::Params {
        depth: u8::try_from(challenge.difficulty).unwrap(),
        challenges: challenge.challenges,
    };
    let proof = posw::solve(challenge.id.as_bytes(), params, &mut workspace).unwrap();
    base64::encode(URL_SAFE_NO_PAD, proof)
}

pub fn nonce_body(challenge: &Challenge, nonce: u64) -> String {
    format!("{{\"challenge_id\":\"{}\",\"nonce\":\"{nonce}\"}}", challenge.id)
}

/// The `name=value` pair of the response's `Set-Cookie`.
pub fn extract_cookie(response: &Response) -> String {
    let set_cookie = response.header("set-cookie").expect("no cookie");
    set_cookie.split(';').next().unwrap().to_owned()
}

/// Solves and verifies an issued hashcash challenge, returning the cookie header lines.
pub fn solve_session(port: u16, ip: &str, challenge: &Challenge) -> String {
    let nonce = solve_hashcash(challenge);
    let response = post(port, "/__sibuna/verify", ip, BROWSER_UA, &nonce_body(challenge, nonce));
    assert_eq!(response.status(), 200, "{}", response.text());
    format!("Cookie: {}\r\n{BROWSER_ACCEPT}", extract_cookie(&response))
}

/// Fetches, solves and verifies a hashcash challenge for `path`.
pub fn hashcash_session(port: u16, ip: &str, path: &str) -> String {
    solve_session(port, ip, &fetch_challenge(port, ip, BROWSER_UA, path))
}

/// The requirement an interstitial carries, as the solver script reads it.
pub fn ticket_of(response: &Response) -> Option<String> {
    let text = response.text();
    let marker = "data-ticket=\"";
    let start = text.find(marker)? + marker.len();
    let end = text[start..].find('"')? + start;
    Some(text[start..end].to_owned())
}

/// One response read read by read, with the arrival time of its first body byte.
pub struct Timed {
    pub first_body_ms: Option<u128>,
    pub total_ms: u128,
    pub body: usize,
    pub response: Response,
}

/// Reads one response read by read until the peer closes or `want` body bytes are in.
pub fn timed_get(port: u16, path: &str, ip: &str, want: usize) -> Timed {
    let mut stream = TcpStream::connect(address(port)).unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\nUser-Agent: curl/8\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let started = Instant::now();
    let mut timed =
        Timed { first_body_ms: None, total_ms: 0, body: 0, response: Response::default() };
    let mut chunk = [0u8; 4096];
    while timed.body < want {
        let Ok(count) = stream.read(&mut chunk) else { break };
        if count == 0 {
            break;
        }
        timed.response.bytes.extend_from_slice(&chunk[..count]);
        let bytes = &timed.response.bytes;
        let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        timed.body = bytes.len() - at - 4;
        if timed.body != 0 && timed.first_body_ms.is_none() {
            timed.first_body_ms = Some(started.elapsed().as_millis());
        }
        timed.total_ms = started.elapsed().as_millis();
    }
    timed
}

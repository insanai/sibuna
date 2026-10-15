//! Fixtures for the console's end-to-end suite (`tests/console_*.rs`): a daemon with its
//! console on a fresh SQLite directory (or a PostgreSQL database), the offline bootstrap
//! and the forced password change, a console client with sessions and CSRF tokens, JSON
//! reading, a WebSocket subscriber and polling.
//!
//! The Zig suite drove a daemon binary from Python (`tools/console_*.py`); here the daemon
//! runs in the test process through [`Daemon::start_with_console`], so every scenario owns
//! its daemons and stops them itself.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sibuna::{Daemon, DaemonOptions, Hooks, Recipe};
use sibuna_challenge::Seed;
use sibuna_console_protocol::subscription_client::{Client, Event};
use sibuna_console_protocol::subscriptions::Topic;
use sibuna_core::Config;
use sibuna_http::websocket::{Event as Frame, FrameReader, Opcode, Receiver, Role, encode};
use sibuna_json::Value;

use super::Response;

/// The permanent password every scenario changes the temporary one to.
pub const PASSWORD: &str = "end to end permanent passphrase";

/// Returns a fresh directory under the system's temporary directory for scenario `name`.
pub fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir()
        .join(format!("sibuna-console-e2e-{name}-{}-{unique}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The data plane's configuration every scenario starts from: SQLite in `dir`, one worker,
/// forwarded client addresses trusted, the stub origin upstream, quick storage polls.
pub fn data_plane(dir: &Path) -> Config {
    Config {
        data_dir: Some(dir.join("data").to_str().unwrap().to_owned()),
        upstream_port: super::origin_port(),
        workers: 1,
        trust_forwarded: Some(true),
        storage_poll_ms: 50,
        ..Config::default()
    }
}

/// The console's configuration: an ephemeral loopback port.
pub fn console_config() -> sibuna_console::Config {
    sibuna_console::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..sibuna_console::Config::default()
    }
}

/// Creates the first administrator `admin` offline and returns its temporary password.
pub fn init_admin(config: &Config) -> String {
    sibuna::console::init::run(config, "admin").unwrap()
}

/// A running daemon with its console.
pub struct Node {
    /// The daemon; `None` once stopped.
    pub daemon: Option<Daemon>,
    /// The data plane's configuration.
    pub config: Config,
    /// The console's configuration.
    pub console: sibuna_console::Config,
    /// The startup policy file, if any.
    pub policy: Option<Vec<u8>>,
    /// The data plane's port; 0 binds an ephemeral one on every start.
    pub data_port: u16,
}

impl Node {
    /// Starts the daemon of `config` with the console of `console` and the startup
    /// `policy` file.
    pub fn start(config: Config, console: sibuna_console::Config, policy: Option<&str>) -> Node {
        Node::start_on(config, console, policy, 0)
    }

    /// Starts the daemon as [`Node::start`] does with its data plane on `data_port`, which
    /// it keeps across restarts.
    pub fn start_on(
        config: Config,
        console: sibuna_console::Config,
        policy: Option<&str>,
        data_port: u16,
    ) -> Node {
        let policy = policy.map(|text| text.into());
        let mut node = Node { daemon: None, config, console, policy, data_port };
        node.restart();
        node
    }

    /// Starts the daemon again with the same configuration (a new boot, new ports).
    pub fn restart(&mut self) {
        assert!(self.daemon.is_none(), "the node is running");
        let options = DaemonOptions {
            config: self.config.clone(),
            recipe: Recipe::new(&self.config, self.policy.clone()),
            seed: Seed::new([7; 32]),
            hooks: Hooks::default(),
        };
        let listener = TcpListener::bind(("127.0.0.1", self.data_port)).unwrap();
        let daemon = Daemon::start_with_console(options, self.console.clone(), listener)
            .unwrap_or_else(|error| panic!("the daemon did not start: {error:?}"));
        self.daemon = Some(daemon);
    }

    /// Stops the daemon and returns how long the stop took; panics when storage could not
    /// confirm the pending incidents.
    pub fn stop(&mut self) -> Duration {
        let started = Instant::now();
        let daemon = self.daemon.take().expect("running");
        assert!(daemon.stop(), "storage did not confirm the pending incidents");
        started.elapsed()
    }

    /// Returns the running daemon.
    pub fn daemon(&self) -> &Daemon {
        self.daemon.as_ref().expect("running")
    }

    /// Returns the data plane's port.
    pub fn port(&self) -> u16 {
        self.daemon().address().unwrap().port()
    }

    /// Returns a client of the console.
    pub fn console(&self) -> Console {
        let console = self.daemon().console().unwrap();
        Console { address: console.address(), origin: console.origin().to_owned() }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            daemon.stop();
        }
    }
}

/// A signed-in browser session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The `Cookie` field value.
    pub cookie: String,
    /// The CSRF token.
    pub csrf: String,
}

/// A client of one console.
#[derive(Clone, Debug)]
pub struct Console {
    /// The listener's address.
    pub address: SocketAddr,
    /// The canonical origin, sent as `Origin` on every request.
    pub origin: String,
}

impl Console {
    /// Sends one request with `body` (as JSON when given), the session's cookie when given
    /// and its CSRF token when `csrf` is set.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        session: Option<&Session>,
        csrf: bool,
    ) -> Response {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nConnection: close\r\n",
            self.address, self.origin
        );
        if let Some(session) = session {
            head.push_str(&format!("Cookie: {}\r\n", session.cookie));
            if csrf {
                head.push_str(&format!("X-Console-CSRF: {}\r\n", session.csrf));
            }
        }
        let body = body.unwrap_or_default();
        if method == "POST" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        head.push_str(body);
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        Response { bytes }
    }

    /// Sends `method path` with `Authorization: Bearer <token>` and, for POST, the JSON
    /// `body`.
    pub fn bearer(&self, method: &str, path: &str, token: &str, body: &str) -> Response {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Authorization: Bearer {token}\r\n",
            self.address
        );
        if method == "POST" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ));
        } else {
            head.push_str("\r\n");
        }
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        Response { bytes }
    }

    /// `GET path` with the session's cookie, if any.
    pub fn get(&self, path: &str, session: Option<&Session>) -> Response {
        self.request("GET", path, None, session, false)
    }

    /// `POST path` with a JSON `body`, the session's cookie and CSRF token.
    pub fn post(&self, path: &str, body: &str, session: &Session) -> Response {
        self.request("POST", path, Some(body), Some(session), true)
    }

    /// `POST path` with a JSON `body` and the session; panics unless the reply is 200.
    pub fn ok(&self, path: &str, body: &str, session: &Session) -> Response {
        let reply = self.post(path, body, session);
        assert_eq!(reply.status(), 200, "{path} {body}: {}", reply.text());
        reply
    }

    /// Signs `username` in with `password` and returns the session; panics unless 200.
    pub fn login(&self, username: &str, password: &str) -> Session {
        let body = format!("{{\"username\":\"{username}\",\"password\":\"{password}\"}}");
        let reply = self.request("POST", "/console/api/login", Some(&body), None, false);
        assert_eq!(reply.status(), 200, "login: {}", reply.text());
        session_of(&reply)
    }

    /// Signs the bootstrap administrator in with its `temporary` password, checks that the
    /// account may only change its password, changes it to [`PASSWORD`] and returns the
    /// new session (Zig's `console_bootstrap_test.change`).
    pub fn change_password(&self, temporary: &str) -> Session {
        let body = format!("{{\"username\":\"admin\",\"password\":\"{temporary}\"}}");
        let login = self.request("POST", "/console/api/login", Some(&body), None, false);
        assert_eq!(login.status(), 200, "{}", login.text());
        assert_eq!(field(&login, "must_change"), "true");
        let first = session_of(&login);
        for path in [
            "/console/api/stats",
            "/console/api/geoip",
            "/console/api/rankings",
            "/console/assets/world-110m.bin",
        ] {
            assert_eq!(self.get(path, Some(&first)).status(), 403, "{path}");
        }
        assert_eq!(self.post("/console/api/challenges", "{}", &first).status(), 403);
        let change = format!("{{\"old_password\":\"{temporary}\",\"password\":\"{PASSWORD}\"}}");
        let no_csrf =
            self.request("POST", "/console/api/password", Some(&change), Some(&first), false);
        assert_eq!(no_csrf.status(), 400);
        let changed = self.ok("/console/api/password", &change, &first);
        let replacement = session_of(&changed);
        assert_ne!(replacement.cookie, first.cookie);
        assert_ne!(replacement.csrf, first.csrf);
        assert_eq!(field(&changed, "must_change"), "false");
        assert_eq!(self.get("/console/api/session", Some(&replacement)).status(), 200);
        assert_eq!(self.get("/console/api/session", Some(&first)).status(), 401);
        replacement
    }

    /// Reads `policies/query` and returns the committed revision.
    pub fn committed(&self, session: &Session) -> u64 {
        let page = self.ok("/console/api/policies/query", "{}", session);
        field(&page, "committed").parse().unwrap()
    }

    /// Saves the managed rule `document` (a JSON object) at the committed revision and
    /// returns the new revision once the node's engine applies it.
    pub fn edit_rule(&self, session: &Session, document: &str) -> u64 {
        let body = format!(
            "{{\"expected_revision\":\"{}\",\"document\":{}}}",
            self.committed(session),
            json_string(document)
        );
        let saved = self.ok("/console/api/policies/edit", &body, session);
        let revision: u64 = field(&saved, "committed").parse().unwrap();
        self.applied(session, revision);
        revision
    }

    /// Waits until the node's engine applies `revision` (Zig's `applied`).
    pub fn applied(&self, session: &Session, revision: u64) {
        until("the revision reaches the live engine", 15, || {
            let page = self.ok("/console/api/policies/query", "{}", session);
            (field(&page, "applied").parse::<u64>().unwrap() >= revision).then_some(())
        });
    }

    /// Returns `/console/api/stats` as parsed text.
    pub fn stats(&self, session: &Session) -> Response {
        let reply = self.get("/console/api/stats", Some(session));
        assert_eq!(reply.status(), 200, "{}", reply.text());
        reply
    }
}

/// Returns the session a login or password change answered with.
pub fn session_of(reply: &Response) -> Session {
    let set_cookie = reply.header("set-cookie").expect("a session cookie");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    Session {
        cookie: set_cookie.split(';').next().unwrap().to_owned(),
        csrf: field(reply, "csrf"),
    }
}

/// Returns `text` as a JSON string literal.
pub fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Returns the value at `path` (members and array indices separated by `.`) of the JSON
/// `body` as text: strings without quotes, numbers as written, `true`, `false`, `null`,
/// arrays and objects as compact JSON; `<missing>` when absent.
pub fn field_of(body: &[u8], path: &str) -> String {
    let value = parse(body);
    match lookup(&value, path) {
        Some(Value::String(text)) => text.to_string(),
        Some(value) => {
            let mut out = String::new();
            render(value, &mut out);
            out
        }
        None => "<missing>".into(),
    }
}

/// [`field_of`] over a reply's body.
pub fn field(reply: &Response, path: &str) -> String {
    field_of(reply.body(), path)
}

/// [`field`] parsed as a number.
pub fn number(reply: &Response, path: &str) -> u64 {
    let text = field(reply, path);
    text.parse().unwrap_or_else(|_| panic!("{path} is {text}: {}", reply.body_text()))
}

/// The length of the array at `path`.
pub fn length(reply: &Response, path: &str) -> usize {
    let value = parse(reply.body());
    match lookup(&value, path) {
        Some(Value::Array(items)) => items.len(),
        _ => panic!("{path} is not an array: {}", reply.body_text()),
    }
}

fn parse(body: &[u8]) -> Value<'_> {
    sibuna_json::parse(body)
        .unwrap_or_else(|error| panic!("not JSON ({error:?}): {}", String::from_utf8_lossy(body)))
}

/// Writes `value` as compact JSON (strings without escapes beyond quotes; test data only).
fn render(value: &Value<'_>, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(number.as_str()),
        Value::String(text) => out.push_str(&json_string(text)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (index, (key, item)) in object.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&json_string(key));
                out.push(':');
                render(item, out);
            }
            out.push('}');
        }
    }
}

fn lookup<'v, 'a>(value: &'v Value<'a>, path: &str) -> Option<&'v Value<'a>> {
    path.split('.').filter(|part| !part.is_empty()).try_fold(value, |value, part| match value {
        Value::Object(object) => object.get(part),
        Value::Array(items) => items.get(part.parse::<usize>().ok()?),
        _ => None,
    })
}

/// Waits until `check` returns a value, at most `seconds`, polling every 200 ms.
pub fn until<T>(what: &str, seconds: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(start.elapsed() < Duration::from_secs(seconds), "timed out: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Imports 200 ranges of 8.8.0.0/16 for the United States as DB-IP 2026-09 and waits for
/// the import to apply (Zig's `geo_import`, first half). Returns the new revision.
pub fn geo_import(console: &Console, session: &Session, expected: u64) -> u64 {
    let csv: String = (0..200).map(|i| format!("8.8.{i}.0,8.8.{i}.255,US\\n")).collect();
    let body = format!(
        "{{\"provider\":\"dbip\",\"source_version\":\"2026-09\",\
         \"expected_revision\":{expected},\"csv\":\"{csv}\"}}"
    );
    console.ok("/console/api/geoip", &body, session);
    until("the GeoIP import applies", 15, || {
        let metadata = console.get("/console/api/geoip", Some(session));
        let status = field(&metadata, "status");
        assert_ne!(status, "failed", "{}", metadata.body_text());
        (status == "applied").then(|| number(&metadata, "revision"))
    })
}

/// A browser WebSocket on `/console/ws`, read with the protocol's subscription client.
pub struct Stream {
    stream: TcpStream,
    frames: FrameReader<TcpStream>,
    receiver: Box<Receiver>,
    /// The subscription views.
    pub client: Client,
}

impl Stream {
    /// Opens the stream of `session` on `console`.
    pub fn open(console: &Console, session: &Session) -> Stream {
        let stream = TcpStream::connect(console.address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let head = format!(
            "GET /console/ws HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nCookie: {}\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            console.address, console.origin, session.cookie
        );
        (&stream).write_all(head.as_bytes()).unwrap();
        // Byte by byte, so that no frame behind the head is consumed here.
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            assert_eq!((&stream).read(&mut byte).unwrap(), 1, "the upgrade head ended early");
            raw.push(byte[0]);
        }
        assert!(raw.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&raw));
        let frames = FrameReader::new(stream.try_clone().unwrap());
        Stream { stream, frames, receiver: Box::new(Receiver::new()), client: Client::new() }
    }

    /// Sends one text command.
    pub fn command(&mut self, text: &str) {
        let mut buffer = vec![0u8; 14 + text.len()];
        let mask = Some([0x5a, 0x17, 0xc3, 0x09]);
        let frame = encode(&mut buffer, Opcode::Text, true, text.as_bytes(), Role::Client, mask);
        let frame = frame.unwrap_or_else(|_| panic!("an unencodable command"));
        self.stream.write_all(frame).unwrap();
    }

    /// Subscribes to `topic` with `args` (a JSON object).
    pub fn subscribe(&mut self, topic: &str, args: &str) {
        self.command(&format!("{{\"op\":\"sub\",\"topic\":\"{topic}\",\"args\":{args}}}"));
    }

    /// Reads messages until `done` accepts the view of `topic`, at most `seconds`; returns
    /// that view.
    pub fn until(&mut self, topic: Topic, seconds: u64, done: impl Fn(&str) -> bool) -> String {
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(seconds), "the view never matched");
            let text = match self.frames.receive(&mut self.receiver, Role::Client) {
                Ok(Frame::Text(text)) => text.to_owned(),
                Ok(Frame::Close(_)) => panic!("the console closed the stream"),
                Ok(_) => continue,
                Err(error) => panic!("the stream failed: {error:?}"),
            };
            let value = sibuna_json::parse(text.as_bytes()).unwrap();
            match self.client.receive(&value) {
                Ok(Event::Changed(changed)) if changed == topic => {
                    let view = self.client.view(topic);
                    if done(view) {
                        return view.to_owned();
                    }
                }
                Ok(Event::Gap(_) | Event::Unauthorized) => panic!("the view broke: {text}"),
                Ok(_) => {}
                Err(error) => panic!("an invalid message ({error:?}): {text}"),
            }
        }
    }
}

/// Returns a loopback port that was free a moment ago, for a listener whose address must
/// be known before it starts (an advertised origin, a probe target).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The PostgreSQL database URL of the test server (`SIBUNA_TEST_DATABASE_URL`), when set.
pub fn postgres_base() -> Option<String> {
    std::env::var("SIBUNA_TEST_DATABASE_URL").ok().filter(|url| !url.is_empty())
}

/// A database of its own on the test server, dropped again when the value is dropped.
#[cfg(feature = "postgres")]
pub struct PostgresDatabase {
    base: String,
    name: String,
    /// The URL of the fresh database.
    pub url: String,
}

#[cfg(feature = "postgres")]
impl PostgresDatabase {
    /// Drops and creates the database `name` (with this process's id) on the server of
    /// `base`, through a storage thread on `base`.
    pub fn create(base: &str, name: &str) -> PostgresDatabase {
        let mut database = format!("sibuna_e2e_{}_{name}", std::process::id());
        database.truncate(63);
        let script =
            format!("DROP DATABASE IF EXISTS {database} WITH (FORCE); CREATE DATABASE {database}");
        // CREATE DATABASE cannot run inside a transaction block: one statement at a time.
        for statement in script.split("; ") {
            postgres_admin(base, statement);
        }
        let (head, query) = base.split_once('?').map_or((base, None), |(h, q)| (h, Some(q)));
        let authority = head.find("://").map_or(0, |at| at + 3);
        let path = head[authority..].find('/').map_or(head.len(), |at| authority + at);
        let mut url = format!("{}/{database}", &head[..path]);
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        PostgresDatabase { base: base.to_owned(), name: database, url }
    }
}

#[cfg(feature = "postgres")]
impl Drop for PostgresDatabase {
    fn drop(&mut self) {
        postgres_admin(&self.base, &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name));
    }
}

/// Runs one administrative `statement` on the server of `base`.
#[cfg(feature = "postgres")]
fn postgres_admin(base: &str, statement: &str) {
    let config = Config { database_url: Some(base.to_owned()), ..Config::default() };
    let storage =
        sibuna_storage::Storage::start(&config, sibuna_storage::Hooks::default()).unwrap();
    let statement = statement.to_owned();
    storage.with_database(move |db| async move { db.execute_script(&statement).await }).unwrap();
    storage.shutdown();
}

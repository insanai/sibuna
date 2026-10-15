//! The console test harness, shared by every integration test of this crate: a fresh SQLite
//! database in a temporary directory, a storage thread with the console's migrations and
//! hooks, a console on an ephemeral loopback port with a fake node, a plain HTTP/1.1
//! client, and helpers to bootstrap an account and sign it in without a password check.
//!
//! Each test file includes it with `mod support;`; a file uses only part of it.

// Test support: a failure to set up is reported by panicking, and not every test file uses
// every helper.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sibuna_console::{AssetBytes, Config, Console, Inputs, Node, RuleHitSample};
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Role, Text, auth};
use sibuna_console_storage::accounts;
use sibuna_console_storage::{CONSOLE, sidecars};
use sibuna_crypto::{hmac, sha256::Sha256};
use sibuna_storage::{Hooks, Param, Sql, Storage};

const INSERT_USER: Sql = Sql::both(
    "INSERT INTO console_users (username, password_hash, role, must_change, modified_at) \
     VALUES ($1, $2, $3, ($4 <> 0), $5) RETURNING id",
);

/// The shell template the harness serves, with all three placeholders.
pub const SHELL: &[u8] = b"<!doctype html><link href=\"/console/assets/{{ css }}/console.css\">\
    <script src=\"/console/assets/{{ glue }}/glue.js\" \
    data-wasm=\"/console/assets/{{ wasm }}/console.wasm\"></script>";
/// A PHC string that is never verified by these tests.
pub const PHC: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaA";

/// The assets the harness serves.
pub fn assets() -> AssetBytes {
    AssetBytes {
        wasm: b"\0asm\x01\0\0\0",
        glue: b"export {};",
        css: b"body{margin:0}",
        shell: SHELL,
        world: b"WORLD110",
    }
}

/// A node whose effects are recorded and whose readings tests set.
#[derive(Debug, Default)]
pub struct FakeNode {
    /// The drain flag.
    pub draining: AtomicBool,
    /// Local bans `clear_local_bans` reports and resets.
    pub bans: AtomicU32,
    /// How often `clear_local_bans` ran.
    pub clears: AtomicU32,
    /// The applied policy revision.
    pub revision: AtomicU64,
    /// The rule-hit sample to report, if any.
    pub sample: Mutex<Option<RuleHitSample>>,
}

impl Node for FakeNode {
    fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::SeqCst);
    }

    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn clear_local_bans(&self, _now: u64) -> u32 {
        self.clears.fetch_add(1, Ordering::SeqCst);
        self.bans.swap(0, Ordering::SeqCst)
    }

    fn active_bans(&self, _now: u64) -> Option<u32> {
        Some(self.bans.load(Ordering::SeqCst))
    }

    fn sample_rule_hits(&self, sample: &mut RuleHitSample) -> bool {
        match self.sample.lock().unwrap().as_ref() {
            Some(stored) => {
                sample.clone_from(stored);
                true
            }
            None => false,
        }
    }

    fn applied_revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }
}

/// A running console over a fresh SQLite database.
pub struct Harness {
    /// The console; `None` after `stop`.
    pub console: Option<Console>,
    /// The storage thread.
    pub storage: Arc<Storage>,
    /// The fake node.
    pub node: Arc<FakeNode>,
    dir: PathBuf,
}

/// A signed-in browser session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The `Cookie` field value.
    pub cookie: String,
    /// The CSRF token as hex.
    pub csrf: String,
}

impl Harness {
    /// Starts a console with the default configuration on an ephemeral loopback port.
    pub fn start(name: &str) -> Harness {
        Harness::start_with(name, Config::default(), |_| {})
    }

    /// Starts a console with `config` (its listener moved to an ephemeral loopback port
    /// unless it already names port 0) after `adjust` changed the inputs.
    pub fn start_with(
        name: &str,
        mut config: Config,
        adjust: impl FnOnce(&mut Inputs),
    ) -> Harness {
        let dir =
            std::env::temp_dir().join(format!("sibuna-console-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let geo = Arc::new(sibuna_console::GeoSlot::new());
        let incidents = Arc::new(sibuna_store::incidents::ConsoleIncidents::new());
        let hooks = Hooks {
            migrations: vec![CONSOLE],
            on_incidents: Some(sidecars::incident_hook(Some(geo.country_lookup()))),
            on_committed: Some(sibuna_console::committed_hook(Arc::clone(&incidents))),
            on_snapshot: Some(sibuna_console::snapshot_hook()),
            ..Hooks::default()
        };
        let storage_config = sibuna_core::Config {
            data_dir: Some(dir.to_string_lossy().into_owned()),
            storage_poll_ms: 50,
            ..sibuna_core::Config::default()
        };
        let storage = Arc::new(Storage::start(&storage_config, hooks).expect("storage"));
        let node = Arc::new(FakeNode::default());
        if config.listen.port() != 0 {
            config.listen = "127.0.0.1:0".parse().unwrap();
        }
        let mut inputs = Inputs {
            node_id: 1,
            version: "0.2.0-test".into(),
            geo,
            incidents,
            assets: assets(),
            ..Inputs::new(Arc::clone(&storage), node.clone(), [7; 16])
        };
        adjust(&mut inputs);
        let console = Console::start(config, inputs).expect("console");
        Harness { console: Some(console), storage, node, dir }
    }

    /// Returns the console.
    pub fn console(&self) -> &Console {
        self.console.as_ref().expect("running")
    }

    /// Returns the listener's address.
    pub fn address(&self) -> SocketAddr {
        self.console().address()
    }

    /// Returns the canonical origin.
    pub fn origin(&self) -> String {
        self.console().origin().to_owned()
    }

    /// Sends one request with `headers` and `body` and returns the response.
    pub fn request(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Response {
        request(self.address(), method, target, headers, body)
    }

    /// `GET target`.
    pub fn get(&self, target: &str, headers: &[(&str, &str)]) -> Response {
        self.request("GET", target, headers, b"")
    }

    /// `POST target` with a JSON body and the canonical `Origin`.
    pub fn post(&self, target: &str, headers: &[(&str, &str)], body: &str) -> Response {
        let origin = self.origin();
        let mut all = vec![("Origin", origin.as_str()), ("Content-Type", "application/json")];
        all.extend_from_slice(headers);
        self.request("POST", target, &all, body.as_bytes())
    }

    /// Runs `job` on the storage thread in one committed transaction.
    pub fn transact<T, F>(&self, job: F) -> T
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut sibuna_storage::Transaction,
            ) -> sibuna_storage::BorrowedFuture<
                'a,
                Result<T, sibuna_console_storage::ConsoleStorageError>,
            > + Send
            + 'static,
    {
        self.storage
            .with_database(move |db| async move {
                let mut tx = db.begin().await?;
                let value = job(&mut tx).await;
                match value {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(Ok(value))
                    }
                    Err(error) => Ok(Err(error)),
                }
            })
            .expect("storage job")
            .expect("storage function")
    }

    /// Creates an account directly in storage, unaudited (a fixture, not the S1 path), and
    /// returns its id; its revision is 1.
    pub fn create_user(&self, username: &str, role: Role, must_change: bool) -> u64 {
        let username = username.to_owned();
        let now = i64::try_from(unix_now()).unwrap();
        self.transact(move |tx| {
            Box::pin(async move {
                let params: [Param<'_>; 5] = [
                    username.as_str().into(),
                    PHC.into(),
                    role.name().into(),
                    i64::from(must_change).into(),
                    now.into(),
                ];
                let rows = tx.fetch_all(INSERT_USER, &params).await?;
                let id = rows[0][0].as_i64().unwrap();
                Ok(u64::try_from(id).unwrap())
            })
        })
    }

    /// Creates a browser session for account `user` at `revision` without a password
    /// check, and returns its cookie and CSRF token.
    pub fn sign_in(&self, user: u64, revision: u64) -> Session {
        let raw: [u8; 32] = sibuna_console::random::array().unwrap();
        let csrf = hmac::hmac_sha256(b"sibuna-console-csrf-v1", &raw);
        let now = unix_now();
        let session = auth::Session {
            user,
            revision,
            digest: Sha256::digest(&raw),
            csrf_digest: Sha256::digest(&csrf),
            expires: now + 3600,
            client: Text::new("127.0.0.1").unwrap(),
            ..auth::Session::default()
        };
        self.transact(move |tx| {
            Box::pin(async move { accounts::insert_session(tx, &session, now).await })
        });
        Session {
            cookie: format!("__sibuna_console={}", sibuna_encoding::hex::encode(&raw)),
            csrf: sibuna_encoding::hex::encode(&csrf),
        }
    }

    /// Stops the console and the storage thread and removes the database.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(console) = self.console.take() {
            console.stop();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One HTTP response.
#[derive(Clone, Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The header fields in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// Returns the value of the first field named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let found = self.headers.iter().find(|(field, _)| field.eq_ignore_ascii_case(name));
        found.map(|(_, value)| value.as_str())
    }

    /// Returns the body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Returns the failure code of a JSON failure body, or an empty string.
    pub fn code(&self) -> String {
        let text = self.text();
        let Some(start) = text.find("\"error\":\"") else { return String::new() };
        let rest = &text[start + 9..];
        rest[..rest.find('"').unwrap_or(0)].to_owned()
    }
}

/// Sends one request to `address` and reads the response until the server closes.
pub fn request(
    address: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Response {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

/// Parses a complete HTTP/1.1 response with a `Content-Length` or a body to the end.
pub fn parse_response(raw: &[u8]) -> Response {
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("a head");
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap();
    let status = status_line.split(' ').nth(1).unwrap().parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let mut body = raw[end + 4..].to_vec();
    let length = headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    if let Some(length) = length.and_then(|(_, value)| value.parse::<usize>().ok()) {
        body.truncate(length);
    }
    Response { status, headers, body }
}

/// Returns the current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

//! Helpers of the account tests (unit U2): accounts with real Argon2id hashes, sign-in
//! through the routes, sessions as a browser holds them, and a console restart over the
//! same database, which also empties the sign-in limiter (Zig's end-to-end scripts
//! restarted the daemon for the same reason).
//!
//! Each test file includes it with `mod signin;` after `mod support;`.

// Test support: a failure to set up is reported by panicking, and not every test file uses
// every helper.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sibuna_console::{Config, Console, ConsoleKey, Inputs, Keys};
use sibuna_console_protocol::{Role, Text, auth};
use sibuna_console_storage::{ConsoleStorageError, Credential, accounts};
use sibuna_crypto::argon2::{self, Block, Params};
use sibuna_json::Value;
use sibuna_storage::{BorrowedFuture, Param, Sql, Transaction};

use crate::support::{self, Harness, Response};

/// The key the TOTP tests seal seeds with.
pub const KEY: [u8; 32] = [0x5a; 32];

/// Returns the Argon2id PHC string of `password` with the console's parameters.
pub fn hash(password: &str) -> String {
    let params = Params::default();
    let mut workspace = vec![Block::ZERO; argon2::block_count(&params).unwrap()];
    let mut output = [0u8; argon2::PHC_MAX_LEN];
    let salt: [u8; 32] = sibuna_console::random::array().unwrap();
    argon2::hash_phc(&params, password.as_bytes(), &salt, &mut workspace, &mut output)
        .unwrap()
        .to_owned()
}

/// Creates the first administrator `username` with `password` through the bootstrap (S1)
/// and returns its id; `must_change` asks for a password change at the first sign-in.
pub fn bootstrap(harness: &Harness, username: &str, password: &str, must_change: bool) -> u64 {
    let input = auth::Bootstrap {
        username: Text::new(username).unwrap(),
        password_hash: Text::new(&hash(password)).unwrap(),
        must_change,
        password_expires: 0,
    };
    let now = support::unix_now();
    let saved = harness
        .transact(move |tx| Box::pin(async move { accounts::bootstrap(tx, &input, now).await }));
    saved.id
}

/// A signed-in browser: the `Cookie` value and the CSRF token, and the sign-in reply.
#[derive(Clone, Debug)]
pub struct Browser {
    /// `__sibuna_console=<hex>`.
    pub cookie: String,
    /// The CSRF token as hex.
    pub csrf: String,
    /// The full `Set-Cookie` value.
    pub set_cookie: String,
    /// The reply body.
    pub body: Vec<u8>,
    /// Header fields sent with every request of this browser (a proxy's forwarding).
    pub extra: Vec<(String, String)>,
}

impl Browser {
    /// Takes the session from a 200 sign-in, password change or kiosk exchange reply.
    pub fn from(response: &Response) -> Browser {
        assert_eq!(response.status, 200, "{}", response.text());
        let set_cookie = response.header("Set-Cookie").expect("a cookie").to_owned();
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let reply = sibuna_json::parse(&response.body).unwrap();
        let csrf = text(&reply, "csrf");
        Browser { cookie, csrf, set_cookie, body: response.body.clone(), extra: Vec::new() }
    }

    /// Returns the field `name` of the sign-in reply as text (see [`text`]).
    pub fn field(&self, name: &str) -> String {
        text(&sibuna_json::parse(&self.body).unwrap(), name)
    }

    /// Returns this browser sending `extra` with every request.
    pub fn with(mut self, extra: &[(&str, &str)]) -> Browser {
        self.extra = extra.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect();
        self
    }

    fn headers<'a>(&'a self, own: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut headers = own.to_vec();
        headers.extend(self.extra.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        headers
    }

    /// `POST path` with this session's cookie and CSRF token.
    pub fn post(&self, harness: &Harness, path: &str, body: &str) -> Response {
        let own = [("Cookie", self.cookie.as_str()), ("X-Console-CSRF", self.csrf.as_str())];
        harness.post(path, &self.headers(&own), body)
    }

    /// `GET path` with this session's cookie.
    pub fn get(&self, harness: &Harness, path: &str) -> Response {
        harness.get(path, &self.headers(&[("Cookie", self.cookie.as_str())]))
    }
}

/// Posts a sign-in for `username` with `password` and, when not empty, `code`.
pub fn login(harness: &Harness, username: &str, password: &str, code: &str) -> Response {
    login_with(harness, username, password, code, &[])
}

/// [`login`] with further header fields, such as a proxy's forwarding.
pub fn login_with(
    harness: &Harness,
    username: &str,
    password: &str,
    code: &str,
    extra: &[(&str, &str)],
) -> Response {
    let body = if code.is_empty() {
        format!("{{\"username\":\"{username}\",\"password\":\"{password}\"}}")
    } else {
        format!("{{\"username\":\"{username}\",\"password\":\"{password}\",\"code\":\"{code}\"}}")
    };
    harness.post("/console/api/login", extra, &body)
}

/// Signs in and returns the browser; panics unless the sign-in succeeds.
pub fn sign_in(harness: &Harness, username: &str, password: &str) -> Browser {
    Browser::from(&login(harness, username, password, ""))
}

/// Changes the password of `browser` from `old` to `new` and returns the rotated session,
/// which keeps the browser's extra fields.
pub fn rotate(harness: &Harness, browser: &Browser, old: &str, new: &str) -> Browser {
    let body = format!("{{\"old_password\":\"{old}\",\"password\":\"{new}\"}}");
    let mut rotated = Browser::from(&browser.post(harness, "/console/api/password", &body));
    rotated.extra.clone_from(&browser.extra);
    rotated
}

/// Parses a JSON reply body.
pub fn json(response: &Response) -> Value<'_> {
    sibuna_json::parse(&response.body).unwrap_or_else(|_| panic!("{}", response.text()))
}

/// Returns member `name` of the object `value`.
pub fn member<'v, 'a>(value: &'v Value<'a>, name: &str) -> &'v Value<'a> {
    value.as_object().unwrap().get(name).unwrap_or_else(|| panic!("no {name} in {value}"))
}

/// Returns member `name` as text: a string's content, or any other value as JSON (a
/// counter written as a number, `true`, `null`).
pub fn text(value: &Value<'_>, name: &str) -> String {
    match member(value, name) {
        Value::String(text) => text.to_string(),
        other => other.to_string(),
    }
}

/// Starts a harness whose console has the TOTP key [`KEY`] and `config`.
pub fn start_with_key(name: &str, config: Config) -> Harness {
    Harness::start_with(name, config, |inputs| {
        inputs.keys = Keys { totp: Some(ConsoleKey::new(KEY)), peer: None };
    })
}

/// Stops the harness's console and starts a new one over the same storage with `config`
/// and, when `key` is set, the TOTP key [`KEY`]: the limiter and every allowance start
/// empty; sessions, accounts and tokens persist.
pub fn restart(harness: &mut Harness, config: Config, key: bool) {
    if let Some(console) = harness.console.take() {
        console.stop();
    }
    let mut config = config;
    if config.listen.port() != 0 {
        config.listen = "127.0.0.1:0".parse().unwrap();
    }
    let keys = Keys { totp: key.then(|| ConsoleKey::new(KEY)), peer: None };
    let node: Arc<dyn sibuna_console::Node> = harness.node.clone();
    let inputs = Inputs {
        node_id: 1,
        version: "0.2.0-test".into(),
        assets: support::assets(),
        keys,
        ..Inputs::new(Arc::clone(&harness.storage), node, [7; 16])
    };
    harness.console = Some(Console::start(config, inputs).expect("console"));
}

/// Returns the role of a sign-in reply.
pub fn role(browser: &Browser) -> Role {
    match browser.field("role").as_str() {
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        _ => Role::Viewer,
    }
}

/// Runs `job` in one transaction on the harness's storage thread, committed when it
/// succeeds, and returns its result (the storage function's refusal included).
pub fn attempt<T, F>(harness: &Harness, job: F) -> Result<T, ConsoleStorageError>
where
    T: Send + 'static,
    F: for<'a> FnOnce(&'a mut Transaction) -> BorrowedFuture<'a, Result<T, ConsoleStorageError>>
        + Send
        + 'static,
{
    let result = harness.storage.with_database(move |db| async move {
        let mut tx = db.begin().await?;
        let value = job(&mut tx).await;
        if value.is_ok() {
            tx.commit().await?;
        }
        Ok(value)
    });
    result.expect("storage job")
}

/// Executes the statement `sql` with integer parameters and returns the changed rows.
pub fn exec(harness: &Harness, sql: Sql, params: Vec<i64>) -> u64 {
    let result = harness.storage.with_database(move |db| async move {
        let params: Vec<Param<'_>> = params.iter().map(|&value| value.into()).collect();
        db.execute(sql, &params).await
    });
    result.expect("statement")
}

/// Returns the integer in the first column of the first row of `sql`.
pub fn count(harness: &Harness, sql: Sql) -> i64 {
    let result = harness.storage.with_database(move |db| async move {
        let rows = db.fetch_all(sql, &[]).await?;
        Ok(rows.first().and_then(|row| row.first()).and_then(|cell| cell.as_i64()))
    });
    result.expect("query").expect("an integer")
}

/// Creates the administrator `policy-admin` (id 1, unaudited) and a browser session whose
/// cookie digest is all 1 and CSRF digest all 2, as Zig's `policySession` fixture did, and
/// returns the storage credential of that session.
pub fn fixture_session(harness: &Harness) -> Credential {
    harness.create_user("policy-admin", Role::Admin, false);
    let now = support::unix_now();
    let session = auth::Session {
        user: 1,
        revision: 1,
        digest: [1; 32],
        csrf_digest: [2; 32],
        expires: now + 1000,
        ..auth::Session::default()
    };
    attempt(harness, move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &session, now).await })
    })
    .unwrap();
    Credential {
        kind: sibuna_console_protocol::CredentialKind::Session,
        digest: [1; 32],
        csrf_digest: [2; 32],
        require_totp: false,
        client: None,
    }
}

/// Resolves the credential with digest `byte` of `kind` at `now`.
pub fn authorize(
    harness: &Harness,
    byte: u8,
    kind: sibuna_console_protocol::CredentialKind,
    now: u64,
) -> Result<sibuna_console_protocol::Principal, ConsoleStorageError> {
    let check = sibuna_console_protocol::AuthorizationCheck {
        session_digest: [byte; 32],
        touch: false,
        kind,
    };
    attempt(harness, move |tx| {
        Box::pin(async move { sibuna_console_storage::access::authorize(tx, &check, now).await })
    })
}

/// Returns the code an authenticator shows for the base32 `secret` at time step `step`.
pub fn totp_code(secret: &str, step: u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u64;
    let mut count = 0;
    let mut seed = Vec::new();
    for character in secret.bytes() {
        let value = ALPHABET.iter().position(|&known| known == character).unwrap();
        bits = bits << 5 | value as u64;
        count += 5;
        if count >= 8 {
            count -= 8;
            seed.push((bits >> count) as u8);
        }
    }
    let seed: [u8; 20] = seed.try_into().unwrap();
    String::from_utf8(sibuna_crypto::totp::code(&seed, step).to_vec()).unwrap()
}

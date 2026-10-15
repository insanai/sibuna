//! The routes `login`, `logout` and `password` (unit U2; Zig's `auth_routes.zig`); the setup
//! status and session replies are the dispatcher's. The module also holds what the other
//! account routes share: the sign-in limiter keys, secrets decoded from a body, password
//! checks against the one verifier, decimal fields and replies that carry a secret.
//!
//! A sign-in runs in this order, so that every refusal looks the same to the client:
//!
//! ```text
//! body -> name check (400) -> limiter, address then account (429 CONSOLE003)
//!      -> account lookup -> password check against its hash, or the dummy hash
//!      -> second factor (TOTP code or recovery code) -> session (S3) -> cookie
//! any refusal after the limiter: session.denied audit row, 401 CONSOLE401
//! ```
//!
//! Passwords are checked before any storage transaction that changes something, and the
//! verifier is never held across a storage call.

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, counter_field, field,
};
use sibuna_console_protocol::{AuthUser, Role, Text, auth, valid_username};
use sibuna_console_storage::access::SESSION_SECONDS;
use sibuna_console_storage::accounts;
use sibuna_crypto::ct;
use sibuna_crypto::sha256::Sha256;
use sibuna_http::Header;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::api::totp;
use crate::auth::password::{DUMMY_HASH, PasswordError};
use crate::dispatch::Call;
use crate::http::RouteError;
use crate::http::body::read_json;
use crate::http::credential::{COOKIE, csrf_token};
use crate::http::reply::json_bytes;
use crate::random;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The largest body of the sign-in, password and second-factor routes.
const BODY: usize = 2048;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::Login => login(shared, context, call),
        Handler::Logout => logout(shared, context, call),
        Handler::Password => password(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// A secret text decoded from a request body (a password or a code), wiped when dropped.
#[derive(Default)]
pub struct Secret(String);

impl Secret {
    /// Borrows the bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true for an empty secret.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Decode for Secret {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Secret, DecodeError> {
        String::decode(value, path).map(Secret)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        ct::zeroize(&mut bytes);
    }
}

/// A fresh session token, its CSRF token and both digests; the raw values are wiped when
/// dropped.
pub struct Issued {
    /// The raw session token the cookie carries.
    pub raw: [u8; 32],
    /// The session's CSRF token.
    pub csrf: [u8; 32],
    /// SHA-256 of `raw`, which storage keeps.
    pub digest: [u8; 32],
    /// SHA-256 of `csrf`, which storage keeps.
    pub csrf_digest: [u8; 32],
}

impl Issued {
    /// Draws a session token and derives its CSRF token.
    ///
    /// Fails with [`RouteError::Unavailable`] when no random bytes can be read.
    pub fn new() -> Result<Issued, RouteError> {
        let raw: [u8; 32] = random::array().map_err(|_| RouteError::Unavailable)?;
        let csrf = csrf_token(&raw);
        Ok(Issued { raw, csrf, digest: Sha256::digest(&raw), csrf_digest: Sha256::digest(&csrf) })
    }
}

impl Drop for Issued {
    fn drop(&mut self) {
        ct::zeroize(&mut self.raw);
        ct::zeroize(&mut self.csrf);
    }
}

/// Returns the `Set-Cookie` value of a session: `HttpOnly`, `SameSite=Strict`, `Path=/console`,
/// `Max-Age` of `lifetime` seconds, and `Secure` behind a proxy or when configured. The
/// caller wipes it after sending.
pub fn session_cookie(shared: &Shared, raw: &[u8; 32], lifetime: u64) -> String {
    let secure = if is_secure(shared) { "; Secure" } else { "" };
    format!(
        "{COOKIE}={}; HttpOnly; SameSite=Strict; Path=/console; Max-Age={lifetime}{secure}",
        sibuna_encoding::hex::encode(raw)
    )
}

fn is_secure(shared: &Shared) -> bool {
    shared.config.behind_proxy || shared.config.cookie_secure
}

/// Encodes `value`, answers 200 with it and `extra` fields, and wipes the encoded body, for
/// replies that carry a token, a password or a code.
///
/// Fails with [`RouteError::Serve`] when writing fails.
pub fn send_secret<T: Encode>(
    context: &mut Context<'_>,
    value: &T,
    extra: &[Header<'_>],
) -> Result<(), RouteError> {
    let mut body = sibuna_console_protocol::codec::to_json(value).into_bytes();
    let sent = json_bytes(context, &body, extra);
    ct::zeroize(&mut body);
    Ok(sent?)
}

/// Counts one password attempt against the address of the transport peer and against
/// `username`, five per minute each (Zig's `allowed`). The account is counted only when
/// the address is still allowed.
pub fn allowed(shared: &Shared, context: &Context<'_>, username: &str, now: u64) -> bool {
    let address = address_key(b"sibuna-console-address-v1", context);
    let mut account = Sha256::new();
    account.update(b"sibuna-console-account-v1");
    account.update(username.as_bytes());
    shared.login_limiter.allow(&address, now)
        && shared.login_limiter.allow(&account.finalize(), now)
}

/// SHA-256 of `domain` and the transport peer's address bytes (4 for IPv4, 16 for IPv6).
pub fn address_key(domain: &[u8], context: &Context<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    match context.peer().ip() {
        std::net::IpAddr::V4(ip) => hash.update(&ip.octets()),
        std::net::IpAddr::V6(ip) => hash.update(&ip.octets()),
    }
    hash.finalize()
}

/// Reads the enabled account named `username` for a password check; `None` when there is
/// none.
///
/// Fails with the storage failure's route error.
pub fn account(shared: &Shared, username: &str) -> Result<Option<AuthUser>, RouteError> {
    let name = username.to_owned();
    let found = shared
        .storage
        .transact(move |tx| Box::pin(async move { accounts::auth_user(tx, &name).await }));
    Ok(found?)
}

/// Checks `password` against `hash` and returns whether it matches.
///
/// Fails with [`RouteError::VerifierBusy`] while another check holds the verifier.
pub fn check_password(shared: &Shared, password: &[u8], hash: &str) -> Result<bool, RouteError> {
    match shared.verifier.verify(password, hash) {
        Ok(()) => Ok(true),
        Err(PasswordError::Busy) => Err(RouteError::VerifierBusy),
        Err(_) => Ok(false),
    }
}

/// Hashes a new password.
///
/// Fails with [`RouteError::BadRequest`] for a password outside 12 to 128 bytes,
/// [`RouteError::VerifierBusy`] while the verifier is in use, and
/// [`RouteError::Unavailable`] when hashing fails.
pub fn hash_password(shared: &Shared, password: &[u8]) -> Result<Text<255>, RouteError> {
    let hash = shared.verifier.hash(password).map_err(|error| match error {
        PasswordError::Busy => RouteError::VerifierBusy,
        PasswordError::InvalidPassword => RouteError::BadRequest,
        PasswordError::InvalidHash | PasswordError::HashFailed => RouteError::Unavailable,
    })?;
    Text::from_string(hash).map_err(|_| RouteError::Unavailable)
}

/// Parses a decimal field of 1 to 19 digits, at most `max` (Zig's `number`).
///
/// Fails with [`RouteError::BadRequest`] for anything else.
pub fn decimal(text: &str, max: u64) -> Result<u64, RouteError> {
    if text.is_empty() || text.len() > 19 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RouteError::BadRequest);
    }
    text.parse::<u64>().ok().filter(|&value| value <= max).ok_or(RouteError::BadRequest)
}

/// Returns the request's client address as the protocol's bounded text.
pub fn client(call: &Call) -> Text<48> {
    Text::new(&call.origin.client).unwrap_or_default()
}

/// The sign-in body.
struct Credentials {
    username: String,
    password: Secret,
    code: Secret,
}

impl Decode for Credentials {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Credentials, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let credentials = Credentials {
            username: fields.required("username")?,
            password: fields.required("password")?,
            code: fields.or_default("code")?,
        };
        fields.finish()?;
        Ok(credentials)
    }
}

fn login(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Credentials = read_json(context, &mut buffer)?;
    if !valid_username(&input.username) {
        return Err(RouteError::BadRequest);
    }
    if !allowed(shared, context, &input.username, call.now) {
        return Err(RouteError::fail(429, "CONSOLE003"));
    }
    let user = account(shared, &input.username)?;
    let hash = user.as_ref().map_or(DUMMY_HASH, |user| user.password_hash.as_str());
    let matches = check_password(shared, input.password.as_bytes(), hash)?;
    let Some(user) = user.filter(|_| matches) else {
        return refuse(shared, &input.username, call);
    };
    let Some(factor) = totp::factor(shared, &user, input.code.as_bytes(), call.now) else {
        return refuse(shared, &input.username, call);
    };
    establish(shared, context, call, &user, factor)
}

/// Audits a refused sign-in and answers 401 `CONSOLE401`: the reply is the same whether
/// the account, the password or the second factor was wrong. A failure to audit does not
/// change the reply (Zig logged it); the audit row is written before replying, where Zig
/// queued it in the background.
fn refuse(shared: &Shared, username: &str, call: &Call) -> Result<(), RouteError> {
    let denied =
        auth::Denied { username: Text::new(username).unwrap_or_default(), client: client(call) };
    let now = call.now;
    let _ = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::record_denied(tx, &denied, now).await })
    });
    Err(RouteError::fail(401, "CONSOLE401"))
}

/// Creates the browser session (S3) and answers with its cookie.
fn establish(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    user: &AuthUser,
    factor: auth::Factor,
) -> Result<(), RouteError> {
    let now = call.now;
    if user.password_expires != 0 && user.password_expires <= now {
        return Err(RouteError::fail(401, "CONSOLE401"));
    }
    let mut expires = now.saturating_add(SESSION_SECONDS);
    if user.password_expires != 0 {
        expires = expires.min(user.password_expires);
    }
    let issued = Issued::new()?;
    let session = auth::Session {
        factor,
        user: user.id,
        revision: user.revision,
        digest: issued.digest,
        csrf_digest: issued.csrf_digest,
        expires,
        client: client(call),
        agent_digest: Text::new(&call.origin.agent_digest).unwrap_or_default(),
    };
    let created = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &session, now).await })
    });
    created.map_err(|failure| conflict_or(failure, "CONSOLE409"))?;
    let reply = SessionReply {
        user: user.id,
        node: shared.identity.node_id,
        role: user.role,
        must_change: user.must_change,
        totp_required: shared.needs_totp(user.role, user.totp_enabled),
        csrf: &issued.csrf,
    };
    send_session(shared, context, &reply, &issued.raw, expires - now)
}

/// Maps a refused storage function to 409 with `code` (Zig answered every refusal of these
/// routes so); queue, wait and database failures keep their own replies.
pub fn conflict_or(failure: StorageFailure, code: &'static str) -> RouteError {
    match failure {
        StorageFailure::Console(sibuna_console_storage::ConsoleStorageError::Storage(_)) => {
            RouteError::fail(503, "CONSOLEQUORUM")
        }
        StorageFailure::Console(_) => RouteError::fail(409, code),
        other => other.route_error(code),
    }
}

/// The reply of a sign-in or password change: the account, this node, the role, the
/// restrictions and the CSRF token. The session token travels only in the cookie.
struct SessionReply<'a> {
    user: u64,
    node: u32,
    role: Role,
    must_change: bool,
    totp_required: bool,
    csrf: &'a [u8; 32],
}

impl Encode for SessionReply<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        let mut csrf = sibuna_encoding::hex::encode(self.csrf);
        json.begin_object()?;
        counter_field(json, "user", self.user)?;
        field(json, "node", &self.node)?;
        field(json, "role", &self.role)?;
        field(json, "must_change", &self.must_change)?;
        field(json, "totp_required", &self.totp_required)?;
        let written = field(json, "csrf", csrf.as_str());
        wipe_string(&mut csrf);
        written?;
        json.end_object()
    }
}

/// Wipes and empties `text`.
pub fn wipe_string(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    ct::zeroize(&mut bytes);
}

fn send_session(
    shared: &Shared,
    context: &mut Context<'_>,
    reply: &SessionReply<'_>,
    raw: &[u8; 32],
    lifetime: u64,
) -> Result<(), RouteError> {
    let mut cookie = session_cookie(shared, raw, lifetime);
    let sent =
        send_secret(context, reply, &[Header { name: b"Set-Cookie", value: cookie.as_bytes() }]);
    wipe_string(&mut cookie);
    sent
}

fn logout(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let presented = call.presented.ok_or(RouteError::Unavailable)?;
    let input = auth::Logout { digest: presented.digest, client: client(call) };
    let now = call.now;
    let ended = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::end_session(tx, &input, now).await })
    })?;
    if !ended {
        return Err(RouteError::Unavailable);
    }
    let secure = if is_secure(shared) { "; Secure" } else { "" };
    let cookie = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0{secure}");
    let header = Header { name: b"Set-Cookie", value: cookie.as_bytes() };
    Ok(json_bytes(context, b"{\"signed_out\":true}", &[header])?)
}

/// The password change body.
struct Change {
    old_password: Secret,
    password: Secret,
}

impl Decode for Change {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Change, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let change = Change {
            old_password: fields.required("old_password")?,
            password: fields.required("password")?,
        };
        fields.finish()?;
        Ok(change)
    }
}

/// Changes the signed-in account's own password and rotates its session (S6).
fn password(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let principal = call.principal()?;
    let presented = call.presented.ok_or(RouteError::Unavailable)?;
    let mut buffer = [0u8; BODY];
    let input: Change = read_json(context, &mut buffer)?;
    if !allowed(shared, context, principal.username.as_str(), call.now) {
        return Err(RouteError::fail(429, "CONSOLE003"));
    }
    let unauthorized = RouteError::fail(401, "CONSOLE401");
    let user = account(shared, principal.username.as_str())?.ok_or(unauthorized)?;
    if !check_password(shared, input.old_password.as_bytes(), user.password_hash.as_str())? {
        return Err(unauthorized);
    }
    if ct::eq(input.old_password.as_bytes(), input.password.as_bytes()) {
        return Err(RouteError::BadRequest);
    }
    let password_hash = hash_password(shared, input.password.as_bytes())?;
    let issued = Issued::new()?;
    let change = auth::PasswordChange {
        expected_revision: user.revision,
        replacement_digest: issued.digest,
        replacement_csrf: issued.csrf_digest,
        session_digest: presented.digest,
        csrf_digest: principal.csrf_digest,
        password_hash,
        client: client(call),
    };
    let now = call.now;
    let changed = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::change_password(tx, &change, now).await })
    });
    changed.map_err(|failure| conflict_or(failure, "CONSOLE409"))?;
    let reply = SessionReply {
        user: user.id,
        node: shared.identity.node_id,
        role: user.role,
        must_change: false,
        totp_required: shared.needs_totp(user.role, user.totp_enabled),
        csrf: &issued.csrf,
    };
    send_session(shared, context, &reply, &issued.raw, SESSION_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn decimals_are_bounded_plain_digits() {
        assert_eq!(decimal("0", u64::MAX), Ok(0));
        assert_eq!(decimal("9223372036854775807", i64::MAX as u64), Ok(i64::MAX as u64));
        for invalid in ["", "-1", "+1", "1e3", " 1", "12345678901234567890", "0x10"] {
            assert_eq!(decimal(invalid, u64::MAX), Err(RouteError::BadRequest), "{invalid}");
        }
        assert_eq!(decimal("9223372036854775808", i64::MAX as u64), Err(RouteError::BadRequest));
    }

    #[test]
    fn credentials_decode_strictly() {
        let input: Credentials =
            from_json(br#"{"username":"admin","password":"secret","code":"123456"}"#).unwrap();
        assert_eq!((input.username.as_str(), input.code.as_bytes()), ("admin", &b"123456"[..]));
        let plain: Credentials = from_json(br#"{"username":"a","password":"b"}"#).unwrap();
        assert!(plain.code.is_empty());
        assert!(from_json::<Credentials>(br#"{"username":"a","password":"b","x":1}"#).is_err());
        assert!(from_json::<Credentials>(br#"{"username":"a"}"#).is_err());
        assert!(from_json::<Change>(br#"{"old_password":"a","password":"b"}"#).is_ok());
    }

    #[test]
    fn session_replies_carry_the_csrf_token_and_never_the_session() {
        let csrf = [0xab; 32];
        let reply = SessionReply {
            user: 1 << 53,
            node: 3,
            role: Role::Operator,
            must_change: true,
            totp_required: false,
            csrf: &csrf,
        };
        assert_eq!(
            sibuna_console_protocol::codec::to_json(&reply),
            format!(
                "{{\"user\":\"9007199254740992\",\"node\":3,\"role\":\"operator\",\
                 \"must_change\":true,\"totp_required\":false,\"csrf\":\"{}\"}}",
                "ab".repeat(32)
            )
        );
    }
}

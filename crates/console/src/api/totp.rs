//! The routes `totp`, `totp/enroll` and `totp/confirm` (unit U2, S5; Zig's
//! `totp_routes.zig`), and the second-factor check of a sign-in.
//!
//! Enrollment draws a 160-bit seed, seals it with the console key bound to the account
//! ([`crate::auth::secrets::seal`]) and shows it once as base32 and as an `otpauth://`
//! address. Confirmation checks a first code, draws ten recovery codes and stores only their
//! digests; enabling the factor revokes every session of the account (S5 through S2), so
//! the browser signs in again with both factors. Both steps need the account's password
//! again, counted by the sign-in limiter.
//!
//! Both factors are submitted with the password at sign-in: no password-only session or
//! partial grant exists for an enrolled account, so neither the world geometry nor a stream
//! can be reached in between.

use sibuna_console_protocol::codec::{Decode, DecodeError, Encode, Fields, Path, field};
use sibuna_console_protocol::{AuthUser, auth};
use sibuna_console_storage::accounts;
use sibuna_crypto::ct;
use sibuna_crypto::totp::{self, Seed};
use sibuna_http::Method;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::api::session::{
    Secret, account, allowed, check_password, client, conflict_or, send_secret, wipe_string,
};
use crate::auth::secrets::{self, Recovery};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::random;
use crate::routes::Handler;
use crate::shared::Shared;

/// The recovery codes a confirmation issues.
pub const RECOVERY_CODES: usize = 10;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    if call.route.handler != Handler::Totp {
        return Err(RouteError::Unavailable);
    }
    if context.method() == Method::Get {
        return status(shared, context, call);
    }
    let enrolling = call.route.path.ends_with("/enroll");
    let principal = call.principal()?;
    let presented = call.presented.ok_or(RouteError::Unavailable)?;
    if !allowed(shared, context, principal.username.as_str(), call.now) {
        return Err(RouteError::fail(429, "CONSOLE003"));
    }
    let mut buffer = [0u8; 2048];
    let input: Input = read_json(context, &mut buffer)?;
    let unauthorized = RouteError::fail(401, "CONSOLE401");
    let user = account(shared, principal.username.as_str())?.ok_or(unauthorized)?;
    if !check_password(shared, input.password.as_bytes(), user.password_hash.as_str())? {
        return Err(unauthorized);
    }
    let authorization = auth::Authorization {
        session_digest: presented.digest,
        csrf_digest: principal.csrf_digest,
        client: client(call),
    };
    if enrolling {
        enroll(shared, context, call, principal.actor, authorization, input.revision)
    } else {
        confirm(shared, context, call, principal.actor, authorization, &input)
    }
}

/// The enrollment and confirmation body.
struct Input {
    password: Secret,
    code: Secret,
    revision: u64,
}

impl Decode for Input {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Input, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let input = Input {
            password: fields.required("password")?,
            code: fields.or_default("code")?,
            revision: fields.or_default("revision")?,
        };
        fields.finish()?;
        Ok(input)
    }
}

/// `{"available":<key configured>,"enabled":<bool>,"revision":<factor revision>}`.
fn status(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let user = call.principal()?.actor;
    let stored = read(shared, user)?;
    let reply = Status {
        available: shared.keys.totp.is_some(),
        enabled: stored.as_ref().is_some_and(|totp| totp.enabled),
        revision: stored.as_ref().map_or(0, |totp| totp.revision),
    };
    Ok(reply::json(context, &reply)?)
}

struct Status {
    available: bool,
    enabled: bool,
    revision: u64,
}

impl Encode for Status {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "available", &self.available)?;
        field(json, "enabled", &self.enabled)?;
        field(json, "revision", &self.revision)?;
        json.end_object()
    }
}

/// Reads the second factor of `user`, or `None` when it has none.
fn read(shared: &Shared, user: u64) -> Result<Option<auth::Totp>, RouteError> {
    let found = shared
        .storage
        .transact(move |tx| Box::pin(async move { accounts::read_totp(tx, user).await }));
    Ok(found?)
}

/// Starts or replaces an unconfirmed enrollment and shows its seed once.
fn enroll(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    user: u64,
    authorization: auth::Authorization,
    revision: u64,
) -> Result<(), RouteError> {
    let key = shared.keys.totp.as_ref().ok_or(RouteError::fail(409, "CONSOLE2FAKEY"))?;
    let mut seed: Seed = random::array().map_err(|_| RouteError::Unavailable)?;
    let sealed = secrets::seal(&seed, key.bytes(), user);
    let encoded = totp::base32(&seed);
    ct::zeroize(&mut seed);
    let enrollment = auth::Enrollment {
        auth: authorization,
        expected_revision: revision,
        envelope: sealed.map_err(|_| RouteError::Unavailable)?,
        key_id: secrets::key_id(key.bytes()),
    };
    let now = call.now;
    let begun = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::begin_totp(tx, &enrollment, now).await })
    });
    begun.map_err(|failure| conflict_or(failure, "CONSOLE409"))?;
    // Base32 is ASCII, so the conversion cannot fail.
    let secret = std::str::from_utf8(&encoded).unwrap_or_default();
    let reply = Enrolled {
        secret,
        uri: format!(
            "otpauth://totp/Sibuna:{user}?secret={secret}&issuer=Sibuna&algorithm=SHA1&digits=6\
             &period=30"
        ),
        revision: revision.saturating_add(1),
    };
    let sent = send_secret(context, &reply, &[]);
    let Enrolled { mut uri, .. } = reply;
    wipe_string(&mut uri);
    let mut encoded = encoded;
    ct::zeroize(&mut encoded);
    sent
}

struct Enrolled<'a> {
    secret: &'a str,
    uri: String,
    revision: u64,
}

impl Encode for Enrolled<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "secret", self.secret)?;
        field(json, "uri", self.uri.as_str())?;
        field(json, "revision", &self.revision)?;
        json.end_object()
    }
}

/// Confirms the enrollment with a first code and issues the recovery codes.
fn confirm(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    user: u64,
    authorization: auth::Authorization,
    input: &Input,
) -> Result<(), RouteError> {
    let conflict = RouteError::fail(409, "CONSOLE409");
    let stored = read(shared, user)?.ok_or(conflict)?;
    if stored.enabled || stored.revision != input.revision {
        return Err(conflict);
    }
    let mut seed = decrypt(shared, &stored).ok_or(RouteError::Unavailable)?;
    let step = totp::verify(&seed, input.code.as_bytes(), call.now, None);
    ct::zeroize(&mut seed);
    let step = step.map_err(|_| RouteError::fail(401, "CONSOLE401"))?;
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut recovery_digests = [[0u8; 32]; RECOVERY_CODES];
    for digest in &mut recovery_digests {
        let mut raw: Recovery = random::array().map_err(|_| RouteError::Unavailable)?;
        *digest = secrets::recovery_digest(user, &raw);
        codes.push(sibuna_encoding::hex::encode(&raw));
        ct::zeroize(&mut raw);
    }
    let confirmation = auth::Confirmation {
        auth: authorization,
        expected_revision: input.revision,
        step,
        recovery_digests,
    };
    let now = call.now;
    let enabled = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::enable_totp(tx, &confirmation, now).await })
    });
    let reply = Confirmed { recovery_codes: codes };
    let sent = match enabled {
        Ok(()) => send_secret(context, &reply, &[]),
        Err(failure) => Err(conflict_or(failure, "CONSOLE409")),
    };
    for code in reply.recovery_codes {
        let mut code = code;
        wipe_string(&mut code);
    }
    sent
}

struct Confirmed {
    recovery_codes: Vec<String>,
}

impl Encode for Confirmed {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "recovery_codes", &self.recovery_codes)?;
        field(json, "sign_in_required", &true)?;
        json.end_object()
    }
}

/// Opens the stored seed with the console key; the caller wipes it. Returns `None` without
/// a console key, for a seed sealed with another key, or for an envelope that does not open.
fn decrypt(shared: &Shared, record: &auth::Totp) -> Option<Seed> {
    let key = shared.keys.totp.as_ref()?;
    if !ct::eq(&secrets::key_id(key.bytes()), &record.key_id) {
        return None;
    }
    secrets::open(&record.envelope, key.bytes(), record.user).ok()
}

/// Returns the factor a sign-in of `user` consumes with `code`: none without an enrolled
/// factor; a recovery slot for 32 hexadecimal digits that match an unused recovery code;
/// otherwise the TOTP step `code` matches after the last consumed one. Returns `None` for
/// any failure, which the sign-in refuses like a wrong password (Zig's `factor`).
pub fn factor(shared: &Shared, user: &AuthUser, code: &[u8], now: u64) -> Option<auth::Factor> {
    if !user.totp_enabled {
        return Some(auth::Factor::None);
    }
    let record = read(shared, user.id).ok().flatten().filter(|record| record.enabled)?;
    if code.len() == 32 {
        let mut raw = secrets::parse_recovery(code)?;
        let digest = secrets::recovery_digest(user.id, &raw);
        ct::zeroize(&mut raw);
        let mut matched = None;
        for (slot, candidate) in (0u8..).zip(&record.recovery_digests) {
            let used = record.recovery_used & (1 << slot) != 0;
            if ct::eq(candidate, &digest) && !used {
                matched = Some(slot);
            }
        }
        let slot = matched?;
        return Some(auth::Factor::Recovery { revision: record.revision, slot, digest });
    }
    let mut seed = decrypt(shared, &record)?;
    let step = totp::verify(&seed, code, now, record.last_step);
    ct::zeroize(&mut seed);
    Some(auth::Factor::Totp { revision: record.revision, step: step.ok()? })
}

//! The routes `kiosk/token` and `kiosk/exchange` (unit U2, S10 and S11; Zig's
//! `kiosk_routes.zig`).
//!
//! An operator mints a one-time code, shown once; a wall display pastes it into the sign-in
//! form and receives a read-only cookie session limited to statistics. No code or session
//! ever appears in a URL. The exchange is rate limited like a sign-in, per address, with
//! buckets of its own: a display that guesses codes is throttled without locking operators
//! out of signing in.

use sibuna_console_protocol::codec::{Decode, DecodeError, Encode, Fields, Path, field};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::{Text, kiosk};
use sibuna_console_storage::kiosk as stored;
use sibuna_crypto::ct;
use sibuna_crypto::sha256::Sha256;
use sibuna_http::Header;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::api::session::{
    Issued, Secret, address_key, client, send_secret, session_cookie, wipe_string,
};
use crate::dispatch::Call;
use crate::http::RouteError;
use crate::http::body::read_json;
use crate::random;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The largest body of these routes.
const BODY: usize = 512;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::KioskToken => grant(shared, context, call),
        Handler::KioskExchange => exchange(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// The grant body: `{"label":"<display>"}`, the label optional.
struct Grant {
    label: String,
}

impl Decode for Grant {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Grant, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let grant = Grant { label: fields.or_default("label")? };
        fields.finish()?;
        Ok(grant)
    }
}

/// Mints a code for the signed-in operator (S10) and shows it once.
fn grant(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Grant = read_json(context, &mut buffer)?;
    let label = Text::new(&input.label).map_err(|_| RouteError::fail(400, "CONSOLEKIOSK"))?;
    let mut raw: [u8; 32] = random::array().map_err(|_| RouteError::Unavailable)?;
    let grant =
        kiosk::Grant { auth: call.auth(shared)?, code_digest: Sha256::digest(&raw), label };
    let mut code = sibuna_encoding::hex::encode(&raw);
    ct::zeroize(&mut raw);
    let credential = call.credential(shared)?;
    let now = call.now;
    let granted = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::grant_kiosk(tx, &credential, &grant, now).await })
    });
    let sent = match granted {
        Ok(granted) => send_secret(context, &Granted { code: &code, granted }, &[]),
        Err(failure) => Err(grant_failure(failure)),
    };
    wipe_string(&mut code);
    sent
}

/// The replies of Zig's grant refusals.
fn grant_failure(failure: StorageFailure) -> RouteError {
    let StorageFailure::Console(error) = &failure else {
        return failure.route_error("CONSOLEKIOSK");
    };
    let status = match error.failure() {
        Failure::Unauthorized => 401,
        Failure::Forbidden => 403,
        Failure::Capacity => 503,
        _ => 409,
    };
    RouteError::fail(status, "CONSOLEKIOSK")
}

/// `{"code":"<hex>","use_by":<seconds>,"expires":<seconds>}`.
struct Granted<'a> {
    code: &'a str,
    granted: kiosk::Granted,
}

impl Encode for Granted<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "code", self.code)?;
        field(json, "use_by", &self.granted.use_by)?;
        field(json, "expires", &self.granted.expires)?;
        json.end_object()
    }
}

/// The exchange body: `{"code":"<64 hex digits>"}`.
struct Exchange {
    code: Secret,
}

impl Decode for Exchange {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Exchange, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let exchange = Exchange { code: fields.required("code")? };
        fields.finish()?;
        Ok(exchange)
    }
}

/// Exchanges a code for a kiosk session (S11) and answers with its cookie.
fn exchange(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let key = address_key(b"sibuna-console-kiosk-address-v1", context);
    if !shared.login_limiter.allow(&key, call.now) {
        return Err(RouteError::fail(429, "CONSOLE429"));
    }
    let mut buffer = [0u8; BODY];
    let input: Exchange = read_json(context, &mut buffer)?;
    let unauthorized = RouteError::fail(401, "CONSOLE401");
    let mut code = [0u8; 32];
    let decoded = sibuna_encoding::hex::decode_to_slice(input.code.as_bytes(), &mut code);
    if input.code.len() != 64 || decoded.is_err() {
        ct::zeroize(&mut code);
        return Err(unauthorized);
    }
    let issued = Issued::new()?;
    let exchange = kiosk::Exchange {
        code_digest: Sha256::digest(&code),
        session_digest: issued.digest,
        csrf_digest: issued.csrf_digest,
        client: client(call),
    };
    ct::zeroize(&mut code);
    let now = call.now;
    let opened = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::exchange_kiosk(tx, &exchange, now).await })
    });
    let session = opened.map_err(|failure| match failure {
        StorageFailure::Console(sibuna_console_storage::ConsoleStorageError::Storage(_)) => {
            RouteError::fail(503, "CONSOLEQUORUM")
        }
        StorageFailure::Console(_) => unauthorized,
        other => other.route_error("CONSOLE401"),
    })?;
    let mut cookie = session_cookie(shared, &issued.raw, session.expires.saturating_sub(now));
    let reply = Opened { expires: session.expires, csrf: &issued.csrf };
    let sent =
        send_secret(context, &reply, &[Header { name: b"Set-Cookie", value: cookie.as_bytes() }]);
    wipe_string(&mut cookie);
    sent
}

/// `{"kiosk":true,"role":"viewer","expires":<seconds>,"csrf":"<hex>"}`.
struct Opened<'a> {
    expires: u64,
    csrf: &'a [u8; 32],
}

impl Encode for Opened<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        let mut csrf = sibuna_encoding::hex::encode(self.csrf);
        json.begin_object()?;
        field(json, "kiosk", &true)?;
        field(json, "role", "viewer")?;
        field(json, "expires", &self.expires)?;
        let written = field(json, "csrf", csrf.as_str());
        wipe_string(&mut csrf);
        written?;
        json.end_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::{from_json, to_json};

    #[test]
    fn kiosk_replies_match_zig() {
        let granted =
            Granted { code: "ab", granted: kiosk::Granted { use_by: 600, expires: 900 } };
        assert_eq!(to_json(&granted), "{\"code\":\"ab\",\"use_by\":600,\"expires\":900}");
        let opened = Opened { expires: 7, csrf: &[1; 32] };
        assert_eq!(
            to_json(&opened),
            format!(
                "{{\"kiosk\":true,\"role\":\"viewer\",\"expires\":7,\"csrf\":\"{}\"}}",
                "01".repeat(32)
            )
        );
        assert!(from_json::<Grant>(b"{}").is_ok());
        assert!(from_json::<Exchange>(b"{}").is_err());
    }
}

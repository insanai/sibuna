//! The routes `tokens/query`, `tokens/create` and `tokens/revoke` (unit U2, S7 to S9; Zig's
//! `token_routes.zig`).
//!
//! A token value exists only in the creating handler and its reply: 256 random bits shown
//! once as 64 hexadecimal digits. Storage receives its SHA-256 digest; the catalog and the
//! revocation replies never carry a credential. Only an administrator's browser session
//! manages tokens (the routes take no token scope, and storage checks the session kind).

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, counter_field, field, optional_counter_field,
};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::tokens::{self, decode_scopes};
use sibuna_console_protocol::{Role, Text};
use sibuna_console_storage::tokens as stored;
use sibuna_crypto::ct;
use sibuna_crypto::sha256::Sha256;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::api::session::{decimal, send_secret, wipe_string};
use crate::api::users::spend;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::random;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The largest body of these routes.
const BODY: usize = 2048;
/// The largest id, revision or expiry a request may name.
const MAX: u64 = i64::MAX as u64;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::TokensQuery => query(shared, context, call),
        Handler::TokensCreate => create(shared, context, call),
        Handler::TokensRevoke => revoke(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// The page query body: `{"after":"<id>"|null,"limit":1..8}`.
struct Query {
    after: Option<String>,
    limit: u8,
}

impl Decode for Query {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Query, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let query = Query {
            after: fields.or_default("after")?,
            limit: fields.or("limit", tokens::PAGE_ROWS as u8)?,
        };
        fields.finish()?;
        Ok(query)
    }
}

fn query(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query)?;
    let mut buffer = [0u8; BODY];
    let input: Query = read_json(context, &mut buffer)?;
    let after = input.after.as_deref().map(|text| decimal(text, MAX)).transpose()?;
    let query =
        tokens::Query { auth: call.auth(shared)?, after: after.unwrap_or(0), limit: input.limit };
    let credential = call.credential(shared)?;
    let now = call.now;
    let page = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::query_tokens(tx, &credential, &query, now).await })
    });
    Ok(reply::json(context, &page.map_err(fail)?)?)
}

/// The creation body: a label, a role, distinct scope names, and an optional expiry as a
/// decimal string.
struct Create {
    label: String,
    role: Role,
    scopes: u32,
    expires: Option<String>,
}

impl Decode for Create {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Create, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let create = Create {
            label: fields.required("label")?,
            role: fields.or_default("role")?,
            scopes: fields.required_with("scopes", decode_scopes)?,
            expires: fields.or_default("expires")?,
        };
        fields.finish()?;
        Ok(create)
    }
}

fn create(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Create = read_json(context, &mut buffer)?;
    if !tokens::valid_label(&input.label) || !tokens::valid_scopes(input.scopes, input.role) {
        return Err(RouteError::BadRequest);
    }
    let expires = input.expires.as_deref().map(|text| decimal(text, MAX)).transpose()?;
    let mut raw: [u8; 32] = random::array().map_err(|_| RouteError::Unavailable)?;
    let digest = Sha256::digest(&raw);
    let mut token = sibuna_encoding::hex::encode(&raw);
    ct::zeroize(&mut raw);
    let create = tokens::Create {
        auth: Default::default(),
        label: Text::new(&input.label).map_err(|_| RouteError::BadRequest)?,
        role: input.role,
        scopes: input.scopes,
        expires,
        digest,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let created = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::create_token(tx, &credential, &create, now).await })
    });
    let sent = match created {
        Ok(id) => send_secret(context, &Created { id, token: &token, expires }, &[]),
        Err(failure) => Err(fail(failure)),
    };
    wipe_string(&mut token);
    sent
}

/// `{"saved":true,"id":<id>,"token":"<hex>","expires":<seconds>|null}`.
struct Created<'a> {
    id: u64,
    token: &'a str,
    expires: Option<u64>,
}

impl Encode for Created<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "saved", &true)?;
        counter_field(json, "id", self.id)?;
        field(json, "token", self.token)?;
        optional_counter_field(json, "expires", self.expires)?;
        json.end_object()
    }
}

/// The revocation body: target and expected revision as decimal strings; `remove` deletes
/// an inactive token instead of disabling it.
struct Revoke {
    target: String,
    expected_revision: String,
    remove: bool,
}

impl Decode for Revoke {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Revoke, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let revoke = Revoke {
            target: fields.required("target")?,
            expected_revision: fields.required("expected_revision")?,
            remove: fields.or_default("remove")?,
        };
        fields.finish()?;
        Ok(revoke)
    }
}

fn revoke(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Revoke = read_json(context, &mut buffer)?;
    let revoke = tokens::Revoke {
        auth: Default::default(),
        target: decimal(&input.target, MAX)?,
        expected_revision: decimal(&input.expected_revision, MAX)?,
        remove: input.remove,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let saved = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::revoke(tx, &credential, &revoke, now).await })
    });
    let id = saved.map_err(fail)?;
    Ok(reply::json(context, &Saved { id })?)
}

/// `{"saved":true,"id":<id>}`.
struct Saved {
    id: u64,
}

impl Encode for Saved {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "saved", &true)?;
        counter_field(json, "id", self.id)?;
        json.end_object()
    }
}

/// The replies of Zig's `token_routes.fail`.
fn fail(failure: StorageFailure) -> RouteError {
    let StorageFailure::Console(error) = &failure else {
        return failure.route_error("CONSOLETOKENS");
    };
    match error.failure() {
        Failure::Unauthorized => RouteError::fail(401, "CONSOLE401"),
        Failure::Forbidden => RouteError::fail(403, "CONSOLETOKEN403"),
        Failure::Conflict => RouteError::fail(409, "CONSOLETOKEN409"),
        Failure::Capacity => RouteError::fail(409, "CONSOLETOKENFULL"),
        Failure::InvalidInput => RouteError::fail(400, "CONSOLETOKENS"),
        _ => RouteError::fail(503, "CONSOLETOKENS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::{from_json, to_json};

    #[test]
    fn creations_name_distinct_known_scopes() {
        let input: Create = from_json(
            br#"{"label":"deploy","role":"operator","scopes":["policy_read","policy_write"],
                "expires":"9007199254740993"}"#,
        )
        .unwrap();
        let bits = tokens::Scope::PolicyRead.bit() | tokens::Scope::PolicyWrite.bit();
        assert_eq!((input.scopes, input.expires.as_deref()), (bits, Some("9007199254740993")));
        for invalid in [
            br#"{"label":"a","scopes":["stats_read","stats_read"]}"#.as_slice(),
            br#"{"label":"a","scopes":["unknown"]}"#,
            br#"{"label":"a"}"#,
            br#"{"label":"a","scopes":[],"digest":"x"}"#,
        ] {
            assert!(from_json::<Create>(invalid).is_err());
        }
    }

    #[test]
    fn replies_never_carry_more_than_the_new_token() {
        let created = Created { id: 1 << 53, token: "ab", expires: None };
        assert_eq!(
            to_json(&created),
            "{\"saved\":true,\"id\":\"9007199254740992\",\"token\":\"ab\",\"expires\":null}"
        );
        assert_eq!(to_json(&Saved { id: 2 }), "{\"saved\":true,\"id\":2}");
    }
}

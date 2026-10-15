//! The routes `users/query`, `users/create` and `users/change` (unit U2, S1 and S2; Zig's
//! `user_routes.zig`).
//!
//! The server mints every password an administrator hands out: 32 random bytes as 64
//! hexadecimal digits, hashed here and shown once in the reply, valid for an hour and to be
//! changed at the first sign-in. Storage never sees a password, only its PHC string. Ids
//! and revisions travel as decimal strings, because JavaScript loses precision above 2^53.

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, decimal_string, field, optional_str,
};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::{Role, Text, users, valid_username};
use sibuna_console_storage::accounts::{self, UserSaved};
use sibuna_crypto::ct;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::api::session::{decimal, hash_password, send_secret, wipe_string};
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

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::UsersQuery => query(shared, context, call),
        Handler::UsersCreate => create(shared, context, call),
        Handler::UsersChange => change(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Spends one read of the credential's query allowance (429 `CONSOLEQUERY` when spent).
///
/// Fails with [`RouteError::Unavailable`] on a public route.
pub fn spend(shared: &Shared, call: &Call, spend: Spend) -> Result<(), RouteError> {
    let presented = call.presented.ok_or(RouteError::Unavailable)?;
    if !shared.query_budget.allow(&presented.digest, call.now, spend) {
        return Err(RouteError::fail(429, "CONSOLEQUERY"));
    }
    Ok(())
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
            limit: fields.or("limit", users::PAGE_ROWS as u8)?,
        };
        fields.finish()?;
        Ok(query)
    }
}

fn query(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query)?;
    let mut buffer = [0u8; BODY];
    let input: Query = read_json(context, &mut buffer)?;
    let after = input.after.as_deref().map(|text| decimal(text, u64::MAX)).transpose()?;
    let query =
        users::Query { auth: call.auth(shared)?, after: after.unwrap_or(0), limit: input.limit };
    let credential = call.credential(shared)?;
    let now = call.now;
    let page = shared.storage.transact(move |tx| {
        Box::pin(async move { accounts::query_users(tx, &credential, &query, now).await })
    });
    let page = page.map_err(fail)?;
    Ok(reply::json(context, &page)?)
}

/// The creation body: `{"username":"<name>","role":"viewer"|"operator"|"admin"}`.
struct Create {
    username: String,
    role: Role,
}

impl Decode for Create {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Create, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let create =
            Create { username: fields.required("username")?, role: fields.or_default("role")? };
        fields.finish()?;
        Ok(create)
    }
}

fn create(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Create = read_json(context, &mut buffer)?;
    if !valid_username(&input.username) {
        return Err(RouteError::BadRequest);
    }
    let username = Text::new(&input.username).map_err(|_| RouteError::BadRequest)?;
    let mut password = mint_password()?;
    let hashed = hash_password(shared, password.as_bytes());
    let request = hashed.map(|password_hash| users::Create {
        auth: Default::default(),
        username,
        role: input.role,
        password_hash,
    });
    submit(shared, context, call, request.map(Operation::Create), &mut password)
}

/// The change body: target and expected revision as decimal strings, the operation, and
/// for `access` both the role and the disabled flag.
struct Change {
    target: String,
    expected_revision: String,
    operation: String,
    role: Option<Role>,
    disabled: Option<bool>,
}

impl Decode for Change {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Change, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let change = Change {
            target: fields.required("target")?,
            expected_revision: fields.required("expected_revision")?,
            operation: fields.required("operation")?,
            role: fields.or_default("role")?,
            disabled: fields.or_default("disabled")?,
        };
        fields.finish()?;
        Ok(change)
    }
}

/// Builds the protocol change from the body (Zig's `change`); an operation other than
/// `access` must not carry a role or disabled flag.
fn operation(input: &Change) -> Result<users::Operation, RouteError> {
    let extra = input.role.is_some() || input.disabled.is_some();
    match input.operation.as_str() {
        "access" => match (input.role, input.disabled) {
            (Some(role), Some(disabled)) => Ok(users::Operation::Access { role, disabled }),
            _ => Err(RouteError::BadRequest),
        },
        "password" if !extra => Ok(users::Operation::Password(Text::default())),
        "revoke" if !extra => Ok(users::Operation::Revoke),
        _ => Err(RouteError::BadRequest),
    }
}

fn change(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Change = read_json(context, &mut buffer)?;
    let mut change = users::Change {
        auth: Default::default(),
        target: decimal(&input.target, u64::MAX)?,
        expected_revision: decimal(&input.expected_revision, u64::MAX)?,
        operation: operation(&input)?,
    };
    let mut password = String::new();
    if matches!(change.operation, users::Operation::Password(_)) {
        password = mint_password()?;
        match hash_password(shared, password.as_bytes()) {
            Ok(hash) => change.operation = users::Operation::Password(hash),
            Err(error) => {
                wipe_string(&mut password);
                return Err(error);
            }
        }
    }
    submit(shared, context, call, Ok(Operation::Change(change)), &mut password)
}

/// Returns a fresh temporary password: 32 random bytes as 64 hexadecimal digits.
///
/// Fails with [`RouteError::Unavailable`] when no random bytes can be read.
fn mint_password() -> Result<String, RouteError> {
    let mut raw: [u8; 32] = random::array().map_err(|_| RouteError::Unavailable)?;
    let password = sibuna_encoding::hex::encode(&raw);
    ct::zeroize(&mut raw);
    Ok(password)
}

enum Operation {
    Create(users::Create),
    Change(users::Change),
}

/// Runs the creation or change and answers with the minted password, if any; `password`
/// is empty when none was minted and is wiped before returning.
fn submit(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    operation: Result<Operation, RouteError>,
    password: &mut String,
) -> Result<(), RouteError> {
    let result = operation.and_then(|operation| save(shared, call, operation));
    let sent = result.and_then(|saved| {
        let reply = Saved {
            temporary_password: (!password.is_empty()).then_some(password.as_str()),
            password_expires: saved.password_expires_at.unwrap_or(0),
        };
        send_secret(context, &reply, &[])
    });
    wipe_string(password);
    sent
}

fn save(shared: &Shared, call: &Call, operation: Operation) -> Result<UserSaved, RouteError> {
    let credential = call.credential(shared)?;
    let now = call.now;
    let saved = match operation {
        Operation::Create(input) => shared.storage.transact(move |tx| {
            Box::pin(async move { accounts::create_user(tx, &credential, &input, now).await })
        }),
        Operation::Change(input) => shared.storage.transact(move |tx| {
            Box::pin(async move { accounts::change_user(tx, &credential, &input, now).await })
        }),
    };
    saved.map_err(fail)
}

/// `{"saved":true,"temporary_password":"<hex>"|null,"password_expires":"<seconds>"}`.
struct Saved<'a> {
    temporary_password: Option<&'a str>,
    password_expires: u64,
}

impl Encode for Saved<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "saved", &true)?;
        json.key("temporary_password")?;
        optional_str(json, self.temporary_password)?;
        json.key("password_expires")?;
        decimal_string(json, self.password_expires)?;
        json.end_object()
    }
}

/// The replies of Zig's `user_routes.fail`.
fn fail(failure: StorageFailure) -> RouteError {
    let StorageFailure::Console(error) = &failure else {
        return failure.route_error("CONSOLEUSERS");
    };
    match error.failure() {
        Failure::Unauthorized => RouteError::fail(401, "CONSOLE401"),
        Failure::Forbidden => RouteError::fail(403, "CONSOLEUSER403"),
        Failure::Conflict => RouteError::fail(409, "CONSOLEUSER409"),
        Failure::Capacity => RouteError::fail(409, "CONSOLEUSERFULL"),
        Failure::InvalidInput => RouteError::fail(400, "CONSOLEUSERS"),
        _ => RouteError::fail(503, "CONSOLEUSERS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::{from_json, to_json};

    fn change(text: &str) -> Result<users::Operation, RouteError> {
        operation(&from_json::<Change>(text.as_bytes()).map_err(|_| RouteError::BadRequest)?)
    }

    #[test]
    fn changes_name_exactly_one_operation() {
        let access = r#"{"target":"2","expected_revision":"1","operation":"access",
            "role":"viewer","disabled":true}"#;
        assert_eq!(
            change(access),
            Ok(users::Operation::Access { role: Role::Viewer, disabled: true })
        );
        let revoke = r#"{"target":"2","expected_revision":"1","operation":"revoke",
            "role":null,"disabled":null}"#;
        assert_eq!(change(revoke), Ok(users::Operation::Revoke));
        for invalid in [
            r#"{"target":"2","expected_revision":"1","operation":"access","role":"viewer"}"#,
            r#"{"target":"2","expected_revision":"1","operation":"revoke","disabled":false}"#,
            r#"{"target":"2","expected_revision":"1","operation":"delete"}"#,
            r#"{"target":"2","expected_revision":"1","operation":"revoke","extra":1}"#,
        ] {
            assert_eq!(change(invalid), Err(RouteError::BadRequest), "{invalid}");
        }
    }

    #[test]
    fn saved_replies_match_zig() {
        let none = Saved { temporary_password: None, password_expires: 0 };
        assert_eq!(
            to_json(&none),
            "{\"saved\":true,\"temporary_password\":null,\"password_expires\":\"0\"}"
        );
        let minted = Saved { temporary_password: Some("ab"), password_expires: 7 };
        assert!(to_json(&minted).contains("\"temporary_password\":\"ab\""));
        assert!(from_json::<Query>(br#"{"limit":9}"#).is_ok());
        assert!(from_json::<Query>(br#"{"after":null}"#).is_ok());
        assert!(from_json::<Query>(br#"{"unknown":true}"#).is_err());
    }
}

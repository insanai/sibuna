//! The routes `audit/query`, `audit/read` and `audit/export` (unit U2, S39; Zig's
//! `audit_routes.zig`): the audit page, one record with its redacted summaries, and the
//! export of a page, which storage audits in the same transaction before the rows leave it.
//!
//! Every account may read the audit trail with its browser session and CSRF token; tokens
//! and kiosk sessions may not. Reads spend the credential's query allowance and exports its
//! export allowance (429 `CONSOLEQUERY`).

use sibuna_console_protocol::Text;
use sibuna_console_protocol::audit::{self, LAST_ID};
use sibuna_console_protocol::codec::{Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_storage::audit as stored;
use sibuna_json::Value;
use sibuna_serve::Context;

use crate::api::session::decimal;
use crate::api::users::spend;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The largest body of these routes.
const BODY: usize = 1024;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let export = call.route.handler == Handler::AuditExport;
    spend(shared, call, if export { Spend::Export } else { Spend::Query })?;
    match call.route.handler {
        Handler::AuditRead => read(shared, context, call),
        Handler::AuditQuery | Handler::AuditExport => query(shared, context, call, export),
        _ => Err(RouteError::Unavailable),
    }
}

/// The read body: `{"id":"<id>"}`.
struct Read {
    id: String,
}

impl Decode for Read {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Read, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let read = Read { id: fields.required("id")? };
        fields.finish()?;
        Ok(read)
    }
}

fn read(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Read = read_json(context, &mut buffer)?;
    let read = audit::Read { auth: call.auth(shared)?, id: decimal(&input.id, LAST_ID)? };
    let credential = call.credential(shared)?;
    let now = call.now;
    let detail = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::read_audit(tx, &credential, &read, now).await })
    });
    Ok(reply::json(context, &detail.map_err(fail)?)?)
}

/// The page body: every member optional; numbers are decimal strings.
struct Query {
    before: Option<String>,
    actor: Option<String>,
    action: String,
    since: Option<String>,
    until: Option<String>,
}

impl Decode for Query {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Query, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let query = Query {
            before: fields.or_default("before")?,
            actor: fields.or_default("actor")?,
            action: fields.or_default("action")?,
            since: fields.or_default("since")?,
            until: fields.or_default("until")?,
        };
        fields.finish()?;
        Ok(query)
    }
}

fn query(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    export_page: bool,
) -> Result<(), RouteError> {
    let mut buffer = [0u8; BODY];
    let input: Query = read_json(context, &mut buffer)?;
    let number = |text: &Option<String>| text.as_deref().map(|text| decimal(text, LAST_ID));
    let query = audit::Query {
        auth: call.auth(shared)?,
        before: number(&input.before).transpose()?.unwrap_or(LAST_ID),
        actor: number(&input.actor).transpose()?,
        action: Text::new(&input.action).map_err(|_| RouteError::BadRequest)?,
        since: number(&input.since).transpose()?.unwrap_or(0),
        until: number(&input.until).transpose()?.unwrap_or(LAST_ID),
        export_page,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let page = shared.storage.transact(move |tx| {
        Box::pin(async move { stored::query_audit(tx, &credential, &query, now).await })
    });
    Ok(reply::json(context, &page.map_err(fail)?)?)
}

/// The replies of Zig's `audit_routes.fail`: a missing record is 404 `CONSOLEAUDIT404`.
fn fail(failure: StorageFailure) -> RouteError {
    let StorageFailure::Console(error) = &failure else {
        return failure.route_error("CONSOLEAUDIT");
    };
    match error.failure() {
        Failure::Unauthorized => RouteError::fail(401, "CONSOLEAUDIT"),
        Failure::Forbidden => RouteError::fail(403, "CONSOLEAUDIT"),
        Failure::Conflict => RouteError::fail(404, "CONSOLEAUDIT404"),
        Failure::InvalidInput => RouteError::fail(400, "CONSOLEAUDIT"),
        _ => RouteError::fail(503, "CONSOLEAUDIT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn audit_bodies_decode_strictly() {
        let query: Query =
            from_json(br#"{"before":"9","actor":null,"action":"user.create"}"#).unwrap();
        assert_eq!((query.before.as_deref(), query.actor), (Some("9"), None));
        assert!(from_json::<Query>(br#"{"limit":1}"#).is_err());
        assert!(from_json::<Read>(br#"{}"#).is_err());
        assert_eq!(decimal("9223372036854775808", LAST_ID), Err(RouteError::BadRequest));
    }
}

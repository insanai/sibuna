//! The routes `security/query` and `security/trends` (Zig's `security_routes.zig`).
//!
//! Both read the security findings of a window, ranked by module, category or path, under
//! the work bound. `security/trends` is the kiosk-safe aggregate: storage leaves out every
//! piece of evidence (`aggregate_only`), which the route chooses, never the body.

use sibuna_console_protocol::security::{Query, Request};
use sibuna_console_storage::security::query_security;
use sibuna_serve::Context;

use super::events::read_error;
use super::policies::{spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with: 429 `CONSOLEQUERY` past the query
/// allowance, and `CONSOLESECURITY` for refused or unanswered reads (503 when the window is
/// too wide for the work bound).
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let aggregate_only = match call.route.handler {
        Handler::SecurityQuery => false,
        Handler::SecurityTrends => true,
        _ => return Err(RouteError::Unavailable),
    };
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = [0u8; 256];
    let request: Request = read_json(context, &mut body)?;
    let input = Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        request,
        aggregate_only,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let page = shared
        .storage
        .transact(move |tx| {
            Box::pin(
                async move { query_security(tx, &credential, &input, work_bound(), now).await },
            )
        })
        .map_err(|failure| read_error(failure, "CONSOLESECURITY"))?;
    Ok(reply::json(context, &page)?)
}

//! The routes `minutes` and `minutes/summary` (Zig's `minute_routes.zig`).
//!
//! `minutes` pages through the retained traffic minutes of a window, newest first;
//! `minutes/summary` sums one bounded part of a window under the work bound, ending at the
//! last sealed minute by default. A window without bounds is the last hour.

use sibuna_console_protocol::minutes::{Query, Reply, Request};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_storage::observations::{query_minutes, summarize_minutes};
use sibuna_serve::Context;

use super::policies::{spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The failure body of a history read storage could not serve, with its own hint.
const UNAVAILABLE: &[u8] = b"{\"error\":\"MINUTES001\",\"hint\":\"Minute history unavailable. \
    Retry after storage recovers.\"}";

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with 429 `CONSOLE429` past the query allowance, 401 `CONSOLE401`, 403
/// `CONSOLE403` or 400 `CONSOLE400` for refusals; a read storage cannot serve answers 503
/// `MINUTES001`.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let summarized = match call.route.handler {
        Handler::Minutes => false,
        Handler::MinuteSummary => true,
        _ => return Err(RouteError::Unavailable),
    };
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 1024];
    let request: Request = read_json(context, &mut body)?;
    let now = call.now;
    // A summary ends at the last sealed minute; a page includes the current one.
    let until = request.until_minute.unwrap_or((now / 60).saturating_sub(u64::from(summarized)));
    let query = Query {
        session_digest: [0; 32],
        observed_at: now,
        require_totp: shared.config.behind_proxy,
        from_minute: request.from_minute.unwrap_or(until.saturating_sub(60)),
        until_minute: until,
        node: request.node,
        before: request.before,
        limit: request.limit,
    };
    let credential = call.credential(shared)?;
    let bound = work_bound(shared);
    if summarized {
        let part = shared.storage.transact(move |tx| {
            Box::pin(async move { summarize_minutes(tx, &credential, &query, bound, now).await })
        });
        return match part {
            Ok(part) => Ok(reply::json(context, &part)?),
            Err(failure) => unavailable(context, failure),
        };
    }
    let page = shared.storage.transact(move |tx| {
        Box::pin(async move { query_minutes(tx, &credential, &query, now).await })
    });
    let page = match page {
        Ok(page) => page,
        Err(failure) => return unavailable(context, failure),
    };
    let retained = (now / 60).saturating_sub(u64::from(page.retention_days) * 1440);
    let reply = Reply {
        version: 1,
        retention_days: page.retention_days,
        from_minute: until.min(query.from_minute.max(retained)),
        until_minute: until,
        observed_at: now,
        rows: page.rows,
        next: page.next,
    };
    Ok(reply::json(context, &reply)?)
}

/// Answers a failed read as Zig did: refusals with the generic codes, everything else 503
/// `MINUTES001`.
fn unavailable(context: &mut Context<'_>, failure: StorageFailure) -> Result<(), RouteError> {
    let code = match failure.failure() {
        Failure::Unauthorized => "CONSOLE401",
        Failure::Forbidden => "CONSOLE403",
        Failure::InvalidInput => "CONSOLE400",
        _ => {
            if matches!(failure, StorageFailure::Busy | StorageFailure::Deferred) {
                return Err(RouteError::StorageBusy);
            }
            return Ok(context.respond(503, reply::JSON, UNAVAILABLE, &[])?);
        }
    };
    Err(failure.route_error(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unavailable_body_is_json() {
        let parsed = sibuna_json::parse(UNAVAILABLE).unwrap();
        let error = parsed.as_object().and_then(|object| object.get("error"));
        assert_eq!(error.and_then(|value| value.as_str()), Some("MINUTES001"));
    }
}

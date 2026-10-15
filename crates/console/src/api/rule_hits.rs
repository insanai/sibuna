//! The route `policies/hits` (Zig's `rule_hit_history_routes.zig`): one bounded part of a
//! rule's retained hit history on one node, read under the work bound.
//!
//! Full policy authorization precedes the read and storage checks it again.

use sibuna_console_protocol::rule_hit_history::{self, Query, Request};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_storage::rule_hits::read_history;
use sibuna_serve::Context;

use super::policies::{spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The failure body of a history read storage could not serve, with its own hint.
const UNAVAILABLE: &[u8] = b"{\"error\":\"RULEHITS001\",\"hint\":\"Rule history is \
    unavailable. Check storage and access, then retry.\"}";

/// Serves `policies/hits` after the dispatcher's checks.
///
/// Fails with 429 `CONSOLE429` past the query allowance and with 401 `CONSOLE401`, 403
/// `CONSOLE403`, 409 `CONSOLE409` or 400 `CONSOLE400` for refusals; a read storage cannot
/// serve answers 503 `RULEHITS001`.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 2048];
    let request: Request = read_json(context, &mut body)?;
    let query = Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        observed_at: call.now,
        request,
    };
    rule_hit_history::validate(&query).map_err(|_| RouteError::fail(400, "CONSOLE400"))?;
    let credential = call.credential(shared)?;
    let now = call.now;
    let part = shared.storage.transact(move |tx| {
        Box::pin(async move { read_history(tx, &credential, &query, work_bound(), now).await })
    });
    match part {
        Ok(part) => Ok(reply::json(context, &part)?),
        Err(failure) => unavailable(context, failure),
    }
}

/// Answers a failed read as Zig did: refusals with the generic codes, everything else 503
/// `RULEHITS001`.
fn unavailable(context: &mut Context<'_>, failure: StorageFailure) -> Result<(), RouteError> {
    let code = match failure.failure() {
        Failure::Unauthorized => "CONSOLE401",
        Failure::Forbidden => "CONSOLE403",
        Failure::Conflict => "CONSOLE409",
        Failure::InvalidInput => "CONSOLE400",
        _ if matches!(failure, StorageFailure::Busy | StorageFailure::Deferred) => {
            return Err(RouteError::StorageBusy);
        }
        _ => return Ok(context.respond(503, reply::JSON, UNAVAILABLE, &[])?),
    };
    Err(failure.route_error(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn requests_decode_and_the_unavailable_body_is_json() {
        let request: Request = from_json(
            br#"{"key":"m:a","node":1,"from_minute":995,"until_minute":999,"revision":null,
            "before":null}"#,
        )
        .unwrap();
        assert_eq!(request.key.as_str(), "m:a");
        assert!(sibuna_json::parse(UNAVAILABLE).is_ok());
    }
}

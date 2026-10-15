//! The routes `stats`, `timeline`, `rankings`, `rankings/query` and `challenges`: the live
//! views of [`crate::collector::Live`] (Zig's stats route of `observation_routes.zig`,
//! `timeline_routes.zig`, `ranking_routes.zig` and the live snapshot of
//! `challenge_routes.zig`).
//!
//! The timeline, rankings and challenges reads spend the caller's query allowance first:
//! 429 `CONSOLE429` for the timeline and challenges, 429 `CONSOLE003` for rankings, as in
//! Zig. A timeline or rankings query for another node is a peer query: it is asked over that
//! node's management stream (`crate::peer`), waited for at most five seconds, and the
//! caller's authority is checked again before the answer is sent (Zig's
//! `peer_query_routes.zig`). An unreachable peer answers 503 `CONSOLEPEERQUERY`, a cursor of
//! another epoch or boot 409 `TIMELINE001`, and a query the peer refuses 400
//! `CONSOLEPEERQUERY`.

use std::time::Instant;

use sibuna_console_protocol::codec::{Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, AuthorizationCheck, Principal, timeline};
use sibuna_console_storage::access;
use sibuna_http::Method;
use sibuna_json::Value;
use sibuna_serve::Context;

use crate::collector::{LiveError, challenge_snapshot, configured_bin};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::peer::{self, Cursor, Kind, Outcome, Status};
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::{HTTP_WAIT, StorageFailure};

/// The body of `rankings/query`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RankingsQuery {
    node: Option<u32>,
}

impl Decode for RankingsQuery {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<RankingsQuery, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let query = RankingsQuery { node: fields.or_default("node")? };
        fields.finish()?;
        Ok(query)
    }
}

/// The body of `challenges`: the parameter bin whose histograms to show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChallengesQuery {
    bin: Option<u8>,
}

impl Decode for ChallengesQuery {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ChallengesQuery, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let query = ChallengesQuery { bin: fields.or_default("bin")? };
        fields.finish()?;
        Ok(query)
    }
}

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with: 400 `CONSOLE002` for a malformed
/// body or timeline query, 409 `TIMELINE001` for a timeline cursor of another epoch or
/// boot, 429 when the query allowance is spent, and the failures of a peer query for
/// another node's view.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::Stats => Ok(reply::json(context, &shared.live.stats(shared))?),
        Handler::Timeline => timeline_page(shared, context, call),
        Handler::Rankings => rankings(shared, context, call),
        Handler::Challenges => challenges(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Spends one read of the caller's allowance, or fails with 429 `code`.
fn spend(shared: &Shared, call: &Call, code: &'static str) -> Result<(), RouteError> {
    let presented = call.presented.as_ref().ok_or(RouteError::Unavailable)?;
    if shared.query_budget.allow(&presented.digest, call.now, Spend::Query) {
        Ok(())
    } else {
        Err(RouteError::fail(429, code))
    }
}

/// Answers the view `kind` of another node `node` with a peer query, then checks the
/// caller's authority again: a kiosk session may read only the timeline.
fn peer_view(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    node: u32,
    query: (Kind, Cursor),
) -> Result<(), RouteError> {
    let (kind, cursor) = query;
    context.extend(peer::TIMEOUT.as_secs() + HTTP_WAIT.as_secs() + 2);
    let outcome = match shared.peers.submit(node, kind, cursor, call.now) {
        Ok(ticket) => ticket.wait(Instant::now() + peer::TIMEOUT, || shared.is_stopping()),
        Err(_) => None,
    };
    let principal = reauthorize(shared, call)?;
    let token_refused =
        principal.token_id.is_some() && principal.scopes & Scope::StatsRead.bit() == 0;
    if shared.is_restricted(&principal)
        || !principal.role.allows(Action::Read)
        || token_refused
        || (principal.kiosk && kind != Kind::Timeline)
    {
        return Err(RouteError::fail(403, "CONSOLE403"));
    }
    match outcome.unwrap_or(Outcome::Failed(Status::Unavailable)) {
        Outcome::Page(page) => Ok(reply::json_bytes(context, page.as_bytes(), &[])?),
        Outcome::Failed(Status::Conflict) => Err(RouteError::fail(409, "TIMELINE001")),
        Outcome::Failed(Status::Invalid) => Err(RouteError::fail(400, "CONSOLEPEERQUERY")),
        Outcome::Failed(_) => Err(RouteError::fail(503, "CONSOLEPEERQUERY")),
    }
}

/// Resolves the caller's credential again, moving a session's idle deadline.
///
/// Fails with 503 `CONSOLEQUORUM` when storage cannot answer and 401 `CONSOLE401` when the
/// credential is no longer valid.
fn reauthorize(shared: &Shared, call: &Call) -> Result<Principal, RouteError> {
    let presented = call.presented.as_ref().ok_or(RouteError::Unavailable)?;
    let check =
        AuthorizationCheck { session_digest: presented.digest, touch: true, kind: presented.kind };
    let now = shared.now();
    let resolved = shared
        .storage
        .transact(move |tx| Box::pin(async move { access::authorize(tx, &check, now).await }));
    match resolved {
        Ok(principal) => Ok(principal),
        Err(StorageFailure::Console(error)) if error.failure() == Failure::Unavailable => {
            Err(RouteError::fail(503, "CONSOLEQUORUM"))
        }
        Err(StorageFailure::Console(_)) => Err(RouteError::fail(401, "CONSOLE401")),
        Err(failure) => Err(failure.route_error("CONSOLEQUORUM")),
    }
}

fn timeline_page(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    spend(shared, call, "CONSOLE429")?;
    let query: timeline::Query = read_json(context, &mut [0u8; 256])?;
    if let Some(node) = query.node.filter(|&node| node != shared.live.node()) {
        let cursor = Cursor::from_query(&query).map_err(|_| RouteError::BadRequest)?;
        return peer_view(shared, context, call, node, (Kind::Timeline, cursor));
    }
    match shared.live.timeline(shared, &query) {
        Ok(page) => Ok(reply::json(context, &page)?),
        Err(LiveError::HistoryChanged) => Err(RouteError::fail(409, "TIMELINE001")),
        Err(LiveError::InvalidQuery) => Err(RouteError::BadRequest),
        Err(LiveError::Unavailable) => Err(RouteError::Unavailable),
    }
}

fn rankings(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, "CONSOLE003")?;
    if call.route.method == Method::Post {
        let query: RankingsQuery = read_json(context, &mut [0u8; 64])?;
        if let Some(node) = query.node.filter(|&node| node != shared.live.node()) {
            return peer_view(shared, context, call, node, (Kind::Rankings, Cursor::default()));
        }
    }
    match shared.live.rankings(shared) {
        Ok(page) => Ok(reply::json(context, &page)?),
        Err(_) => Err(RouteError::Unavailable),
    }
}

fn challenges(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, "CONSOLE429")?;
    let query: ChallengesQuery = read_json(context, &mut [0u8; 128])?;
    let defaults = shared.identity.challenge_defaults;
    let selected = query.bin.unwrap_or_else(|| configured_bin(&defaults));
    let snapshot = challenge_snapshot(&shared.telemetry.challenges, defaults, selected, call.now);
    Ok(reply::json(context, &snapshot)?)
}

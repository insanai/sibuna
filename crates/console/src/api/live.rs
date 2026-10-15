//! The routes `stats`, `timeline`, `rankings`, `rankings/query` and `challenges`: the live
//! views of [`crate::collector::Live`] (Zig's stats route of `observation_routes.zig`,
//! `timeline_routes.zig`, `ranking_routes.zig` and the live snapshot of
//! `challenge_routes.zig`).
//!
//! The timeline, rankings and challenges reads spend the caller's query allowance first:
//! 429 `CONSOLE429` for the timeline and challenges, 429 `CONSOLE003` for rankings, as in
//! Zig. A timeline or rankings query for another node is a peer query (unit U7); until that
//! lands it answers 503 `CONSOLEPEERQUERY`, the reply of an unreachable peer.

use sibuna_console_protocol::codec::{Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::timeline;
use sibuna_http::Method;
use sibuna_json::Value;
use sibuna_serve::Context;

use crate::collector::{LiveError, challenge_snapshot, configured_bin};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;

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
/// boot, 429 when the query allowance is spent, and 503 `CONSOLEPEERQUERY` for another
/// node's view.
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

/// Answers a view of another node: a peer query (unit U7).
fn peer_view() -> Result<(), RouteError> {
    Err(RouteError::fail(503, "CONSOLEPEERQUERY"))
}

fn timeline_page(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    spend(shared, call, "CONSOLE429")?;
    let query: timeline::Query = read_json(context, &mut [0u8; 256])?;
    if query.node.is_some_and(|node| node != shared.live.node()) {
        return peer_view();
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
        if query.node.is_some_and(|node| node != shared.live.node()) {
            return peer_view();
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

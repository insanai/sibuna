//! The console's seams on the request path.
//!
//! The Zig daemon counted request outcomes, sampled requests, observed challenge
//! submissions, held audit findings back for the origin's head and recorded rule hits for
//! its console (SID 0007, SID 0008) at the points below. With the `console` feature each
//! function forwards to `console::seams`, which returns at once unless `--console` gave the
//! server its telemetry. Without the feature every function is an empty `#[inline]` call
//! that compiles to nothing, so the request path pays nothing for the seams.

use std::io::Write;

use sibuna_challenge::{Challenge, Verified, VerifyError};
use sibuna_core::incident::Evidence;
use sibuna_core::incident_heads::REQUEST_BYTES;
use sibuna_policy::RequestView;

use crate::context::Ctx;
use crate::dispatch::Verdict;
use crate::slot::{EngineCache, EngineSlot};

#[cfg(feature = "console")]
use crate::console::seams;

/// The outcome selected for an external request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Admitted,
    Challenged,
    Denied,
    RateLimited,
    Banned,
    Other,
}

/// Why a parsed submission was rejected before verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    BodyTooLarge,
    MissingId,
    MalformedSolution,
}

/// The per-request console state.
#[cfg(feature = "console")]
pub(crate) type RequestState = seams::RequestState;

/// The origin head capture of one relay; never built without the console.
#[cfg(feature = "console")]
pub(crate) type OriginHead = seams::OriginHead;
/// The origin head capture of one relay; never built without the console.
#[cfg(not(feature = "console"))]
pub(crate) struct OriginHead;

#[cfg(not(feature = "console"))]
impl OriginHead {
    pub(crate) fn capture(&mut self, _raw: &[u8], _extra: &sibuna_core::incident_heads::Extra) {}
}

/// Seeds the connection thread's sampler when the console runs; once per connection.
#[inline]
pub(crate) fn begin_connection(server: &crate::server::Server) {
    #[cfg(feature = "console")]
    seams::begin_connection(server);
    #[cfg(not(feature = "console"))]
    let _ = server;
}

/// Evaluates the request with the current engine; with the console, also records which
/// rules matched in the engine's own rule-hit counters (only when it has them).
#[inline]
pub(crate) fn evaluate(
    cache: &mut EngineCache,
    slot: &EngineSlot,
    view: &RequestView<'_>,
) -> Verdict {
    #[cfg(feature = "console")]
    {
        let (engine, hits) = cache.refresh_observed(slot);
        if let Some(hits) = hits {
            let mut matches = sibuna_policy::RuleMatches::new();
            let decision = engine.evaluate_with_matches(view, &mut matches);
            hits.record(&matches, engine.rule_count());
            return Verdict::of(&decision);
        }
        Verdict::of(&engine.evaluate(view))
    }
    #[cfg(not(feature = "console"))]
    Verdict::of(&cache.refresh(slot).evaluate(view))
}

/// Counts and samples the outcome selected for the request, with the status sent.
#[inline]
pub(crate) fn record_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome, status: u16) {
    count_outcome(ctx, outcome);
    sample_outcome(ctx, outcome, status);
}

/// Counts the outcome; once per external request.
#[inline]
pub(crate) fn count_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome) {
    #[cfg(feature = "console")]
    seams::count_outcome(ctx, outcome);
    #[cfg(not(feature = "console"))]
    let _ = (ctx, outcome);
}

/// Samples one request in 64 with the status the client receives.
#[inline]
pub(crate) fn sample_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome, status: u16) {
    #[cfg(feature = "console")]
    seams::sample_outcome(ctx, outcome, status);
    #[cfg(not(feature = "console"))]
    let _ = (ctx, outcome, status);
}

/// Records the fallback outcome (`other`, 400) of a request that ended without one.
#[inline]
pub(crate) fn finish<W>(ctx: &mut Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::finish(ctx);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// A submission of a solution arrived.
#[inline]
pub(crate) fn observe_submission<W>(ctx: &Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::observe_submission(ctx);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// A submission arrived from a banned address.
#[inline]
pub(crate) fn observe_banned_submission<W>(ctx: &Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::reject(ctx, sibuna_store::challenge_metrics::Cause::AddressBanned);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// A request's body was truncated or malformed (a submission counts as malformed).
#[inline]
pub(crate) fn observe_rejected_body<W>(ctx: &Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::observe_rejected_body(ctx);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// A submission was rejected before verification.
#[inline]
pub(crate) fn observe_rejection<W>(ctx: &Ctx<'_, W>, cause: Rejection) {
    #[cfg(feature = "console")]
    seams::reject(ctx, seams::rejection_cause(cause));
    #[cfg(not(feature = "console"))]
    let _ = (ctx, cause);
}

/// A submission failed verification.
#[inline]
pub(crate) fn observe_verification_failure<W>(ctx: &Ctx<'_, W>, error: VerifyError) {
    #[cfg(feature = "console")]
    seams::reject(ctx, seams::verification_cause(error));
    #[cfg(not(feature = "console"))]
    let _ = (ctx, error);
}

/// A challenge was issued.
#[inline]
pub(crate) fn observe_issue<W>(ctx: &Ctx<'_, W>, challenge: &Challenge) {
    #[cfg(feature = "console")]
    seams::observe_issue(ctx, challenge);
    #[cfg(not(feature = "console"))]
    let _ = (ctx, challenge);
}

/// A solution was accepted.
#[inline]
pub(crate) fn observe_accept<W>(ctx: &Ctx<'_, W>, verified: &Verified) {
    #[cfg(feature = "console")]
    seams::observe_accept(ctx, verified);
    #[cfg(not(feature = "console"))]
    let _ = (ctx, verified);
}

/// Where the proxy reports the origin's status; only the console reads it.
#[inline]
pub(crate) fn origin_status_sink<'s, W>(
    ctx: &Ctx<'_, W>,
    status: &'s mut u16,
) -> Option<&'s mut u16> {
    #[cfg(feature = "console")]
    if ctx.server.hooks.telemetry.is_some() {
        return Some(status);
    }
    let _ = (ctx, status);
    None
}

/// A capture buffer for the origin's response head, when audit findings wait for it.
#[inline]
pub(crate) fn origin_head<W>(ctx: &Ctx<'_, W>) -> Option<OriginHead> {
    #[cfg(feature = "console")]
    return seams::origin_head(ctx);
    #[cfg(not(feature = "console"))]
    {
        let _ = ctx;
        None
    }
}

/// The relay ended with `origin_status` (0 when no head arrived) and the captured head.
#[inline]
pub(crate) fn admitted_complete<W: Write>(
    ctx: &mut Ctx<'_, W>,
    origin_status: u16,
    origin: Option<&OriginHead>,
) {
    #[cfg(feature = "console")]
    seams::admitted_complete(ctx, origin_status, origin);
    #[cfg(not(feature = "console"))]
    let _ = (ctx, origin_status, origin);
}

/// Forward authorization approved the request.
#[inline]
pub(crate) fn forward_complete<W: Write>(ctx: &mut Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::forward_complete(ctx);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// Holds audit findings back until the response is known (console head capture); returns
/// whether they were held.
#[inline]
pub(crate) fn defer_findings<W>(ctx: &mut Ctx<'_, W>, findings: u8) -> bool {
    #[cfg(feature = "console")]
    return seams::defer_findings(ctx, findings);
    #[cfg(not(feature = "console"))]
    {
        let _ = (ctx, findings);
        false
    }
}

/// Records findings still held back at the end of the policy step (a local answer).
#[inline]
pub(crate) fn flush_findings<W: Write>(ctx: &mut Ctx<'_, W>) {
    #[cfg(feature = "console")]
    seams::flush_findings(ctx);
    #[cfg(not(feature = "console"))]
    let _ = ctx;
}

/// The redacted request head for an incident, written into `buffer`, and whether it was
/// cut; empty unless the console captures heads.
#[inline]
pub(crate) fn request_head<'b, W>(
    ctx: &Ctx<'_, W>,
    buffer: &'b mut Option<[u8; REQUEST_BYTES]>,
) -> (&'b [u8], bool) {
    #[cfg(feature = "console")]
    return seams::request_head(ctx, buffer);
    #[cfg(not(feature = "console"))]
    {
        let _ = (ctx, buffer);
        (&[], false)
    }
}

/// The evidence envelope of a denial; version 1 while the console runs, else empty.
#[inline]
pub(crate) fn denial_evidence<W>(ctx: &Ctx<'_, W>) -> Evidence {
    #[cfg(feature = "console")]
    return seams::denial_evidence(ctx);
    #[cfg(not(feature = "console"))]
    {
        let _ = ctx;
        Evidence::default()
    }
}

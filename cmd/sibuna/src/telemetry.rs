//! The console's seams on the request path.
//!
//! The Zig daemon counted request outcomes, sampled requests and observed challenge
//! submissions for its console (SID 0007, SID 0008) at the points below. The console is not
//! ported yet; it will fill these functions in behind a `console` feature. Without it every
//! function is an empty `#[inline]` call that compiles to nothing, so the request path pays
//! nothing for the seams.

use sibuna_challenge::{Challenge, Verified, VerifyError};

use crate::context::Ctx;

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

/// Counts and samples the outcome selected for the request, with the status sent.
#[inline]
pub(crate) fn record_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome, status: u16) {
    count_outcome(ctx, outcome);
    sample_outcome(ctx, outcome, status);
}

/// Counts the outcome; once per external request.
#[inline]
pub(crate) fn count_outcome<W>(_ctx: &mut Ctx<'_, W>, _outcome: Outcome) {}

/// Samples one request in 64 with the status the client receives.
#[inline]
pub(crate) fn sample_outcome<W>(_ctx: &mut Ctx<'_, W>, _outcome: Outcome, _status: u16) {}

/// Records the fallback outcome (`other`, 400) of a request that ended without one.
#[inline]
pub(crate) fn finish<W>(_ctx: &mut Ctx<'_, W>) {}

/// A submission of a solution arrived.
#[inline]
pub(crate) fn observe_submission<W>(_ctx: &Ctx<'_, W>) {}

/// A submission arrived from a banned address.
#[inline]
pub(crate) fn observe_banned_submission<W>(_ctx: &Ctx<'_, W>) {}

/// A request's body was truncated or malformed (a submission counts as malformed).
#[inline]
pub(crate) fn observe_rejected_body<W>(_ctx: &Ctx<'_, W>) {}

/// A submission was rejected before verification.
#[inline]
pub(crate) fn observe_rejection<W>(_ctx: &Ctx<'_, W>, _cause: Rejection) {}

/// A submission failed verification.
#[inline]
pub(crate) fn observe_verification_failure<W>(_ctx: &Ctx<'_, W>, _error: VerifyError) {}

/// A challenge was issued.
#[inline]
pub(crate) fn observe_issue<W>(_ctx: &Ctx<'_, W>, _challenge: &Challenge) {}

/// A solution was accepted.
#[inline]
pub(crate) fn observe_accept<W>(_ctx: &Ctx<'_, W>, _verified: &Verified) {}

/// Where the proxy reports the origin's status; only the console reads it.
#[inline]
pub(crate) fn origin_status_sink(_status: &mut u16) -> Option<&mut u16> {
    None
}

/// The relay ended with `origin_status` (0 when no head arrived).
#[inline]
pub(crate) fn admitted_complete<W>(_ctx: &mut Ctx<'_, W>, _origin_status: u16) {}

/// Forward authorization approved the request.
#[inline]
pub(crate) fn forward_complete<W>(_ctx: &mut Ctx<'_, W>) {}

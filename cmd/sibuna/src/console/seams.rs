//! The console's seams on the request path, filled in (Zig's console parts of `server.zig`
//! and `challenge_observe.zig`; SID 0007, "Telemetry" and "Incident evidence").
//!
//! [`crate::telemetry`] calls these functions with the console compiled in. Each begins by
//! reading `Hooks::telemetry`: without `--console` it is `None` and the call returns at
//! once, one predictable branch. With it:
//!
//! - every external request counts exactly one outcome, before its response is written;
//! - one request in 64 is sampled with its status, client family labels and referring host
//!   (only the sampled request pays for classification and the referer parse);
//! - challenge submissions, refusals, issues and accepted solutions update the challenge
//!   counters and the challenge event ring;
//! - with `--console-capture-heads`, audit findings wait until the response side is known
//!   (the origin's redacted head, the forward-auth approval, or a local answer).
//!
//! Nothing here allocates, blocks or takes a lock a console thread holds.

use std::hash::{BuildHasher, RandomState};
use std::io::Write;

use sibuna_challenge::{Algorithm, Challenge, Verified, VerifyError};
use sibuna_console_protocol::client_family;
use sibuna_core::incident::Evidence;
use sibuna_core::incident_heads::{self, Head, REQUEST_BYTES, RESPONSE_BYTES, ResponseState};
use sibuna_json::{Event, PullReader};
use sibuna_store::challenge_metrics::{self, Cause, Solver, Timing};
use sibuna_store::telemetry::{
    self as store, ChallengeOutcome, ChallengeRecord, ConsoleTelemetry,
};

use crate::connection::UNKNOWN_LENGTH;
use crate::context::Ctx;
use crate::incidents::{self, ResponseEvidence};
use crate::telemetry::{Outcome, Rejection};

/// The evidence flag for a body that continued past what was buffered (bit 6).
const INCOMPLETE_BODY: u16 = 1 << 6;
/// The evidence flag for a declared body length beyond `u32` (bit 7).
const SATURATED_LENGTH: u16 = 1 << 7;
/// The longest valid reported solve time, one hour.
const MAX_DURATION_MS: f64 = 3_600_000.0;

/// What one request carries for the console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RequestState {
    /// The request's outcome has been counted; it is counted once.
    pub outcome_recorded: bool,
    /// Audit findings held back until the response side is known (capture only).
    pub deferred_findings: u8,
}

/// The origin's redacted response head, captured during the relay when findings wait for it.
pub(crate) struct OriginHead {
    bytes: [u8; RESPONSE_BYTES],
    head: Head,
    seen: bool,
}

impl OriginHead {
    /// Redacts `raw` into the bound, keeping the operator's extra header names.
    pub(crate) fn capture(&mut self, raw: &[u8], extra: &incident_heads::Extra) {
        self.head = incident_heads::response_head(raw, extra, &mut self.bytes);
        self.seen = true;
    }
}

fn telemetry<'s, W>(ctx: &Ctx<'s, W>) -> Option<&'s ConsoleTelemetry> {
    ctx.server.hooks.telemetry.as_deref()
}

fn store_outcome(outcome: Outcome) -> store::Outcome {
    match outcome {
        Outcome::Admitted => store::Outcome::Admitted,
        Outcome::Challenged => store::Outcome::Challenged,
        Outcome::Denied => store::Outcome::Denied,
        Outcome::RateLimited => store::Outcome::RateLimited,
        Outcome::Banned => store::Outcome::Banned,
        Outcome::Other => store::Outcome::Other,
    }
}

/// Seeds this connection thread's sampler and counter stripe; called once per connection.
pub(crate) fn begin_connection(server: &crate::server::Server) {
    if server.hooks.telemetry.is_none() {
        return;
    }
    // `RandomState::new` draws fresh keys per call from per-thread random state.
    store::seed(RandomState::new().hash_one(std::thread::current().id()));
}

/// Counts `outcome` for an external request, once.
pub(crate) fn count_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome) {
    let Some(telemetry) = telemetry(ctx) else { return };
    if ctx.internal || ctx.console.outcome_recorded {
        return;
    }
    ctx.console.outcome_recorded = true;
    telemetry.count(store_outcome(outcome));
}

/// Samples one external request in 64 with the status the client receives.
pub(crate) fn sample_outcome<W>(ctx: &mut Ctx<'_, W>, outcome: Outcome, status: u16) {
    let Some(telemetry) = telemetry(ctx) else { return };
    if ctx.internal || !store::selected() {
        return;
    }
    // Labels come from the full agent; the queue never carries the agent itself.
    let family = client_family::classify(utf8_prefix(ctx.user_agent));
    let referer = referer_host(ctx.request.header(b"referer").unwrap_or_default());
    let sample = store::Sample {
        second: ctx.now,
        ip: ctx.client_ip,
        path: ctx.request.path,
        referer,
        status,
        os: family.os as u8,
        browser: family.browser as u8,
    };
    telemetry.push(store_outcome(outcome), &sample);
}

/// Records the fallback outcome (`other`, 400) of a request that ended without one.
pub(crate) fn finish<W>(ctx: &mut Ctx<'_, W>) {
    if telemetry(ctx).is_some() && !ctx.console.outcome_recorded {
        count_outcome(ctx, Outcome::Other);
        sample_outcome(ctx, Outcome::Other, 400);
    }
}

/// The host of a `Referer` value: scheme and user information dropped, ending before the
/// port, path, query or fragment. Paths and queries never reach the sample.
pub(crate) fn referer_host(value: &[u8]) -> &[u8] {
    let mut rest = value;
    if let Some(at) = rest.windows(3).position(|window| window == b"://") {
        rest = rest.get(at + 3..).unwrap_or_default();
    }
    if let Some(at) = rest.iter().position(|&byte| byte == b'@') {
        rest = rest.get(at + 1..).unwrap_or_default();
    }
    let end = rest.iter().position(|byte| b"/?#:".contains(byte)).unwrap_or(rest.len());
    rest.get(..end).unwrap_or_default()
}

/// The longest valid UTF-8 prefix of `bytes`.
fn utf8_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(bytes.get(..error.valid_up_to()).unwrap_or_default())
            .unwrap_or_default(),
    }
}

/// A solution submission arrived.
pub(crate) fn observe_submission<W>(ctx: &Ctx<'_, W>) {
    if let Some(telemetry) = telemetry(ctx) {
        telemetry.challenges.submitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A submission was refused for `cause` before or during verification.
pub(crate) fn reject<W>(ctx: &Ctx<'_, W>, cause: Cause) {
    let Some(telemetry) = telemetry(ctx) else { return };
    telemetry.challenges.reject(cause);
    let mut record = event(ctx, ChallengeOutcome::Rejected);
    record.cause = Some(cause);
    telemetry.challenge_event(record);
}

/// A challenge event of this request at its time, from its client.
fn event<W>(ctx: &Ctx<'_, W>, outcome: ChallengeOutcome) -> ChallengeRecord {
    let mut record = ChallengeRecord::default();
    record.second = ctx.now;
    record.outcome = outcome;
    record.set_ip(ctx.client_ip);
    record
}

/// A request body was truncated or malformed; a submission counts as a malformed solution.
pub(crate) fn observe_rejected_body<W>(ctx: &Ctx<'_, W>) {
    if crate::challenge::is_submission(&ctx.request) {
        observe_submission(ctx);
        reject(ctx, Cause::MalformedSolution);
    }
}

/// The counter cause of a refusal before verification.
pub(crate) fn rejection_cause(rejection: Rejection) -> Cause {
    match rejection {
        Rejection::BodyTooLarge => Cause::BodyTooLarge,
        Rejection::MissingId => Cause::MissingId,
        Rejection::MalformedSolution => Cause::MalformedSolution,
    }
}

/// The counter cause of a failed verification.
pub(crate) fn verification_cause(error: VerifyError) -> Cause {
    match error {
        VerifyError::MalformedChallenge => Cause::MalformedChallenge,
        VerifyError::InvalidChallengeTag => Cause::InvalidTag,
        VerifyError::ChallengeExpired => Cause::Expired,
        VerifyError::FingerprintMismatch => Cause::FingerprintMismatch,
        VerifyError::DifficultyNotMet => Cause::DifficultyNotMet,
        VerifyError::InvalidProof => Cause::InvalidProof,
        VerifyError::WrongSolutionType => Cause::WrongSolutionType,
        VerifyError::DoubleSpendAttempt => Cause::Replay,
        VerifyError::StoreFull => Cause::Capacity,
    }
}

fn kind(algorithm: Algorithm) -> challenge_metrics::Algorithm {
    match algorithm {
        Algorithm::Hashcash => challenge_metrics::Algorithm::Hashcash,
        Algorithm::Posw => challenge_metrics::Algorithm::Posw,
    }
}

/// A challenge was issued: its bin, the adaptive controller's state and an event.
pub(crate) fn observe_issue<W>(ctx: &Ctx<'_, W>, challenge: &Challenge) {
    let Some(telemetry) = telemetry(ctx) else { return };
    let algorithm = kind(challenge.algorithm);
    telemetry.challenges.issue(algorithm, challenge.difficulty, challenge.challenges);
    let adaptive = ctx.server.coordinator.adaptive();
    let relaxed = std::sync::atomic::Ordering::Relaxed;
    telemetry.adaptive_bits.store(adaptive.bump(), relaxed);
    telemetry.adaptive_rate_256.store(adaptive.rate_256(), relaxed);
    let mut record = event(ctx, ChallengeOutcome::Issued);
    record.algorithm = algorithm;
    record.parameter = challenge.difficulty;
    record.openings = challenge.challenges;
    telemetry.challenge_event(record);
}

/// A solution was accepted: its bin with the client's reported solve time and solver (never
/// trusted for admission), and an event.
pub(crate) fn observe_accept<W>(ctx: &Ctx<'_, W>, verified: &Verified) {
    let Some(telemetry) = telemetry(ctx) else { return };
    let algorithm = kind(verified.algorithm);
    let (timing, solver) = solve_metadata(ctx.request.body);
    let (parameter, openings) = (verified.difficulty, verified.challenges);
    telemetry.challenges.accept(algorithm, parameter, openings, timing, solver);
    let duration_ms = match timing {
        // Inside 0..=3,600,000, so the conversion is exact enough and fits.
        Timing::Milliseconds(ms) if ms.is_finite() && (0.0..=MAX_DURATION_MS).contains(&ms) => {
            Some(ms as u32)
        }
        _ => None,
    };
    let mut record = event(ctx, ChallengeOutcome::Accepted);
    record.duration_ms = duration_ms;
    record.algorithm = algorithm;
    record.parameter = parameter;
    record.openings = openings;
    telemetry.challenge_event(record);
}

/// Reads `elapsed_ms` and `solver` from the top level of a submission. Any other shape,
/// a duplicate, a wrong type or trailing bytes make the timing invalid; nested fields are
/// ignored. This is telemetry only: admission never reads it.
pub(crate) fn solve_metadata(body: &[u8]) -> (Timing, Solver) {
    read_metadata(body).unwrap_or((Timing::Invalid, Solver::Unknown))
}

fn read_metadata(body: &[u8]) -> Option<(Timing, Solver)> {
    let mut reader = PullReader::new(body);
    if reader.next().ok()? != Some(Event::BeginObject) {
        return None;
    }
    let (mut timing, mut solver) = (Timing::Missing, Solver::Unknown);
    let (mut timing_seen, mut solver_seen) = (false, false);
    loop {
        let key = match reader.next().ok()? {
            Some(Event::EndObject) => break,
            Some(Event::Key(key)) => key,
            _ => return None,
        };
        match key.as_ref() {
            "elapsed_ms" if !timing_seen => {
                timing_seen = true;
                let Some(Event::Number(number)) = reader.next().ok()? else { return None };
                timing = Timing::Milliseconds(number.as_f64().ok()?);
            }
            "solver" if !solver_seen => {
                solver_seen = true;
                let Some(Event::String(name)) = reader.next().ok()? else { return None };
                solver = match name.as_ref() {
                    "wasm" => Solver::Wasm,
                    "javascript" => Solver::Javascript,
                    _ => Solver::Unknown,
                };
            }
            "elapsed_ms" | "solver" => return None,
            _ => {
                reader.skip_value().ok()?;
            }
        }
    }
    reader.next().ok()?.is_none().then_some((timing, solver))
}

/// The request's redacted head when capture is on; `buffer` holds it. Empty otherwise.
pub(crate) fn request_head<'b, W>(
    ctx: &Ctx<'_, W>,
    buffer: &'b mut Option<[u8; REQUEST_BYTES]>,
) -> (&'b [u8], bool) {
    let config = &ctx.server.config;
    if !config.console_capture_heads {
        return (&[], false);
    }
    let request = &ctx.request;
    let line = incident_heads::RequestLine {
        method: request.method_text,
        path: request.path,
        query: request.query,
        version: request.version.as_bytes(),
    };
    let fields = request.headers().iter().map(|field| (field.name, field.value));
    let out = buffer.insert([0; REQUEST_BYTES]);
    let head = incident_heads::request_head(&line, fields, &config.console_capture_headers, out);
    (out.get(..head.len).unwrap_or_default(), head.truncated)
}

/// The evidence of a denial (version 1) while the console runs; empty otherwise.
pub(crate) fn denial_evidence<W>(ctx: &Ctx<'_, W>) -> Evidence {
    if telemetry(ctx).is_none() {
        return Evidence::default();
    }
    let declared = if ctx.declared_body == UNKNOWN_LENGTH {
        ctx.request.body.len()
    } else {
        ctx.declared_body
    };
    let truncated = if ctx.declared_body == UNKNOWN_LENGTH {
        INCOMPLETE_BODY
    } else if u32::try_from(ctx.declared_body).is_err() {
        SATURATED_LENGTH
    } else {
        0
    };
    let saturated = |length: usize| u32::try_from(length).unwrap_or(u32::MAX);
    Evidence {
        version: 1,
        selected_status: 403,
        query_bytes: saturated(ctx.request.query.len()),
        body_bytes: saturated(ctx.request.body.len()),
        declared_body_bytes: saturated(declared),
        truncated,
    }
}

/// Holds `findings` back until the response side is known, when capture is on; returns
/// whether it did.
pub(crate) fn defer_findings<W>(ctx: &mut Ctx<'_, W>, findings: u8) -> bool {
    if !ctx.server.config.console_capture_heads {
        return false;
    }
    ctx.console.deferred_findings = findings;
    true
}

/// Takes the findings held back, if any.
fn take_findings<W>(ctx: &mut Ctx<'_, W>) -> u8 {
    std::mem::take(&mut ctx.console.deferred_findings)
}

/// Records findings still held back when the request ends without an origin exchange: the
/// response was local or the relay never started.
pub(crate) fn flush_findings<W: Write>(ctx: &mut Ctx<'_, W>) {
    let findings = take_findings(ctx);
    if findings != 0 {
        incidents::record_findings(ctx, findings, ResponseEvidence::LOCAL);
    }
}

/// Forward authorization approved the request; findings held back record now, with the
/// origin's response unobserved.
pub(crate) fn forward_complete<W: Write>(ctx: &mut Ctx<'_, W>) {
    let findings = take_findings(ctx);
    if findings != 0 {
        let unobserved =
            ResponseEvidence { state: ResponseState::Unobserved, ..Default::default() };
        incidents::record_findings(ctx, findings, unobserved);
    }
}

/// Returns a capture buffer for the origin's head when findings wait for it.
pub(crate) fn origin_head<W>(ctx: &Ctx<'_, W>) -> Option<OriginHead> {
    (ctx.console.deferred_findings != 0).then(|| OriginHead {
        bytes: [0; RESPONSE_BYTES],
        head: Head::default(),
        seen: false,
    })
}

/// After the relay: the origin status counters and the sample (a failed relay reports 502),
/// and findings held back until the origin head was known.
pub(crate) fn admitted_complete<W: Write>(
    ctx: &mut Ctx<'_, W>,
    origin_status: u16,
    origin: Option<&OriginHead>,
) {
    let Some(telemetry) = telemetry(ctx) else { return };
    telemetry.origin(origin_status);
    sample_outcome(ctx, Outcome::Admitted, if origin_status == 0 { 502 } else { origin_status });
    let findings = take_findings(ctx);
    if findings == 0 {
        return;
    }
    let response = match origin {
        Some(origin) if origin.seen => ResponseEvidence {
            head: origin.bytes.get(..origin.head.len).unwrap_or_default(),
            truncated: origin.head.truncated,
            state: ResponseState::Captured,
        },
        _ => ResponseEvidence { state: ResponseState::Unavailable, ..Default::default() },
    };
    incidents::record_findings(ctx, findings, response);
}

#[cfg(test)]
mod tests {
    use super::*;

    // server.zig: "referring hosts drop scheme, credentials, ports and paths".
    #[test]
    fn referring_hosts_drop_scheme_credentials_ports_and_paths() {
        let full = b"https://user:pw@news.example.test:8443/story?id=1#top";
        assert_eq!(referer_host(full), b"news.example.test");
        assert_eq!(referer_host(b"a.example/"), b"a.example");
        assert_eq!(referer_host(b""), b"");
    }

    // challenge_observe.zig: "timing metadata excludes nested fields and rejects ambiguous
    // or malformed values".
    #[test]
    fn timing_metadata_excludes_nested_fields_and_rejects_ambiguous_values() {
        assert_eq!(solve_metadata(b"{\"nonce\":1}").0, Timing::Missing);
        let good = solve_metadata(b"{\"elapsed_ms\":12.5,\"solver\":\"wasm\",\"nonce\":1}");
        assert_eq!(good, (Timing::Milliseconds(12.5), Solver::Wasm));
        assert_eq!(solve_metadata(b"{\"other\":{\"elapsed_ms\":1}}").0, Timing::Missing);
        for body in [
            &b"{\"elapsed_ms\":\"12\"}"[..],
            b"{\"elapsed_ms\":1,\"elapsed_ms\":2}",
            b"{\"elapsed_ms\":null}",
            b"{\"elapsed_ms\":1}garbage",
        ] {
            assert_eq!(solve_metadata(body).0, Timing::Invalid, "{body:?}");
        }
    }

    #[test]
    fn every_verification_error_has_its_own_cause() {
        let errors = [
            VerifyError::MalformedChallenge,
            VerifyError::InvalidChallengeTag,
            VerifyError::ChallengeExpired,
            VerifyError::FingerprintMismatch,
            VerifyError::DifficultyNotMet,
            VerifyError::InvalidProof,
            VerifyError::WrongSolutionType,
            VerifyError::DoubleSpendAttempt,
            VerifyError::StoreFull,
        ];
        let causes: std::collections::HashSet<u8> =
            errors.iter().map(|&error| verification_cause(error) as u8).collect();
        assert_eq!(causes.len(), errors.len());
        assert_eq!(rejection_cause(Rejection::MissingId), Cause::MissingId);
    }
}

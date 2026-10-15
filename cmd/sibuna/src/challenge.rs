//! The challenge routes and session checks: the interstitial, issuance
//! (`/__sibuna/challenge.json`), verification (`/__sibuna/verify`) and the session cookie
//! that clears an admission challenge.
//!
//! The challenge a decision demands is derived in one place ([`challenge_spec`]): the
//! session requirement of admission, the ticket a challenged response carries and the
//! fallback of issuance all come from it, so the work a session is asked for is exactly the
//! work it is later checked against.

use std::io::{self, Write};

use sibuna_challenge::{
    Algorithm, ChallengeSpec, Requirement, RequirementTicket, Solution, WorkLevel, required_work,
    rule_hash,
};
use sibuna_core::ErrorKind;
use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};
use sibuna_http::response::{self, Extra, Status};
use sibuna_http::{Method, Request, forwarded, split_target};
use sibuna_policy::normalizer::percent_decode;
use sibuna_pow::posw::MAX_PROOF_SIZE;

use crate::context::Ctx;
use crate::dispatch::{Verdict, format_into, target_verdict};
use crate::pages::{self, Page, PageExtra};
use crate::server::is_forward_auth;
use crate::telemetry;

/// The longest reported target issuance evaluates (the forwarded-metadata bound). A longer
/// one is refused, never truncated into a different path.
const MAX_REPORTED_TARGET: usize = 8192;

const CHALLENGE_HEADER: &[u8] = b"X-Sibuna-Status: CHALLENGE\r\n";

/// True for a solution submission: `POST /__sibuna/verify`.
pub(crate) fn is_submission(request: &Request<'_>) -> bool {
    request.method == Method::Post && request.path == b"/__sibuna/verify"
}

/// True for the routes that spend the challenge budget: issuance and submissions.
pub(crate) fn is_work(request: &Request<'_>) -> bool {
    request.path == b"/__sibuna/challenge.json" || is_submission(request)
}

/// The challenge a decision demands: the configured default with the deciding rule's
/// difficulty and algorithm overrides.
fn challenge_spec<W: Write>(ctx: &Ctx<'_, W>, verdict: &Verdict) -> ChallengeSpec {
    let mut spec = ctx.server.coordinator.default_spec();
    if verdict.difficulty > 0 {
        spec.difficulty = verdict.difficulty;
    }
    if let Some(algorithm) = verdict.algorithm {
        spec.algorithm = challenge_algorithm(algorithm);
    }
    spec
}

/// The policy and challenge crates name the same two mechanisms independently.
fn challenge_algorithm(algorithm: sibuna_policy::Algorithm) -> Algorithm {
    match algorithm {
        sibuna_policy::Algorithm::Hashcash => Algorithm::Hashcash,
        sibuna_policy::Algorithm::Posw => Algorithm::Posw,
    }
}

/// The work a decision demands of a session, in the token's own unit.
fn required<W: Write>(ctx: &Ctx<'_, W>, verdict: &Verdict) -> WorkLevel {
    let spec = challenge_spec(ctx, verdict);
    required_work(spec.algorithm, spec.difficulty)
}

/// Returns the rule hash a valid session cookie carries when its work reaches what
/// `verdict` demands; `None` when there is no cookie, it does not verify, or it paid less.
pub(crate) fn session_rule_hash<W: Write>(ctx: &Ctx<'_, W>, verdict: &Verdict) -> Option<u64> {
    let server = ctx.server;
    let cookie = ctx.request.cookie(server.config.cookie_name.as_bytes())?;
    let coordinator = &server.coordinator;
    let session =
        coordinator.verify_cookie(cookie, ctx.client_ip, ctx.user_agent, ctx.now).ok()?;
    session.work.satisfies(required(ctx, verdict)).then_some(session.rule_hash)
}

/// The requirement a challenged response carries to issuance, sealed for this client.
fn requirement_ticket<W: Write>(ctx: &Ctx<'_, W>, verdict: &Verdict) -> RequirementTicket {
    let requirement = Requirement {
        spec: challenge_spec(ctx, verdict),
        rule_hash: rule_hash(verdict.rule_name()),
    };
    ctx.server.coordinator.requirement_ticket(requirement, ctx.client_ip, ctx.user_agent, ctx.now)
}

/// Answers a request the policy challenges. Forward authorization keeps the interstitial at
/// 401 so an ingress returns its HTML without forwarding an unverified request.
pub(crate) fn write_challenged<W: Write>(
    ctx: &mut Ctx<'_, W>,
    verdict: &Verdict,
) -> io::Result<()> {
    let ticket = requirement_ticket(ctx, verdict);
    let forward_auth = is_forward_auth(&ctx.server.config);
    let status = if forward_auth { Status::Unauthorized } else { Status::Ok };
    write_challenge(ctx, status, ticket.as_bytes())
}

/// Browsers receive the interstitial with the requirement in its markup; other clients
/// receive an issuance URL that already carries it.
fn write_challenge<W: Write>(
    ctx: &mut Ctx<'_, W>,
    status: Status,
    ticket: &[u8],
) -> io::Result<()> {
    if ctx.request.accepts_html() {
        let extra = PageExtra { headers: CHALLENGE_HEADER, ticket, ..PageExtra::default() };
        return pages::respond(ctx, Page::Challenge, status, "", extra);
    }
    let mut buffer = [0u8; 192];
    let mut cursor = io::Cursor::new(&mut buffer[..]);
    cursor.write_all(
        b"{\"error\":\"challenge_required\",\"challenge\":\"/__sibuna/challenge.json",
    )?;
    if !ticket.is_empty() {
        cursor.write_all(b"?need=")?;
        cursor.write_all(ticket)?;
    }
    cursor.write_all(b"\"}")?;
    let length = usize::try_from(cursor.position()).unwrap_or(0);
    let body = buffer.get(..length).unwrap_or_default();
    let extra =
        Extra { headers: CHALLENGE_HEADER, keep_alive: ctx.keep_alive, ..Extra::default() };
    response::write_response(ctx.writer, Status::Unauthorized, b"application/json", body, extra)
}

/// `/__sibuna/challenge`: the interstitial served from an ingress error handler. With
/// trusted metadata naming the original URI, the page carries the requirement that request
/// was given, evaluated from the same request headers; otherwise it carries none.
pub(crate) fn handle_page<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let ticket = error_page_ticket(ctx);
    let ticket = ticket.as_ref().map(|ticket| &ticket.as_bytes()[..]).unwrap_or_default();
    write_challenge(ctx, Status::Ok, ticket)
}

fn error_page_ticket<W: Write>(ctx: &mut Ctx<'_, W>) -> Option<RequirementTicket> {
    let trusted = ctx.server.config.trusts_forwarded();
    let original = forwarded::target(&ctx.request, trusted).ok()??;
    let verdict = target_verdict(ctx, original.path, original.query);
    if !verdict.is_challenge() {
        return None;
    }
    Some(requirement_ticket(ctx, &verdict))
}

/// `/__sibuna/challenge.json`: issues a challenge. The challenged response's own ticket
/// decides the work; only without a valid ticket is the reported URL evaluated, through the
/// same target split admission uses.
pub(crate) fn handle_issue<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let requirement = match ticket_requirement(ctx) {
        Some(requirement) => requirement,
        None => match reported_requirement(ctx)? {
            Some(requirement) => requirement,
            None => return Ok(()),
        },
    };
    let server = ctx.server;
    let challenge = server.coordinator.create_challenge_with_spec(
        ctx.client_ip,
        ctx.user_agent,
        ctx.now,
        requirement.spec,
        requirement.rule_hash,
    );
    server.metrics.challenges_issued.bump();
    telemetry::observe_issue(ctx, &challenge);
    let mut buffer = [0u8; 320];
    let body = format_into(
        &mut buffer,
        format_args!(
            "{{\"id\":\"{}\",\"algorithm\":\"{}\",\"difficulty\":{},\"challenges\":{},\
             \"expires_at\":{}}}",
            challenge.id.as_str(),
            challenge.algorithm.name(),
            challenge.difficulty,
            challenge.challenges,
            challenge.expires_at
        ),
    );
    let extra = Extra { keep_alive: ctx.keep_alive, ..Extra::default() };
    response::write_response(ctx.writer, Status::Ok, b"application/json", body, extra)
}

fn ticket_requirement<W: Write>(ctx: &Ctx<'_, W>) -> Option<Requirement> {
    let text = query_param(ctx.request.query, b"need")?;
    ctx.server.coordinator.open_ticket(text, ctx.client_ip, ctx.user_agent, ctx.now)
}

/// A client without a ticket (an API client, an expired page) reports the URL it protects.
/// Returns `None` after answering 414 for a target that is too long.
fn reported_requirement<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<Option<Requirement>> {
    let raw = query_param(ctx.request.query, b"path").unwrap_or(b"/");
    if raw.len() > MAX_REPORTED_TARGET {
        let text = b"Challenge target too long";
        response::write_text(ctx.writer, Status::UriTooLong, text, ctx.keep_alive)?;
        return Ok(None);
    }
    let mut decoded = [0u8; MAX_REPORTED_TARGET];
    let target = split_target(percent_decode(raw, &mut decoded));
    let verdict = target_verdict(ctx, target.path, target.query);
    Ok(Some(Requirement {
        spec: challenge_spec(ctx, &verdict),
        rule_hash: rule_hash(verdict.rule_name()),
    }))
}

/// `POST /__sibuna/verify`: checks a solution and sets the session cookie.
pub(crate) fn handle_verify<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let server = ctx.server;
    let keep = ctx.keep_alive;
    let body = ctx.request.body;
    if body.len() < ctx.declared_body {
        telemetry::observe_rejection(ctx, telemetry::Rejection::BodyTooLarge);
        let text = b"Solution body exceeds 64 KB";
        return response::write_text(ctx.writer, Status::PayloadTooLarge, text, keep);
    }
    let Some(challenge_id) = extract_json_string(body, b"challenge_id") else {
        telemetry::observe_rejection(ctx, telemetry::Rejection::MissingId);
        let text = b"Missing challenge_id field";
        return response::write_text(ctx.writer, Status::BadRequest, text, keep);
    };
    let mut proof = [0u8; MAX_PROOF_SIZE];
    let solution = match parse_solution(body, &mut proof) {
        Ok(solution) => solution,
        Err(message) => {
            telemetry::observe_rejection(ctx, telemetry::Rejection::MalformedSolution);
            return response::write_text(ctx.writer, Status::BadRequest, message, keep);
        }
    };
    let coordinator = &server.coordinator;
    let (ip, agent) = (ctx.client_ip, ctx.user_agent);
    let verified = match coordinator.verify_and_mint(challenge_id, solution, ip, agent, ctx.now) {
        Ok(verified) => verified,
        Err(error) => {
            server.metrics.solutions_rejected.bump();
            telemetry::observe_verification_failure(ctx, error);
            let text = ErrorKind::from(error).explain().as_bytes();
            return response::write_text(ctx.writer, Status::BadRequest, text, keep);
        }
    };
    server.metrics.solutions_accepted.bump();
    telemetry::observe_accept(ctx, &verified);
    let config = &server.config;
    let mut cookie = [0u8; 512];
    let cookie = response::cookie_header(
        &mut cookie,
        config.cookie_name.as_bytes(),
        verified.token.as_str().as_bytes(),
        verified.ttl_seconds,
        config.secure_cookie,
    )
    .map_err(io::Error::other)?;
    let extra = Extra { headers: cookie, keep_alive: keep, ..Extra::default() };
    response::write_response(
        ctx.writer,
        Status::Ok,
        b"application/json",
        b"{\"status\":\"ok\"}",
        extra,
    )
}

/// Reads the solution of a submission: a base64url `proof`, else a decimal `nonce`.
/// Fails with the text the client receives.
fn parse_solution<'p>(body: &[u8], proof: &'p mut [u8]) -> Result<Solution<'p>, &'static [u8]> {
    if let Some(encoded) = extract_json_string(body, b"proof") {
        let decoded = decode_proof(encoded, proof).ok_or(&b"Malformed proof encoding"[..])?;
        return Ok(Solution::Proof(decoded));
    }
    if let Some(digits) = extract_json_string(body, b"nonce") {
        let nonce = parse_u64(digits).ok_or(&b"Invalid numeric nonce"[..])?;
        return Ok(Solution::Nonce(nonce));
    }
    Err(b"Missing nonce or proof field")
}

/// Decodes a base64url proof without padding into `out`; `None` when it is not canonical
/// or does not fit.
fn decode_proof<'o>(encoded: &[u8], out: &'o mut [u8]) -> Option<&'o [u8]> {
    let size = base64::decoded_len(URL_SAFE_NO_PAD, encoded).ok()?;
    let target = out.get_mut(..size)?;
    let written = base64::decode_to_slice(URL_SAFE_NO_PAD, encoded, target).ok()?;
    let decoded: &'o [u8] = target;
    decoded.get(..written)
}

/// Parses an unsigned decimal exactly as Zig's `std.fmt.parseInt(u64, text, 10)`: an
/// optional `+` (or `-` before zeros only), and `_` between digits.
fn parse_u64(text: &[u8]) -> Option<u64> {
    let (negative, digits) = match text.split_first()? {
        (b'+', rest) => (false, rest),
        (b'-', rest) => (true, rest),
        _ => (false, text),
    };
    if digits.first()? == &b'_' || digits.last()? == &b'_' {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in digits.iter().filter(|&&byte| byte != b'_') {
        let digit = u64::from(byte.checked_sub(b'0').filter(|digit| *digit < 10)?);
        if negative && digit != 0 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Query parameter lookup over the zero-copy query: the value after the first `=` of the
/// first pair named `key`, empty when the pair has no `=`.
pub(crate) fn query_param<'q>(query: &'q [u8], key: &[u8]) -> Option<&'q [u8]> {
    query.split(|&byte| byte == b'&').find_map(|pair| {
        let mut parts = pair.splitn(2, |&byte| byte == b'=');
        let name = parts.next()?;
        (name == key).then(|| parts.next().unwrap_or_default())
    })
}

/// Minimal zero-copy lookup of a top-level JSON string or number value, exactly as the Zig
/// daemon read submissions: the first `"key"`, then the first `:` after it, then the value
/// up to a quote, comma, brace, space or line break.
pub fn extract_json_string<'j>(json: &'j [u8], key: &[u8]) -> Option<&'j [u8]> {
    // Zig formatted the quoted key into a 64-byte buffer and gave up when it did not fit.
    if key.len() + 2 > 64 {
        return None;
    }
    let after_key = find_quoted(json, key)?;
    let rest = json.get(after_key..)?;
    let colon = rest.iter().position(|&byte| byte == b':')?;
    let mut value = rest.get(colon + 1..)?;
    while let [b' ' | b'\t' | b'"', tail @ ..] = value {
        value = tail;
    }
    let end = value
        .iter()
        .position(|&byte| matches!(byte, b'"' | b',' | b'}' | b' ' | b'\r' | b'\n'))
        .unwrap_or(value.len());
    value.get(..end)
}

/// Returns the offset just past the first `"key"` in `json`.
fn find_quoted(json: &[u8], key: &[u8]) -> Option<usize> {
    let length = key.len() + 2;
    json.windows(length)
        .position(|window| {
            window.first() == Some(&b'"')
                && window.last() == Some(&b'"')
                && window.get(1..length - 1) == Some(key)
        })
        .map(|at| at + length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_string_handles_various_json_formats() {
        let first = b"{\"challenge_id\":\"cid123\",\"nonce\":\"456\"}";
        assert_eq!(extract_json_string(first, b"challenge_id"), Some(&b"cid123"[..]));
        assert_eq!(extract_json_string(first, b"nonce"), Some(&b"456"[..]));
        let second = b"{\n  \"challenge_id\": \"cid456\" ,\n  \"nonce\": 789\n}";
        assert_eq!(extract_json_string(second, b"challenge_id"), Some(&b"cid456"[..]));
        assert_eq!(extract_json_string(second, b"nonce"), Some(&b"789"[..]));
        assert_eq!(extract_json_string(second, b"proof"), None);
    }

    #[test]
    fn query_parameter_lookup() {
        assert_eq!(query_param(b"x=1&path=/a/b&y=2", b"path"), Some(&b"/a/b"[..]));
        assert_eq!(query_param(b"x=1", b"path"), None);
        assert_eq!(query_param(b"path", b"path"), Some(&b""[..]));
        assert_eq!(query_param(b"path=a=b", b"path"), Some(&b"a=b"[..]));
    }

    #[test]
    fn nonces_parse_as_zig_parse_int_did() {
        assert_eq!(parse_u64(b"456"), Some(456));
        assert_eq!(parse_u64(b"+7"), Some(7));
        assert_eq!(parse_u64(b"1_000"), Some(1000));
        assert_eq!(parse_u64(b"-0"), Some(0));
        assert_eq!(parse_u64(b"-1"), None);
        assert_eq!(parse_u64(b"_1"), None);
        assert_eq!(parse_u64(b"1_"), None);
        assert_eq!(parse_u64(b""), None);
        assert_eq!(parse_u64(b"+"), None);
        assert_eq!(parse_u64(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_u64(b"18446744073709551616"), None);
        assert_eq!(parse_u64(b"12a"), None);
    }

    #[test]
    fn proofs_decode_strictly() {
        let mut out = [0u8; 8];
        assert_eq!(decode_proof(b"AQID", &mut out), Some(&[1u8, 2, 3][..]));
        assert_eq!(decode_proof(b"AQI=", &mut out), None);
        assert_eq!(decode_proof(b"AQIDBAUGBwgJ", &mut out), None);
    }

    #[test]
    fn submissions_parse_into_solutions() {
        let mut proof = [0u8; 16];
        let parsed = parse_solution(b"{\"challenge_id\":\"x\",\"nonce\":\"12\"}", &mut proof);
        assert_eq!(parsed, Ok(Solution::Nonce(12)));
        let parsed = parse_solution(b"{\"proof\":\"!!\"}", &mut proof);
        assert_eq!(parsed, Err(&b"Malformed proof encoding"[..]));
        let parsed = parse_solution(b"{\"nonce\":\"x\"}", &mut proof);
        assert_eq!(parsed, Err(&b"Invalid numeric nonce"[..]));
        let parsed = parse_solution(b"{}", &mut proof);
        assert_eq!(parsed, Err(&b"Missing nonce or proof field"[..]));
    }
}

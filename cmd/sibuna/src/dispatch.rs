//! The decision path of one request (SID 0002, "Request contract"):
//!
//! 1. the local ban table;
//! 2. the reserved routes under `/__sibuna/` (with their own challenge budget);
//! 3. the local GCRA limiter;
//! 4. the published policy snapshot: inspection, reputation, rules, scoring, static paths,
//!    bot signatures and the default;
//! 5. a rule's own quota;
//! 6. a valid session clears an admission challenge whose work it already paid, never a
//!    denial;
//! 7. an admitted request streams to the origin, or forward authorization answers.
//!
//! Before any step the request path is put in normal form ([`normalize_target`]): every
//! decision above, the reserved-route match and the path the origin receives read that one
//! path, so the origin never routes on a spelling policy did not judge.

use std::io::{self, Write};

use sibuna_http::response::{self, Extra, Status};
use sibuna_http::{PathError, Request, forwarded, normalize_path};
use sibuna_net::{Audit, Client, Exchange, ProxyError};
use sibuna_policy::{Action, Algorithm, Engine, Header, Limits, MAX_RULE_NAME, RequestView};
use sibuna_store::limiter::{
    DEFAULT_SCOPE, Decision as RateDecision, Limits as RateLimits, RateLimiter,
};

use crate::context::Ctx;
use crate::pages::{self, Page, PageExtra};
use crate::server::is_forward_auth;
use crate::telemetry::{self, Outcome};

/// Puts the path of `request` in normal form ([`sibuna_http::normalize_path`]), written
/// into the front of `buffer`, and returns the request with it and the rest of `buffer`.
/// The rest holds the normal form of a trusted forwarded path later; both paths lie inside
/// one request head, so a buffer of the head's size holds both.
///
/// # Errors
///
/// The [`PathError`] of a path that has no normal form; the caller answers 400.
pub(crate) fn normalize_target<'b>(
    mut request: Request<'b>,
    buffer: &'b mut [u8],
) -> Result<(Request<'b>, &'b mut [u8]), PathError> {
    let (front, spare) =
        buffer.split_at_mut_checked(request.path.len()).ok_or(PathError::TooLong)?;
    request.path = normalize_path(request.path, front)?.as_bytes();
    Ok((request, spare))
}

/// Dispatches one request whose path is in normal form. `spare` receives the normal form of
/// a trusted forwarded path. Returns whether the connection may serve another; an error is
/// a failed write, after which the connection closes.
pub(crate) fn dispatch<'c, W: Write>(
    ctx: &mut Ctx<'c, W>,
    spare: &'c mut [u8],
) -> io::Result<bool> {
    let result = route(ctx, spare);
    // Every parsed external request gets one selected outcome, even on an early error.
    telemetry::finish(ctx);
    crate::access::capture(ctx);
    result
}

/// The rule name reported for a request on a route without the firewall.
const BYPASS_RULE: &str = "load-balancer";

fn route<'c, W: Write>(ctx: &mut Ctx<'c, W>, spare: &'c mut [u8]) -> io::Result<bool> {
    let server = ctx.server;
    server.metrics.requests.bump();
    if ctx.ingress.is_some() && edge_host(ctx).is_err() {
        response::write_text(ctx.writer, Status::BadRequest, b"Invalid Host", false)?;
        return Ok(false);
    }
    // An ACME challenge and the redirect to HTTPS come before any decision (SID 0021).
    #[cfg(feature = "https")]
    if let Some(keep) = crate::acme::intercept(ctx)? {
        return Ok(keep);
    }
    if !ctx.internal && !restore_authorization_target(ctx, spare)? {
        return Ok(false);
    }
    let submission = ctx.internal && crate::challenge::is_submission(&ctx.request);
    if submission {
        telemetry::observe_submission(ctx);
    }
    if server.bans.is_banned_hashed(ctx.client_hash, ctx.now) {
        if submission {
            telemetry::observe_banned_submission(ctx);
        }
        server.metrics.banned.bump();
        telemetry::record_outcome(ctx, Outcome::Banned, 403);
        let text = "Forbidden: address is banned";
        pages::respond(ctx, Page::Banned, Status::Forbidden, text, PageExtra::default())?;
        return Ok(ctx.keep_alive);
    }
    if ctx.internal {
        if crate::challenge::is_work(&ctx.request) {
            // Issuance and verification bypass policy, so they spend a budget of their own,
            // in a table of its own that challenge traffic cannot crowd request cells out of.
            let budget = RateLimits {
                rate: server.config.challenge_rate_limit,
                window_ms: server.config.rate_window_seconds.saturating_mul(1000),
            };
            let limiter = &server.challenge_rate_limiter;
            let spend = check_rate(ctx, limiter, DEFAULT_SCOPE, budget);
            if spend.limited {
                return rate_limited(ctx, spend, 0);
            }
        }
        crate::routes::handle_internal(ctx)?;
        return Ok(ctx.keep_alive);
    }
    let limits = RateLimits {
        rate: server.config.rate_limit,
        window_ms: server.config.rate_window_seconds.saturating_mul(1000),
    };
    // An edge topology may leave pacing to the policy rules (`http.rate_limit: "off"`).
    if !server.unlimited {
        let rate = check_rate(ctx, &server.rate_limiter, DEFAULT_SCOPE, limits);
        if rate.limited {
            return rate_limited(ctx, rate, 0);
        }
    }
    // The policy of the frontend or route may answer at once (SID 0019).
    if let Some(answered) = crate::traffic::intercept(ctx) {
        return answered;
    }
    // A frontend or route with `"firewall": false` only balances load: no policy,
    // challenge or WAF decision applies to it. Bans and the request limiter above do.
    if let (Some(routes), Some(ingress)) = (&server.edge_routes, ctx.ingress)
        && !routes.firewall_applies(
            ingress.vip,
            ctx.request.header(b"host").unwrap_or_default(),
            ctx.request.path,
        )
    {
        // Origin selection checks that the routes belong to the current publication.
        ctx.cache.refresh(&server.slot);
        return forward(ctx, "PASS", BYPASS_RULE, sibuna_challenge::rule_hash(BYPASS_RULE));
    }
    apply_policy(ctx)
}

/// Records one arrival of the client in `limiter` within `scope`, counting an eviction.
fn check_rate<W: Write>(
    ctx: &Ctx<'_, W>,
    limiter: &RateLimiter,
    scope: u64,
    limits: RateLimits,
) -> RateDecision {
    let decision = limiter.check_hashed(ctx.client_hash, scope, ctx.now_ms, limits);
    if decision.evicted {
        ctx.server.metrics.rate_evictions.bump();
    }
    decision
}

/// Bans the client until `until` and counts the ban; a ban the table refuses (every slot
/// the key may take holds a ban in effect) is counted in `bans_refused` instead. Returns
/// whether the ban was recorded.
pub(crate) fn ban_client<W: Write>(ctx: &Ctx<'_, W>, until: u64) -> bool {
    let metrics = &ctx.server.metrics;
    match ctx.server.bans.ban_hashed(ctx.client_hash, until, ctx.now) {
        Ok(()) => {
            metrics.bans_issued.bump();
            if let Some(feed) = ctx.server.ban_feed.get() {
                let prefix = ctx.server.config.ipv6_prefix;
                let key =
                    crate::context::ClientKey::new(ctx.client_ip, ctx.client_address, prefix);
                feed.publish(key.as_bytes(), until);
            }
            true
        }
        Err(_) => {
            metrics.bans_refused.bump();
            false
        }
    }
}

/// Answers 429 with `Retry-After`. A rule's quota may also ban the address for
/// `ban_seconds`.
pub(crate) fn rate_limited<W: Write>(
    ctx: &mut Ctx<'_, W>,
    rate: RateDecision,
    ban_seconds: u32,
) -> io::Result<bool> {
    let server = ctx.server;
    server.metrics.rate_limited.bump();
    telemetry::record_outcome(ctx, Outcome::RateLimited, 429);
    let mut ban = u64::from(ban_seconds);
    if ban != 0 && !ban_client(ctx, ctx.now.saturating_add(ban)) {
        ban = 0;
    }
    let retry_seconds = ban.max(rate.retry_after_ms.div_ceil(1000));
    let mut buffer = [0u8; 64];
    let headers = format_into(&mut buffer, format_args!("Retry-After: {retry_seconds}\r\n"));
    let extra = PageExtra {
        headers,
        retry_after: u32::try_from(retry_seconds).unwrap_or(u32::MAX),
        ..PageExtra::default()
    };
    let text = "Rate limit exceeded";
    pages::respond(ctx, Page::RateLimited, Status::TooManyRequests, text, extra)?;
    Ok(ctx.keep_alive)
}

/// Writes formatted text into `buffer` and returns it; text that does not fit is cut.
pub(crate) fn format_into<'b>(
    buffer: &'b mut [u8],
    arguments: std::fmt::Arguments<'_>,
) -> &'b [u8] {
    let capacity = buffer.len();
    let mut cursor = &mut buffer[..];
    let _ = cursor.write_fmt(arguments);
    let written = capacity - cursor.len();
    buffer.get(..written).unwrap_or_default()
}

/// A policy decision copied out of the engine, so the response can be written after the
/// engine reference is released (a slow client must not hold a snapshot).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Verdict {
    pub action: Action,
    pub difficulty: u32,
    pub algorithm: Option<Algorithm>,
    pub audited: u8,
    pub limits: Option<Limits>,
    pub limit_scope: u64,
    rule: [u8; MAX_RULE_NAME],
    rule_len: usize,
}

impl Verdict {
    /// Copies what the response needs out of `decision`.
    pub(crate) fn of(decision: &sibuna_policy::Decision<'_>) -> Verdict {
        let mut rule = [0u8; MAX_RULE_NAME];
        let name = decision.rule_name;
        // Rule names are at most 128 bytes (the engine refuses longer ones); a longer
        // built-in name would be cut at a character boundary.
        let mut rule_len = name.len().min(MAX_RULE_NAME);
        while !name.is_char_boundary(rule_len) {
            rule_len -= 1;
        }
        rule[..rule_len].copy_from_slice(&name.as_bytes()[..rule_len]);
        Verdict {
            action: decision.action,
            difficulty: decision.difficulty,
            algorithm: decision.algorithm,
            audited: decision.audited,
            limits: decision.limits,
            limit_scope: decision.limit_scope,
            rule,
            rule_len,
        }
    }

    /// The deciding rule's name.
    pub fn rule_name(&self) -> &str {
        std::str::from_utf8(&self.rule[..self.rule_len]).unwrap_or_default()
    }

    /// True for the actions a session may clear.
    pub fn is_challenge(&self) -> bool {
        matches!(self.action, Action::Challenge | Action::Weigh)
    }
}

/// Converts the request's fields into the engine's view of them.
pub(crate) fn policy_headers<'r>(
    request: &Request<'r>,
    out: &mut [Header<'r>; sibuna_http::MAX_HEADERS],
) -> usize {
    let mut count = 0;
    for (slot, field) in out.iter_mut().zip(request.headers()) {
        *slot = Header { name: field.name, value: field.value };
        count += 1;
    }
    count
}

/// Evaluates the request with the current engine (recording rule hits with the console).
fn request_verdict<W: Write>(ctx: &mut Ctx<'_, W>) -> Verdict {
    let mut fields = [Header::default(); sibuna_http::MAX_HEADERS];
    let count = policy_headers(&ctx.request, &mut fields);
    let view = RequestView {
        path: ctx.request.path,
        query: ctx.request.query,
        client_ip: ctx.client_ip,
        client_address: ctx.client_address,
        user_agent: ctx.user_agent,
        ja4: ctx.ja4,
        headers: fields.get(..count).unwrap_or_default(),
        body: ctx.request.body,
    };
    telemetry::evaluate(ctx.cache, &ctx.server.slot, &view)
}

/// Evaluates a protected request that is described rather than present (the interstitial's
/// reported URL, an ingress error page's original URI) with this request's identity and
/// headers.
pub(crate) fn target_verdict<W: Write>(
    ctx: &mut Ctx<'_, W>,
    path: &[u8],
    query: &[u8],
) -> Verdict {
    let mut fields = [Header::default(); sibuna_http::MAX_HEADERS];
    let count = policy_headers(&ctx.request, &mut fields);
    let view = RequestView {
        path,
        query,
        client_ip: ctx.client_ip,
        client_address: ctx.client_address,
        user_agent: ctx.user_agent,
        ja4: ctx.ja4,
        headers: fields.get(..count).unwrap_or_default(),
        body: b"",
    };
    let engine: &Engine = ctx.cache.refresh(&ctx.server.slot);
    Verdict::of(&engine.evaluate(&view))
}

fn apply_policy<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<bool> {
    let verdict = request_verdict(ctx);
    crate::incidents::record_audit_findings(ctx, verdict.audited);
    let result = answer_verdict(ctx, &verdict);
    // Findings held back for the origin's head are recorded on every other exit as well.
    telemetry::flush_findings(ctx);
    result
}

fn answer_verdict<W: Write>(ctx: &mut Ctx<'_, W>, verdict: &Verdict) -> io::Result<bool> {
    let server = ctx.server;
    if let Some(limits) = verdict.limits {
        let window_ms = u64::from(limits.window_seconds) * 1000;
        let quota = RateLimits { rate: limits.rate, window_ms };
        let rate = check_rate(ctx, &server.rule_rate_limiter, verdict.limit_scope, quota);
        if rate.limited {
            return rate_limited(ctx, rate, limits.ban_seconds);
        }
    }
    // A session clears an admission challenge whose work it already paid: the token's level
    // must reach what this route demands. WAF and explicit denials are never cleared, and a
    // cheaper session falls through to the stronger challenge instead of admitting.
    if verdict.is_challenge()
        && let Some(rule_hash) = crate::challenge::session_rule_hash(ctx, verdict)
    {
        return forward(ctx, "PASS", "session", rule_hash);
    }
    match verdict.action {
        Action::Allow => {
            let rule_hash = sibuna_challenge::rule_hash(verdict.rule_name());
            forward(ctx, "PASS", verdict.rule_name(), rule_hash)
        }
        Action::Deny => {
            server.metrics.denied.bump();
            telemetry::record_outcome(ctx, Outcome::Denied, 403);
            if verdict.rule_name().starts_with("waf:") {
                crate::incidents::record_incident(ctx, verdict.rule_name());
            }
            let extra = PageExtra { reason: verdict.rule_name(), ..PageExtra::default() };
            let text = "Forbidden: blocked by Sibuna policy";
            pages::respond(ctx, Page::Denied, Status::Forbidden, text, extra)?;
            Ok(ctx.keep_alive)
        }
        Action::Challenge | Action::Weigh => {
            server.metrics.challenged.bump();
            telemetry::record_outcome(ctx, Outcome::Challenged, 401);
            crate::challenge::write_challenged(ctx, verdict)?;
            Ok(ctx.keep_alive)
        }
    }
}

/// Restores ingress metadata for external authorization requests before any decision; the
/// original path is normalised into `spare`. Returns false after answering 400 for invalid
/// metadata.
fn restore_authorization_target<'c, W: Write>(
    ctx: &mut Ctx<'c, W>,
    spare: &'c mut [u8],
) -> io::Result<bool> {
    let config = &ctx.server.config;
    if !is_forward_auth(config) {
        return Ok(true);
    }
    match forwarded::target(&ctx.request, config.trusts_forwarded(), spare) {
        Ok(Some(original)) => {
            original.apply(&mut ctx.request);
            Ok(true)
        }
        Ok(None) => Ok(true),
        Err(_) => {
            response::write_400(ctx.writer, b"Invalid forwarded request metadata")?;
            Ok(false)
        }
    }
}

/// Hands an admitted request to the origin (reverse proxy) or answers the ingress (forward
/// authorization).
pub(crate) fn forward<W: Write>(
    ctx: &mut Ctx<'_, W>,
    status: &str,
    rule_name: &str,
    rule_hash: u64,
) -> io::Result<bool> {
    let server = ctx.server;
    server.metrics.allowed.bump();
    telemetry::count_outcome(ctx, Outcome::Admitted);
    if is_forward_auth(&server.config) {
        return forward_auth(ctx, status, rule_name, rule_hash);
    }
    let (selected, tunnel) = match select_origin(ctx) {
        Ok(selected) => selected,
        Err(status) => {
            response::write_text(ctx.writer, status, status.reason().as_bytes(), false)?;
            return Ok(false);
        }
    };
    server.metrics.proxied.bump();
    crate::access::selected(ctx, selected.as_ref());
    if ctx.defer.is_some() {
        return plan(ctx, status, rule_name, selected, tunnel);
    }
    if ctx.request.header(b"upgrade").is_some() {
        // An upgraded connection may live for hours; it must not pin this snapshot.
        ctx.cache.release();
    }
    // Only a planned request has no client socket, and it returned above.
    let Some(stream) = ctx.stream else { return Ok(false) };
    let config = &server.config;
    let mut origin_status = 0u16;
    let status_sink = telemetry::origin_status_sink(ctx, &mut origin_status);
    // A capture buffer only when audit findings wait for the origin's head (console).
    let mut origin = telemetry::origin_head(ctx);
    let capturing = origin.is_some();
    let extra_headers = &config.console_capture_headers;
    let mut capture = |raw: &[u8]| {
        if let Some(origin) = origin.as_mut() {
            origin.capture(raw, extra_headers);
        }
    };
    let head_sink: Option<sibuna_net::HeadSink<'_>> =
        if capturing { Some(&mut capture) } else { None };
    let exchange = Exchange {
        client: Client {
            stream,
            pending: ctx.pending,
            writer: &mut *ctx.writer,
            activity: Some(ctx.activity),
            websocket_idle_timeout_seconds: config.websocket_idle_timeout_seconds,
        },
        upstream_host: &config.upstream_host,
        upstream_port: config.upstream_port,
        request: &ctx.request,
        upload: ctx.upload,
        audit: Audit {
            client_ip: ctx.client_ip,
            peer: ctx.peer,
            trusts_forwarded: config.trusts_forwarded(),
            ja4_header: config.ja4_header.as_deref().unwrap_or_default().as_bytes(),
            client_cert: ctx.ingress.and_then(|i| i.cert),
            status: status.as_bytes(),
            rule: rule_name.as_bytes(),
            scheme: if ctx.ingress.is_some_and(|i| i.secure) {
                b"https"
            } else {
                forwarded::scheme(&ctx.request, config.trusts_forwarded()).as_bytes()
            },
            response_status: status_sink,
            response_head: head_sink,
            ..crate::traffic::audit(&ctx.request, ctx.ingress, selected.as_ref())
        },
        keep_alive: ctx.keep_alive,
    };
    let relayed = relay(&server.pool, ctx.workspace, exchange, selected.as_ref());
    telemetry::admitted_complete(ctx, origin_status, origin.as_ref());
    // The tunnel has ended by now, so its place under the rule is free.
    drop(tunnel);
    relayed.or_else(|error| refuse_proxy_error(ctx, error))
}

/// Counts a failed exchange and answers it. The connection closes after the answer.
fn refuse_proxy_error<W: Write>(ctx: &mut Ctx<'_, W>, error: ProxyError) -> io::Result<bool> {
    ctx.server.metrics.upstream_errors.bump();
    answer_proxy_error(ctx.writer, error)?;
    Ok(false)
}

/// The scratch space an event-driven worker lends to a dispatch (SID 0016).
#[derive(Default)]
pub(crate) struct Defer {
    /// The origin request of the admitted request: its head and buffered body.
    pub wire: Vec<u8>,
    /// Set when the request was admitted.
    pub plan: Option<Plan>,
}

/// What a worker needs to carry out an admitted request.
pub(crate) struct Plan {
    /// The server reservation. It records the outcome and is released when dropped.
    pub target: sibuna_lb::HttpTarget,
    /// The framing of the request and what remains of its body.
    pub outbound: sibuna_net::machine::Outbound,
    /// The client asked to keep its connection.
    pub keep_alive: bool,
    /// The place of an upgrade under its WebSocket rule, held while the exchange lives.
    pub tunnel: Option<sibuna_lb::TunnelPermit>,
    /// The body bytes that were buffered with the head, for `max_body` (SID 0019).
    pub body_seen: u64,
}

/// Plans an admitted request in place of relaying it: encodes the origin request and
/// hands the reservation to the worker. A request without a selected server is refused.
fn plan<W: Write>(
    ctx: &mut Ctx<'_, W>,
    status: &str,
    rule_name: &str,
    selected: Option<sibuna_lb::HttpTarget>,
    tunnel: Option<sibuna_lb::TunnelPermit>,
) -> io::Result<bool> {
    let Some(target) = selected else {
        let status = Status::ServiceUnavailable;
        response::write_text(ctx.writer, status, status.reason().as_bytes(), false)?;
        return Ok(false);
    };
    let config = &ctx.server.config;
    let audit = Audit {
        client_ip: ctx.client_ip,
        peer: ctx.peer,
        trusts_forwarded: config.trusts_forwarded(),
        ja4_header: config.ja4_header.as_deref().unwrap_or_default().as_bytes(),
        client_cert: ctx.ingress.and_then(|i| i.cert),
        status: status.as_bytes(),
        rule: rule_name.as_bytes(),
        scheme: if ctx.ingress.is_some_and(|i| i.secure) {
            b"https"
        } else {
            forwarded::scheme(&ctx.request, config.trusts_forwarded()).as_bytes()
        },
        response_status: None,
        response_head: None,
        // The response edit is unused here: a worker edits the head when it relays it.
        ..crate::traffic::audit(&ctx.request, ctx.ingress, Some(&target))
    };
    let Some(defer) = ctx.defer.as_deref_mut() else { return Ok(false) };
    defer.wire.clear();
    match sibuna_net::machine::encode_request(&mut defer.wire, &ctx.request, ctx.upload, &audit) {
        Ok(outbound) => {
            let body_seen = ctx.request.body.len() as u64;
            let keep_alive = ctx.keep_alive;
            defer.plan = Some(Plan { target, outbound, keep_alive, tunnel, body_seen });
            Ok(ctx.keep_alive)
        }
        Err(error) => refuse_proxy_error(ctx, error),
    }
}

fn edge_host<'a, W>(ctx: &'a Ctx<'_, W>) -> Result<&'a [u8], Status> {
    let mut hosts = ctx.request.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(b"host"));
    let host = hosts.next().map_or(&[][..], |h| h.value);
    if hosts.next().is_some()
        || (host.is_empty() && ctx.request.version == sibuna_http::Version::Http11)
        || (!host.is_empty() && !sibuna_lb::valid_authority(host))
    {
        return Err(Status::BadRequest);
    }
    Ok(host)
}

/// The server of an admitted request and, for an upgrade, its place under the tunnel rule.
type Selected = (Option<sibuna_lb::HttpTarget>, Option<sibuna_lb::TunnelPermit>);

fn select_origin<W>(ctx: &Ctx<'_, W>) -> Result<Selected, Status> {
    let (Some(routes), Some(i)) = (&ctx.server.edge_routes, ctx.ingress) else {
        return Ok((None, None));
    };
    let host = ctx.request.header(b"host").unwrap_or_default();
    let path = ctx.request.path;
    // The rule applies whether or not the route uses the firewall.
    let tunnel = match ctx.request.header(b"upgrade") {
        Some(_) => routes.websocket(i.vip, host, path).map(|rule| {
            let client = ctx.client_address.unwrap_or(i.peer.ip());
            rule.admit(ctx.request.header(b"origin"), client).map_err(|refusal| match refusal {
                sibuna_lb::TunnelRefusal::Origin => Status::Forbidden,
                sibuna_lb::TunnelRefusal::Limit => Status::TooManyRequests,
            })
        }),
        None => None,
    };
    let tunnel = tunnel.transpose()?;
    crate::traffic::choose(ctx, routes, i)
        .map(|target| (Some(target), tunnel))
        .ok_or(Status::ServiceUnavailable)
}

fn relay<W: Write>(
    pool: &sibuna_net::Pool,
    workspace: &mut sibuna_net::Workspace,
    exchange: Exchange<'_, W>,
    selected: Option<&sibuna_lb::HttpTarget>,
) -> Result<bool, ProxyError> {
    if let Some(target) = selected {
        let start = std::time::Instant::now();
        let result = sibuna_net::stream_proxy_to(pool, workspace, exchange, target.address());
        match &result {
            Ok(_) => target.completed(start),
            Err(ProxyError::UpstreamUnreachable) => target.failed(),
            _ => {}
        }
        result
    } else {
        sibuna_net::stream_proxy(pool, workspace, exchange)
    }
}

pub(crate) fn answer_proxy_error<W: Write>(writer: &mut W, error: ProxyError) -> io::Result<()> {
    match error {
        ProxyError::InvalidUpgrade => response::write_400(writer, b"Invalid upgrade"),
        ProxyError::UpstreamUnreachable => {
            response::write_502(writer, b"Bad Gateway: upstream unreachable")
        }
        ProxyError::UpstreamReadFailed => {
            response::write_502(writer, b"Bad Gateway: malformed upstream response")
        }
        ProxyError::MalformedRequestBody => {
            response::write_400(writer, b"Malformed chunked request body")
        }
        ProxyError::UpstreamWriteFailed
        | ProxyError::UpstreamClosed
        | ProxyError::UpstreamTruncated
        | ProxyError::ClientFailed => Ok(()),
    }
}

/// Forward authorization approves the request for the ingress to relay.
fn forward_auth<W: Write>(
    ctx: &mut Ctx<'_, W>,
    status: &str,
    rule_name: &str,
    rule_hash: u64,
) -> io::Result<bool> {
    telemetry::sample_outcome(ctx, Outcome::Admitted, 200);
    telemetry::forward_complete(ctx);
    let mut buffer = [0u8; 256];
    let headers = format_into(
        &mut buffer,
        format_args!(
            "X-Sibuna-Status: {status}\r\nX-Sibuna-Rule: {rule_name}\r\n\
             X-Sibuna-Rule-Hash: {rule_hash:x}\r\n"
        ),
    );
    let extra = Extra { headers, keep_alive: ctx.keep_alive, ..Extra::default() };
    response::write_response(ctx.writer, Status::Ok, b"text/plain; charset=utf-8", b"OK", extra)?;
    Ok(ctx.keep_alive)
}

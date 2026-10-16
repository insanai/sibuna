//! Incidents handed to the storage layer: WAF denials, honeypot hits and audit findings.
//! The hook copies what it keeps into a bounded ring, so recording never allocates or
//! blocks the request.

use std::io::Write;

use sibuna_core::Incident;
use sibuna_core::incident::ResponseState;
use sibuna_http::Method;
use sibuna_policy::inspection::{audit_name, bit};
use sibuna_policy::waf::AttackCategory;

use crate::context::Ctx;
use crate::telemetry;

/// The longest forensic payload recorded.
const MAX_PAYLOAD: usize = 2048;

/// The response side of an incident's evidence: the origin's redacted head, if one was
/// captured, and how the response was observed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ResponseEvidence<'a> {
    /// The redacted origin response head; empty without one.
    pub head: &'a [u8],
    /// The head was cut at its capacity.
    pub truncated: bool,
    /// How the response was observed.
    pub state: ResponseState,
}

impl ResponseEvidence<'_> {
    /// A response the daemon answered itself.
    pub(crate) const LOCAL: ResponseEvidence<'static> =
        ResponseEvidence { head: b"", truncated: false, state: ResponseState::Local };
}

/// Records a denial or honeypot hit in `category`, with the query (or else the body) as its
/// forensic payload. With the console, the incident carries its evidence envelope and,
/// when heads are captured, the redacted request head.
pub(crate) fn record_incident<W: Write>(ctx: &Ctx<'_, W>, category: &str) {
    let Some(hook) = ctx.server.hooks.record_incident.as_ref() else { return };
    let request = &ctx.request;
    let payload = if request.query.is_empty() { request.body } else { request.query };
    let mut buffer = None;
    let (request_head, request_truncated) = telemetry::request_head(ctx, &mut buffer);
    let incident = Incident {
        client_ip: text(ctx.client_ip),
        user_agent: ctx.user_agent,
        ja4: ctx.ja4.map(|fingerprint| fingerprint.as_str()),
        method: method_name(request.method),
        path: request.path,
        category,
        payload: payload.get(..payload.len().min(MAX_PAYLOAD)).unwrap_or_default(),
        now: ctx.now,
        evidence: telemetry::denial_evidence(ctx),
        request_head,
        request_truncated,
        response_state: ResponseState::Local,
        ..Incident::default()
    };
    hook(&incident);
}

/// Records one incident per audited WAF category in `findings`, or, while the console
/// captures heads, holds them back until the response side is known.
pub(crate) fn record_audit_findings<W: Write>(ctx: &mut Ctx<'_, W>, findings: u8) {
    if findings == 0 || telemetry::defer_findings(ctx, findings) {
        return;
    }
    record_findings(ctx, findings, ResponseEvidence::LOCAL);
}

/// Records one incident per audited WAF category in `findings` with `response` as its
/// response evidence. An audit finding is not a response outcome: it keeps no raw query or
/// body payload.
pub(crate) fn record_findings<W: Write>(
    ctx: &Ctx<'_, W>,
    findings: u8,
    response: ResponseEvidence<'_>,
) {
    let Some(hook) = ctx.server.hooks.record_incident.as_ref() else { return };
    let mut buffer = None;
    let (request_head, request_truncated) = telemetry::request_head(ctx, &mut buffer);
    for category in AttackCategory::ALL {
        if findings & bit(category) == 0 {
            continue;
        }
        hook(&Incident {
            client_ip: text(ctx.client_ip),
            user_agent: ctx.user_agent,
            ja4: ctx.ja4.map(|fingerprint| fingerprint.as_str()),
            method: method_name(ctx.request.method),
            path: ctx.request.path,
            category: audit_name(category),
            payload: b"",
            now: ctx.now,
            request_head,
            request_truncated,
            response_head: response.head,
            response_truncated: response.truncated,
            response_state: response.state,
            ..Incident::default()
        });
    }
}

/// The method's name as the Zig daemon wrote it (`@tagName` of its method enum).
pub(crate) fn method_name(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Head => "HEAD",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Options => "OPTIONS",
        Method::Patch => "PATCH",
        Method::Other => "OTHER",
    }
}

/// The client address as text: its longest valid UTF-8 prefix (an address read from a
/// forwarded header is not checked to be one).
fn text(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_keep_their_valid_prefix() {
        assert_eq!(text(b"203.0.113.1"), "203.0.113.1");
        assert_eq!(text(b"10.\xff1"), "10.");
        assert_eq!(method_name(Method::Other), "OTHER");
    }
}

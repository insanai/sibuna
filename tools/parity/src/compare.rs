//! Compares what the two daemons answered to one scenario, after masking the values that
//! are random or time-dependent by design.
//!
//! The masks, each for a documented reason:
//!
//! - `"id":"..."` in an issued challenge: the identifier carries a random nonce and the
//!   issue time (SID 0006, Part C).
//! - `"expires_at":N`: the issue time plus the challenge lifetime.
//! - `need=...` and `data-ticket="..."`: requirement tickets are sealed with a random
//!   nonce and the issue time.
//! - `Reference <16 hex digits>` on HTML pages: a random request reference.
//! - The value of the session cookie (`Set-Cookie`, and in the origin's echo of a
//!   forwarded `Cookie`): the token holds the issue time and the random challenge it paid
//!   for; its attributes (`Max-Age`, `Path`, `Secure`, ...) are compared.
//! - `Content-Length` when the body held a masked value: masked values may differ in
//!   length. Each side's length is first checked against its own body.
//! - When the bodies differ, `Content-Length` is checked against each side's own body and
//!   the difference is reported once, as the body's.
//! - The difference between a FIN and a reset when a daemon closes: which one the kernel
//!   sends depends on unread bytes at the time of the close, which is timing.
//!
//! The origin's echo masks the session cookie itself (see `origin.rs`).

use crate::client::{Exchange, Transcript};
use crate::configs::COOKIE_NAME;
use crate::response::{Event, Response, find};

/// One field that differs between the daemons' answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// The connection's index in the scenario.
    pub connection: usize,
    /// The request's index on its connection.
    pub step: usize,
    /// What differs: `status`, `header:<name>`, `body`, `origin` (the echo of what the
    /// origin received), `framing`, `event`, `events`, `exchanges` or `connect`.
    pub field: String,
    /// The Zig daemon's (masked) value.
    pub zig: String,
    /// The Rust daemon's (masked) value.
    pub rust: String,
}

/// Masks the body markers listed in the module documentation. Returns the masked text
/// and whether anything was masked.
pub fn mask_body(body: &[u8]) -> (Vec<u8>, bool) {
    let cookie = format!("{COOKIE_NAME}=");
    let rules: [(&[u8], &[u8], &str); 6] = [
        (b"\"id\":\"", b"\"", "<challenge-id>"),
        (b"\"expires_at\":", b"},", "<time>"),
        (b"need=", b"\"&", "<ticket>"),
        (b"data-ticket=\"", b"\"", "<ticket>"),
        (b"Reference ", b" <", "<request-ref>"),
        (cookie.as_bytes(), b";\r\n", "<token>"),
    ];
    let mut text = body.to_vec();
    let mut changed = false;
    for (marker, ends, replacement) in rules {
        let (masked, hit) = mask_after(&text, marker, ends, replacement.as_bytes());
        text = masked;
        changed |= hit;
    }
    (text, changed)
}

/// Replaces the text after each `marker` up to the next byte in `ends` by `replacement`.
fn mask_after(text: &[u8], marker: &[u8], ends: &[u8], replacement: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    let mut hit = false;
    while let Some(at) = find(rest, marker) {
        let start = at + marker.len();
        out.extend_from_slice(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.iter().position(|byte| ends.contains(byte)).unwrap_or(tail.len());
        if tail[..end] != *replacement {
            out.extend_from_slice(replacement);
            hit = true;
        }
        rest = &tail[end..];
    }
    out.extend_from_slice(rest);
    (out, hit)
}

/// A response with the masks applied: headers sorted (the comparison is over the set of
/// fields), the body masked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Masked {
    /// The status line.
    pub status_line: String,
    /// `(lower-case name, value)` pairs, sorted.
    pub headers: Vec<(String, String)>,
    /// The masked body.
    pub body: Vec<u8>,
    /// The framing's name.
    pub framing: &'static str,
}

/// Applies the masks to `response`.
pub fn mask_response(response: &Response) -> Masked {
    let (body, body_masked) = mask_body(&response.body);
    let cookie = format!("{COOKIE_NAME}=");
    let mut headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            let value = if name == "set-cookie" && value.starts_with(&cookie) {
                let attributes = value.find(';').map_or("", |at| &value[at..]);
                format!("{cookie}<token>{attributes}")
            } else if name == "content-length" && body_masked {
                let consistent = value.trim().parse::<usize>().ok() == Some(response.body.len());
                if consistent { "<checked>".to_owned() } else { value.clone() }
            } else {
                value.clone()
            };
            (name, value)
        })
        .collect();
    headers.sort();
    Masked {
        status_line: response.status_line.clone(),
        headers,
        body,
        framing: response.framing.name(),
    }
}

/// Compares two transcripts of one scenario.
pub fn compare(zig: &Transcript, rust: &Transcript) -> Vec<Difference> {
    let mut differences = Vec::new();
    if zig.connect_error != rust.connect_error {
        differences.push(Difference {
            connection: 0,
            step: 0,
            field: "connect".into(),
            zig: zig.connect_error.clone().unwrap_or_default(),
            rust: rust.connect_error.clone().unwrap_or_default(),
        });
    }
    for (connection, (ours, theirs)) in zig.connections.iter().zip(&rust.connections).enumerate() {
        compare_connection(connection, ours, theirs, &mut differences);
    }
    if zig.connections.len() != rust.connections.len() {
        differences.push(Difference {
            connection: zig.connections.len().min(rust.connections.len()),
            step: 0,
            field: "connections".into(),
            zig: zig.connections.len().to_string(),
            rust: rust.connections.len().to_string(),
        });
    }
    differences
}

fn compare_connection(
    connection: usize,
    zig: &[Exchange],
    rust: &[Exchange],
    out: &mut Vec<Difference>,
) {
    for (step, (a, b)) in zig.iter().zip(rust).enumerate() {
        let count = a.events.len().max(b.events.len());
        for index in 0..count {
            let (left, right) = (a.events.get(index), b.events.get(index));
            for (field, zig, rust) in compare_events(left, right) {
                out.push(Difference { connection, step, field, zig, rust });
            }
        }
    }
    if zig.len() != rust.len() {
        let describe = |exchanges: &[Exchange]| format!("{} requests answered", exchanges.len());
        out.push(Difference {
            connection,
            step: zig.len().min(rust.len()),
            field: "exchanges".into(),
            zig: describe(zig),
            rust: describe(rust),
        });
    }
}

/// What a daemon answered to request `step` of connection `connection`: each event's kind
/// joined by ` + `, or `nothing` when the request was not sent.
pub fn answer_of(transcript: &Transcript, connection: usize, step: usize) -> String {
    let exchange = transcript.connections.get(connection).and_then(|list| list.get(step));
    match exchange {
        None => "nothing".into(),
        Some(exchange) => {
            let kinds: Vec<String> =
                exchange.events.iter().map(|event| kind(Some(event))).collect();
            kinds.join(" + ")
        }
    }
}

/// The kind of an event, for a kind mismatch.
fn kind(event: Option<&Event>) -> String {
    match event {
        None => "nothing".into(),
        Some(Event::Response(response)) => format!("response {}", response.status_line),
        Some(Event::Closed) => "connection closed".into(),
        Some(Event::Timeout(bytes)) => format!("timeout after {} bytes", bytes.len()),
        Some(Event::Garbage(bytes)) => format!("non-response bytes {}", escape(bytes, 200)),
    }
}

/// The differing fields of two events as `(field, zig, rust)`.
fn compare_events(zig: Option<&Event>, rust: Option<&Event>) -> Vec<(String, String, String)> {
    match (zig, rust) {
        (Some(Event::Response(a)), Some(Event::Response(b))) => compare_responses(a, b),
        (Some(Event::Closed), Some(Event::Closed)) => Vec::new(),
        (Some(Event::Timeout(a)), Some(Event::Timeout(b)))
        | (Some(Event::Garbage(a)), Some(Event::Garbage(b))) => {
            let (a, _) = mask_body(a);
            let (b, _) = mask_body(b);
            if a == b {
                Vec::new()
            } else {
                vec![("bytes".into(), escape(&a, 4096), escape(&b, 4096))]
            }
        }
        _ => vec![("event".into(), kind(zig), kind(rust))],
    }
}

fn compare_responses(zig: &Response, rust: &Response) -> Vec<(String, String, String)> {
    let (a, b) = (mask_response(zig), mask_response(rust));
    let mut out = Vec::new();
    if a.status_line != b.status_line {
        out.push(("status".into(), a.status_line.clone(), b.status_line.clone()));
    }
    let mut names: Vec<&str> =
        a.headers.iter().chain(&b.headers).map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    // When the bodies differ, so may their lengths: each length is then only checked
    // against its own body, and the body difference is reported once.
    let consistent = |response: &Response| {
        response.header("content-length").and_then(|v| v.trim().parse::<usize>().ok())
            == Some(response.body.len())
    };
    let lengths_follow_bodies = a.body != b.body && consistent(zig) && consistent(rust);
    for name in names {
        if name == "content-length" && lengths_follow_bodies {
            continue;
        }
        let values = |masked: &Masked| {
            let list: Vec<&str> = masked
                .headers
                .iter()
                .filter(|(field, _)| field == name)
                .map(|(_, value)| value.as_str())
                .collect();
            if list.is_empty() { "<absent>".to_owned() } else { list.join(" | ") }
        };
        let (left, right) = (values(&a), values(&b));
        if left != right {
            out.push((format!("header:{name}"), left, right));
        }
    }
    if a.framing != b.framing {
        out.push(("framing".into(), a.framing.into(), b.framing.into()));
    }
    if a.body != b.body {
        let echo = a.body.starts_with(b"ORIGIN\n") && b.body.starts_with(b"ORIGIN\n");
        let field = if echo { "origin" } else { "body" };
        out.push((field.into(), escape(&a.body, 8192), escape(&b.body, 8192)));
    }
    out
}

/// Renders bytes for a report: printable ASCII as is, line breaks kept, everything else
/// as `\xHH`, cut after `limit` bytes.
pub fn escape(bytes: &[u8], limit: usize) -> String {
    let mut out = String::with_capacity(bytes.len().min(limit) + 16);
    for &byte in bytes.iter().take(limit) {
        match byte {
            b'\n' => out.push_str("\\n\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            0x20..0x7f => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    if bytes.len() > limit {
        out.push_str(&format!("... ({} bytes in all)", bytes.len()));
    }
    out
}

#[cfg(test)]
mod tests;

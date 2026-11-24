//! Automatic HTTPS in the daemon (SID 0021): the answer to an HTTP-01 challenge, the
//! redirect to HTTPS, the log lines of the certificate thread, and the text of
//! `show certs` and of the metrics.
//!
//! ```text
//!   request on any HTTP frontend
//!     |
//!     +-- GET /.well-known/acme-challenge/TOKEN, answer known --> 200, the answer
//!     +-- plain HTTP, Host is a managed name ------------------> 308, https://HOST/...
//!     +-- anything else ---------------------------------------> the firewall
//! ```
//!
//! Both answers are written before any firewall decision. A ban or a challenge page must
//! not keep the certificate authority from validating a name.

use std::fmt::Write as _;
use std::io::{self, Write};

use sibuna_core::diagnostic;
use sibuna_http::response::{self, Extra, Status};
use sibuna_ingress::{Automatic, CertificateStatus, Event};

use crate::context::Ctx;
use crate::telemetry::{self, Outcome};

/// The path prefix of an HTTP-01 challenge (RFC 8555, section 8.3).
const CHALLENGE_PREFIX: &[u8] = b"/.well-known/acme-challenge/";
/// The longest `Location` we write. A longer target is left to the firewall.
const MAX_LOCATION: usize = 4096;

/// Seconds since 1970.
pub(crate) fn unix_now() -> u64 {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    elapsed.map_or(0, |elapsed| elapsed.as_secs())
}

/// Answers a request that automatic HTTPS owns. Returns `None` for every other request,
/// and otherwise whether the connection may be kept.
pub(crate) fn intercept<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<Option<bool>> {
    let (Some(automatic), Some(ingress)) = (&ctx.server.automatic, ctx.ingress) else {
        return Ok(None);
    };
    let host = ctx.request.header(b"host").unwrap_or_default();
    let token = ctx.request.path.strip_prefix(CHALLENGE_PREFIX);
    if let Some(answer) = token.and_then(|token| automatic.challenge_answer(token, host)) {
        telemetry::record_outcome(ctx, Outcome::Other, Status::Ok.code());
        let extra = Extra { keep_alive: ctx.keep_alive, ..Extra::default() };
        let body = answer.as_bytes();
        response::write_response(ctx.writer, Status::Ok, b"text/plain", body, extra)?;
        return Ok(Some(ctx.keep_alive));
    }
    if ingress.secure {
        return Ok(None);
    }
    let Some(port) = automatic.redirect_port(host) else { return Ok(None) };
    let Some(header) = location(host, port, ctx.request.path, ctx.request.query) else {
        return Ok(None);
    };
    telemetry::record_outcome(ctx, Outcome::Other, Status::PermanentRedirect.code());
    let extra = Extra { headers: &header, keep_alive: ctx.keep_alive, ..Extra::default() };
    let content_type = b"text/plain; charset=utf-8";
    response::write_response(ctx.writer, Status::PermanentRedirect, content_type, b"", extra)?;
    Ok(Some(ctx.keep_alive))
}

/// The header line `Location: https://NAME[:PORT]PATH[?QUERY]`. The name is the host
/// without its port. Returns `None` for a target that is too long or holds a byte that
/// cannot stand in a header.
fn location(host: &[u8], port: u16, path: &[u8], query: &[u8]) -> Option<Vec<u8>> {
    let plain = |bytes: &[u8]| bytes.iter().all(|byte| (0x21..0x7f).contains(byte));
    let name = match host.iter().rposition(|byte| *byte == b':') {
        Some(colon) => &host[..colon],
        None => host,
    };
    let length = name.len() + path.len() + query.len();
    if length > MAX_LOCATION || !plain(name) || !plain(path) || !plain(query) {
        return None;
    }
    let mut line = Vec::with_capacity(length + 32);
    line.extend_from_slice(b"Location: https://");
    line.extend_from_slice(name);
    if port != 443 {
        line.extend_from_slice(format!(":{port}").as_bytes());
    }
    line.extend_from_slice(path);
    if !query.is_empty() {
        line.push(b'?');
        line.extend_from_slice(query);
    }
    line.extend_from_slice(b"\r\n");
    Some(line)
}

/// Writes an event of the certificate thread to standard error: one line for a
/// certificate, a diagnostic with a hint for a failure.
pub(crate) fn log(event: &Event) {
    let time = sibuna_acme::format_rfc3339;
    match event {
        Event::Obtained { name, not_after, renewed } => {
            let verb = if *renewed { "renewed" } else { "obtained" };
            eprintln!("ACME000: certificate for {name} {verb}, valid until {}", time(*not_after));
        }
        Event::Loaded { name, not_after } => {
            eprintln!(
                "ACME000: certificate for {name} loaded from storage, valid until {}",
                time(*not_after)
            );
        }
        Event::Failed { name, error, retry_at } => {
            let subject = match name {
                Some(name) => format!("No new certificate for `{name}`. "),
                None => String::new(),
            };
            let title = format!("{} ({})", error.title, error.code);
            let reason = error.message.trim_end();
            let stop = if reason.ends_with('.') { "" } else { "." };
            let message = format!(
                "{subject}{reason}{stop} The listeners keep serving. Next attempt at {}.",
                time(*retry_at)
            );
            let mut text = String::new();
            let _ = diagnostic::render(&mut text, &title, &message, &error.hint);
            eprint!("{text}");
        }
    }
}

/// The answer to `show certs`: one line per managed name under a header.
pub(crate) fn render_certs(certificates: &[CertificateStatus]) -> String {
    let time = |seconds: Option<u64>| seconds.map_or("-".to_owned(), sibuna_acme::format_rfc3339);
    let header = ["name", "issuer", "expires", "renews", "state", "error"];
    let mut rows = vec![header.map(str::to_owned)];
    for certificate in certificates {
        rows.push([
            certificate.name.clone(),
            // One word per column: a script splits the line at spaces.
            certificate
                .issuer
                .as_deref()
                .map_or("-".to_owned(), |issuer| issuer.replace(' ', "_")),
            time(certificate.not_after),
            time(certificate.next_attempt),
            certificate.state.word().to_owned(),
            certificate.error.clone().unwrap_or_else(|| "-".to_owned()),
        ]);
    }
    let mut widths = [0; 6];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut out = String::new();
    for row in &rows {
        for (index, (cell, width)) in row.iter().zip(widths).enumerate() {
            let _ = if index + 1 < row.len() {
                write!(out, "{cell:<width$} ")
            } else {
                writeln!(out, "{cell}")
            };
        }
    }
    out
}

/// Appends the series of automatic HTTPS to a metrics text. `now` is in seconds since
/// 1970. The expiry series is absent while no certificate is served.
pub(crate) fn write_metrics(automatic: &Automatic, now: u64, out: &mut String) {
    let certificates = automatic.status();
    let served = certificates.iter().filter(|certificate| certificate.not_after.is_some());
    let nearest = certificates.iter().filter_map(|certificate| certificate.not_after).min();
    let mut series = vec![
        ("sibuna_edge_acme_certificates_managed", "gauge", certificates.len() as u64),
        ("sibuna_edge_acme_certificates_served", "gauge", served.count() as u64),
        ("sibuna_edge_acme_failures_total", "counter", automatic.failure_count()),
    ];
    if let Some(nearest) = nearest {
        let left = nearest.saturating_sub(now);
        series.push(("sibuna_edge_acme_nearest_expiry_seconds", "gauge", left));
    }
    for (name, kind, value) in series {
        let _ = writeln!(out, "# TYPE {name} {kind}\n{name} {value}");
    }
}

#[cfg(test)]
mod tests {
    use sibuna_ingress::CertificateState;

    use super::*;

    fn text(host: &str, port: u16, path: &str, query: &str) -> Option<String> {
        location(host.as_bytes(), port, path.as_bytes(), query.as_bytes())
            .map(|line| String::from_utf8(line).unwrap())
    }

    #[test]
    fn the_location_keeps_the_path_and_the_query() {
        assert_eq!(
            text("example.org", 443, "/a/b", "x=1&y=2").as_deref(),
            Some("Location: https://example.org/a/b?x=1&y=2\r\n")
        );
        assert_eq!(
            text("example.org:80", 8443, "/", "").as_deref(),
            Some("Location: https://example.org:8443/\r\n")
        );
    }

    #[test]
    fn a_target_that_cannot_stand_in_a_header_is_not_redirected() {
        assert_eq!(text("example.org", 443, "/a\r\nSet-Cookie: x", ""), None);
        assert_eq!(text("example.org", 443, "/a b", ""), None);
        assert_eq!(text("example.org", 443, "/", "q=\x7f"), None);
        assert_eq!(text("example.org", 443, &"/".repeat(MAX_LOCATION), ""), None);
    }

    #[test]
    fn show_certs_is_a_table_with_one_word_per_column() {
        let ready = CertificateStatus {
            name: "example.org".to_owned(),
            issuer: Some("Test Authority".to_owned()),
            not_after: Some(1_800_000_000),
            next_attempt: Some(1_799_000_000),
            state: CertificateState::Ready,
            error: None,
        };
        let failing = CertificateStatus {
            name: "b.example.org".to_owned(),
            issuer: None,
            not_after: None,
            next_attempt: Some(1_799_000_120),
            state: CertificateState::Retry,
            error: Some("VALIDATION FAILED (ACME005)".to_owned()),
        };
        let table = render_certs(&[ready, failing]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("name "));
        let words: Vec<&str> = lines[1].split_ascii_whitespace().collect();
        assert_eq!(
            words,
            [
                "example.org",
                "Test_Authority",
                "2027-01-15T08:00:00Z",
                "2027-01-03T18:13:20Z",
                "ready",
                "-"
            ]
        );
        assert!(lines[2].ends_with("retry VALIDATION FAILED (ACME005)"));
    }
}

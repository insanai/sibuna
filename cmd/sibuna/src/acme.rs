//! Automatic HTTPS in the daemon (SID 0021): the answer to an HTTP-01 challenge, the
//! redirect to HTTPS, the log lines of the certificate thread, and the text of
//! `show certs` and of the metrics.
//!
//! ```text
//!   request on any HTTP frontend
//!     |
//!     +-- GET /.well-known/acme-challenge/TOKEN, answer known --> 200, the answer
//!     +-- for the ACME server of the local authority ----------> its reply (`serve`)
//!     +-- plain HTTP, Host is a managed name ------------------> 308, https://HOST/...
//!     |     (unless the route states `redirect_https` itself: SID 0019 then decides)
//!     +-- anything else ---------------------------------------> the firewall
//! ```
//!
//! Both answers are written before any firewall decision. A ban or a challenge page must
//! not keep the certificate authority from validating a name.

mod serve;

use std::fmt::Write as _;
use std::io::{self, Write};

use sibuna_core::diagnostic;
use sibuna_http::response::{self, Extra, Status};
use sibuna_ingress::{Automatic, CertificateStatus, Event};
use sibuna_lb::RoutePolicy;

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
    // The answer to a challenge of our own order came first: a server whose URL has
    // no path must not hide it.
    if let Some((server, config)) = automatic.acme_server() {
        let answered = serve::intercept(ctx, server, config, ingress.secure)?;
        if answered.is_some() {
            return Ok(answered);
        }
    }
    if ingress.secure {
        return Ok(None);
    }
    let Some(port) = automatic.redirect_port(host) else { return Ok(None) };
    let (path, query) = (ctx.request.path, ctx.request.query);
    // Where the operator states `redirect_https`, that statement decides (SID 0019):
    // `false` keeps the request on HTTP, and a redirect of its own is answered by the
    // traffic policy, with its status and port.
    let routes = ctx.server.edge_routes.as_ref();
    let stated = routes.and_then(|routes| routes.policy(ingress.vip, host, path));
    if stated.is_some_and(|policy| policy.keeps_http || policy.redirect_https.is_some()) {
        return Ok(None);
    }
    if !is_header_safe(path) || !is_header_safe(query) {
        return Ok(None);
    }
    crate::traffic::redirect(ctx, &RoutePolicy::redirect_to(port)).map(Some)
}

/// Whether `bytes` may stand in the `Location` of a redirect: printable ASCII without
/// a space, and not too long. Any other target is left to the firewall.
fn is_header_safe(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_LOCATION && bytes.iter().all(|byte| (0x21..0x7f).contains(byte))
}

/// Writes a diagnostic with the title and the hint of `error`. The message is
/// `before`, the reason of the error as a sentence, and `after`.
fn diagnose(error: &sibuna_acme::Error, before: &str, after: &str) {
    let title = format!("{} ({})", error.title, error.code);
    let reason = error.message.trim_end();
    let stop = if reason.ends_with('.') { "" } else { "." };
    let message = format!("{before}{reason}{stop}{after}");
    let mut text = String::new();
    let _ = diagnostic::render(&mut text, &title, &message, &error.hint);
    crate::edge::note(format_args!("{}", text.trim_end_matches('\n')));
}

/// Writes the events that are failures: a diagnostic with a hint each. Returns whether
/// `event` was one.
fn log_failure(event: &Event) -> bool {
    let time = sibuna_acme::format_rfc3339;
    match event {
        Event::CleanupFailed { name, error } => {
            let before =
                format!("The TXT record of the DNS-01 challenge for `{name}` was not removed. ");
            let after = " The certificate is not affected. The daemon removes the record at \
                         the next attempt for the name.";
            diagnose(error, &before, after);
        }
        Event::StapleFailed { name, error, retry_at } => {
            let before = format!("No OCSP response for the certificate of `{name}`. ");
            diagnose(error, &before, &format!(" The daemon asks again at {}.", time(*retry_at)));
        }
        Event::Fallback { name, authority, next, error } => {
            let before = format!("No certificate for `{name}` from {authority}. ");
            diagnose(error, &before, &format!(" The daemon asks {next} now."));
        }
        Event::Failed { name, error, retry_at } => {
            let before = match name {
                Some(name) => format!("No new certificate for `{name}`. "),
                None => String::new(),
            };
            let after =
                format!(" The listeners keep serving. Next attempt at {}.", time(*retry_at));
            diagnose(error, &before, &after);
        }
        _ => return false,
    }
    true
}

/// Writes an event of the certificate thread to standard error: one line for a
/// certificate, a diagnostic with a hint for a failure.
pub(crate) fn log(event: &Event) {
    let time = sibuna_acme::format_rfc3339;
    if log_failure(event) {
        return;
    }
    match event {
        Event::Panicked { message, restart_in } => {
            crate::edge::note(format_args!(
                "ACME014: the certificate thread stopped on a defect ({message}); the served \
                 certificates stay, and the thread starts again in {restart_in} second(s). \
                 Please report this line"
            ));
        }
        Event::Refused { name, reason, seconds } => {
            crate::edge::note(format_args!(
                "ACME000: no certificate on demand for {name}: {reason}; refused for \
                 {seconds} second(s)"
            ));
        }
        Event::Released { name, reason } => {
            crate::edge::note(format_args!(
                "ACME000: certificate on demand for {name} released: {reason}"
            ));
        }
        Event::Stapled { name, until } => {
            crate::edge::note(format_args!(
                "ACME000: OCSP response stapled to the certificate for {name}, valid until {}",
                time(*until)
            ));
        }
        Event::Revoked { name } => {
            crate::edge::note(format_args!(
                "ACME000: the OCSP responder says the certificate for {name} is revoked; \
                 no response is stapled and the certificate is renewed now"
            ));
        }
        Event::ServerValidated { name, failure: None } => {
            crate::edge::note(format_args!("ACME000: ACME server: {name} validated for a client"));
        }
        Event::ServerValidated { name, failure: Some(reason) } => {
            crate::edge::note(format_args!(
                "ACME000: ACME server: {name} not validated for a client: {reason}"
            ));
        }
        Event::ServerIssued { names } => {
            crate::edge::note(format_args!(
                "ACME000: ACME server: certificate issued to a client for {}",
                names.join(", ")
            ));
        }
        Event::Obtained { name, not_after, renewed } => {
            let verb = if *renewed { "renewed" } else { "obtained" };
            crate::edge::note(format_args!(
                "ACME000: certificate for {name} {verb}, valid until {}",
                time(*not_after)
            ));
        }
        Event::Loaded { name, not_after } => {
            crate::edge::note(format_args!(
                "ACME000: certificate for {name} loaded from storage, valid until {}",
                time(*not_after)
            ));
        }
        // The failures were written above.
        Event::CleanupFailed { .. }
        | Event::StapleFailed { .. }
        | Event::Fallback { .. }
        | Event::Failed { .. } => {}
    }
}

/// Revokes a certificate of the local authority for the admin command `revoke cert`
/// and returns the answer: the serial number, the name, and what happens next.
pub(crate) fn revoke(
    automatic: Option<&Automatic>,
    target: &str,
) -> Result<String, sibuna_lb::RuntimeError> {
    use sibuna_ingress::RevokeError;
    let nothing = |message: String| sibuna_lb::RuntimeError {
        code: "ADM013",
        title: "NOT REVOKED",
        message,
        hint: "Name a host or an address that the local authority issues for here, as \
               `show certs` lists it with `local`, or the serial number of a certificate \
               in 1 to 16 hexadecimal digits."
            .to_owned(),
    };
    let Some(automatic) = automatic else {
        return Err(nothing(
            "This daemon has no automatic HTTPS, and so no local authority.".into(),
        ));
    };
    match automatic.revoke(target, unix_now()) {
        Ok(entry) => Ok(format!(
            "revoked serial {:016x} name {}\n# The revocation lists are written. A served \
             certificate with this serial number is replaced now.\n",
            entry.serial, entry.name
        )),
        Err(RevokeError::Nothing(message)) => Err(nothing(message)),
        Err(RevokeError::Failed(error)) => Err(sibuna_lb::RuntimeError {
            code: error.code,
            title: error.title,
            message: error.message,
            hint: error.hint,
        }),
    }
}

/// The answer to `show ca`. The lines that start with `#` say where the root is and
/// how long it is valid. The rest is the PEM text, so that
/// `sibuna ctl SOCKET show ca > root.crt` writes a file that every tool reads.
pub(crate) fn render_ca(
    root: Option<Result<Option<sibuna_acme::local::Root>, sibuna_acme::Error>>,
) -> String {
    let none = "# no local authority: no `auto` name of this daemon is an internal name, \
                an IP address or under `issuer: \"internal\"`\n";
    match root {
        None | Some(Ok(None)) => none.to_owned(),
        Some(Err(error)) => format!("# {} ({}): {}\n", error.title, error.code, error.message),
        Some(Ok(Some(root))) => format!(
            "# root certificate of the local authority: {}\n# file: {}\n# valid until: {}\n\
             # install this file in the trust store of each client; see the book, \
             \"Automatic HTTPS\"\n{}",
            root.fields.issuer,
            root.path.display(),
            sibuna_acme::format_rfc3339(root.fields.not_after),
            root.pem
        ),
    }
}

/// The answer to `show certs`: one line per managed name under a header.
pub(crate) fn render_certs(certificates: &[CertificateStatus]) -> String {
    let time = |seconds: Option<u64>| seconds.map_or("-".to_owned(), sibuna_acme::format_rfc3339);
    let header =
        ["name", "via", "issuer", "expires", "renews", "state", "origin", "ocsp", "error"];
    let mut rows = vec![header.map(str::to_owned)];
    for certificate in certificates {
        rows.push([
            certificate.name.clone(),
            certificate.via.to_owned(),
            // One word per column: a script splits the line at spaces.
            certificate
                .issuer
                .as_deref()
                .map_or("-".to_owned(), |issuer| issuer.replace(' ', "_")),
            time(certificate.not_after),
            time(certificate.next_attempt),
            certificate.state.word().to_owned(),
            certificate.origin.to_owned(),
            certificate.staple.to_owned(),
            certificate.error.clone().unwrap_or_else(|| "-".to_owned()),
        ]);
    }
    let mut widths = [0; 9];
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

    #[test]
    fn a_target_that_cannot_stand_in_a_header_is_not_redirected() {
        assert!(is_header_safe(b"/a/b") && is_header_safe(b"x=1&y=2") && is_header_safe(b""));
        assert!(!is_header_safe(b"/a\r\nSet-Cookie: x"));
        assert!(!is_header_safe(b"/a b") && !is_header_safe(b"q=\x7f"));
        assert!(!is_header_safe("/".repeat(MAX_LOCATION + 1).as_bytes()));
    }

    #[test]
    fn show_certs_is_a_table_with_one_word_per_column() {
        let ready = CertificateStatus {
            name: "example.org".to_owned(),
            origin: "listed",
            staple: "good",
            via: "dns-01",
            issuer: Some("Test Authority".to_owned()),
            not_after: Some(1_800_000_000),
            next_attempt: Some(1_799_000_000),
            state: CertificateState::Ready,
            error: None,
        };
        let failing = CertificateStatus {
            name: "b.example.org".to_owned(),
            origin: "on-demand",
            staple: "-",
            via: "local",
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
                "dns-01",
                "Test_Authority",
                "2027-01-15T08:00:00Z",
                "2027-01-03T18:13:20Z",
                "ready",
                "listed",
                "good",
                "-"
            ]
        );
        let words: Vec<&str> = lines[2].split_ascii_whitespace().collect();
        assert_eq!(words[5..], ["retry", "on-demand", "-", "VALIDATION", "FAILED", "(ACME005)"]);
    }
}

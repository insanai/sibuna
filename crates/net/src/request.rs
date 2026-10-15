//! The request head Sibuna sends to the origin.
//!
//! The head is re-emitted field by field into the origin writer, so hop-by-hop fields are
//! dropped and the audit fields are added without copying the request anywhere else. Framing
//! is always generated, never copied.

use std::io::{self, Write};

use sibuna_http::Request;

use crate::proxy::{Audit, Upload};
use crate::upgrade::nominated;

/// Fields that describe one hop, or that Sibuna writes itself, never forwarded. The
/// alternative forwarded host and port fields go too, so the origin sees the client's `Host`
/// and Sibuna's own forwarding fields only.
const HOP_BY_HOP: [&[u8]; 19] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"te",
    b"trailer",
    b"upgrade",
    b"x-forwarded-for",
    b"x-real-ip",
    b"x-sibuna-status",
    b"x-sibuna-rule",
    b"content-length",
    b"proxy-authorization",
    b"proxy-authenticate",
    b"forwarded",
    b"x-forwarded-proto",
    b"x-forwarded-host",
    b"x-forwarded-port",
    b"expect",
];

/// True when `name` is one of [`HOP_BY_HOP`] in any case, with any `-` written as `_`.
///
/// CGI, WSGI and Rack map both `X-Forwarded-For` and `X_Forwarded_For` to the variable
/// `HTTP_X_FORWARDED_FOR`, so a client could otherwise spoof a field Sibuna sets or strips
/// by spelling it with underscores.
fn is_hop_by_hop(name: &[u8]) -> bool {
    HOP_BY_HOP.iter().any(|hop| same_field_name(name, hop))
}

/// Compares a field name with a lower-case `wanted` name, ignoring case and reading `_` as
/// `-`.
fn same_field_name(name: &[u8], wanted: &[u8]) -> bool {
    name.len() == wanted.len()
        && name.iter().zip(wanted).all(|(&byte, &want)| {
            let byte = if byte == b'_' { b'-' } else { byte.to_ascii_lowercase() };
            byte == want
        })
}

/// True when a request field is not forwarded: a hop-by-hop or Sibuna field (see
/// [`is_hop_by_hop`]), or one the client's `Connection` field nominates. `Host` is always
/// forwarded: a client cannot nominate it away and deliver a request without one.
fn is_dropped(request: &Request<'_>, name: &[u8]) -> bool {
    is_hop_by_hop(name) || (nominated(request, name) && !name.eq_ignore_ascii_case(b"host"))
}

/// Writes the origin request head for `request`: the request line in HTTP/1.1, the
/// end-to-end fields in order, the framing `upload` declares, Sibuna's connection fields
/// (`switching` for an upgrade) and the audit fields, then the blank line.
///
/// # Errors
///
/// Any error of `out`.
pub(crate) fn write_request_head<W: Write + ?Sized>(
    out: &mut W,
    request: &Request<'_>,
    upload: &Upload,
    audit: &Audit<'_>,
    switching: bool,
) -> io::Result<()> {
    // The origin must route on the path policy judged, so only a normal path (or `*`) is
    // written; a caller that skipped `sibuna_http::normalize_path` fails closed here.
    if !sibuna_http::is_normal_path(request.path) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "request path is not normal"));
    }
    out.write_all(request.method_text)?;
    out.write_all(b" ")?;
    out.write_all(request.path)?;
    if !request.query.is_empty() {
        out.write_all(b"?")?;
        out.write_all(request.query)?;
    }
    out.write_all(b" HTTP/1.1\r\n")?;
    for header in request.headers() {
        if is_dropped(request, header.name) {
            continue;
        }
        out.write_all(header.name)?;
        out.write_all(b": ")?;
        out.write_all(header.value)?;
        out.write_all(b"\r\n")?;
    }
    match upload {
        Upload::None => {}
        Upload::Length(length) => {
            out.write_all(b"Content-Length: ")?;
            write_decimal(out, *length)?;
            out.write_all(b"\r\n")?;
        }
        Upload::Chunked(_) => out.write_all(b"Transfer-Encoding: chunked\r\n")?,
    }
    out.write_all(if switching {
        b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
    } else {
        b"Connection: keep-alive\r\n"
    })?;
    write_audit(out, audit)
}

fn write_audit<W: Write + ?Sized>(out: &mut W, audit: &Audit<'_>) -> io::Result<()> {
    let fields: [(&[u8], &[u8]); 5] = [
        (b"X-Forwarded-For: ", audit.client_ip),
        (b"X-Forwarded-Proto: ", audit.scheme),
        (b"X-Real-IP: ", audit.client_ip),
        (b"X-Sibuna-Status: ", audit.status),
        (b"X-Sibuna-Rule: ", audit.rule),
    ];
    for (name, value) in fields {
        out.write_all(name)?;
        out.write_all(value)?;
        out.write_all(b"\r\n")?;
    }
    out.write_all(b"\r\n")
}

/// Writes `value` in decimal without leading zeros.
fn write_decimal<W: Write + ?Sized>(out: &mut W, mut value: u64) -> io::Result<()> {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        // A u64 has at most 20 decimal digits, so `start` stays in bounds.
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.write_all(digits.get(start..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use sibuna_http::parse_request;

    use super::*;

    fn audit() -> Audit<'static> {
        Audit {
            client_ip: b"203.0.113.4",
            status: b"PASS",
            rule: b"default/allow",
            ..Audit::default()
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn proxy_head_rewrite_drops_hop_by_hop_headers_and_injects_audit_fields() {
        let raw = b"POST /api?x=1 HTTP/1.1\r\nHost: origin\r\nConnection: keep-alive\r\n\
            X-Forwarded-For: 9.9.9.9\r\nUser-Agent: ua\r\nContent-Length: 2\r\n\r\nhi";
        let request = parse_request(raw).unwrap();
        let mut out = Vec::new();
        write_request_head(&mut out, &request, &Upload::declared(&request), &audit(), false)
            .unwrap();
        assert!(out.starts_with(b"POST /api?x=1 HTTP/1.1\r\n"));
        assert!(contains(&out, b"Host: origin\r\n"));
        assert!(contains(&out, b"Connection: keep-alive\r\n"));
        assert!(!contains(&out, b"9.9.9.9"));
        assert!(contains(&out, b"X-Forwarded-For: 203.0.113.4\r\n"));
        assert!(contains(&out, b"X-Sibuna-Rule: default/allow\r\n"));
        assert!(out.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn framing_is_generated_and_nominated_fields_are_dropped() {
        let raw = b"GET /a? HTTP/1.0\r\nHost: h\r\nConnection: X-Secret, content-length\r\n\
            X-Secret: s\r\nX-Forwarded-Host: evil\r\n\r\n";
        let request = parse_request(raw).unwrap();
        let mut out = Vec::new();
        let chunked = Upload::Chunked(sibuna_http::chunked::Decoder::new());
        write_request_head(&mut out, &request, &chunked, &audit(), false).unwrap();
        let expected = b"GET /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\
            Connection: keep-alive\r\nX-Forwarded-For: 203.0.113.4\r\n\
            X-Forwarded-Proto: http\r\nX-Real-IP: 203.0.113.4\r\nX-Sibuna-Status: PASS\r\n\
            X-Sibuna-Rule: default/allow\r\n\r\n";
        assert_eq!(out, expected);
        out.clear();
        write_request_head(&mut out, &request, &Upload::Length(1234567890), &audit(), true)
            .unwrap();
        assert!(contains(&out, b"Content-Length: 1234567890\r\nConnection: Upgrade\r\n"));
        assert!(contains(&out, b"Upgrade: websocket\r\n"));
    }

    #[test]
    fn underscore_spellings_of_dropped_fields_are_dropped_too() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\nX_Forwarded_For: 6.6.6.6\r\n\
            x_sibuna_status: PASS\r\nX-Real_IP: 6.6.6.7\r\nCONTENT_LENGTH: 5\r\n\
            Transfer_Encoding: chunked\r\nX_Keep: yes\r\nX-Forwarded_Proto: https\r\n\r\n";
        let request = parse_request(raw).unwrap();
        let mut out = Vec::new();
        write_request_head(&mut out, &request, &Upload::None, &audit(), false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("6.6.6"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("sibuna_status"), "{text}");
        assert!(!text.contains("CONTENT_LENGTH") && !text.contains("Transfer_Encoding"));
        assert!(!text.contains("https"), "{text}");
        assert!(text.contains("X_Keep: yes\r\n"), "{text}");
        assert!(same_field_name(b"X_FORWARDED_FOR", b"x-forwarded-for"));
        assert!(!same_field_name(b"X-Forwarded-Fo", b"x-forwarded-for"));
        assert!(!same_field_name(b"x-forwarded_for", b"x_forwarded_for"));
    }

    #[test]
    fn a_connection_field_cannot_nominate_host_away() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: host, X-Drop\r\nX-Drop: 1\r\n\r\n";
        let request = parse_request(raw).unwrap();
        let mut out = Vec::new();
        write_request_head(&mut out, &request, &Upload::None, &audit(), false).unwrap();
        assert!(contains(&out, b"\r\nHost: h\r\n"));
        assert!(!contains(&out, b"X-Drop"));
    }

    #[test]
    fn only_a_normal_path_is_written_to_the_origin() {
        let mut out = Vec::new();
        for raw in [&b"GET //admin/x HTTP/1.1\r\n\r\n"[..], b"GET /%61dmin HTTP/1.1\r\n\r\n"] {
            let request = parse_request(raw).unwrap();
            let written = write_request_head(&mut out, &request, &Upload::None, &audit(), false);
            assert_eq!(written.map_err(|error| error.kind()), Err(io::ErrorKind::InvalidInput));
            assert!(out.is_empty());
        }
        let request = parse_request(b"OPTIONS * HTTP/1.1\r\n\r\n").unwrap();
        write_request_head(&mut out, &request, &Upload::None, &audit(), false).unwrap();
        assert!(out.starts_with(b"OPTIONS * HTTP/1.1\r\n"));
    }

    #[test]
    fn decimal_lengths() {
        for value in [0, 7, 10, 99, 100, u64::MAX] {
            let mut out = Vec::new();
            write_decimal(&mut out, value).unwrap();
            assert_eq!(out, value.to_string().as_bytes());
        }
    }
}

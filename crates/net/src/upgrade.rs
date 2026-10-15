//! HTTP/1.1 WebSocket upgrade validation for the proxy. Framing and extensions stay end to end
//! once the origin has accepted the exact client nonce (RFC 6455 sections 4.1 and 4.2.2).

use sibuna_http::websocket::accept_key;
use sibuna_http::{Method, Request, Version};

use crate::fields::{crlf_lines, find_byte, has_token, trim_ws};
use crate::response::response_nominated;

/// The `Sec-WebSocket-Accept` value the origin must answer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Handshake {
    pub(crate) accept: [u8; 28],
}

/// The request is not a valid WebSocket upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidUpgrade;

/// True when a `Connection` field of `request` lists `name`.
pub(crate) fn nominated(request: &Request<'_>, name: &[u8]) -> bool {
    request.headers().iter().any(|header| {
        header.name.eq_ignore_ascii_case(b"connection") && has_token(header.value, name)
    })
}

/// The handshake a request offers: `Ok(None)` for an ordinary request, the expected accept
/// value for a valid upgrade.
///
/// A valid upgrade is an HTTP/1.1 `GET` with exactly one `Upgrade: websocket` (any case), a
/// `Connection` field that nominates `upgrade`, no body (a `Content-Length` of zero is
/// allowed), exactly one `Sec-WebSocket-Version: 13` and exactly one `Sec-WebSocket-Key`
/// that decodes to 16 bytes.
///
/// # Errors
///
/// [`InvalidUpgrade`] for a request that names an upgrade in any other way, including a
/// `Connection: upgrade` without an `Upgrade` field.
pub(crate) fn offered(request: &Request<'_>) -> Result<Option<Handshake>, InvalidUpgrade> {
    let Some(upgrade) = one(request, b"upgrade")? else {
        if nominated(request, b"upgrade") {
            return Err(InvalidUpgrade);
        }
        return Ok(None);
    };
    if request.method != Method::Get
        || request.version != Version::Http11
        || !upgrade.eq_ignore_ascii_case(b"websocket")
        || !nominated(request, b"upgrade")
        || request.content_length().unwrap_or(0) != 0
        || request.chunked
    {
        return Err(InvalidUpgrade);
    }
    let version = one(request, b"sec-websocket-version")?.ok_or(InvalidUpgrade)?;
    if version != b"13" {
        return Err(InvalidUpgrade);
    }
    let key = one(request, b"sec-websocket-key")?.ok_or(InvalidUpgrade)?;
    let accept = accept_key(key).map_err(|_| InvalidUpgrade)?;
    Ok(Some(Handshake { accept }))
}

/// The only field named `name`; two of them are an invalid upgrade.
fn one<'a>(request: &Request<'a>, name: &[u8]) -> Result<Option<&'a [u8]>, InvalidUpgrade> {
    let mut found = None;
    for header in request.headers().iter().filter(|header| header.name.eq_ignore_ascii_case(name))
    {
        if found.replace(header.value).is_some() {
            return Err(InvalidUpgrade);
        }
    }
    Ok(found)
}

/// True when the origin head accepts `handshake`: an HTTP/1.1 101 with exactly one
/// `Upgrade: websocket`, a `Connection` listing `upgrade`, exactly one matching
/// `Sec-WebSocket-Accept`, no body framing, and no `Connection` nomination of the accept
/// field.
pub(crate) fn accepted(handshake: &Handshake, head: &[u8]) -> bool {
    if response_nominated(head, b"sec-websocket-accept") {
        return false;
    }
    let mut lines = crlf_lines(head);
    if !lines.next().is_some_and(|status| status.starts_with(b"HTTP/1.1 101 ")) {
        return false;
    }
    let (mut upgrade, mut connection, mut accept) = (false, false, false);
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, rest)) = find_byte(line, b':').and_then(|at| line.split_at_checked(at))
        else {
            return false;
        };
        let value = trim_ws(rest.get(1..).unwrap_or_default());
        if name.eq_ignore_ascii_case(b"upgrade") {
            if upgrade || !value.eq_ignore_ascii_case(b"websocket") {
                return false;
            }
            upgrade = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            connection = connection || has_token(value, b"upgrade");
        } else if name.eq_ignore_ascii_case(b"sec-websocket-accept") {
            if accept || value != handshake.accept {
                return false;
            }
            accept = true;
        } else if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
        {
            return false;
        }
    }
    upgrade && connection && accept
}

#[cfg(test)]
mod tests {
    use sibuna_http::parse_request;

    use super::*;

    const HEADERS: &str = "Host: example\r\nUpgrade: WebSocket\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

    fn request(text: &str) -> Request<'_> {
        parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn websocket_upgrades_require_exact_tokens_and_a_valid_matching_nonce() {
        let text = format!("GET /ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\n{HEADERS}\r\n");
        let handshake = offered(&request(&text)).unwrap().unwrap();
        assert_eq!(&handshake.accept, b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(accepted(
            &handshake,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        ));
        assert!(!accepted(
            &handshake,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Accept: other\r\n\r\n"
        ));
        let text = format!("GET /ws HTTP/1.1\r\nConnection: not-upgrade\r\n{HEADERS}\r\n");
        assert_eq!(offered(&request(&text)), Err(InvalidUpgrade));
        let text = format!("POST /ws HTTP/1.1\r\nConnection: upgrade\r\n{HEADERS}\r\n");
        assert_eq!(offered(&request(&text)), Err(InvalidUpgrade));
    }

    #[test]
    fn ordinary_requests_and_body_rules() {
        assert_eq!(offered(&request("GET / HTTP/1.1\r\nHost: a\r\n\r\n")), Ok(None));
        let nominated_only = "GET / HTTP/1.1\r\nConnection: upgrade\r\n\r\n";
        assert_eq!(offered(&request(nominated_only)), Err(InvalidUpgrade));
        let zero = format!(
            "GET /ws HTTP/1.1\r\nConnection: upgrade\r\nContent-Length: 0\r\n{HEADERS}\r\n"
        );
        assert!(offered(&request(&zero)).unwrap().is_some());
        let body = format!(
            "GET /ws HTTP/1.1\r\nConnection: upgrade\r\nContent-Length: 1\r\n{HEADERS}\r\n"
        );
        assert_eq!(offered(&request(&body)), Err(InvalidUpgrade));
        let twice = format!(
            "GET /ws HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n{HEADERS}\r\n"
        );
        assert_eq!(offered(&request(&twice)), Err(InvalidUpgrade));
        let old = format!("GET /ws HTTP/1.0\r\nConnection: upgrade\r\n{HEADERS}\r\n");
        assert_eq!(offered(&request(&old)), Err(InvalidUpgrade));
    }

    #[test]
    fn accepted_heads_carry_no_framing_or_nominated_accept() {
        let handshake = Handshake { accept: *b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" };
        let base = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
            Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
        let ok = format!("{base}Connection: Upgrade\r\n\r\n");
        assert!(accepted(&handshake, ok.as_bytes()));
        let nominated = format!("{base}Connection: Upgrade, Sec-WebSocket-Accept\r\n\r\n");
        assert!(!accepted(&handshake, nominated.as_bytes()));
        let framed = format!("{base}Connection: Upgrade\r\nContent-Length: 0\r\n\r\n");
        assert!(!accepted(&handshake, framed.as_bytes()));
        let missing = format!("{base}\r\n");
        assert!(!accepted(&handshake, missing.as_bytes()));
        let old = ok.replacen("HTTP/1.1", "HTTP/1.0", 1);
        assert!(!accepted(&handshake, old.as_bytes()));
    }
}

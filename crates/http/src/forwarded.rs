//! Request metadata supplied by a trusted HTTP ingress.
//!
//! An ingress that delegates authorization to Sibuna (Caddy's `forward_auth`, nginx's
//! `auth_request`) describes the original request in header fields. These borrowed fields
//! are used only for authorization subrequests; they never turn an untrusted public request
//! into another URL.

use std::fmt;

use crate::request::{Method, Request, split_target};

/// The longest forwarded URI accepted.
pub const MAX_URI: usize = 8192;

/// The longest forwarded method accepted.
pub const MAX_METHOD: usize = 32;

/// Why forwarded metadata was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ForwardedError {
    /// A field is repeated, the aliases disagree, or the URI or method is malformed.
    InvalidMetadata,
}

impl fmt::Display for ForwardedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid forwarded request metadata")
    }
}

impl std::error::Error for ForwardedError {}

/// The original request an ingress asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardedTarget<'a> {
    /// The original path.
    pub path: &'a [u8],
    /// The original query, without `?`.
    pub query: &'a [u8],
    /// The original method token.
    pub method: &'a [u8],
}

impl<'a> ForwardedTarget<'a> {
    /// Replaces the path, query and method of `request` with the forwarded ones, so policy
    /// evaluates the original request.
    pub fn apply(&self, request: &mut Request<'a>) {
        request.path = self.path;
        request.query = self.query;
        request.method_text = self.method;
        request.method = Method::from_bytes(self.method);
    }
}

/// Reads the original request from `X-Forwarded-Uri` (Caddy) or `X-Original-URI` (common
/// nginx recipes), and `X-Forwarded-Method`, when the peer is a `trusted` ingress.
///
/// Returns `Ok(None)` for an untrusted peer or when neither URI field is present. Borrows the
/// field values from the request's bytes.
///
/// # Errors
///
/// [`ForwardedError::InvalidMetadata`] when a field appears twice, the two URI aliases
/// disagree (never an arbitrary precedence), the URI is empty, longer than [`MAX_URI`], not
/// origin-form (`/` but not `//`), or holds whitespace, control bytes, `#` or `\`, or the
/// method is not a token of at most [`MAX_METHOD`] bytes.
pub fn target<'a>(
    request: &Request<'a>,
    trusted: bool,
) -> Result<Option<ForwardedTarget<'a>>, ForwardedError> {
    if !trusted {
        return Ok(None);
    }
    let forwarded = one(request, b"x-forwarded-uri")?;
    let original = one(request, b"x-original-uri")?;
    if let (Some(forwarded), Some(original)) = (forwarded, original)
        && forwarded != original
    {
        return Err(ForwardedError::InvalidMetadata);
    }
    let Some(uri) = forwarded.or(original) else { return Ok(None) };
    let origin_form = uri.first() == Some(&b'/') && !uri.starts_with(b"//");
    let clean = uri.iter().all(|&byte| byte > 32 && byte != 127 && byte != b'#' && byte != b'\\');
    if uri.len() > MAX_URI || !origin_form || !clean {
        return Err(ForwardedError::InvalidMetadata);
    }
    let method = one(request, b"x-forwarded-method")?.unwrap_or(request.method_text);
    if method.len() > MAX_METHOD || !crate::is_valid_token(method) {
        return Err(ForwardedError::InvalidMetadata);
    }
    let split = split_target(uri);
    Ok(Some(ForwardedTarget { path: split.path, query: split.query, method }))
}

fn one<'a>(request: &Request<'a>, name: &[u8]) -> Result<Option<&'a [u8]>, ForwardedError> {
    request.unique_header(name).map_err(|()| ForwardedError::InvalidMetadata)
}

/// The scheme of the original request: `https` when a `trusted` ingress sends exactly one
/// `X-Forwarded-Proto: https` (any case), otherwise `http`. Never fails.
pub fn scheme(request: &Request<'_>, trusted: bool) -> &'static str {
    if !trusted {
        return "http";
    }
    match one(request, b"x-forwarded-proto") {
        Ok(Some(proto)) if proto.eq_ignore_ascii_case(b"https") => "https",
        _ => "http",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_request;

    #[test]
    fn authorization_target_uses_only_trusted_unambiguous_ingress_metadata() {
        let raw = b"GET /auth HTTP/1.1\r\nHost: app\r\nX-Forwarded-Uri: /private?q=%2F\r\n\
            X-Forwarded-Method: POST\r\nX-Forwarded-Proto: https\r\n\r\n";
        let mut request = parse_request(raw).unwrap();
        assert_eq!(target(&request, false), Ok(None));
        let supplied = target(&request, true).unwrap().unwrap();
        supplied.apply(&mut request);
        assert_eq!(request.path, b"/private");
        assert_eq!(request.query, b"q=%2F");
        assert_eq!(request.method, Method::Post);
        assert_eq!(scheme(&request, true), "https");
        assert_eq!(scheme(&request, false), "http");

        let raw = b"GET /auth HTTP/1.1\r\nHost: app\r\nX-Original-URI: /first\r\n\
            X-Forwarded-Uri: /second\r\n\r\n";
        let request = parse_request(raw).unwrap();
        assert_eq!(target(&request, true), Err(ForwardedError::InvalidMetadata));
        let raw = b"GET /auth HTTP/1.1\r\nHost: app\r\n\
            X-Original-URI: //unrelated.example/private\r\n\r\n";
        let request = parse_request(raw).unwrap();
        assert_eq!(target(&request, true), Err(ForwardedError::InvalidMetadata));
    }

    #[test]
    fn malformed_or_repeated_metadata_is_refused() {
        let refused: [&[u8]; 6] = [
            b"X-Forwarded-Uri: /a\r\nX-Forwarded-Uri: /a",
            b"X-Forwarded-Uri: a",
            b"X-Forwarded-Uri: /a#b",
            b"X-Forwarded-Uri: /a\\b",
            b"X-Forwarded-Uri: /a\r\nX-Forwarded-Method: GE T",
            b"X-Forwarded-Uri: /a\r\nX-Forwarded-Method: GET\r\nx-forwarded-method: GET",
        ];
        for fields in refused {
            let raw = [&b"GET / HTTP/1.1\r\n"[..], fields, b"\r\n\r\n"].concat();
            let request = parse_request(&raw).unwrap();
            assert_eq!(target(&request, true), Err(ForwardedError::InvalidMetadata));
        }
        let long = format!("GET / HTTP/1.1\r\nX-Original-URI: /{}\r\n\r\n", "a".repeat(MAX_URI));
        let request = parse_request(long.as_bytes()).unwrap();
        assert_eq!(target(&request, true), Err(ForwardedError::InvalidMetadata));
        let agree = b"GET / HTTP/1.1\r\nX-Original-URI: /a\r\nX-Forwarded-Uri: /a\r\n\r\n";
        let request = parse_request(agree).unwrap();
        let found = target(&request, true).unwrap().unwrap();
        assert_eq!((found.path, found.query, found.method), (&b"/a"[..], &b""[..], &b"GET"[..]));
        let none = parse_request(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(target(&none, true), Ok(None));
        let twice =
            b"GET / HTTP/1.1\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Proto: https\r\n\r\n";
        assert_eq!(scheme(&parse_request(twice).unwrap(), true), "http");
    }
}

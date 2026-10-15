//! Request metadata supplied by a trusted HTTP ingress.
//!
//! An ingress that delegates authorization to Sibuna (Caddy's `forward_auth`, nginx's
//! `auth_request`) describes the original request in header fields. These borrowed fields
//! are used only for authorization subrequests; they never turn an untrusted public request
//! into another URL. The original path is normalised as the request line's path is
//! ([`crate::normalize_path`]), so policy judges the path the origin will route on.

use std::fmt;

use crate::path::{PathError, normalize_path};
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
    /// The original path has no normal form.
    InvalidPath(PathError),
}

impl fmt::Display for ForwardedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardedError::InvalidMetadata => f.write_str("invalid forwarded request metadata"),
            ForwardedError::InvalidPath(error) => write!(f, "invalid forwarded path: {error}"),
        }
    }
}

impl std::error::Error for ForwardedError {}

/// The original request an ingress asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardedTarget<'a> {
    /// The original path in normal form.
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
/// Returns `Ok(None)` for an untrusted peer or when neither URI field is present. The path
/// is normalised into `buffer`, which must hold at least the URI's path ([`MAX_URI`] bytes
/// always suffice); the query and method borrow the field values from the request's bytes.
///
/// # Errors
///
/// [`ForwardedError::InvalidMetadata`] when a field appears twice, the two URI aliases
/// disagree (never an arbitrary precedence), the URI is empty, longer than [`MAX_URI`], not
/// origin-form (`/` but not `//`), or holds whitespace, control bytes, `#` or `\`, or the
/// method is not a token of at most [`MAX_METHOD`] bytes. [`ForwardedError::InvalidPath`]
/// when the path has no normal form, or does not fit `buffer`.
pub fn target<'a>(
    request: &Request<'a>,
    trusted: bool,
    buffer: &'a mut [u8],
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
    let path = normalize_path(split.path, buffer).map_err(ForwardedError::InvalidPath)?;
    Ok(Some(ForwardedTarget { path: path.as_bytes(), query: split.query, method }))
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
        assert_eq!(target(&request, false, &mut [0; MAX_URI]), Ok(None));
        let mut buffer = [0u8; MAX_URI];
        let supplied = target(&request, true, &mut buffer).unwrap().unwrap();
        supplied.apply(&mut request);
        assert_eq!(request.path, b"/private");
        assert_eq!(request.query, b"q=%2F");
        assert_eq!(request.method, Method::Post);
        assert_eq!(scheme(&request, true), "https");
        assert_eq!(scheme(&request, false), "http");

        let raw = b"GET /auth HTTP/1.1\r\nHost: app\r\nX-Original-URI: /first\r\n\
            X-Forwarded-Uri: /second\r\n\r\n";
        let request = parse_request(raw).unwrap();
        assert_eq!(
            target(&request, true, &mut [0; MAX_URI]),
            Err(ForwardedError::InvalidMetadata)
        );
        let raw = b"GET /auth HTTP/1.1\r\nHost: app\r\n\
            X-Original-URI: //unrelated.example/private\r\n\r\n";
        let request = parse_request(raw).unwrap();
        assert_eq!(
            target(&request, true, &mut [0; MAX_URI]),
            Err(ForwardedError::InvalidMetadata)
        );
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
            assert_eq!(
                target(&request, true, &mut [0; MAX_URI]),
                Err(ForwardedError::InvalidMetadata)
            );
        }
        let long = format!("GET / HTTP/1.1\r\nX-Original-URI: /{}\r\n\r\n", "a".repeat(MAX_URI));
        let request = parse_request(long.as_bytes()).unwrap();
        assert_eq!(
            target(&request, true, &mut [0; MAX_URI]),
            Err(ForwardedError::InvalidMetadata)
        );
        let agree = b"GET / HTTP/1.1\r\nX-Original-URI: /a\r\nX-Forwarded-Uri: /a\r\n\r\n";
        let request = parse_request(agree).unwrap();
        let mut buffer = [0u8; MAX_URI];
        let found = target(&request, true, &mut buffer).unwrap().unwrap();
        assert_eq!((found.path, found.query, found.method), (&b"/a"[..], &b""[..], &b"GET"[..]));
        let none = parse_request(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(target(&none, true, &mut [0; MAX_URI]), Ok(None));
        let twice =
            b"GET / HTTP/1.1\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Proto: https\r\n\r\n";
        assert_eq!(scheme(&parse_request(twice).unwrap(), true), "http");
    }

    #[test]
    fn the_original_path_is_normalised_like_the_request_line() {
        let fields = |uri: &str| format!("GET /auth HTTP/1.1\r\nX-Forwarded-Uri: {uri}\r\n\r\n");
        let raw = fields("/public/..//%61dmin/./x?q=%2F");
        let request = parse_request(raw.as_bytes()).unwrap();
        let mut buffer = [0u8; MAX_URI];
        let found = target(&request, true, &mut buffer).unwrap().unwrap();
        assert_eq!((found.path, found.query), (&b"/admin/x"[..], &b"q=%2F"[..]));
        let refused = [
            ("/admin%2fx", PathError::EncodedSeparator),
            ("/admin;x/y", PathError::Parameter),
            ("/.well-known/..;x/admin", PathError::Parameter),
            ("/a/../..", PathError::AboveRoot),
        ];
        for (uri, error) in refused {
            let raw = fields(uri);
            let request = parse_request(raw.as_bytes()).unwrap();
            let mut buffer = [0u8; MAX_URI];
            let found = target(&request, true, &mut buffer);
            assert_eq!(found, Err(ForwardedError::InvalidPath(error)), "{uri}");
        }
        let raw = fields("/abc");
        let request = parse_request(raw.as_bytes()).unwrap();
        let mut buffer = [0u8; 3];
        let short = target(&request, true, &mut buffer);
        assert_eq!(short, Err(ForwardedError::InvalidPath(PathError::TooLong)));
    }
}

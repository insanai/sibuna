//! The credential a request presents (Zig's `http.credential`, `http.sessionToken`,
//! `http.csrf`, `http.csrfToken` and `bearer.zig`).
//!
//! A request authenticates with either a session cookie or a bearer token, never both:
//! with an `Authorization` field present the cookie is not consulted and a `Cookie` field
//! refuses the request. Only digests leave this module: the raw cookie and token are wiped
//! as soon as they are hashed. Cookie-authenticated `POST`s also present the session's CSRF
//! token in `X-Console-CSRF`, compared by digest in constant time.

use sibuna_console_protocol::CredentialKind;
use sibuna_crypto::{ct, hmac, sha256::Sha256};
use sibuna_serve::{Context, ServeError};

/// The session cookie's name.
pub const COOKIE: &str = "__sibuna_console";
/// The field that carries the CSRF token.
pub const CSRF_FIELD: &[u8] = b"X-Console-CSRF";
/// The HMAC key that derives a session's CSRF token from its raw token.
pub const CSRF_DOMAIN: &[u8] = b"sibuna-console-csrf-v1";
/// The longest `Authorization` field accepted, in bytes.
pub const MAX_AUTHORIZATION: usize = 1024;

/// What a request presented: how, and the SHA-256 digest of the token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Presented {
    /// A session cookie or a bearer token.
    pub kind: CredentialKind,
    /// SHA-256 of the raw token.
    pub digest: [u8; 32],
}

impl std::fmt::Debug for Presented {
    /// Shows the kind only: the digest finds the session in storage.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presented").field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// Returns the credential the request presents: the bearer token of `Authorization`, or
/// else the session cookie.
///
/// Fails with [`ServeError::InvalidRequest`] when both are present, when the bearer field
/// or the cookie is malformed, or when there is none.
pub fn presented(context: &Context<'_>) -> Result<Presented, ServeError> {
    if let Some(field) = context.header(b"Authorization")? {
        if context.header(b"Cookie")?.is_some() {
            return Err(ServeError::InvalidRequest);
        }
        return Ok(Presented { kind: CredentialKind::Bearer, digest: parse_bearer(field)? });
    }
    let mut raw = session_token(context)?;
    let digest = Sha256::digest(&raw);
    ct::zeroize(&mut raw);
    Ok(Presented { kind: CredentialKind::Session, digest })
}

/// Parses `Authorization: Bearer <64 hex digits>` and returns the token's SHA-256 digest.
/// The scheme is case-insensitive and followed by one space; spaces around the token are
/// allowed, a tab is not. The field is at most [`MAX_AUTHORIZATION`] bytes.
///
/// Fails with [`ServeError::InvalidRequest`] for anything else.
pub fn parse_bearer(field: &[u8]) -> Result<[u8; 32], ServeError> {
    if !(7..=MAX_AUTHORIZATION).contains(&field.len()) {
        return Err(ServeError::InvalidRequest);
    }
    let (scheme, rest) = field.split_at(6);
    if !scheme.eq_ignore_ascii_case(b"Bearer") || rest.first() != Some(&b' ') {
        return Err(ServeError::InvalidRequest);
    }
    let mut raw = parse_token(trim_spaces(rest))?;
    let digest = Sha256::digest(&raw);
    ct::zeroize(&mut raw);
    Ok(digest)
}

/// Decodes a 64-digit hexadecimal token of either case.
///
/// Fails with [`ServeError::InvalidRequest`] for any other text.
pub fn parse_token(text: &[u8]) -> Result<[u8; 32], ServeError> {
    let mut raw = [0u8; 32];
    if text.len() != 64 || sibuna_encoding::hex::decode_to_slice(text, &mut raw).is_err() {
        ct::zeroize(&mut raw);
        return Err(ServeError::InvalidRequest);
    }
    Ok(raw)
}

/// Returns the raw session token of the request's single `__sibuna_console` cookie. The
/// caller wipes it after use.
///
/// Fails with [`ServeError::InvalidRequest`] when there is no `Cookie` field, no such
/// cookie, more than one, or a value that is not 64 hexadecimal digits.
pub fn session_token(context: &Context<'_>) -> Result<[u8; 32], ServeError> {
    let field = context.header(b"Cookie")?.ok_or(ServeError::InvalidRequest)?;
    let prefix = format!("{COOKIE}=");
    let mut found: Option<[u8; 32]> = None;
    for pair in field.split(|&byte| byte == b';') {
        let pair = trim_spaces(pair);
        let Some(value) = pair.strip_prefix(prefix.as_bytes()) else { continue };
        if let Some(mut earlier) = found.take() {
            ct::zeroize(&mut earlier);
            return Err(ServeError::InvalidRequest);
        }
        found = Some(parse_token(value)?);
    }
    found.ok_or(ServeError::InvalidRequest)
}

/// Trims spaces, and only spaces (as Zig's `trim(" ")`), from both ends of `bytes`.
fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&byte| byte != b' ').unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|&byte| byte != b' ').map_or(start, |at| at + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// Checks the request's `X-Console-CSRF` token against `expected`, the SHA-256 digest of
/// the session's CSRF token, in constant time.
///
/// Fails with [`ServeError::InvalidRequest`] when the field is missing, malformed or does
/// not match.
pub fn check_csrf(context: &Context<'_>, expected: &[u8; 32]) -> Result<(), ServeError> {
    let field = context.header(CSRF_FIELD)?.ok_or(ServeError::InvalidRequest)?;
    let mut raw = parse_token(field)?;
    let digest = Sha256::digest(&raw);
    ct::zeroize(&mut raw);
    if !ct::eq(&digest, expected) {
        return Err(ServeError::InvalidRequest);
    }
    Ok(())
}

/// Returns the CSRF token of the session whose raw token is `raw`:
/// HMAC-SHA256 keyed with [`CSRF_DOMAIN`] over the raw token.
pub fn csrf_token(raw: &[u8; 32]) -> [u8; 32] {
    hmac::hmac_sha256(CSRF_DOMAIN, raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // bearer.zig: "bearer schemes accept bounded spaces but never malformed or partial
    // credentials".
    #[test]
    fn bearer_schemes_accept_bounded_spaces_but_nothing_malformed() {
        let value = "a".repeat(64);
        let expected = parse_bearer(format!("Bearer {value}").as_bytes()).unwrap();
        assert_eq!(expected, Sha256::digest(&[0xaa; 32]));
        assert_eq!(parse_bearer(format!("bEaReR   {value} ").as_bytes()).unwrap(), expected);
        assert_eq!(
            parse_bearer(format!("Bearer {}", "A".repeat(64)).as_bytes()).unwrap(),
            expected
        );
        for invalid in [
            String::new(),
            "Bearer".into(),
            format!("Bearer {}", "a".repeat(63)),
            format!("Basic {value}"),
            format!("Bearer\t{value}"),
            format!("Bearer {}", "z".repeat(64)),
            format!("Bearer {value},other"),
            format!("Bearer {}{value}", " ".repeat(1024)),
        ] {
            assert_eq!(
                parse_bearer(invalid.as_bytes()),
                Err(ServeError::InvalidRequest),
                "{invalid}"
            );
        }
    }

    #[test]
    fn csrf_tokens_are_keyed_digests_of_the_session() {
        let token = csrf_token(&[7; 32]);
        assert_eq!(token, hmac::hmac_sha256(b"sibuna-console-csrf-v1", &[7; 32]));
        assert_ne!(token, csrf_token(&[8; 32]));
        assert_eq!(trim_spaces(b"  a b  "), b"a b");
        assert_eq!(trim_spaces(b"   "), b"");
    }
}

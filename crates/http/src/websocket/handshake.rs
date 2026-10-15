//! The RFC 6455 opening handshake, shared by browser and peer listeners.

use std::fmt;

use sibuna_crypto::sha1::Sha1;
use sibuna_encoding::base64;

use crate::request::{Method, Request, Version};

/// The GUID that RFC 6455 section 1.3 appends to the client's key.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Why an upgrade request or key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandshakeError {
    /// The request is not a valid RFC 6455 upgrade, or its key is not 16 bytes in base64.
    InvalidRequest,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid WebSocket upgrade request")
    }
}

impl std::error::Error for HandshakeError {}

/// Checks that `request` is a WebSocket upgrade and returns its `Sec-WebSocket-Key`,
/// borrowed from the request's bytes.
///
/// The request must be an HTTP/1.1 `GET` without `Expect`, `Content-Length` or
/// `Transfer-Encoding`, with exactly one each of `Sec-WebSocket-Version: 13`,
/// `Upgrade: websocket` (any case), a `Connection` field listing `upgrade`, and a
/// `Sec-WebSocket-Key` that decodes to 16 bytes. Repeated fields are refused rather than
/// one of them chosen.
///
/// # Errors
///
/// [`HandshakeError::InvalidRequest`] when any condition fails.
pub fn upgrade_key<'a>(request: &Request<'a>) -> Result<&'a [u8], HandshakeError> {
    let one =
        |name: &[u8]| request.unique_header(name).map_err(|()| HandshakeError::InvalidRequest);
    let required = |name: &[u8]| one(name)?.ok_or(HandshakeError::InvalidRequest);
    if request.version != Version::Http11
        || request.method != Method::Get
        || one(b"expect")?.is_some()
    {
        return Err(HandshakeError::InvalidRequest);
    }
    if required(b"sec-websocket-version")? != b"13"
        || !required(b"upgrade")?.eq_ignore_ascii_case(b"websocket")
        || !contains_token(required(b"connection")?, b"upgrade")
        || request.header(b"content-length").is_some()
        || request.header(b"transfer-encoding").is_some()
    {
        return Err(HandshakeError::InvalidRequest);
    }
    let key = required(b"sec-websocket-key")?;
    decode_key(key)?;
    Ok(key)
}

/// Decodes a `Sec-WebSocket-Key`: standard padded base64 of exactly 16 bytes.
///
/// # Errors
///
/// [`HandshakeError::InvalidRequest`] for any other text.
pub fn decode_key(encoded: &[u8]) -> Result<[u8; 16], HandshakeError> {
    if base64::decoded_len(base64::STANDARD, encoded) != Ok(16) {
        return Err(HandshakeError::InvalidRequest);
    }
    let mut bytes = [0u8; 16];
    base64::decode_to_slice(base64::STANDARD, encoded, &mut bytes)
        .map_err(|_| HandshakeError::InvalidRequest)?;
    Ok(bytes)
}

/// The `Sec-WebSocket-Accept` value for a client's key: base64 of the SHA-1 of the key and
/// the RFC 6455 GUID.
///
/// # Errors
///
/// [`HandshakeError::InvalidRequest`] when `encoded` is not a valid key ([`decode_key`]).
pub fn accept_key(encoded: &[u8]) -> Result<[u8; 28], HandshakeError> {
    decode_key(encoded)?;
    let mut sha1 = Sha1::new();
    sha1.update(encoded);
    sha1.update(GUID);
    let digest = sha1.finalize();
    let mut output = [0u8; 28];
    base64::encode_to_slice(base64::STANDARD, &digest, &mut output)
        .map_err(|_| HandshakeError::InvalidRequest)?;
    Ok(output)
}

/// True when the comma-separated `value` lists `expected` (ASCII case-insensitive, trimmed
/// of SP and HTAB), as in `Connection: keep-alive, Upgrade`.
pub fn contains_token(value: &[u8], expected: &[u8]) -> bool {
    value
        .split(|&byte| byte == b',')
        .any(|token| crate::bytes::trim_space(token).eq_ignore_ascii_case(expected))
}

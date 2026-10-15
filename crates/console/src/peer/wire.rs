//! The authenticated upgrade's header fields (Zig's `peer_wire.zig`). Fields have fixed
//! sizes; a repeated or ambiguous field is refused on both sides.
//!
//! ```text
//! client -> GET /console/peer          server -> 101 Switching Protocols
//!   Sec-WebSocket-Key: base64(16)        Sec-WebSocket-Accept: (RFC 6455)
//!   X-Sibuna-Peer: hex(transcript, 64)   X-Sibuna-Peer: hex(boot 16 | nonce 32)
//!   X-Sibuna-Proof: hex(client proof)    X-Sibuna-Proof: hex(server proof)
//! ```

use std::fmt;

use sibuna_encoding::{base64, hex};
use sibuna_http::is_valid_token;
use sibuna_http::websocket::{accept_key, contains_token, decode_key};
use sibuna_serve::Context;

use super::auth::{self, AuthError, Reply, Transcript};

/// The transcript field.
pub const PEER_FIELD: &str = "X-Sibuna-Peer";
/// The proof field.
pub const PROOF_FIELD: &str = "X-Sibuna-Proof";

/// Why an upgrade request or reply was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WireError {
    /// A field is missing, repeated, malformed or inconsistent, or the reply is not a clean
    /// WebSocket upgrade.
    InvalidRequest,
    /// The server's proof does not match.
    InvalidProof,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WireError::InvalidRequest => "invalid peer upgrade",
            WireError::InvalidProof => "invalid peer proof",
        })
    }
}

impl std::error::Error for WireError {}

impl From<AuthError> for WireError {
    fn from(_: AuthError) -> WireError {
        WireError::InvalidProof
    }
}

/// An upgrade request the server read: the transcript and the client's proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The client's transcript; its WebSocket key matches the request's.
    pub transcript: Transcript,
    /// The client's proof.
    pub proof: [u8; 32],
}

/// Returns the client's upgrade request head for `transcript` to the console at
/// `authority` (`host[:port]`), proved under `key`.
pub fn request_head(authority: &str, key: &[u8; 32], transcript: &Transcript) -> String {
    let encoded = hex::encode(&transcript.encode());
    let proof = hex::encode(&auth::request_proof(key, transcript));
    let websocket_key = base64::encode(base64::STANDARD, &transcript.websocket_key);
    format!(
        "GET /console/peer HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \
         {websocket_key}\r\n{PEER_FIELD}: {encoded}\r\n{PROOF_FIELD}: {proof}\r\n\r\n"
    )
}

/// Reads the transcript and proof of the upgrade request in `context`, after checking the
/// WebSocket upgrade itself.
///
/// Fails with [`WireError::InvalidRequest`] for an invalid upgrade, a missing, repeated or
/// malformed field, or a transcript whose WebSocket key is not the request's.
pub fn read_request(context: &Context<'_>) -> Result<Request, WireError> {
    let invalid = |_| WireError::InvalidRequest;
    let websocket_key = context.websocket_key().map_err(invalid)?;
    let peer = context.header(PEER_FIELD.as_bytes()).map_err(invalid)?;
    let transcript = Transcript::decode(&hex_array::<64>(peer)?);
    if decode_key(websocket_key).map_err(|_| WireError::InvalidRequest)?
        != transcript.websocket_key
    {
        return Err(WireError::InvalidRequest);
    }
    let proof = hex_array::<32>(context.header(PROOF_FIELD.as_bytes()).map_err(invalid)?)?;
    Ok(Request { transcript, proof })
}

/// The server's reply fields: the identity (boot and nonce) and the proof, as hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyFields {
    /// `X-Sibuna-Peer`: 96 hex digits.
    pub identity: String,
    /// `X-Sibuna-Proof`: 64 hex digits.
    pub proof: String,
}

impl ReplyFields {
    /// Returns the fields of `reply` to `transcript`, proved under `key`.
    pub fn new(key: &[u8; 32], transcript: &Transcript, reply: &Reply) -> ReplyFields {
        let mut identity = [0u8; 48];
        identity[..16].copy_from_slice(&reply.boot);
        identity[16..].copy_from_slice(&reply.nonce);
        ReplyFields {
            identity: hex::encode(&identity),
            proof: hex::encode(&auth::reply_proof(key, transcript, reply)),
        }
    }
}

/// Checks the server's reply head `head` (the status line and fields, with or without the
/// blank line) to `transcript` under `key`, and returns the server's boot and nonce.
///
/// The reply must be `HTTP/1.1 101` with `Upgrade: websocket`, a `Connection` listing
/// `upgrade`, the right `Sec-WebSocket-Accept`, no body framing, content coding, extension
/// or subprotocol, and exactly one valid identity and proof.
///
/// Fails with [`WireError::InvalidProof`] when the server's proof does not match and with
/// [`WireError::InvalidRequest`] for anything else.
pub fn check_reply(
    head: &[u8],
    key: &[u8; 32],
    transcript: &Transcript,
) -> Result<Reply, WireError> {
    let invalid = WireError::InvalidRequest;
    let text = std::str::from_utf8(head).map_err(|_| invalid)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(invalid)?;
    if !status.starts_with("HTTP/1.1 101") || status.as_bytes().get(12).is_some_and(|b| *b != b' ')
    {
        return Err(invalid);
    }
    let fields = Fields::parse(lines)?;
    let upgrade = fields.one("Upgrade")?.unwrap_or_default();
    let connection = fields.one("Connection")?.unwrap_or_default();
    if !contains_token(upgrade.as_bytes(), b"websocket")
        || !contains_token(connection.as_bytes(), b"upgrade")
    {
        return Err(invalid);
    }
    let identity = hex_array::<48>(fields.one(PEER_FIELD)?.map(str::as_bytes))?;
    let mut reply = Reply::default();
    reply.boot.copy_from_slice(&identity[..16]);
    reply.nonce.copy_from_slice(&identity[16..]);
    let proof = hex_array::<32>(fields.one(PROOF_FIELD)?.map(str::as_bytes))?;
    auth::verify(&auth::reply_proof(key, transcript, &reply), &proof)?;
    let sent = base64::encode(base64::STANDARD, &transcript.websocket_key);
    let accept = accept_key(sent.as_bytes()).map_err(|_| invalid)?;
    if fields.one("Sec-WebSocket-Accept")?.map(str::as_bytes) != Some(&accept[..]) {
        return Err(invalid);
    }
    let coding = fields.one("Content-Encoding")?;
    if fields.one("Content-Length")?.is_some()
        || fields.one("Transfer-Encoding")?.is_some()
        || coding.is_some_and(|coding| !coding.eq_ignore_ascii_case("identity"))
        || fields.one("Sec-WebSocket-Extensions")?.is_some()
        || fields.one("Sec-WebSocket-Protocol")?.is_some()
    {
        return Err(invalid);
    }
    Ok(reply)
}

/// The fields of a response head, at most [`MAX_FIELDS`].
struct Fields<'a> {
    fields: Vec<(&'a str, &'a str)>,
}

/// The most fields a reply may carry.
const MAX_FIELDS: usize = 64;

impl<'a> Fields<'a> {
    /// Reads `name: value` lines up to the first empty line; values are trimmed.
    fn parse(lines: impl Iterator<Item = &'a str>) -> Result<Fields<'a>, WireError> {
        let mut fields = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').ok_or(WireError::InvalidRequest)?;
            let clean = value.bytes().all(|byte| byte == b'\t' || (32..127).contains(&byte));
            if !is_valid_token(name.as_bytes()) || !clean || fields.len() == MAX_FIELDS {
                return Err(WireError::InvalidRequest);
            }
            fields.push((name, value.trim_matches([' ', '\t'])));
        }
        Ok(Fields { fields })
    }

    /// Returns the value of the only field named `name` (case-insensitive).
    ///
    /// Fails with [`WireError::InvalidRequest`] when the field is repeated.
    fn one(&self, name: &str) -> Result<Option<&'a str>, WireError> {
        let mut named = self.fields.iter().filter(|(field, _)| field.eq_ignore_ascii_case(name));
        let first = named.next().map(|(_, value)| *value);
        if named.next().is_some() {
            return Err(WireError::InvalidRequest);
        }
        Ok(first)
    }
}

/// Decodes exactly `N` bytes from `2 * N` hex digits.
fn hex_array<const N: usize>(text: Option<&[u8]>) -> Result<[u8; N], WireError> {
    let text = text.ok_or(WireError::InvalidRequest)?;
    let mut bytes = [0u8; N];
    if text.len() != 2 * N {
        return Err(WireError::InvalidRequest);
    }
    hex::decode_to_slice(text, &mut bytes).map_err(|_| WireError::InvalidRequest)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange() -> ([u8; 32], Transcript, Reply) {
        let key = auth::derive(&[9; 32]);
        let transcript = Transcript {
            from: 1,
            to: 2,
            timestamp: 1_000,
            nonce: [3; 32],
            websocket_key: [4; 16],
        };
        (key, transcript, Reply { boot: [5; 16], nonce: [6; 32] })
    }

    fn reply_head(fields: &ReplyFields, transcript: &Transcript, extra: &str) -> String {
        let sent = base64::encode(base64::STANDARD, &transcript.websocket_key);
        let accept = accept_key(sent.as_bytes()).unwrap();
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Accept: {}\r\nX-Sibuna-Peer: {}\r\nX-Sibuna-Proof: {}\r\n{extra}\r\n",
            std::str::from_utf8(&accept).unwrap(),
            fields.identity,
            fields.proof
        )
    }

    #[test]
    fn a_proved_reply_is_accepted_and_returns_the_server_identity() {
        let (key, transcript, reply) = exchange();
        let fields = ReplyFields::new(&key, &transcript, &reply);
        assert_eq!(fields.identity.len(), 96);
        let head = reply_head(&fields, &transcript, "");
        assert_eq!(check_reply(head.as_bytes(), &key, &transcript), Ok(reply));
        let request = request_head("localhost:9443", &key, &transcript);
        assert!(request.starts_with("GET /console/peer HTTP/1.1\r\nHost: localhost:9443\r\n"));
        assert!(
            request.contains(&format!("X-Sibuna-Peer: {}\r\n", hex::encode(&transcript.encode())))
        );
    }

    #[test]
    fn forged_ambiguous_or_framed_replies_are_refused() {
        let (key, transcript, reply) = exchange();
        let fields = ReplyFields::new(&key, &transcript, &reply);
        let forged = ReplyFields { proof: "00".repeat(32), ..fields.clone() };
        let head = reply_head(&forged, &transcript, "");
        assert_eq!(check_reply(head.as_bytes(), &key, &transcript), Err(WireError::InvalidProof));
        for extra in [
            "X-Sibuna-Peer: 00\r\n",
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Encoding: gzip\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "Sec-WebSocket-Protocol: chat\r\n",
            "Upgrade: websocket\r\n",
            "bad line\r\n",
        ] {
            let head = reply_head(&fields, &transcript, extra);
            assert_eq!(
                check_reply(head.as_bytes(), &key, &transcript),
                Err(WireError::InvalidRequest),
                "{extra}"
            );
        }
        let head = reply_head(&fields, &transcript, "Content-Encoding: identity\r\n");
        assert_eq!(check_reply(head.as_bytes(), &key, &transcript), Ok(reply));
        let head = reply_head(&fields, &transcript, "").replace("101", "200");
        assert_eq!(
            check_reply(head.as_bytes(), &key, &transcript),
            Err(WireError::InvalidRequest)
        );
        let other = Transcript { websocket_key: [7; 16], ..transcript };
        let head = reply_head(&ReplyFields::new(&key, &other, &reply), &transcript, "");
        assert_eq!(check_reply(head.as_bytes(), &key, &other), Err(WireError::InvalidRequest));
    }

    #[test]
    fn hex_fields_have_exact_lengths() {
        assert_eq!(hex_array::<2>(Some(b"0aff")), Ok([0x0a, 0xff]));
        for text in [&b"0af"[..], b"0aff00", b"zzzz", b""] {
            assert_eq!(hex_array::<2>(Some(text)), Err(WireError::InvalidRequest));
        }
        assert_eq!(hex_array::<2>(None), Err(WireError::InvalidRequest));
    }
}

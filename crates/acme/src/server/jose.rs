//! Reading and verifying the flattened JWS of an ACME request (RFC 8555, section 6.2),
//! on the side of the server.
//!
//! ```text
//! {"protected": b64({"alg", "nonce", "url", "jwk" | "kid"}),
//!  "payload": b64(..), "signature": b64(..)}
//! ```
//!
//! The account key is a P-256 key with ES256 or an RSA key with RS256. A request with
//! `kid` carries its key inside the `kid`: the account URL ends with the base64url of
//! the canonical JWK, so the server keeps no table of accounts.

use ring::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};
use sibuna_json::{Object, Value};

use crate::jws;

/// Bounds of the JSON documents of a client. A document is at most a request body.
const LIMITS: sibuna_json::Limits = sibuna_json::Limits {
    max_input_bytes: super::MAX_BODY,
    max_values: 256,
    max_string_bytes: super::MAX_BODY,
    max_depth: 8,
};
/// The longest nonce a request may carry.
const MAX_NONCE: usize = 64;
/// The longest modulus of an RSA account key, in bytes: 8192 bits.
const MAX_MODULUS: usize = 1024;

/// Why a request is refused, as an ACME error type and a sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Refusal {
    /// The last word of `urn:ietf:params:acme:error:WORD`.
    pub kind: &'static str,
    /// What is wrong, for the client.
    pub detail: String,
}

impl Refusal {
    pub fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self { kind, detail: detail.into() }
    }

    fn malformed(detail: &str) -> Self {
        Self::new("malformed", detail)
    }
}

/// The public key of an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AccountKey {
    /// A point on P-256 in uncompressed form.
    P256(Vec<u8>),
    /// The modulus and the exponent of an RSA key, big endian without leading zeros.
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl AccountKey {
    /// Reads a JWK. Returns `None` for another key type, another curve, or members of
    /// the wrong size.
    fn from_jwk(jwk: &Object<'_>) -> Option<Self> {
        let member = |name: &str| decode(jwk.get(name)?.as_str()?);
        match jwk.get("kty")?.as_str()? {
            "EC" if jwk.get("crv")?.as_str()? == "P-256" => {
                let (x, y) = (member("x")?, member("y")?);
                (x.len() == 32 && y.len() == 32).then(|| Self::P256([&[4][..], &x, &y].concat()))
            }
            "RSA" => {
                let strip = |bytes: Vec<u8>| {
                    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
                    bytes[zeros..].to_vec()
                };
                let (n, e) = (strip(member("n")?), strip(member("e")?));
                let sized = (256..=MAX_MODULUS).contains(&n.len()) && (1..=8).contains(&e.len());
                sized.then_some(Self::Rsa { n, e })
            }
            _ => None,
        }
    }

    /// The JWK with its members in lexicographic order and no white space: the form
    /// that the thumbprint hashes (RFC 7638) and that the account URL carries.
    pub fn canonical_jwk(&self) -> String {
        match self {
            Self::P256(point) => {
                let x = jws::base64url(point.get(1..33).unwrap_or_default());
                let y = jws::base64url(point.get(33..65).unwrap_or_default());
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            Self::Rsa { n, e } => {
                format!(
                    r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                    jws::base64url(e),
                    jws::base64url(n)
                )
            }
        }
    }

    /// The thumbprint of the key: the owner of an order, and the second half of a key
    /// authorization.
    pub fn thumbprint(&self) -> String {
        jws::thumbprint_of(&self.canonical_jwk())
    }

    /// The last segment of the account URL of this key.
    pub fn account_id(&self) -> String {
        jws::base64url(self.canonical_jwk().as_bytes())
    }

    /// Reads the key out of the last segment of an account URL. The segment must be
    /// the one that [`AccountKey::account_id`] writes, so one key has one URL.
    pub fn from_account_id(id: &str) -> Option<Self> {
        let text = decode(id)?;
        let value = sibuna_json::parse_with_limits(&text, &LIMITS).ok()?;
        let key = Self::from_jwk(value.as_object()?)?;
        (key.account_id() == id).then_some(key)
    }

    /// The algorithm that a request of this key must name.
    fn algorithm(&self) -> &'static str {
        match self {
            Self::P256(_) => "ES256",
            Self::Rsa { .. } => "RS256",
        }
    }

    /// Whether `signature` over `message` verifies with this key.
    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::P256(point) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .is_ok(),
            Self::Rsa { n, e } => ring::rsa::PublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
        }
    }
}

/// A request whose signature verified. The nonce is not checked yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Signed {
    /// The key that signed.
    pub key: AccountKey,
    /// Whether the request named its key by `kid`, as every request but `newAccount`
    /// must.
    pub by_kid: bool,
    /// The nonce of the protected header.
    pub nonce: String,
    /// The payload. Empty for a POST-as-GET.
    pub payload: Vec<u8>,
}

/// Decodes base64url without padding. Returns `None` for any other text.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    base64::decode(URL_SAFE_NO_PAD, text.as_bytes()).ok()
}

/// Parses a JSON document of a client within the bounds of the server.
pub(super) fn parse(text: &[u8]) -> Option<Value<'_>> {
    sibuna_json::parse_with_limits(text, &LIMITS).ok()
}

/// Reads the body of a POST and verifies its signature.
///
/// `url` is the URL of the resource: the protected header must name exactly it.
/// `accounts` is the prefix of every account URL, with its final slash. The work is
/// bounded by the length of `body`, which the caller bounds.
pub(super) fn verify(body: &[u8], url: &str, accounts: &str) -> Result<Signed, Refusal> {
    let outer = parse(body).ok_or_else(|| Refusal::malformed("The body is no JSON document."))?;
    let text = |name: &str| outer.as_object().and_then(|o| o.get(name)).and_then(Value::as_str);
    let (Some(protected), Some(payload), Some(signature)) =
        (text("protected"), text("payload"), text("signature"))
    else {
        return Err(Refusal::malformed("The body is no flattened JWS."));
    };
    let header = decode(protected);
    let header = header.as_deref().and_then(parse);
    let header = header.as_ref().and_then(Value::as_object);
    let header =
        header.ok_or_else(|| Refusal::malformed("The protected header is unreadable."))?;
    let field = |name: &str| header.get(name).and_then(Value::as_str);
    if field("url") != Some(url) {
        return Err(Refusal::new(
            "unauthorized",
            "The header `url` is not the URL of the request.",
        ));
    }
    let key = match (header.get("jwk").and_then(Value::as_object), field("kid")) {
        (Some(jwk), None) => AccountKey::from_jwk(jwk),
        (None, Some(kid)) => kid.strip_prefix(accounts).and_then(AccountKey::from_account_id),
        _ => return Err(Refusal::malformed("The header needs exactly one of `jwk` and `kid`.")),
    };
    let by_kid = field("kid").is_some();
    let Some(key) = key else {
        let (kind, detail) = match by_kid {
            true => ("accountDoesNotExist", "The `kid` is no account URL of this server."),
            false => {
                ("badPublicKey", "The key is no P-256 key and no RSA key of 2048 to 8192 bits.")
            }
        };
        return Err(Refusal::new(kind, detail));
    };
    if field("alg") != Some(key.algorithm()) {
        let detail = format!("The key needs the algorithm {}.", key.algorithm());
        return Err(Refusal::new("badSignatureAlgorithm", detail));
    }
    let signature = decode(signature);
    let message = format!("{protected}.{payload}");
    if !signature.is_some_and(|signature| key.verifies(message.as_bytes(), &signature)) {
        return Err(Refusal::new("unauthorized", "The signature does not verify."));
    }
    let nonce = field("nonce").filter(|nonce| nonce.len() <= MAX_NONCE).unwrap_or_default();
    let payload =
        decode(payload).ok_or_else(|| Refusal::malformed("The payload is unreadable."))?;
    Ok(Signed { key, by_kid, nonce: nonce.to_owned(), payload })
}

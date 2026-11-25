//! JSON Web Signature for ACME: the public key as a JWK, its thumbprint (RFC 7638) and
//! the flattened JWS with ES256 (RFC 7515, RFC 8555 section 6.2).

use std::fmt::Write as _;

use sibuna_crypto::hmac::hmac_sha256;
use sibuna_crypto::sha256::Sha256;
use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};

use crate::{Error, KeyPair};

/// Encodes bytes in base64url without padding, the encoding of every JOSE field.
pub fn base64url(bytes: &[u8]) -> String {
    base64::encode(URL_SAFE_NO_PAD, bytes)
}

/// The public key as a JSON Web Key. The members are in lexicographic order and there is
/// no white space, which is the form that the thumbprint hashes.
pub fn jwk(key: &KeyPair) -> String {
    let point = key.public_point();
    let x = base64url(point.get(1..33).unwrap_or_default());
    let y = base64url(point.get(33..65).unwrap_or_default());
    format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
}

/// The thumbprint of a JWK in its canonical form: the SHA-256 digest in base64url.
pub fn thumbprint_of(canonical_jwk: &str) -> String {
    base64url(&Sha256::digest(canonical_jwk.as_bytes()))
}

/// The thumbprint of the public key. A key authorization is a token, a dot and this.
pub fn thumbprint(key: &KeyPair) -> String {
    thumbprint_of(&jwk(key))
}

/// Signs `payload` for `url` and returns the flattened JWS as a JSON document.
///
/// `account` is the account URL. Without it the header carries the public key, as the
/// request that registers the account needs. An empty `payload` makes a POST-as-GET.
/// Fails only when the key cannot sign.
pub fn sign(
    key: &KeyPair,
    account: Option<&str>,
    nonce: &str,
    url: &str,
    payload: &str,
) -> Result<String, Error> {
    let mut header = String::from(r#"{"alg":"ES256","#);
    match account {
        Some(account) => {
            header.push_str(r#""kid":"#);
            let _ = sibuna_json::write_string(&mut header, account);
        }
        None => {
            let _ = write!(header, r#""jwk":{}"#, jwk(key));
        }
    }
    header.push_str(r#","nonce":"#);
    let _ = sibuna_json::write_string(&mut header, nonce);
    header.push_str(r#","url":"#);
    let _ = sibuna_json::write_string(&mut header, url);
    header.push('}');
    let protected = base64url(header.as_bytes());
    let payload = base64url(payload.as_bytes());
    let signature = key.sign_fixed(format!("{protected}.{payload}").as_bytes())?;
    Ok(format!(
        r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
        base64url(&signature)
    ))
}

/// An external account binding (RFC 8555, section 7.3.4): the key identifier and the
/// MAC key that an authority hands out for an account it knows already.
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    /// The key identifier.
    pub kid: String,
    /// The MAC key, decoded.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding").field("kid", &self.kid).finish_non_exhaustive()
    }
}

impl Binding {
    /// Reads a binding from its identifier and the text of its key file: base64url,
    /// with or without padding, and white space around it. Returns `None` for an empty
    /// identifier or key and for a key that is not base64url.
    pub fn parse(kid: &str, key_text: &str) -> Option<Self> {
        let text = key_text.trim().trim_end_matches('=');
        let key = base64::decode(URL_SAFE_NO_PAD, text.as_bytes()).ok()?;
        (!kid.is_empty() && !key.is_empty()).then(|| Self { kid: kid.to_owned(), key })
    }

    /// The member `externalAccountBinding` of a registration at `url`: a flattened JWS
    /// with HS256 whose payload is the account key.
    pub fn bind(&self, account: &KeyPair, url: &str) -> String {
        let mut header = String::from(r#"{"alg":"HS256","kid":"#);
        let _ = sibuna_json::write_string(&mut header, &self.kid);
        header.push_str(r#","url":"#);
        let _ = sibuna_json::write_string(&mut header, url);
        header.push('}');
        let protected = base64url(header.as_bytes());
        let payload = base64url(jwk(account).as_bytes());
        let mac = hmac_sha256(&self.key, format!("{protected}.{payload}").as_bytes());
        format!(
            r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
            base64url(&mac)
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    use super::*;
    use crate::key::pkcs8_from_parts;

    fn decode(text: &str) -> Vec<u8> {
        base64::decode(URL_SAFE_NO_PAD, text.as_bytes()).unwrap()
    }

    /// The key of RFC 7515, appendix A.3.
    fn rfc7515_key() -> KeyPair {
        let x = decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        let y = decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        let d = decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI");
        let mut point = [4u8; 65];
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        KeyPair::from_pkcs8(&pkcs8_from_parts(&d.try_into().unwrap(), &point)).unwrap()
    }

    #[test]
    fn the_thumbprint_matches_rfc_7638() {
        // The canonical JWK of RFC 7638, section 3.1, on one line.
        let jwk = concat!(
            r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"#,
            "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9",
            "yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu",
            "6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBni",
            r#"Iqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#
        );
        assert_eq!(thumbprint_of(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn the_jwk_of_the_rfc_7515_key_has_its_coordinates() {
        let key = rfc7515_key();
        let expected = concat!(
            r#"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","#,
            r#""y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#
        );
        assert_eq!(jwk(&key), expected);
        assert_eq!(thumbprint(&key).len(), 43);
    }

    #[test]
    fn a_signed_request_verifies_and_names_its_parts() {
        let key = rfc7515_key();
        let url = "https://ca.example/acme/new-order";
        let jws =
            sign(&key, Some("https://ca.example/acct/1"), "nonce-1", url, r#"{"a":1}"#).unwrap();
        let value = sibuna_json::parse(jws.as_bytes()).unwrap();
        let field = |name: &str| value.as_object().unwrap().get(name).unwrap().as_str().unwrap();
        let header = String::from_utf8(decode(field("protected"))).unwrap();
        let expected = concat!(
            r#"{"alg":"ES256","kid":"https://ca.example/acct/1","nonce":"nonce-1","#,
            r#""url":"https://ca.example/acme/new-order"}"#
        );
        assert_eq!(header, expected);
        assert_eq!(decode(field("payload")), br#"{"a":1}"#);
        let signed = format!("{}.{}", field("protected"), field("payload"));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_point())
            .verify(signed.as_bytes(), &decode(field("signature")))
            .unwrap();
    }

    #[test]
    fn registration_carries_the_key_and_post_as_get_an_empty_payload() {
        let key = KeyPair::generate().unwrap();
        let jws = sign(&key, None, "n\"1", "https://ca.example/new-acct", "").unwrap();
        let value = sibuna_json::parse(jws.as_bytes()).unwrap();
        let field = |name: &str| value.as_object().unwrap().get(name).unwrap().as_str().unwrap();
        let header = String::from_utf8(decode(field("protected"))).unwrap();
        assert!(header.contains(&format!(r#""jwk":{}"#, jwk(&key))), "{header}");
        assert!(header.contains(r#""nonce":"n\"1""#), "{header}");
        assert_eq!(field("payload"), "");
    }
}

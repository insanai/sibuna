//! The PKCS#10 certificate request (RFC 2986) that finalizes an order: the public key and
//! the DNS names in a subjectAltName extension, signed with the private key.

use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, UnparsedPublicKey};

use crate::{Error, KeyPair, der, x509};

/// `extensionRequest`, 1.2.840.113549.1.9.14.
const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
/// The most names of one request.
pub const MAX_NAMES: usize = 100;

/// Writes the DER request for `names`, signed by `key`. The subject is empty, as RFC 8555
/// allows: the names are in the extension. Fails for no name, too many names, or a key
/// that cannot sign.
pub fn write(key: &KeyPair, names: &[&str]) -> Result<Vec<u8>, Error> {
    if names.is_empty() || names.len() > MAX_NAMES {
        return Err(Error::unexpected("A certificate request has 1 to 100 names."));
    }
    let extensions = der::sequence(&[&x509::subject_alt_name(names)]);
    let attribute = der::sequence(&[
        &der::element(der::OID, EXTENSION_REQUEST),
        &der::constructed(der::SET, &[&extensions]),
    ]);
    let info = der::sequence(&[
        &der::integer(&[0]),
        &der::sequence(&[]),
        &key.subject_public_key_info(),
        &der::element(0xa0, &attribute),
    ]);
    key.sign_der(&info)
}

/// What a certificate request asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// The DNS names of the subjectAltName extension.
    pub names: Vec<String>,
    /// The public key as a DER `SubjectPublicKeyInfo`.
    pub public_key: Vec<u8>,
}

/// Reads a request and checks its signature with the key it carries, on P-256 or on
/// P-384. Returns `None` for any other key type, a bad signature or a malformed request.
/// A test authority uses this; the client itself only writes requests.
pub fn read(request: &[u8]) -> Option<Parsed> {
    let (der::SEQUENCE, outer, _) = der::read(request)? else { return None };
    let (info_raw, rest) = der::read_raw(outer)?;
    let (der::SEQUENCE, _, rest) = der::read(rest)? else { return None };
    let (der::BIT_STRING, signature, _) = der::read(rest)? else { return None };
    let (der::SEQUENCE, info, _) = der::read(info_raw)? else { return None };
    let mut fields = der::children(info);
    let _version = fields.next()?;
    let _subject = fields.next()?;
    let (der::SEQUENCE, key_fields) = fields.next()? else { return None };
    let (0xa0, attributes) = fields.next()? else { return None };
    let mut key_parts = der::children(key_fields);
    let (der::SEQUENCE, key_type) = key_parts.next()? else { return None };
    let (_, point) = key_parts.next()?;
    let point = point.get(1..)?;
    let on_p384 = key_type.ends_with(crate::key::SECP384R1);
    let algorithm = if on_p384 { &ECDSA_P384_SHA384_ASN1 } else { &ECDSA_P256_SHA256_ASN1 };
    UnparsedPublicKey::new(algorithm, point).verify(info_raw, signature.get(1..)?).ok()?;
    let mut names = Vec::new();
    for (_, attribute) in der::children(attributes) {
        let mut parts = der::children(attribute);
        if parts.next() != Some((der::OID, EXTENSION_REQUEST)) {
            continue;
        }
        let (der::SET, set) = parts.next()? else { return None };
        let (der::SEQUENCE, extensions, _) = der::read(set)? else { return None };
        names.extend(x509::alt_names(extensions));
    }
    let public_key = der::element(der::SEQUENCE, key_fields);
    (names.len() <= MAX_NAMES).then_some(Parsed { names, public_key })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    use super::*;
    use crate::pem;

    #[test]
    fn a_request_reads_back_with_its_names_and_key() {
        let key = KeyPair::generate().unwrap();
        let request = write(&key, &["example.org", "www.example.org"]).unwrap();
        let parsed = read(&request).unwrap();
        assert_eq!(parsed.names, ["example.org", "www.example.org"]);
        assert_eq!(parsed.public_key, key.subject_public_key_info());
    }

    #[test]
    fn a_changed_request_fails_its_signature() {
        let key = KeyPair::generate().unwrap();
        let mut request = write(&key, &["example.org"]).unwrap();
        let at = request.windows(7).position(|window| window == b"example").unwrap();
        request[at] = b'f';
        assert_eq!(read(&request), None);
        assert_eq!(read(&[]), None);
        assert_eq!(read(&request[..40]), None);
    }

    #[test]
    fn the_name_count_is_bounded() {
        let key = KeyPair::generate().unwrap();
        assert!(write(&key, &[]).is_err());
        let many = vec!["a.example"; MAX_NAMES + 1];
        assert!(write(&key, &many).is_err());
    }

    /// `openssl req -verify` accepts the request, when OpenSSL is installed.
    #[test]
    fn openssl_verifies_the_request() {
        openssl_verifies(crate::Curve::P256, "prime256v1", "ecdsa-with-SHA256");
        openssl_verifies(crate::Curve::P384, "secp384r1", "ecdsa-with-SHA384");
    }

    fn openssl_verifies(curve: crate::Curve, curve_name: &str, signature: &str) {
        let key = KeyPair::generate_on(curve).unwrap();
        let request = write(&key, &["example.org", "www.example.org"]).unwrap();
        // Our own reader accepts the request of either curve too.
        assert_eq!(read(&request).unwrap().public_key, key.subject_public_key_info());
        let text = pem::encode("CERTIFICATE REQUEST", &request);
        let spawned = Command::new("openssl")
            .args(["req", "-verify", "-noout", "-text"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let Ok(mut child) = spawned else {
            eprintln!("openssl is not installed; the structural test covers the request");
            return;
        };
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{all}");
        assert!(all.contains("DNS:example.org") && all.contains("DNS:www.example.org"), "{all}");
        assert!(all.to_ascii_lowercase().contains("verify ok"), "{all}");
        assert!(all.contains(curve_name) && all.contains(signature), "{all}");
    }
}

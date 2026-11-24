//! An ECDSA P-256 key pair: the account key that signs every request, and the key of
//! each certificate. The arithmetic is `ring`'s.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
};

use crate::{Error, der, pem};

/// The PEM label of a PKCS#8 private key.
const LABEL: &str = "PRIVATE KEY";
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// A P-256 private key with its public point. It owns the PKCS#8 encoding and never
/// prints it: `Debug` shows the public point only.
pub struct KeyPair {
    pkcs8: Vec<u8>,
    /// Signs with the fixed-width signature of JWS.
    fixed: EcdsaKeyPair,
    /// Signs with the DER signature of X.509.
    asn1: EcdsaKeyPair,
    random: SystemRandom,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair").field("public", &self.public_point()).finish_non_exhaustive()
    }
}

fn key_failure(what: &str) -> Error {
    Error::unexpected(format!("The P-256 key could not be {what}."))
}

impl KeyPair {
    /// Draws a new key from the system's random source. Fails only when that source does.
    pub fn generate() -> Result<Self, Error> {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| key_failure("generated"))?;
        Self::from_pkcs8(document.as_ref())
    }

    /// Reads a key from its PKCS#8 DER encoding. Fails for any other key type and for an
    /// encoding without the public point.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let load = |algorithm| {
            EcdsaKeyPair::from_pkcs8(algorithm, der, &random).map_err(|_| key_failure("read"))
        };
        let fixed = load(&ECDSA_P256_SHA256_FIXED_SIGNING)?;
        let asn1 = load(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
        Ok(Self { pkcs8: der.to_vec(), fixed, asn1, random })
    }

    /// Reads the first `PRIVATE KEY` block of a PEM text.
    pub fn from_pem(text: &str) -> Result<Self, Error> {
        let blocks = pem::decode(LABEL, text).ok_or_else(|| key_failure("read"))?;
        Self::from_pkcs8(blocks.first().ok_or_else(|| key_failure("found"))?)
    }

    /// The private key as a PEM text. Write it with mode 0600 only.
    pub fn to_pem(&self) -> String {
        pem::encode(LABEL, &self.pkcs8)
    }

    /// The private key in PKCS#8 DER, for the TLS library.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public point in uncompressed form: `0x04`, then X and Y of 32 bytes each.
    pub fn public_point(&self) -> &[u8] {
        self.fixed.public_key().as_ref()
    }

    /// The public key as a DER `SubjectPublicKeyInfo`.
    pub(crate) fn subject_public_key_info(&self) -> Vec<u8> {
        let algorithm = der::sequence(&[
            &der::element(der::OID, EC_PUBLIC_KEY),
            &der::element(der::OID, PRIME256V1),
        ]);
        der::sequence(&[&algorithm, &der::bit_string(self.public_point())])
    }

    /// Signs `message` for a JWS: R and S of 32 bytes each.
    pub(crate) fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature =
            self.fixed.sign(&self.random, message).map_err(|_| key_failure("used to sign"))?;
        Ok(signature.as_ref().to_vec())
    }

    /// Signs the DER element `body` and returns `SEQUENCE { body, algorithm, signature }`,
    /// the outer form of a certificate and of a certificate request.
    pub(crate) fn sign_der(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let signature =
            self.asn1.sign(&self.random, body).map_err(|_| key_failure("used to sign"))?;
        let algorithm = signature_algorithm();
        Ok(der::sequence(&[body, &algorithm, &der::bit_string(signature.as_ref())]))
    }
}

/// The DER `AlgorithmIdentifier` of ECDSA with SHA-256.
pub(crate) fn signature_algorithm() -> Vec<u8> {
    der::sequence(&[&der::element(der::OID, ECDSA_WITH_SHA256)])
}

/// The PKCS#8 encoding of a P-256 key from its scalar and its public point, for tests
/// with the keys of the RFCs.
#[cfg(test)]
pub(crate) fn pkcs8_from_parts(scalar: &[u8; 32], point: &[u8; 65]) -> Vec<u8> {
    let algorithm = der::sequence(&[
        &der::element(der::OID, EC_PUBLIC_KEY),
        &der::element(der::OID, PRIME256V1),
    ]);
    let public = der::element(0xa1, &der::bit_string(point));
    let private =
        der::sequence(&[&der::integer(&[1]), &der::element(der::OCTET_STRING, scalar), &public]);
    der::sequence(&[&der::integer(&[0]), &algorithm, &der::element(der::OCTET_STRING, &private)])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    use super::*;

    #[test]
    fn a_key_survives_its_pem_form() {
        let key = KeyPair::generate().unwrap();
        let again = KeyPair::from_pem(&key.to_pem()).unwrap();
        assert_eq!(key.public_point(), again.public_point());
        assert_eq!(key.public_point().len(), 65);
        assert!(key.to_pem().starts_with("-----BEGIN PRIVATE KEY-----\n"));
    }

    #[test]
    fn debug_output_has_no_private_key() {
        let key = KeyPair::generate().unwrap();
        let text = format!("{key:?}");
        let secret = &key.pkcs8()[36..68];
        let leaked = text.contains(&format!("{secret:?}"));
        assert!(!leaked && text.starts_with("KeyPair"));
    }

    #[test]
    fn both_signature_forms_verify() {
        let key = KeyPair::generate().unwrap();
        let fixed = key.sign_fixed(b"message").unwrap();
        assert_eq!(fixed.len(), 64);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_point())
            .verify(b"message", &fixed)
            .unwrap();
        let body = der::sequence(&[&der::integer(&[7])]);
        let signed = key.sign_der(&body).unwrap();
        let (_, content, _) = der::read(&signed).unwrap();
        let parts: Vec<_> = der::children(content).collect();
        assert_eq!(parts.len(), 3);
        let signature = &parts[2].1[1..];
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_point())
            .verify(&body, signature)
            .unwrap();
    }

    #[test]
    fn other_input_is_no_key() {
        assert!(KeyPair::from_pkcs8(b"not a key").is_err());
        assert!(KeyPair::from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
        assert!(KeyPair::from_pem("").is_err());
    }
}

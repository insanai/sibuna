//! An ECDSA key pair: the account key that signs every request, and the key of each
//! certificate. The account key and the keys of the local authority are on P-256. The
//! key of a certificate is on P-256 or on P-384. The arithmetic is `ring`'s. `ring`
//! signs with an RSA key and cannot make one, so there are no RSA keys here.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair as _,
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
/// `secp384r1`, 1.3.132.0.34.
pub(crate) const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3.
const ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// The curve of a key. A key on P-256 signs with SHA-256, one on P-384 with SHA-384.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256, the default.
    #[default]
    P256,
    /// NIST P-384.
    P384,
}

impl Curve {
    /// The algorithms of `ring` for the fixed-width and for the DER signature.
    fn algorithms(self) -> (&'static EcdsaSigningAlgorithm, &'static EcdsaSigningAlgorithm) {
        match self {
            Self::P256 => (&ECDSA_P256_SHA256_FIXED_SIGNING, &ECDSA_P256_SHA256_ASN1_SIGNING),
            Self::P384 => (&ECDSA_P384_SHA384_FIXED_SIGNING, &ECDSA_P384_SHA384_ASN1_SIGNING),
        }
    }

    /// The object identifiers of the curve and of its signature algorithm.
    fn identifiers(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::P256 => (PRIME256V1, ECDSA_WITH_SHA256),
            Self::P384 => (SECP384R1, ECDSA_WITH_SHA384),
        }
    }
}

/// A private key with its public point. It owns the PKCS#8 encoding and never prints
/// it: `Debug` shows the public point only.
pub struct KeyPair {
    pkcs8: Vec<u8>,
    curve: Curve,
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
    Error::unexpected(format!("The key could not be {what}."))
}

/// Eight bytes from the system's random source, for a serial number. Fails only when
/// that source does.
pub fn random_serial() -> Result<u64, Error> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0; 8];
    SystemRandom::new().fill(&mut bytes).map_err(|_| key_failure("given a serial number"))?;
    Ok(u64::from_be_bytes(bytes))
}

impl KeyPair {
    /// Draws a new key on P-256 from the system's random source. Fails only when that
    /// source does.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_on(Curve::P256)
    }

    /// Draws a new key on `curve` from the system's random source. Fails only when
    /// that source does.
    pub fn generate_on(curve: Curve) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(curve.algorithms().0, &random)
            .map_err(|_| key_failure("generated"))?;
        Self::from_pkcs8(document.as_ref())
    }

    /// Reads a key on P-256 or P-384 from its PKCS#8 DER encoding. Fails for any other
    /// key type and for an encoding without the public point.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let load = |curve: Curve| {
            let (fixed, asn1) = curve.algorithms();
            let fixed = EcdsaKeyPair::from_pkcs8(fixed, der, &random).ok()?;
            let asn1 = EcdsaKeyPair::from_pkcs8(asn1, der, &random).ok()?;
            Some((curve, fixed, asn1))
        };
        let (curve, fixed, asn1) =
            load(Curve::P256).or_else(|| load(Curve::P384)).ok_or_else(|| key_failure("read"))?;
        Ok(Self { pkcs8: der.to_vec(), curve, fixed, asn1, random })
    }

    /// The curve of the key.
    pub fn curve(&self) -> Curve {
        self.curve
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

    /// The public point in uncompressed form: `0x04`, then X and Y, of 32 bytes each
    /// on P-256 and of 48 bytes each on P-384.
    pub fn public_point(&self) -> &[u8] {
        self.fixed.public_key().as_ref()
    }

    /// The public key as a DER `SubjectPublicKeyInfo`, as a certificate carries it.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        let algorithm = der::sequence(&[
            &der::element(der::OID, EC_PUBLIC_KEY),
            &der::element(der::OID, self.curve.identifiers().0),
        ]);
        der::sequence(&[&algorithm, &der::bit_string(self.public_point())])
    }

    /// The DER `AlgorithmIdentifier` of the signatures of this key: ECDSA with SHA-256
    /// or with SHA-384.
    pub(crate) fn signature_algorithm(&self) -> Vec<u8> {
        der::sequence(&[&der::element(der::OID, self.curve.identifiers().1)])
    }

    /// Signs `message` for a JWS with the algorithm ES256: R and S of 32 bytes each.
    /// Fails for a key on another curve; the account key is always on P-256.
    pub(crate) fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if self.curve != Curve::P256 {
            return Err(key_failure("used for a request: the account key is on P-256"));
        }
        let signature =
            self.fixed.sign(&self.random, message).map_err(|_| key_failure("used to sign"))?;
        Ok(signature.as_ref().to_vec())
    }

    /// Signs the DER element `body` and returns `SEQUENCE { body, algorithm, signature }`,
    /// the outer form of a certificate and of a certificate request.
    pub(crate) fn sign_der(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let signature =
            self.asn1.sign(&self.random, body).map_err(|_| key_failure("used to sign"))?;
        let algorithm = self.signature_algorithm();
        Ok(der::sequence(&[body, &algorithm, &der::bit_string(signature.as_ref())]))
    }
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
    fn a_key_on_p384_signs_with_sha384_and_survives_its_pem_form() {
        use ring::signature::ECDSA_P384_SHA384_ASN1;
        let key = KeyPair::generate_on(Curve::P384).unwrap();
        assert_eq!((key.curve(), key.public_point().len()), (Curve::P384, 97));
        let again = KeyPair::from_pem(&key.to_pem()).unwrap();
        assert_eq!((again.curve(), again.public_point()), (Curve::P384, key.public_point()));
        assert_eq!(KeyPair::generate().unwrap().curve(), Curve::P256);
        let body = der::sequence(&[&der::integer(&[7])]);
        let signed = key.sign_der(&body).unwrap();
        let (_, content, _) = der::read(&signed).unwrap();
        let parts: Vec<_> = der::children(content).collect();
        assert!(parts[1].1.ends_with(ECDSA_WITH_SHA384));
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key.public_point())
            .verify(&body, &parts[2].1[1..])
            .unwrap();
        assert!(key.subject_public_key_info().windows(5).any(|window| window == SECP384R1));
        // A request to the authority is signed with ES256, by a key on P-256 only.
        assert!(key.sign_fixed(b"message").is_err());
    }

    #[test]
    fn other_input_is_no_key() {
        assert!(KeyPair::from_pkcs8(b"not a key").is_err());
        assert!(KeyPair::from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
        assert!(KeyPair::from_pem("").is_err());
    }
}

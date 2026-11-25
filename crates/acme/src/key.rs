//! A key pair: the account key that signs every request, and the key of each
//! certificate. The account key and the keys of the local authority are ECDSA keys on
//! P-256. The key of a certificate is on P-256, on P-384, or an RSA key of 2048, 3072
//! or 4096 bits. The arithmetic is `ring`'s. `ring` signs with an RSA key and cannot
//! make one, so an RSA key comes from the `openssl` program ([`crate::keygen`]).

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair,
};

use crate::{Error, der, keygen, pem};

/// The PEM label of a PKCS#8 private key.
const LABEL: &str = "PRIVATE KEY";
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `secp384r1`, 1.3.132.0.34.
const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3.
const ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11.
const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// The curve of an ECDSA key. A key on P-256 signs with SHA-256, one on P-384 with
/// SHA-384.
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

/// The kind of the key of a certificate: `global.acme.key`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyType {
    /// ECDSA on P-256, the default.
    #[default]
    P256,
    /// ECDSA on P-384.
    P384,
    /// RSA with a modulus of 2048 bits.
    Rsa2048,
    /// RSA with a modulus of 3072 bits.
    Rsa3072,
    /// RSA with a modulus of 4096 bits.
    Rsa4096,
}

impl KeyType {
    /// The bits of the modulus of an RSA key, and `None` for an ECDSA key.
    pub fn rsa_bits(self) -> Option<u32> {
        match self {
            Self::P256 | Self::P384 => None,
            Self::Rsa2048 => Some(2048),
            Self::Rsa3072 => Some(3072),
            Self::Rsa4096 => Some(4096),
        }
    }
}

/// The two signers of an ECDSA key.
struct Ecdsa {
    curve: Curve,
    /// Signs with the fixed-width signature of JWS.
    fixed: EcdsaKeyPair,
    /// Signs with the DER signature of X.509.
    asn1: EcdsaKeyPair,
}

/// The signers of a key. Both are large, so each lives behind a pointer.
enum Signer {
    Ecdsa(Box<Ecdsa>),
    /// Signs with PKCS#1 version 1.5 and SHA-256.
    Rsa(Box<RsaKeyPair>),
}

/// A private key with its public key. It owns the PKCS#8 encoding and never prints
/// it: `Debug` shows the public key only.
pub struct KeyPair {
    pkcs8: Vec<u8>,
    signer: Signer,
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

    /// Makes a new key of the kind `kind`. An ECDSA key is drawn here. An RSA key is
    /// made by the `openssl` program, which may take seconds. Fails with `ACME015`
    /// when that program cannot be run or writes no RSA key of the asked size.
    pub fn generate_as(kind: KeyType) -> Result<Self, Error> {
        let Some(bits) = kind.rsa_bits() else {
            let curve = if kind == KeyType::P384 { Curve::P384 } else { Curve::P256 };
            return Self::generate_on(curve);
        };
        let wrong = || Error::key_tool(format!("The program wrote no RSA key of {bits} bits."));
        let key = Self::from_pem(&keygen::rsa_pem(bits)?).map_err(|_| wrong())?;
        if key.key_type() == kind { Ok(key) } else { Err(wrong()) }
    }

    /// Reads a key from its PKCS#8 DER encoding: ECDSA on P-256 or P-384, or RSA of
    /// 2048 to 4096 bits. Fails for any other key type and for an ECDSA encoding
    /// without the public point.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let ecdsa = |curve: Curve| {
            let (fixed, asn1) = curve.algorithms();
            let fixed = EcdsaKeyPair::from_pkcs8(fixed, der, &random).ok()?;
            let asn1 = EcdsaKeyPair::from_pkcs8(asn1, der, &random).ok()?;
            Some(Signer::Ecdsa(Box::new(Ecdsa { curve, fixed, asn1 })))
        };
        let rsa = || RsaKeyPair::from_pkcs8(der).ok().map(|key| Signer::Rsa(Box::new(key)));
        let signer = ecdsa(Curve::P256)
            .or_else(|| ecdsa(Curve::P384))
            .or_else(rsa)
            .ok_or_else(|| key_failure("read"))?;
        Ok(Self { pkcs8: der.to_vec(), signer, random })
    }

    /// The kind of the key. An RSA key of another size than the three we make counts
    /// as the next larger one.
    pub fn key_type(&self) -> KeyType {
        match &self.signer {
            Signer::Ecdsa(key) => match key.curve {
                Curve::P256 => KeyType::P256,
                Curve::P384 => KeyType::P384,
            },
            Signer::Rsa(key) => match key.public().modulus_len() * 8 {
                ..=2048 => KeyType::Rsa2048,
                2049..=3072 => KeyType::Rsa3072,
                _ => KeyType::Rsa4096,
            },
        }
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

    /// The public key. For an ECDSA key it is the point in uncompressed form: `0x04`,
    /// then X and Y, of 32 bytes each on P-256 and of 48 bytes each on P-384. For an
    /// RSA key it is the DER `RSAPublicKey` of PKCS#1.
    pub fn public_point(&self) -> &[u8] {
        match &self.signer {
            Signer::Ecdsa(key) => key.fixed.public_key().as_ref(),
            Signer::Rsa(key) => key.public_key().as_ref(),
        }
    }

    /// The public key as a DER `SubjectPublicKeyInfo`, as a certificate carries it.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        let algorithm = match &self.signer {
            Signer::Ecdsa(key) => der::sequence(&[
                &der::element(der::OID, EC_PUBLIC_KEY),
                &der::element(der::OID, key.curve.identifiers().0),
            ]),
            Signer::Rsa(_) => der::sequence(&[
                &der::element(der::OID, RSA_ENCRYPTION),
                &der::element(der::NULL, &[]),
            ]),
        };
        der::sequence(&[&algorithm, &der::bit_string(self.public_point())])
    }

    /// The DER `AlgorithmIdentifier` of the signatures of this key: ECDSA with SHA-256
    /// or with SHA-384, or RSA with PKCS#1 version 1.5 and SHA-256.
    pub(crate) fn signature_algorithm(&self) -> Vec<u8> {
        match &self.signer {
            Signer::Ecdsa(key) => {
                der::sequence(&[&der::element(der::OID, key.curve.identifiers().1)])
            }
            Signer::Rsa(_) => der::sequence(&[
                &der::element(der::OID, SHA256_WITH_RSA),
                &der::element(der::NULL, &[]),
            ]),
        }
    }

    /// Signs `message` for a JWS with the algorithm ES256: R and S of 32 bytes each.
    /// Fails for any other key than one on P-256; the account key is always on P-256.
    pub(crate) fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let on_p256 = match &self.signer {
            Signer::Ecdsa(key) if key.curve == Curve::P256 => Some(&key.fixed),
            _ => None,
        };
        let Some(fixed) = on_p256 else {
            return Err(key_failure("used for a request: the account key is on P-256"));
        };
        let signature =
            fixed.sign(&self.random, message).map_err(|_| key_failure("used to sign"))?;
        Ok(signature.as_ref().to_vec())
    }

    /// Signs the DER element `body` and returns `SEQUENCE { body, algorithm, signature }`,
    /// the outer form of a certificate, of a certificate request and of a revocation
    /// list.
    pub(crate) fn sign_der(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = match &self.signer {
            Signer::Ecdsa(key) => {
                let signed = key.asn1.sign(&self.random, body);
                signed.map_err(|_| key_failure("used to sign"))?.as_ref().to_vec()
            }
            Signer::Rsa(key) => {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &self.random, body, &mut signature)
                    .map_err(|_| key_failure("used to sign"))?;
                signature
            }
        };
        let algorithm = self.signature_algorithm();
        Ok(der::sequence(&[body, &algorithm, &der::bit_string(&signature)]))
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

/// One RSA key of 2048 bits for the tests of the crate, made once: a key takes a
/// noticeable part of a second. `None` when `openssl` is not installed.
#[cfg(test)]
pub(crate) fn test_rsa_key() -> Option<KeyPair> {
    static PEM: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let text = PEM.get_or_init(|| {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        keygen::probe().ok()?;
        KeyPair::generate_as(KeyType::Rsa2048).ok().map(|key| key.to_pem())
    });
    text.as_deref().and_then(|text| KeyPair::from_pem(text).ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256,
        UnparsedPublicKey,
    };

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
        assert_eq!((key.key_type(), key.public_point().len()), (KeyType::P384, 97));
        let again = KeyPair::from_pem(&key.to_pem()).unwrap();
        assert_eq!((again.key_type(), again.public_point()), (KeyType::P384, key.public_point()));
        assert_eq!(KeyPair::generate().unwrap().key_type(), KeyType::P256);
        assert_eq!(KeyPair::generate_as(KeyType::P384).unwrap().key_type(), KeyType::P384);
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

    /// An RSA key from `openssl` loads, signs with PKCS#1 and SHA-256, and survives its
    /// PEM form, when OpenSSL is installed.
    #[test]
    fn an_rsa_key_signs_with_pkcs1_and_sha256_and_survives_its_pem_form() {
        let Some(key) = test_rsa_key() else {
            eprintln!("openssl is not installed; no RSA key is made");
            return;
        };
        assert_eq!((key.key_type(), key.key_type().rsa_bits()), (KeyType::Rsa2048, Some(2048)));
        let again = KeyPair::from_pem(&key.to_pem()).unwrap();
        assert_eq!(again.public_point(), key.public_point());
        let body = der::sequence(&[&der::integer(&[7])]);
        let signed = key.sign_der(&body).unwrap();
        let (_, content, _) = der::read(&signed).unwrap();
        let parts: Vec<_> = der::children(content).collect();
        assert!(parts[1].1.starts_with(&der::element(der::OID, SHA256_WITH_RSA)));
        let signature = &parts[2].1[1..];
        assert_eq!(signature.len(), 256);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_point())
            .verify(&body, signature)
            .unwrap();
        assert!(crate::verify::verifies(
            &key.subject_public_key_info(),
            SHA256_WITH_RSA,
            &body,
            signature
        ));
        // The account key is never an RSA key, and the debug form shows no private part.
        assert!(key.sign_fixed(b"message").is_err());
        assert!(format!("{key:?}").len() < 2048);
    }

    #[test]
    fn other_input_is_no_key() {
        assert!(KeyPair::from_pkcs8(b"not a key").is_err());
        assert!(KeyPair::from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
        assert!(KeyPair::from_pem("").is_err());
    }
}

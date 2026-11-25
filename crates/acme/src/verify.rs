//! Signature verification for what an authority sends us signed: an OCSP response and
//! the certificate of its delegated signer (SID 0021).
//!
//! We verify ECDSA on P-256 and P-384 and RSA PKCS#1 v1.5, each with SHA-256, SHA-384
//! and, for RSA, SHA-512. Anything else does not verify.

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

use crate::der;

/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `secp384r1`, 1.3.132.0.34.
const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3.
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11.
const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// `sha384WithRSAEncryption`, 1.2.840.113549.1.1.12.
const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/// `sha512WithRSAEncryption`, 1.2.840.113549.1.1.13.
const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];

/// The key inside a DER `SubjectPublicKeyInfo`.
struct PublicKey<'a> {
    /// The object identifier of the key type.
    kind: &'a [u8],
    /// The object identifier of the curve of an EC key.
    curve: Option<&'a [u8]>,
    /// The key bytes of the bit string.
    key: &'a [u8],
}

fn public_key(spki: &[u8]) -> Option<PublicKey<'_>> {
    let (der::SEQUENCE, content, _) = der::read(spki)? else { return None };
    let mut fields = der::children(content);
    let (der::SEQUENCE, algorithm) = fields.next()? else { return None };
    let (der::BIT_STRING, bits) = fields.next()? else { return None };
    let mut algorithm = der::children(algorithm);
    let (der::OID, kind) = algorithm.next()? else { return None };
    let curve = algorithm.next().filter(|(tag, _)| *tag == der::OID).map(|(_, curve)| curve);
    // The first byte counts unused bits. A key has none.
    let (&0, key) = bits.split_first()? else { return None };
    Some(PublicKey { kind, curve, key })
}

/// The verification that a key type, a curve and a signature algorithm select.
fn algorithm(
    kind: &[u8],
    curve: Option<&[u8]>,
    signature_oid: &[u8],
) -> Option<&'static dyn VerificationAlgorithm> {
    if kind == RSA_ENCRYPTION {
        return match signature_oid {
            RSA_SHA256 => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
            RSA_SHA384 => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
            RSA_SHA512 => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
            _ => None,
        };
    }
    if kind != EC_PUBLIC_KEY {
        return None;
    }
    match (curve?, signature_oid) {
        (PRIME256V1, ECDSA_SHA256) => Some(&signature::ECDSA_P256_SHA256_ASN1),
        (PRIME256V1, ECDSA_SHA384) => Some(&signature::ECDSA_P256_SHA384_ASN1),
        (SECP384R1, ECDSA_SHA256) => Some(&signature::ECDSA_P384_SHA256_ASN1),
        (SECP384R1, ECDSA_SHA384) => Some(&signature::ECDSA_P384_SHA384_ASN1),
        _ => None,
    }
}

/// Whether `signature` over `message` verifies with the key of the DER
/// `SubjectPublicKeyInfo` `spki`. `signature_oid` is the object identifier of the
/// signature algorithm. An unknown key or algorithm does not verify.
pub(crate) fn verifies(
    spki: &[u8],
    signature_oid: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Some(PublicKey { kind, curve, key }) = public_key(spki) else { return false };
    let Some(algorithm) = algorithm(kind, curve, signature_oid) else { return false };
    UnparsedPublicKey::new(algorithm, key).verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{KeyPair, x509};

    #[test]
    fn a_certificate_verifies_with_the_key_of_its_signer_only() {
        let signer = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let template =
            x509::Template { issuer: "A", subject: "B", not_after: 10, ..Default::default() };
        let der = x509::write(&template, &other.subject_public_key_info(), &signer).unwrap();
        let parts = x509::parts(&der).unwrap();
        let spki = signer.subject_public_key_info();
        assert!(verifies(&spki, parts.algorithm, parts.tbs, parts.signature));
        let wrong = other.subject_public_key_info();
        assert!(!verifies(&wrong, parts.algorithm, parts.tbs, parts.signature));
        assert!(!verifies(&spki, RSA_SHA256, parts.tbs, parts.signature));
        assert!(!verifies(&spki, parts.algorithm, &parts.tbs[1..], parts.signature));
        assert!(!verifies(&[], parts.algorithm, parts.tbs, parts.signature));
        assert!(!verifies(&spki[..spki.len() - 1], parts.algorithm, parts.tbs, parts.signature));
    }
}

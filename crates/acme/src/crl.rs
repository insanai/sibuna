//! The certificate revocation list of the local authority (RFC 5280, version 2): a
//! writer, and a reader for the schedule and for tests.
//!
//! ```text
//! CertificateList  = SEQUENCE { tbsCertList, signatureAlgorithm, signature }
//! tbsCertList      = SEQUENCE { version 1, signature, issuer, thisUpdate, nextUpdate,
//!                               revokedCertificates (absent when empty),
//!                               [0] { authorityKeyIdentifier, cRLNumber } }
//! revoked entry    = SEQUENCE { serial, revocationDate }
//! ```

use crate::{Error, KeyPair, der, time, verify, x509};

/// `cRLNumber`, 2.5.29.20.
const CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
/// The PEM label of a revocation list.
pub const LABEL: &str = "X509 CRL";
/// The most entries that [`read`] takes from a list.
pub const MAX_ENTRIES: usize = 4096;

/// One revoked certificate of a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// The serial number of the certificate.
    pub serial: u64,
    /// When it was revoked, in seconds since 1970.
    pub revoked_at: u64,
}

/// A revocation list to write, or one that was read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct List {
    /// The common name of the issuer: the subject of the certificate that signs.
    pub issuer: String,
    /// The start of the validity, in seconds since 1970.
    pub this_update: u64,
    /// The time by which the next list is published. The year must be before 2050.
    pub next_update: u64,
    /// The number of the list. A later list has a larger number.
    pub number: u64,
    /// The key identifier of the key that signs: [`x509::key_id`] of it.
    pub authority_key_id: Vec<u8>,
    /// The revoked certificates.
    pub entries: Vec<Entry>,
}

/// A `UTCTime` element.
fn utc(seconds: u64) -> Vec<u8> {
    der::element(der::UTC_TIME, time::format_utc_time(seconds).as_bytes())
}

/// Writes the DER list, signed by `signer`. The caller gives the name and the key
/// identifier of the certificate of `signer`. Fails only when the key cannot sign.
pub fn write(list: &List, signer: &KeyPair) -> Result<Vec<u8>, Error> {
    let entries: Vec<u8> = list
        .entries
        .iter()
        .flat_map(|entry| {
            der::sequence(&[&der::integer(&entry.serial.to_be_bytes()), &utc(entry.revoked_at)])
        })
        .collect();
    // An empty list of entries is left out, as the encoding rules demand.
    let revoked = if entries.is_empty() { Vec::new() } else { der::sequence(&[&entries]) };
    let key_id = der::sequence(&[&der::element(0x80, &list.authority_key_id)]);
    let extensions = [
        x509::extension(x509::AUTHORITY_KEY_ID, false, &key_id),
        x509::extension(CRL_NUMBER, false, &der::integer(&list.number.to_be_bytes())),
    ]
    .concat();
    let body = der::sequence(&[
        &der::integer(&[1]),
        &signer.signature_algorithm(),
        &x509::common_name(&list.issuer),
        &utc(list.this_update),
        &utc(list.next_update),
        &revoked,
        &der::element(0xa0, &der::sequence(&[&extensions])),
    ]);
    signer.sign_der(&body)
}

/// A non-negative `INTEGER` of at most 64 bits.
fn number(content: &[u8]) -> Option<u64> {
    let digits = match content {
        [0, rest @ ..] => rest,
        other => other,
    };
    (digits.len() <= 8).then(|| digits.iter().fold(0, |n, &byte| (n << 8) | u64::from(byte)))
}

/// A `UTCTime` or `GeneralizedTime` element.
fn instant(tag: u8, text: &[u8]) -> Option<u64> {
    match tag {
        der::UTC_TIME => time::parse_der_time(text, true),
        der::GENERALIZED_TIME => time::parse_der_time(text, false),
        _ => None,
    }
}

/// Reads a DER list. With `signer`, a DER `SubjectPublicKeyInfo`, the signature must
/// verify with that key. Returns `None` for a list that cannot be walked, that has more
/// than [`MAX_ENTRIES`] entries or a serial of more than 64 bits, or whose signature
/// does not verify.
pub fn read(list: &[u8], signer: Option<&[u8]>) -> Option<List> {
    let (der::SEQUENCE, outer, _) = der::read(list)? else { return None };
    let (body_raw, rest) = der::read_raw(outer)?;
    let (der::SEQUENCE, algorithm, rest) = der::read(rest)? else { return None };
    let (der::OID, signature_oid, _) = der::read(algorithm)? else { return None };
    let (der::BIT_STRING, signature, _) = der::read(rest)? else { return None };
    if let Some(key) = signer
        && !verify::verifies(key, signature_oid, body_raw, signature.get(1..)?)
    {
        return None;
    }
    let (der::SEQUENCE, body, _) = der::read(body_raw)? else { return None };
    let mut fields = der::children(body).peekable();
    fields.next_if(|(tag, _)| *tag == der::INTEGER);
    let _algorithm = fields.next()?;
    let (der::SEQUENCE, issuer) = fields.next()? else { return None };
    let (tag, text) = fields.next()?;
    let this_update = instant(tag, text)?;
    let (tag, text) = fields.next()?;
    let next_update = instant(tag, text)?;
    let mut found =
        List { issuer: x509::issuer_name(issuer), this_update, next_update, ..List::default() };
    if let Some((_, revoked)) = fields.next_if(|(tag, _)| *tag == der::SEQUENCE) {
        for (_, entry) in der::children(revoked) {
            let mut parts = der::children(entry);
            let (der::INTEGER, serial) = parts.next()? else { return None };
            let (tag, text) = parts.next()?;
            found.entries.push(Entry { serial: number(serial)?, revoked_at: instant(tag, text)? });
            if found.entries.len() > MAX_ENTRIES {
                return None;
            }
        }
    }
    if let Some((0xa0, extensions)) = fields.next() {
        let (der::SEQUENCE, extensions, _) = der::read(extensions)? else { return None };
        found.authority_key_id = x509::authority_key_id(extensions);
        if let Some(value) = x509::extension_value(extensions, CRL_NUMBER) {
            let (der::INTEGER, digits, _) = der::read(value)? else { return None };
            found.number = number(digits)?;
        }
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn list() -> List {
        List {
            issuer: "Test Issuer".to_owned(),
            this_update: 1_800_000_000,
            next_update: 1_800_086_400,
            number: 1_800_000_060,
            authority_key_id: vec![7; 20],
            entries: vec![
                Entry { serial: 0x8000_0000_0000_0001, revoked_at: 1_799_999_000 },
                Entry { serial: 5, revoked_at: 1_799_999_500 },
            ],
        }
    }

    #[test]
    fn a_list_reads_back_and_verifies_with_its_signer_only() {
        let key = KeyPair::generate().unwrap();
        let written = write(&list(), &key).unwrap();
        assert_eq!(read(&written, Some(&key.subject_public_key_info())), Some(list()));
        assert_eq!(read(&written, None), Some(list()));
        let other = KeyPair::generate().unwrap();
        assert_eq!(read(&written, Some(&other.subject_public_key_info())), None);
    }

    #[test]
    fn an_empty_list_has_no_entries_element() {
        let key = KeyPair::generate().unwrap();
        let empty = List { entries: Vec::new(), ..list() };
        let written = write(&empty, &key).unwrap();
        assert_eq!(read(&written, Some(&key.subject_public_key_info())), Some(empty));
        let with_entries = write(&list(), &key).unwrap();
        assert!(written.len() < with_entries.len());
    }

    #[test]
    fn no_prefix_and_no_changed_byte_reads_as_a_signed_list() {
        let key = KeyPair::generate().unwrap();
        let public = key.subject_public_key_info();
        let written = write(&list(), &key).unwrap();
        for length in 0..written.len() {
            assert_eq!(read(&written[..length], Some(&public)), None, "prefix {length}");
            let _ = read(&written[..length], None);
        }
        for at in 0..written.len() {
            for bit in [0x01, 0x80] {
                let mut changed = written.clone();
                changed[at] ^= bit;
                // A changed byte either breaks the signature or leaves the list as it
                // was: the encoding of a signature has bytes that carry nothing.
                let found = read(&changed, Some(&public));
                assert!(found.is_none() || found == Some(list()), "byte {at}");
                let _ = read(&changed, None);
            }
        }
    }
}

//! Certificates: reading the few fields that renewal needs, and writing the self-signed
//! certificate of the TLS-ALPN-01 challenge (RFC 8737).

use std::net::IpAddr;

use sibuna_crypto::sha256::Sha256;

use crate::error::printable;
use crate::key::signature_algorithm;
use crate::{Error, KeyPair, der, time};

/// `subjectAltName`, 2.5.29.17.
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// `basicConstraints`, 2.5.29.19.
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// `commonName`, 2.5.4.3.
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `organizationName`, 2.5.4.10.
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
/// `id-pe-acmeIdentifier`, 1.3.6.1.5.5.7.1.31.
const ACME_IDENTIFIER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
/// `subjectKeyIdentifier`, 2.5.29.14.
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
/// `keyUsage`, 2.5.29.15.
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// `authorityKeyIdentifier`, 2.5.29.35.
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
/// `extKeyUsage`, 2.5.29.37.
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
/// `id-kp-serverAuth`, 1.3.6.1.5.5.7.3.1.
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// The key usage of an authority: keyCertSign and cRLSign.
const USAGE_AUTHORITY: &[u8] = &[0x03, 0x02, 0x01, 0x06];
/// The key usage of a server with an ECDSA key: digitalSignature.
const USAGE_SERVER: &[u8] = &[0x03, 0x02, 0x07, 0x80];
/// The `iPAddress` choice of a general name.
const IP_ADDRESS: u8 = 0x87;
/// DER `BOOLEAN TRUE`.
const TRUE: &[u8] = &[0x01, 0x01, 0xff];
/// The `dNSName` choice of a general name.
const DNS_NAME: u8 = 0x82;
/// How long a challenge certificate is valid, in seconds.
const CHALLENGE_LIFETIME: u64 = 7 * 86_400;

/// The fields of a certificate that the renewal schedule and the status table use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The start of the validity, in seconds since 1970.
    pub not_before: u64,
    /// The end of the validity, in seconds since 1970.
    pub not_after: u64,
    /// The common name of the issuer, or its organization. Printable ASCII.
    pub issuer: String,
    /// The DNS names and the IP addresses of the subjectAltName extension. An address
    /// is in the text form of [`std::net::IpAddr`].
    pub names: Vec<String>,
}

impl Certificate {
    /// Whether the certificate names `host`, exactly or by a wildcard of one label.
    pub fn names_host(&self, host: &str) -> bool {
        self.names.iter().any(|name| {
            name.eq_ignore_ascii_case(host)
                || name.strip_prefix("*.").is_some_and(|parent| {
                    host.split_once('.').is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(parent))
                })
        })
    }
}

/// Reads a DER certificate. Returns `None` when it cannot be walked.
pub fn read(certificate: &[u8]) -> Option<Certificate> {
    let (der::SEQUENCE, outer, _) = der::read(certificate)? else { return None };
    let (der::SEQUENCE, tbs, _) = der::read(outer)? else { return None };
    let mut fields = der::children(tbs).peekable();
    // The version is the optional explicit field [0].
    if fields.peek().is_some_and(|(tag, _)| *tag == 0xa0) {
        fields.next();
    }
    let _serial = fields.next()?;
    let _algorithm = fields.next()?;
    let (der::SEQUENCE, issuer) = fields.next()? else { return None };
    let (der::SEQUENCE, validity) = fields.next()? else { return None };
    let mut times = der::children(validity).map(|(tag, text)| match tag {
        der::UTC_TIME => time::parse_der_time(text, true),
        der::GENERALIZED_TIME => time::parse_der_time(text, false),
        _ => None,
    });
    let not_before = times.next()??;
    let not_after = times.next()??;
    let names = fields
        .find(|(tag, _)| *tag == 0xa3)
        .and_then(|(_, extensions)| der::read(extensions))
        .map(|(_, extensions, _)| alt_names(extensions))
        .unwrap_or_default();
    Some(Certificate { not_before, not_after, issuer: issuer_name(issuer), names })
}

/// The common name in a DER `Name`, or else the organization, or `-`.
fn issuer_name(name: &[u8]) -> String {
    attribute(name, COMMON_NAME)
        .or_else(|| attribute(name, ORGANIZATION))
        .map_or_else(|| "-".to_owned(), |text| printable(&String::from_utf8_lossy(text), 64))
}

/// The value of the first attribute of the type `wanted` in a DER `Name`.
fn attribute<'a>(name: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    for (_, set) in der::children(name) {
        for (_, pair) in der::children(set) {
            let mut parts = der::children(pair);
            if parts.next() == Some((der::OID, wanted)) {
                return parts.next().map(|(_, text)| text);
            }
        }
    }
    None
}

/// The DNS names in the content of a DER `Extensions` sequence.
pub(crate) fn alt_names(extensions: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for (_, extension) in der::children(extensions) {
        let mut fields = der::children(extension);
        if fields.next() != Some((der::OID, SUBJECT_ALT_NAME)) {
            continue;
        }
        // The value is the last field. An optional critical flag may precede it.
        let Some((der::OCTET_STRING, value)) = fields.last() else { continue };
        let Some((der::SEQUENCE, general_names, _)) = der::read(value) else { continue };
        for (tag, name) in der::children(general_names) {
            if tag == DNS_NAME
                && let Ok(name) = std::str::from_utf8(name)
            {
                names.push(name.to_owned());
            }
            if tag == IP_ADDRESS {
                let address = match name.len() {
                    4 => <[u8; 4]>::try_from(name).ok().map(IpAddr::from),
                    16 => <[u8; 16]>::try_from(name).ok().map(IpAddr::from),
                    _ => None,
                };
                names.extend(address.map(|address| address.to_string()));
            }
        }
    }
    names
}

/// One general name: an `iPAddress` for the text of an address, else a `dNSName`.
fn general_name(name: &str) -> Vec<u8> {
    match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => der::element(IP_ADDRESS, &address.octets()),
        Ok(IpAddr::V6(address)) => der::element(IP_ADDRESS, &address.octets()),
        Err(_) => der::element(DNS_NAME, name.as_bytes()),
    }
}

/// The DER subjectAltName extension for DNS names and IP addresses.
pub(crate) fn subject_alt_name(names: &[&str]) -> Vec<u8> {
    let general: Vec<u8> = names.iter().flat_map(|name| general_name(name)).collect();
    let value = der::element(der::SEQUENCE, &general);
    der::sequence(&[
        &der::element(der::OID, SUBJECT_ALT_NAME),
        &der::element(der::OCTET_STRING, &value),
    ])
}

/// A certificate to write. Fill the fields and call [`write`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Template<'a> {
    /// The common name of the issuer.
    pub issuer: &'a str,
    /// The common name of the subject.
    pub subject: &'a str,
    /// The names of the subjectAltName extension. The text of an IP address becomes an
    /// `iPAddress` entry, anything else a `dNSName`. May be empty for an authority.
    pub names: &'a [&'a str],
    /// The start of the validity, in seconds since 1970.
    pub not_before: u64,
    /// The end of the validity, in seconds since 1970. The year must be before 2050.
    pub not_after: u64,
    /// The serial number.
    pub serial: u64,
    /// Mark the certificate as a certificate authority: basicConstraints and the key
    /// usage keyCertSign and cRLSign, both critical.
    pub authority: bool,
    /// With `authority`: how many authorities may follow below this one.
    pub path_len: Option<u8>,
    /// Mark the certificate as that of a TLS server: the key usage digitalSignature,
    /// critical, and the extended key usage serverAuth.
    pub server: bool,
    /// Add the subject key identifier, [`key_id`] of the subject's key.
    pub subject_key_id: bool,
    /// The authority key identifier: [`key_id`] of the issuer's key.
    pub authority_key_id: Option<[u8; 20]>,
    /// The digest of the critical acmeIdentifier extension of TLS-ALPN-01.
    pub acme_identifier: Option<[u8; 32]>,
}

fn common_name(text: &str) -> Vec<u8> {
    let pair = der::sequence(&[
        &der::element(der::OID, COMMON_NAME),
        &der::element(der::UTF8_STRING, text.as_bytes()),
    ]);
    der::sequence(&[&der::constructed(der::SET, &[&pair])])
}

/// The identifier of a public key in the key identifier extensions: the first 160 bits
/// of the SHA-256 digest of its DER `SubjectPublicKeyInfo` (RFC 7093, method 4).
pub fn key_id(subject_public_key_info: &[u8]) -> [u8; 20] {
    let digest = Sha256::digest(subject_public_key_info);
    let mut id = [0; 20];
    id.copy_from_slice(&digest[..20]);
    id
}

/// One extension: its type, the critical flag, and the DER of its value.
fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let flag: &[u8] = if critical { TRUE } else { &[] };
    der::sequence(&[&der::element(der::OID, oid), flag, &der::element(der::OCTET_STRING, value)])
}

fn extensions(template: &Template<'_>, subject_key: &[u8]) -> Vec<u8> {
    let mut list = Vec::new();
    if template.authority {
        let length = template.path_len.map(|length| der::integer(&[length]));
        let value = der::sequence(&[TRUE, length.as_deref().unwrap_or_default()]);
        list.extend(extension(BASIC_CONSTRAINTS, true, &value));
        list.extend(extension(KEY_USAGE, true, USAGE_AUTHORITY));
    }
    if template.server {
        list.extend(extension(KEY_USAGE, true, USAGE_SERVER));
        let purposes = der::sequence(&[&der::element(der::OID, SERVER_AUTH)]);
        list.extend(extension(EXT_KEY_USAGE, false, &purposes));
    }
    if template.subject_key_id {
        let value = der::element(der::OCTET_STRING, &key_id(subject_key));
        list.extend(extension(SUBJECT_KEY_ID, false, &value));
    }
    if let Some(id) = template.authority_key_id {
        let value = der::sequence(&[&der::element(0x80, &id)]);
        list.extend(extension(AUTHORITY_KEY_ID, false, &value));
    }
    if !template.names.is_empty() {
        list.extend(subject_alt_name(template.names));
    }
    if let Some(digest) = template.acme_identifier {
        let value = der::element(der::OCTET_STRING, &digest);
        list.extend(der::sequence(&[
            &der::element(der::OID, ACME_IDENTIFIER),
            TRUE,
            &der::element(der::OCTET_STRING, &value),
        ]));
    }
    der::element(0xa3, &der::element(der::SEQUENCE, &list))
}

/// Writes a DER certificate of version 3 for the public key `subject_key` (a DER
/// `SubjectPublicKeyInfo`), signed by `signer`. The client uses it for the challenge
/// certificate. A test authority uses it to issue. Fails only when the key cannot sign.
pub fn write(
    template: &Template<'_>,
    subject_key: &[u8],
    signer: &KeyPair,
) -> Result<Vec<u8>, Error> {
    let time = |seconds| der::element(der::UTC_TIME, time::format_utc_time(seconds).as_bytes());
    let validity = der::sequence(&[&time(template.not_before), &time(template.not_after)]);
    let tbs = der::sequence(&[
        &der::element(0xa0, &der::integer(&[2])),
        &der::integer(&template.serial.max(1).to_be_bytes()),
        &signature_algorithm(),
        &common_name(template.issuer),
        &validity,
        &common_name(template.subject),
        subject_key,
        &extensions(template, subject_key),
    ]);
    signer.sign_der(&tbs)
}

/// Writes the self-signed certificate that answers TLS-ALPN-01 for `name`: the name in
/// subjectAltName, and the SHA-256 digest of the key authorization in the critical
/// acmeIdentifier extension. It is valid from one hour before `now` for one week.
pub fn challenge_certificate(
    key: &KeyPair,
    name: &str,
    key_authorization: &str,
    now: u64,
) -> Result<Vec<u8>, Error> {
    let template = Template {
        issuer: "Sibuna ACME challenge",
        subject: "Sibuna ACME challenge",
        names: &[name],
        not_before: now.saturating_sub(3600),
        not_after: now.saturating_add(CHALLENGE_LIFETIME),
        serial: now,
        acme_identifier: Some(Sha256::digest(key_authorization.as_bytes())),
        ..Template::default()
    };
    write(&template, &key.subject_public_key_info(), key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

    use super::*;

    const NOW: u64 = 1_795_516_496;

    #[test]
    fn a_written_certificate_reads_back() {
        let authority = KeyPair::generate().unwrap();
        let leaf = KeyPair::generate().unwrap();
        let template = Template {
            issuer: "Test Authority",
            subject: "example.org",
            names: &["example.org", "*.example.net"],
            not_before: NOW,
            not_after: NOW + 90 * 86_400,
            serial: 7,
            ..Template::default()
        };
        let der = write(&template, &leaf.subject_public_key_info(), &authority).unwrap();
        let certificate = read(&der).unwrap();
        assert_eq!(certificate.not_before, NOW);
        assert_eq!(certificate.not_after, NOW + 90 * 86_400);
        assert_eq!(certificate.issuer, "Test Authority");
        assert_eq!(certificate.names, ["example.org", "*.example.net"]);
        assert!(certificate.names_host("EXAMPLE.org"));
        assert!(certificate.names_host("a.example.net"));
        assert!(!certificate.names_host("a.b.example.net"));
        assert!(!certificate.names_host("example.net"));
    }

    #[test]
    fn the_challenge_certificate_carries_the_digest_and_verifies() {
        let key = KeyPair::generate().unwrap();
        let der = challenge_certificate(&key, "example.org", "token.thumbprint", NOW).unwrap();
        let digest = Sha256::digest(b"token.thumbprint");
        // The extension: the object identifier, critical, and an octet string in an
        // octet string.
        let mut expected = der::element(der::OID, ACME_IDENTIFIER);
        expected.extend_from_slice(TRUE);
        expected
            .extend(der::element(der::OCTET_STRING, &der::element(der::OCTET_STRING, &digest)));
        assert!(der.windows(expected.len()).any(|window| window == expected));
        let certificate = read(&der).unwrap();
        assert_eq!(certificate.names, ["example.org"]);
        assert!(certificate.not_before < NOW && NOW < certificate.not_after);
        let (_, outer, _) = der::read(&der).unwrap();
        let (tbs, rest) = der::read_raw(outer).unwrap();
        let signature = der::children(rest).nth(1).unwrap().1;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_point())
            .verify(tbs, &signature[1..])
            .unwrap();
    }

    #[test]
    fn unreadable_certificates_yield_nothing() {
        assert_eq!(read(&[]), None);
        assert_eq!(read(&[0x30, 0x03, 0x30, 0x01, 0x00]), None);
        let key = KeyPair::generate().unwrap();
        let der = challenge_certificate(&key, "example.org", "a.b", NOW).unwrap();
        for cut in [1, 10, 60, der.len() / 2] {
            assert_eq!(read(&der[..cut]), None, "cut at {cut}");
        }
    }
}

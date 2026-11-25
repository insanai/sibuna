//! OCSP stapling without I/O (RFC 6960, SID 0021): the question to the responder that a
//! certificate names, and the check of its answer.
//!
//! ```text
//!   caller                              this module
//!   ------                              -----------
//!   Responder::find(leaf, issuer) ----> the URL and the request, or nothing
//!   POST responder.call(), read the body
//!   responder.check(body, now) -------> good, revoked or unknown, with its window
//!   staple the body while `now` is inside the window
//! ```
//!
//! An answer is accepted when the issuer of the certificate signed it, or a certificate
//! inside the answer that the issuer signed for that purpose. Nothing here trusts the
//! responder or the network.

use sibuna_crypto::sha1::Sha1;

use crate::error::printable;
use crate::verify::verifies;
use crate::{Call, Error, der, time, x509};

/// The largest answer that we read.
pub const MAX_RESPONSE: usize = 64 * 1024;
/// The longest URL of a responder.
const MAX_URL: usize = 512;
/// How many certificates of an answer we look at for the delegated signer.
const MAX_SIGNERS: usize = 4;
/// `id-sha1`, 1.3.14.3.2.26.
const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// `id-pkix-ocsp-basic`, 1.3.6.1.5.5.7.48.1.1.
const BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// `extKeyUsage`, 2.5.29.37.
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

/// What the responder says about the certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The certificate is not revoked.
    Good,
    /// The certificate is revoked.
    Revoked,
    /// The responder does not know the certificate.
    Unknown,
}

/// A verified answer: the status and the window in which it may be stapled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// What the responder says.
    pub status: Status,
    /// The start of the window, in seconds since 1970.
    pub this_update: u64,
    /// The end of the window, in seconds since 1970.
    pub next_update: u64,
}

/// The responder of one certificate: where to ask, what to ask, and what an answer must
/// name and be signed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Responder {
    /// The `http` URL of the responder.
    pub url: String,
    request: Vec<u8>,
    name_hash: [u8; 20],
    key_hash: [u8; 20],
    serial: Vec<u8>,
    /// The DER `SubjectPublicKeyInfo` of the issuer.
    issuer_key: Vec<u8>,
}

fn refused(what: impl std::fmt::Display) -> Error {
    Error::stapling(format!("The OCSP response {what}."))
}

/// The `http` URL of the OCSP responder in the content of a DER `Extensions` sequence.
fn responder_url(extensions: &[u8]) -> Option<String> {
    let value = x509::extension_value(extensions, x509::AUTHORITY_INFO_ACCESS)?;
    let (der::SEQUENCE, descriptions, _) = der::read(value)? else { return None };
    der::children(descriptions).find_map(|(_, description)| {
        let mut fields = der::children(description);
        if fields.next() != Some((der::OID, x509::AD_OCSP)) {
            return None;
        }
        let (x509::URI, url) = fields.next()? else { return None };
        let url = std::str::from_utf8(url).ok()?;
        let plain = url.len() <= MAX_URL && url.bytes().all(|byte| byte.is_ascii_graphic());
        (plain && url.starts_with("http://") && url.len() > 7).then(|| url.to_owned())
    })
}

/// The key bytes of a DER `SubjectPublicKeyInfo`: the bit string without its first byte.
fn key_bits(spki: &[u8]) -> Option<&[u8]> {
    let (der::SEQUENCE, content, _) = der::read(spki)? else { return None };
    let (der::BIT_STRING, bits) = der::children(content).nth(1)? else { return None };
    bits.split_first().map(|(_, key)| key)
}

/// The DER `CertID` with SHA-1, as the request carries it.
fn cert_id(name_hash: &[u8], key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    let algorithm = der::sequence(&[&der::element(der::OID, SHA1), &der::element(der::NULL, &[])]);
    der::sequence(&[
        &algorithm,
        &der::element(der::OCTET_STRING, name_hash),
        &der::element(der::OCTET_STRING, key_hash),
        &der::element(der::INTEGER, serial),
    ])
}

impl Responder {
    /// The responder that the certificate `leaf` names, with the request for it.
    /// `issuer` is the certificate that signed the leaf, the next one of the chain.
    /// Both are DER. Returns `None` when the leaf names no responder with an `http`
    /// URL, or when a certificate cannot be walked.
    pub fn find(leaf: &[u8], issuer: &[u8]) -> Option<Self> {
        let url = responder_url(x509::parts(leaf)?.extensions)?;
        Some(Self { url, ..Self::identify(leaf, issuer)? })
    }

    /// As [`Responder::find`], without the URL: what identifies the certificate.
    fn identify(leaf: &[u8], issuer: &[u8]) -> Option<Self> {
        let leaf = x509::parts(leaf)?;
        let issuer = x509::parts(issuer)?;
        let url = String::new();
        let name_hash = Sha1::digest(leaf.issuer);
        let key_hash = Sha1::digest(key_bits(issuer.spki)?);
        let single = der::sequence(&[&cert_id(&name_hash, &key_hash, leaf.serial)]);
        let list = der::sequence(&[&single]);
        let request = der::sequence(&[&der::sequence(&[&list])]);
        Some(Self {
            url,
            request,
            name_hash,
            key_hash,
            serial: leaf.serial.to_vec(),
            issuer_key: issuer.spki.to_vec(),
        })
    }

    /// The request to send: a POST of the DER request to the URL of the responder.
    pub fn call(&self) -> Call {
        Call {
            method: "POST",
            url: self.url.clone(),
            headers: vec![("content-type", "application/ocsp-request".to_owned())],
            body: self.request.clone(),
        }
    }

    /// Checks the body of an answer at the time `now`, in seconds since 1970. It must
    /// be at most [`MAX_RESPONSE`] bytes, successful, signed by the issuer or its
    /// delegate, name our certificate, and have `this_update <= now < next_update`.
    /// Fails with `ACME013` otherwise. The returned status may be `Revoked` or
    /// `Unknown`: only `Good` is to be stapled.
    pub fn check(&self, response: &[u8], now: u64) -> Result<Answer, Error> {
        if response.len() > MAX_RESPONSE {
            return Err(refused("is larger than 64 KiB"));
        }
        let basic = Basic::read(response)?;
        if !self.signed(&basic, now) {
            return Err(refused("is not signed by the issuer of the certificate"));
        }
        let answer = self.single(&basic)?;
        if answer.this_update > now {
            return Err(refused(format_args!(
                "starts at {}, which is in the future",
                time::format_rfc3339(answer.this_update)
            )));
        }
        if answer.next_update <= now {
            return Err(refused(format_args!(
                "expired at {}",
                time::format_rfc3339(answer.next_update)
            )));
        }
        Ok(answer)
    }

    /// Whether the issuer signed the response, or a certificate of the response that the
    /// issuer signed, that has the purpose OCSP signing and that is valid at `now`.
    fn signed(&self, basic: &Basic<'_>, now: u64) -> bool {
        let by = |key: &[u8]| verifies(key, basic.algorithm, basic.data, basic.signature);
        if by(&self.issuer_key) {
            return true;
        }
        let mut certificates = basic.certificates;
        let delegates = std::iter::from_fn(|| der::take(&mut certificates));
        delegates.take(MAX_SIGNERS).any(|(_, _, certificate)| {
            let Some(parts) = x509::parts(certificate) else { return false };
            let issued = verifies(&self.issuer_key, parts.algorithm, parts.tbs, parts.signature);
            let valid = parts.not_before <= now && now < parts.not_after;
            issued && valid && signs_ocsp(parts.extensions) && by(parts.spki)
        })
    }

    /// The answer about our certificate among the single responses.
    fn single(&self, basic: &Basic<'_>) -> Result<Answer, Error> {
        let other = || refused("does not name our certificate");
        let ours = der::children(basic.responses).find_map(|(_, single)| {
            let mut fields = der::children(single);
            let (der::SEQUENCE, id) = fields.next()? else { return None };
            self.names(id).then_some(fields)
        });
        let mut fields = ours.ok_or_else(other)?;
        let status = match fields.next() {
            Some((0x80, _)) => Status::Good,
            Some((0xa1, _)) => Status::Revoked,
            Some((0x82, _)) => Status::Unknown,
            _ => return Err(refused("has no certificate status")),
        };
        let time = |text| time::parse_der_time(text, false);
        let this_update = match fields.next() {
            Some((der::GENERALIZED_TIME, text)) => time(text),
            _ => None,
        };
        let this_update = this_update.ok_or_else(|| refused("has no time"))?;
        // The end of the window is the explicit field [0].
        let next_update = fields
            .find(|(tag, _)| *tag == 0xa0)
            .and_then(|(_, field)| der::read(field))
            .filter(|(tag, _, _)| *tag == der::GENERALIZED_TIME)
            .and_then(|(_, text, _)| time(text));
        let next_update = next_update.ok_or_else(|| refused("has no next update"))?;
        Ok(Answer { status, this_update, next_update })
    }

    /// Whether the content of a `CertID` names our certificate with SHA-1.
    fn names(&self, id: &[u8]) -> bool {
        let mut fields = der::children(id);
        let sha1 = fields.next().is_some_and(|(tag, algorithm)| {
            tag == der::SEQUENCE && der::children(algorithm).next() == Some((der::OID, SHA1))
        });
        sha1 && fields.next() == Some((der::OCTET_STRING, &self.name_hash[..]))
            && fields.next() == Some((der::OCTET_STRING, &self.key_hash[..]))
            && fields.next() == Some((der::INTEGER, &self.serial[..]))
    }
}

/// Whether the content of a DER `Extensions` sequence has the extended key usage
/// OCSPSigning.
fn signs_ocsp(extensions: &[u8]) -> bool {
    let Some(value) = x509::extension_value(extensions, EXT_KEY_USAGE) else { return false };
    let Some((der::SEQUENCE, purposes, _)) = der::read(value) else { return false };
    der::children(purposes).any(|purpose| purpose == (der::OID, x509::OCSP_SIGNING))
}

/// The parts of a `BasicOCSPResponse` that the check reads.
struct Basic<'a> {
    /// The signed `ResponseData`, with its tag and length.
    data: &'a [u8],
    /// The content of the sequence of single responses.
    responses: &'a [u8],
    /// The object identifier of the signature algorithm.
    algorithm: &'a [u8],
    signature: &'a [u8],
    /// The certificates that the responder added, one DER certificate after another.
    certificates: &'a [u8],
}

impl<'a> Basic<'a> {
    /// Walks an `OCSPResponse` down to its basic response. Fails for a response that is
    /// not successful or cannot be walked.
    fn read(response: &'a [u8]) -> Result<Self, Error> {
        let malformed = || refused("cannot be read");
        let (der::SEQUENCE, mut outer, _) = der::read(response).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        let (der::ENUMERATED, status, _) = der::take(&mut outer).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        if status != [0] {
            let code = status.first().copied().unwrap_or(u8::MAX);
            return Err(refused(format_args!("has the status {}", status_word(code))));
        }
        Self::inner(outer).ok_or_else(malformed)
    }

    fn inner(after_status: &'a [u8]) -> Option<Self> {
        let (0xa0, bytes, _) = der::read(after_status)? else { return None };
        let (der::SEQUENCE, bytes, _) = der::read(bytes)? else { return None };
        let mut fields = der::children(bytes);
        if fields.next() != Some((der::OID, BASIC)) {
            return None;
        }
        let (der::OCTET_STRING, basic) = fields.next()? else { return None };
        let (der::SEQUENCE, mut basic, _) = der::read(basic)? else { return None };
        let (der::SEQUENCE, data_fields, data) = der::take(&mut basic)? else { return None };
        let (der::SEQUENCE, algorithm, _) = der::take(&mut basic)? else { return None };
        let (der::OID, algorithm, _) = der::read(algorithm)? else { return None };
        let (der::BIT_STRING, bits, _) = der::take(&mut basic)? else { return None };
        let (&0, signature) = bits.split_first()? else { return None };
        let certificates = match der::read(basic) {
            Some((0xa0, list, _)) => match der::read(list)? {
                (der::SEQUENCE, list, _) => list,
                _ => return None,
            },
            _ => &[],
        };
        // The version [0] and the responder [1] or [2] come before the time. The
        // responses are the first plain sequence.
        let responses = der::children(data_fields).find(|(tag, _)| *tag == der::SEQUENCE)?.1;
        Some(Self { data, responses, algorithm, signature, certificates })
    }
}

/// The name of a response status of RFC 6960, section 4.2.1.
fn status_word(code: u8) -> String {
    let word = match code {
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        other => return printable(&other.to_string(), 8),
    };
    word.to_owned()
}

/// When to ask the responder again: at half of the window of the answer, or, once that
/// has passed, at half of the time that is left. Always later than `now` while the
/// window is open.
pub fn refresh_at(answer: &Answer, now: u64) -> u64 {
    let middle = answer.this_update + answer.next_update.saturating_sub(answer.this_update) / 2;
    let left = answer.next_update.saturating_sub(now);
    if middle > now { middle } else { now + (left / 2).max(1) }
}

#[cfg(any(test, feature = "test-server"))]
pub mod build;

#[cfg(test)]
mod tests;

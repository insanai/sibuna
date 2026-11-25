//! Writes OCSP responses, for the tests of this crate and the responder inside the
//! tests of the daemon. A real responder is another program.

use sibuna_crypto::sha1::Sha1;

use super::{BASIC, Responder, Status, cert_id, key_bits};
use crate::{Error, KeyPair, der, time};

/// One answer to write.
#[derive(Clone, Copy, Debug)]
pub struct Reply<'a> {
    /// The DER certificate that the answer is about.
    pub leaf: &'a [u8],
    /// The DER certificate of its issuer.
    pub issuer: &'a [u8],
    /// What to say.
    pub status: Status,
    /// The start of the window, in seconds since 1970.
    pub this_update: u64,
    /// The end of the window, in seconds since 1970.
    pub next_update: u64,
    /// The DER certificate of the delegated signer, to put into the response.
    pub delegate: Option<&'a [u8]>,
}

fn generalized(seconds: u64) -> Vec<u8> {
    der::element(der::GENERALIZED_TIME, time::format_generalized_time(seconds).as_bytes())
}

/// Writes a successful response signed by `signer`: the key of the issuer, or that of
/// the delegate. Fails when the certificates cannot be walked or the key cannot sign.
pub fn response(reply: &Reply<'_>, signer: &KeyPair) -> Result<Vec<u8>, Error> {
    let unreadable = || Error::unexpected("The certificates of the OCSP reply are unusable.");
    // The leaf of a test may name no responder. The identifier needs none.
    let responder = Responder::identify(reply.leaf, reply.issuer).ok_or_else(unreadable)?;
    let id = cert_id(&responder.name_hash, &responder.key_hash, &responder.serial);
    let status = match reply.status {
        Status::Good => der::element(0x80, &[]),
        Status::Revoked => der::element(0xa1, &generalized(reply.this_update)),
        Status::Unknown => der::element(0x82, &[]),
    };
    let next = der::element(0xa0, &generalized(reply.next_update));
    let single = der::sequence(&[&id, &status, &generalized(reply.this_update), &next]);
    let spki = signer.subject_public_key_info();
    let key_hash = Sha1::digest(key_bits(&spki).ok_or_else(unreadable)?);
    let by_key = der::element(0xa2, &der::element(der::OCTET_STRING, &key_hash));
    let data =
        der::sequence(&[&by_key, &generalized(reply.this_update), &der::sequence(&[&single])]);
    let signed = signer.sign_der(&data)?;
    let (_, mut basic, _) = der::read(&signed).ok_or_else(unreadable)?;
    let with_delegate;
    if let Some(delegate) = reply.delegate {
        let certificates = der::element(0xa0, &der::sequence(&[delegate]));
        with_delegate = [basic, &certificates].concat();
        basic = &with_delegate;
    }
    let basic = der::element(der::SEQUENCE, basic);
    let bytes =
        der::sequence(&[&der::element(der::OID, BASIC), &der::element(der::OCTET_STRING, &basic)]);
    Ok(der::sequence(&[&der::element(der::ENUMERATED, &[0]), &der::element(0xa0, &bytes)]))
}

/// Writes a response without an answer: `code` is a status of RFC 6960, section 4.2.1,
/// for example 3 for `tryLater`.
pub fn failure(code: u8) -> Vec<u8> {
    der::sequence(&[&der::element(der::ENUMERATED, &[code])])
}

/// The serial number that a DER request asks about: the content of its integer.
pub fn asked_serial(request: &[u8]) -> Option<Vec<u8>> {
    let mut inner = request;
    // OCSPRequest, TBSRequest, the request list, the request and its CertID.
    for _ in 0..5 {
        let (der::SEQUENCE, content, _) = der::read(inner)? else { return None };
        inner = content;
    }
    let (der::INTEGER, serial) = der::children(inner).nth(3)? else { return None };
    Some(serial.to_vec())
}

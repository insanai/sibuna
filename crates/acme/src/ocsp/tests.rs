#![allow(clippy::unwrap_used)]

use std::process::Command;

use super::build::{Reply, asked_serial, failure, response};
use super::*;
use crate::{KeyPair, pem};

const NOW: u64 = 1_795_516_496;
const URL: &str = "http://127.0.0.1:20999/ocsp";

/// An authority, a leaf that names its responder, and their keys.
struct Fixture {
    authority_key: KeyPair,
    authority: Vec<u8>,
    leaf: Vec<u8>,
}

fn authority(name: &str, key: &KeyPair) -> Vec<u8> {
    let template = x509::Template {
        issuer: name,
        subject: name,
        not_before: NOW - 86_400,
        not_after: NOW + 86_400,
        serial: 1,
        authority: true,
        subject_key_id: true,
        ..x509::Template::default()
    };
    x509::write(&template, &key.subject_public_key_info(), key).unwrap()
}

fn leaf(authority_key: &KeyPair, serial: u64, url: Option<&str>) -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let template = x509::Template {
        issuer: "Test Authority",
        subject: "example.org",
        names: &["example.org"],
        not_before: NOW - 3600,
        not_after: NOW + 3600,
        serial,
        server: true,
        ocsp_url: url,
        ..x509::Template::default()
    };
    x509::write(&template, &key.subject_public_key_info(), authority_key).unwrap()
}

fn fixture() -> Fixture {
    let authority_key = KeyPair::generate().unwrap();
    let authority = authority("Test Authority", &authority_key);
    let leaf = leaf(&authority_key, 0x8765_4321, Some(URL));
    Fixture { authority_key, authority, leaf }
}

impl Fixture {
    fn responder(&self) -> Responder {
        Responder::find(&self.leaf, &self.authority).unwrap()
    }

    fn reply(&self, status: Status) -> Reply<'_> {
        Reply {
            leaf: &self.leaf,
            issuer: &self.authority,
            status,
            this_update: NOW - 100,
            next_update: NOW + 100,
            delegate: None,
        }
    }

    /// The certificate of a delegated signer that `signer` issued.
    fn delegate(&self, key: &KeyPair, signer: &KeyPair, purpose: bool, until: u64) -> Vec<u8> {
        let template = x509::Template {
            issuer: "Test Authority",
            subject: "Test Responder",
            not_before: NOW - 3600,
            not_after: until,
            serial: 9,
            ocsp_signing: purpose,
            ..x509::Template::default()
        };
        x509::write(&template, &key.subject_public_key_info(), signer).unwrap()
    }
}

fn message(result: Result<Answer, Error>) -> String {
    let error = result.unwrap_err();
    assert_eq!((error.code, error.title), ("ACME013", "NO OCSP RESPONSE"));
    error.message
}

#[test]
fn a_leaf_names_its_responder_and_the_request_asks_about_its_serial() {
    let f = fixture();
    let responder = f.responder();
    assert_eq!(responder.url, URL);
    let call = responder.call();
    assert_eq!((call.method, call.url.as_str()), ("POST", URL));
    assert_eq!(call.headers, [("content-type", "application/ocsp-request".to_owned())]);
    assert_eq!(asked_serial(&call.body).unwrap(), [0x00, 0x87, 0x65, 0x43, 0x21]);
    // No responder, a responder that is not plain HTTP, and what is no certificate.
    let silent = leaf(&f.authority_key, 5, None);
    assert_eq!(Responder::find(&silent, &f.authority), None);
    let secure = leaf(&f.authority_key, 5, Some("https://ocsp.example/"));
    assert_eq!(Responder::find(&secure, &f.authority), None);
    let bare = leaf(&f.authority_key, 5, Some("http://"));
    assert_eq!(Responder::find(&bare, &f.authority), None);
    assert_eq!(Responder::find(&f.leaf, &[]), None);
    assert_eq!(Responder::find(&[], &f.authority), None);
}

#[test]
fn an_answer_of_the_issuer_is_accepted_inside_its_window() {
    let f = fixture();
    let responder = f.responder();
    for status in [Status::Good, Status::Revoked, Status::Unknown] {
        let body = response(&f.reply(status), &f.authority_key).unwrap();
        let answer = responder.check(&body, NOW).unwrap();
        assert_eq!(answer, Answer { status, this_update: NOW - 100, next_update: NOW + 100 });
    }
    let body = response(&f.reply(Status::Good), &f.authority_key).unwrap();
    assert!(responder.check(&body, NOW - 100).is_ok());
    assert!(responder.check(&body, NOW + 99).is_ok());
    assert!(message(responder.check(&body, NOW - 101)).contains("in the future"));
    assert!(message(responder.check(&body, NOW + 100)).contains("expired at"));
}

#[test]
fn another_signer_another_certificate_and_a_failure_are_refused() {
    let f = fixture();
    let responder = f.responder();
    let stranger = KeyPair::generate().unwrap();
    let body = response(&f.reply(Status::Good), &stranger).unwrap();
    assert!(message(responder.check(&body, NOW)).contains("not signed by the issuer"));
    // An answer about another serial of the same issuer.
    let other = leaf(&f.authority_key, 7, Some(URL));
    let reply = Reply { leaf: &other, ..f.reply(Status::Good) };
    let body = response(&reply, &f.authority_key).unwrap();
    assert!(message(responder.check(&body, NOW)).contains("does not name our certificate"));
    assert!(message(responder.check(&failure(3), NOW)).contains("status tryLater"));
    assert!(message(responder.check(&failure(6), NOW)).contains("status unauthorized"));
    assert!(message(responder.check(&failure(77), NOW)).contains("status 77"));
    assert!(message(responder.check(&[], NOW)).contains("cannot be read"));
    let large = vec![0x30; MAX_RESPONSE + 1];
    assert!(message(responder.check(&large, NOW)).contains("64 KiB"));
}

#[test]
fn a_delegate_signs_only_with_the_purpose_the_issuer_and_its_validity() {
    let f = fixture();
    let responder = f.responder();
    let key = KeyPair::generate().unwrap();
    let check = |delegate: &[u8]| {
        let reply = Reply { delegate: Some(delegate), ..f.reply(Status::Good) };
        responder.check(&response(&reply, &key).unwrap(), NOW)
    };
    let good = f.delegate(&key, &f.authority_key, true, NOW + 3600);
    assert_eq!(check(&good).unwrap().status, Status::Good);
    let no_purpose = f.delegate(&key, &f.authority_key, false, NOW + 3600);
    assert!(message(check(&no_purpose)).contains("not signed by the issuer"));
    let expired = f.delegate(&key, &f.authority_key, true, NOW);
    assert!(message(check(&expired)).contains("not signed by the issuer"));
    let stranger = KeyPair::generate().unwrap();
    let foreign = f.delegate(&key, &stranger, true, NOW + 3600);
    assert!(message(check(&foreign)).contains("not signed by the issuer"));
    // A delegate with every right, and a response that another key signed.
    let reply = Reply { delegate: Some(&good), ..f.reply(Status::Good) };
    let body = response(&reply, &stranger).unwrap();
    assert!(message(responder.check(&body, NOW)).contains("not signed by the issuer"));
}

#[test]
fn no_cut_and_no_changed_byte_is_accepted() {
    let f = fixture();
    let responder = f.responder();
    let key = KeyPair::generate().unwrap();
    let delegate = f.delegate(&key, &f.authority_key, true, NOW + 3600);
    let direct = response(&f.reply(Status::Good), &f.authority_key).unwrap();
    let reply = Reply { delegate: Some(&delegate), ..f.reply(Status::Good) };
    let delegated = response(&reply, &key).unwrap();
    for body in [direct, delegated] {
        assert!(responder.check(&body, NOW).is_ok());
        for cut in 0..body.len() {
            assert!(responder.check(&body[..cut], NOW).is_err(), "cut at {cut}");
        }
        for at in 0..body.len() {
            for flip in [0x01, 0x02, 0x10, 0x40, 0x80, 0xff] {
                let mut changed = body.clone();
                changed[at] ^= flip;
                assert!(responder.check(&changed, NOW).is_err(), "byte {at} flipped by {flip}");
            }
        }
    }
}

#[test]
fn the_refresh_is_inside_the_window_and_after_now() {
    let answer = Answer { status: Status::Good, this_update: 1000, next_update: 2000 };
    assert_eq!(refresh_at(&answer, 1000), 1500);
    assert_eq!(refresh_at(&answer, 1200), 1500);
    // Past the middle: half of what is left.
    assert_eq!(refresh_at(&answer, 1600), 1800);
    assert_eq!(refresh_at(&answer, 1998), 1999);
    for now in 1000..2000 {
        let at = refresh_at(&answer, now);
        assert!(now < at && at <= 2000, "now {now} at {at}");
    }
    // Outside the window the next question is one second away, never in the past.
    assert_eq!(refresh_at(&answer, 5000), 5001);
}

/// Runs `openssl` in `dir` and returns its standard output. `None`: it is not installed.
fn openssl(dir: &std::path::Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("openssl").current_dir(dir).args(arguments).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "openssl {arguments:?}: {text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(text)
}

fn clock() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Makes an authority and a leaf with `openssl`, lets `openssl ocsp` answer our request
/// for the leaf, and returns our responder with that answer. `None`: no `openssl`.
fn openssl_answer(
    dir: &std::path::Path,
    kind: &str,
    key: &[&str],
    digest: &str,
) -> Option<(Responder, Vec<u8>)> {
    let file = |name: &str| format!("{kind}-{name}");
    let (ca, ca_key, csr, cert) = (file("ca.pem"), file("ca.key"), file("csr"), file("pem"));
    let mut make = vec!["req", "-x509", "-nodes", "-days", "2", "-subj", "/CN=Test CA"];
    make.extend_from_slice(key);
    make.extend_from_slice(&["-keyout", &ca_key, "-out", &ca]);
    openssl(dir, &make)?;
    let leaf_key = file("leaf.key");
    let mut request = vec!["req", "-nodes", "-subj", "/CN=leaf"];
    request.extend_from_slice(key);
    request.extend_from_slice(&["-keyout", &leaf_key, "-out", &csr]);
    openssl(dir, &request)?;
    let sign = ["x509", "-req", "-in", &csr, "-CA", &ca, "-CAkey", &ca_key, "-CAcreateserial"];
    let mut sign = sign.to_vec();
    sign.extend_from_slice(&["-days", "1", "-extfile", "ext", "-out", &cert]);
    openssl(dir, &sign)?;
    let serial = openssl(dir, &["x509", "-in", &cert, "-noout", "-serial"])?;
    let serial = serial.trim().trim_start_matches("serial=").to_owned();
    let index = file("index.txt");
    let line = format!("V\t491231235959Z\t\t{serial}\tunknown\t/CN=leaf\n");
    std::fs::write(dir.join(&index), line).unwrap();
    let der = |name: &str| {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        pem::decode("CERTIFICATE", &text).unwrap().remove(0)
    };
    let responder = Responder::find(&der(&cert), &der(&ca)).unwrap();
    let (asked, answered) = (file("req.der"), file("resp.der"));
    std::fs::write(dir.join(&asked), responder.call().body).unwrap();
    let answer = ["ocsp", "-index", &index, "-CA", &ca, "-rsigner", &ca, "-rkey", &ca_key];
    let mut answer = answer.to_vec();
    answer.extend_from_slice(&["-rmd", digest, "-reqin", &asked, "-respout", &answered]);
    answer.extend_from_slice(&["-ndays", "1"]);
    openssl(dir, &answer)?;
    Some((responder, std::fs::read(dir.join(&answered)).unwrap()))
}

/// `openssl ocsp` reads our request and answers it with an RSA and with a P-384
/// authority. We accept each answer, and refuse it for the certificate of the other
/// authority. Skipped when `openssl` is not installed.
#[test]
fn openssl_answers_our_request_and_we_accept_its_response() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = std::env::temp_dir().join(format!("sibuna-acme-ocsp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ext"), format!("authorityInfoAccess = OCSP;URI:{URL}\n")).unwrap();
    let Some(rsa) = openssl_answer(&dir, "rsa", &["-newkey", "rsa:2048"], "sha256") else {
        return;
    };
    let curve = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"];
    let ec = openssl_answer(&dir, "ec", &curve, "sha384").unwrap();
    // The clock is read after the last answer: an answer is not valid before it is made.
    let now = clock();
    for (responder, body) in [&rsa, &ec] {
        let checked = responder.check(body, now).unwrap();
        assert_eq!(checked.status, Status::Good);
        assert!(checked.this_update <= now && now < checked.next_update);
    }
    assert!(rsa.0.check(&ec.1, now).is_err());
    assert!(ec.0.check(&rsa.1, now).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

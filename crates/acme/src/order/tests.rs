//! The order machine against a scripted authority in memory. No socket is opened.
#![allow(clippy::unwrap_used)]

use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};

use super::*;
use crate::{pem, x509};

const BASE: &str = "https://ca.example";
const NOW: u64 = 1_795_516_496;

/// How the scripted authority behaves.
struct Script {
    /// Answer `badNonce` once to the request for this path.
    bad_nonce_at: Option<&'static str>,
    /// The status of the authorization before a challenge was answered.
    first_status: &'static str,
    /// The status of the authorization after the challenge was answered.
    final_status: &'static str,
    /// Polls that answer `processing` before the final status.
    slow_polls: u32,
    /// The challenge types offered.
    offered: &'static [&'static str],
    /// The `Retry-After` of polls.
    retry_after: Option<u64>,
    /// Answer `orderNotReady` to the first finalize.
    not_ready_once: bool,
    /// Authorizations listed in the order.
    authorizations: usize,
    /// The key identifier and the MAC key of the binding that a new account needs.
    binding: Option<(&'static str, &'static [u8])>,
    /// Offer renewal information in the directory.
    renewal_info: bool,
    /// Refuse an order that names a certificate to replace.
    refuse_replaces: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            bad_nonce_at: None,
            first_status: "pending",
            final_status: "valid",
            slow_polls: 0,
            offered: &["http-01", "tls-alpn-01", "dns-01"],
            retry_after: None,
            not_ready_once: false,
            authorizations: 1,
            binding: None,
            renewal_info: false,
            refuse_replaces: false,
        }
    }
}

/// An ACME server in memory: it checks every signature and nonce, and issues from the
/// request it is sent.
struct Authority {
    script: Script,
    account_point: Vec<u8>,
    key: KeyPair,
    nonce: u32,
    registered: bool,
    answered: bool,
    polls: u32,
    issued: Option<String>,
    /// The path of every request, in order.
    log: Vec<String>,
    /// The `replaces` member of every order placed, empty without one.
    replaces: Vec<String>,
}

fn decode(text: &str) -> Vec<u8> {
    base64::decode(URL_SAFE_NO_PAD, text.as_bytes()).unwrap()
}

fn field(document: &[u8], name: &str) -> String {
    let value = sibuna_json::parse(document).unwrap();
    value.as_object().unwrap().get(name).unwrap().as_str().unwrap().to_owned()
}

impl Authority {
    fn new(account: &Account, script: Script) -> Self {
        Self {
            script,
            account_point: account.key().public_point().to_vec(),
            key: KeyPair::generate().unwrap(),
            nonce: 0,
            registered: false,
            answered: false,
            polls: 0,
            issued: None,
            log: Vec::new(),
            replaces: Vec::new(),
        }
    }

    fn fresh_nonce(&mut self) -> Option<String> {
        self.nonce += 1;
        Some(format!("nonce-{}", self.nonce))
    }

    fn json(&mut self, status: u16, body: String) -> Response {
        Response {
            status,
            nonce: self.fresh_nonce(),
            body: body.into_bytes(),
            ..Response::default()
        }
    }

    /// Checks the JWS of a POST and returns its header and its payload.
    fn open(&self, request: &Request) -> (String, String) {
        assert_eq!(request.method, Method::Post);
        let body = request.body.as_bytes();
        let (protected, payload) = (field(body, "protected"), field(body, "payload"));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.account_point)
            .verify(
                format!("{protected}.{payload}").as_bytes(),
                &decode(&field(body, "signature")),
            )
            .unwrap();
        let header = String::from_utf8(decode(&protected)).unwrap();
        assert_eq!(field(header.as_bytes(), "nonce"), format!("nonce-{}", self.nonce));
        assert_eq!(field(header.as_bytes(), "url"), request.url);
        assert_eq!(header.contains("\"kid\""), !request.url.ends_with("/new-account"));
        (header, String::from_utf8(decode(&payload)).unwrap())
    }

    fn handle(&mut self, request: &Request) -> Response {
        let path = request.url.strip_prefix(BASE).unwrap().to_owned();
        self.log.push(path.clone());
        match (request.method, path.as_str()) {
            (Method::Get, "/directory") => {
                let required = self.script.binding.is_some();
                let ari = match self.script.renewal_info {
                    true => format!(r#""renewalInfo":"{BASE}/renewal-info","#),
                    false => String::new(),
                };
                let body = format!(
                    r#"{{"newNonce":"{BASE}/new-nonce","newAccount":"{BASE}/new-account",{ari}
                        "newOrder":"{BASE}/new-order",
                        "meta":{{"website":"x","externalAccountRequired":{required}}}}}"#
                );
                Response { status: 200, body: body.into_bytes(), ..Response::default() }
            }
            (Method::Head, "/new-nonce") => {
                Response { status: 200, nonce: self.fresh_nonce(), ..Response::default() }
            }
            _ => self.post(request, &path),
        }
    }

    fn post(&mut self, request: &Request, path: &str) -> Response {
        let (_, payload) = self.open(request);
        if self.script.bad_nonce_at.take_if(|at| *at == path).is_some() {
            let kind = "urn:ietf:params:acme:error:badNonce";
            return self.json(400, format!(r#"{{"type":"{kind}","detail":"stale"}}"#));
        }
        match path {
            "/new-account" => {
                assert!(payload.contains("\"termsOfServiceAgreed\":true"), "{payload}");
                if !self.is_bound(&payload, &request.url) {
                    let kind = "urn:ietf:params:acme:error:unauthorized";
                    return self.json(401, format!(r#"{{"type":"{kind}","detail":"bad MAC"}}"#));
                }
                self.registered = true;
                let mut response = self.json(201, r#"{"status":"valid"}"#.to_owned());
                response.location = Some(format!("{BASE}/account/1"));
                response
            }
            "/new-order" => {
                assert!(self.registered);
                assert!(payload.contains(r#"{"type":"dns","value":"example.org"}"#), "{payload}");
                let order = sibuna_json::parse(payload.as_bytes()).unwrap();
                let replaces = order.as_object().unwrap().get("replaces");
                let replaces = replaces.and_then(|value| value.as_str()).unwrap_or_default();
                self.replaces.push(replaces.to_owned());
                if self.script.refuse_replaces && !replaces.is_empty() {
                    let kind = "urn:ietf:params:acme:error:alreadyReplaced";
                    return self.json(409, format!(r#"{{"type":"{kind}","detail":"done"}}"#));
                }
                let list: Vec<String> = (0..self.script.authorizations)
                    .map(|index| format!(r#""{BASE}/authz/{index}""#))
                    .collect();
                let body = format!(
                    r#"{{"status":"pending","authorizations":[{}],"finalize":"{BASE}/finalize"}}"#,
                    list.join(",")
                );
                let mut response = self.json(201, body);
                response.location = Some(format!("{BASE}/order/1"));
                response
            }
            "/authz/0" => self.authorization(),
            "/challenge/http-01" | "/challenge/tls-alpn-01" => {
                assert_eq!(payload, "{}");
                self.answered = true;
                self.json(200, r#"{"status":"processing"}"#.to_owned())
            }
            "/finalize" => self.finalize(&payload),
            "/order/1" => {
                let body = format!(r#"{{"status":"valid","certificate":"{BASE}/cert/1"}}"#);
                self.json(200, body)
            }
            "/cert/1" => {
                let chain = self.issued.clone().unwrap();
                self.json(200, chain)
            }
            other => panic!("unexpected request for {other}"),
        }
    }

    /// Whether a registration carries the binding that the script wants: a JWS with
    /// HS256 over the account key, for this URL. The MAC is computed with `ring`, not
    /// with the code under test.
    fn is_bound(&self, payload: &str, url: &str) -> bool {
        let Some((kid, key)) = self.script.binding else { return true };
        let registration = sibuna_json::parse(payload.as_bytes()).unwrap();
        let Some(binding) = registration.as_object().unwrap().get("externalAccountBinding") else {
            return false;
        };
        let part = |name: &str| binding.as_object().unwrap().get(name).unwrap().as_str().unwrap();
        let (protected, bound) = (part("protected"), part("payload"));
        let header = decode(protected);
        assert_eq!(field(&header, "alg"), "HS256");
        assert_eq!(field(&header, "kid"), kid);
        assert_eq!(field(&header, "url"), url);
        assert!(!String::from_utf8(header).unwrap().contains("nonce"));
        let jwk = decode(bound);
        let x = base64::encode(URL_SAFE_NO_PAD, &self.account_point[1..33]);
        assert_eq!((field(&jwk, "kty").as_str(), field(&jwk, "x")), ("EC", x));
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let signed = format!("{protected}.{bound}");
        ring::hmac::verify(&key, signed.as_bytes(), &decode(part("signature"))).is_ok()
    }

    fn authorization(&mut self) -> Response {
        let status = if !self.answered {
            self.script.first_status
        } else if self.polls < self.script.slow_polls {
            self.polls += 1;
            "processing"
        } else {
            self.script.final_status
        };
        let challenges: Vec<String> = self
            .script
            .offered
            .iter()
            .map(|kind| {
                let error = if status == "invalid" {
                    r#","error":{"type":"x","detail":"connection refused\u001b"}"#
                } else {
                    ""
                };
                let url = format!("{BASE}/challenge/{kind}");
                format!(r#"{{"type":"{kind}","url":"{url}","token":"tok_-9"{error}}}"#)
            })
            .collect();
        let body = format!(r#"{{"status":"{status}","challenges":[{}]}}"#, challenges.join(","));
        let mut response = self.json(200, body);
        response.retry_after = self.script.retry_after;
        response
    }

    fn finalize(&mut self, payload: &str) -> Response {
        if std::mem::take(&mut self.script.not_ready_once) {
            let kind = "urn:ietf:params:acme:error:orderNotReady";
            return self.json(403, format!(r#"{{"type":"{kind}","detail":"wait"}}"#));
        }
        let request = csr::read(&decode(&field(payload.as_bytes(), "csr"))).unwrap();
        assert_eq!(request.names, ["example.org"]);
        let template = x509::Template {
            issuer: "Scripted Authority",
            subject: "example.org",
            names: &["example.org"],
            not_before: NOW,
            not_after: NOW + 90 * 86_400,
            serial: 1,
            ..x509::Template::default()
        };
        let leaf = x509::write(&template, &request.public_key, &self.key).unwrap();
        self.issued = Some(pem::encode("CERTIFICATE", &leaf));
        self.json(200, r#"{"status":"processing"}"#.to_owned())
    }
}

fn options() -> OrderOptions {
    OrderOptions {
        directory: format!("{BASE}/directory"),
        name: "example.org".to_owned(),
        email: Some("ops@example.org".to_owned()),
        ..OrderOptions::default()
    }
}

/// The result of one scripted order.
struct Run {
    result: Result<Issued, Error>,
    log: Vec<String>,
    presented: Vec<Challenge>,
    waits: Vec<u64>,
    replaces: Vec<String>,
}

fn run_with(account: &mut Account, options: OrderOptions, script: Script) -> Run {
    let mut authority = Authority::new(account, script);
    let mut presented = Vec::new();
    let mut waits = Vec::new();
    let result = obtain(
        account,
        options,
        |request| Ok(authority.handle(request)),
        |challenge| {
            presented.push(challenge.clone());
            Ok(())
        },
        |seconds| waits.push(seconds),
    );
    Run { result, log: authority.log, presented, waits, replaces: authority.replaces }
}

fn run(script: Script) -> Run {
    let mut account = Account::new(KeyPair::generate().unwrap());
    run_with(&mut account, options(), script)
}

#[test]
fn an_order_walks_the_phases_and_returns_a_matching_certificate() {
    let mut account = Account::new(KeyPair::generate().unwrap());
    let thumbprint = account.thumbprint();
    let run = run_with(&mut account, options(), Script::default());
    let issued = run.result.unwrap();
    let expected = [
        "/directory",
        "/new-nonce",
        "/new-account",
        "/new-order",
        "/authz/0",
        "/challenge/http-01",
        "/authz/0",
        "/finalize",
        "/order/1",
        "/cert/1",
    ];
    assert_eq!(run.log, expected);
    let [challenge] = &run.presented[..] else { panic!("one challenge") };
    assert_eq!(challenge.kind, ChallengeKind::Http01);
    assert_eq!(challenge.key_authorization, format!("tok_-9.{thumbprint}"));
    assert_eq!(run.waits, [1, 1]);
    let leaf = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap().remove(0);
    assert!(x509::read(&leaf).unwrap().names_host("example.org"));
    let key = issued.key.subject_public_key_info();
    assert!(leaf.windows(key.len()).any(|window| window == key));
}

#[test]
fn a_second_order_reuses_the_account() {
    let mut account = Account::new(KeyPair::generate().unwrap());
    run_with(&mut account, options(), Script::default()).result.unwrap();
    let mut authority = Authority::new(&account, Script::default());
    authority.registered = true;
    let result = obtain(
        &mut account,
        options(),
        |request| Ok(authority.handle(request)),
        |_| Ok(()),
        |_| {},
    );
    result.unwrap();
    assert!(!authority.log.iter().any(|path| path == "/new-account"));
}

#[test]
fn a_stale_nonce_is_repeated_with_the_fresh_one() {
    let script = Script { bad_nonce_at: Some("/new-order"), ..Script::default() };
    let run = run(script);
    run.result.unwrap();
    assert_eq!(run.log.iter().filter(|path| *path == "/new-order").count(), 2);
}

#[test]
fn a_valid_authorization_needs_no_challenge() {
    let run = run(Script { first_status: "valid", ..Script::default() });
    run.result.unwrap();
    assert!(run.presented.is_empty());
    assert!(!run.log.iter().any(|path| path.starts_with("/challenge")));
}

#[test]
fn an_invalid_authorization_quotes_the_authority() {
    let run = run(Script { final_status: "invalid", ..Script::default() });
    let error = run.result.unwrap_err();
    assert_eq!((error.code, error.title), ("ACME005", "VALIDATION FAILED"));
    assert!(error.message.contains("connection refused?"), "{}", error.message);
    assert!(error.message.contains("http-01"), "{}", error.message);
    assert!(error.hint.contains("port 80"));
}

#[test]
fn an_authority_that_never_decides_exhausts_the_budget() {
    let run = run(Script { slow_polls: u32::MAX, ..Script::default() });
    let error = run.result.unwrap_err();
    assert_eq!(error.code, "ACME006");
    assert_eq!(run.log.len(), BUDGET as usize);
    assert_eq!(run.waits[..6], [1, 2, 4, 8, 8, 8]);
}

#[test]
fn the_wait_of_the_authority_is_clamped() {
    let slow = Script { slow_polls: 2, retry_after: Some(3600), ..Script::default() };
    assert_eq!(run(slow).waits, [1, 30, 30, 1]);
    let eager = Script { slow_polls: 1, retry_after: Some(0), ..Script::default() };
    assert_eq!(run(eager).waits, [1, 1, 1]);
}

#[test]
fn the_other_challenge_is_taken_only_when_allowed() {
    let only_alpn = || Script { offered: &["tls-alpn-01"], ..Script::default() };
    let taken = run(only_alpn());
    taken.result.unwrap();
    assert_eq!(taken.presented[0].kind, ChallengeKind::TlsAlpn01);
    let mut account = Account::new(KeyPair::generate().unwrap());
    let strict = OrderOptions { any_challenge: false, ..options() };
    let refused = run_with(&mut account, strict, only_alpn());
    assert_eq!(refused.result.unwrap_err().code, "ACME005");
    let mut account = Account::new(KeyPair::generate().unwrap());
    let wanted = OrderOptions { challenge: ChallengeKind::TlsAlpn01, ..options() };
    let chosen = run_with(&mut account, wanted, Script::default());
    assert_eq!(chosen.presented[0].kind, ChallengeKind::TlsAlpn01);
}

#[test]
fn an_order_that_is_not_ready_is_finalized_again() {
    let run = run(Script { not_ready_once: true, ..Script::default() });
    run.result.unwrap();
    assert_eq!(run.log.iter().filter(|path| *path == "/finalize").count(), 2);
}

#[test]
fn an_order_with_two_authorizations_is_refused() {
    let error = run(Script { authorizations: 2, ..Script::default() }).result.unwrap_err();
    assert_eq!(error.code, "ACME006");
}

/// Drives an order by hand up to the response under test.
fn first_request(account: &mut Account) -> Order<'_> {
    let (order, action) = Order::begin(account, options());
    assert!(matches!(action, Action::Send(Request { method: Method::Get, .. })));
    order
}

fn failure(action: Action) -> Error {
    match action {
        Action::Failed(error) => error,
        other => panic!("expected a failure, found {other:?}"),
    }
}

#[test]
fn a_rate_limit_carries_the_wait_of_the_authority() {
    let mut account = Account::new(KeyPair::generate().unwrap());
    let mut order = first_request(&mut account);
    let body = br#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many"}"#;
    let response = Response {
        status: 429,
        retry_after: Some(7200),
        body: body.to_vec(),
        ..Response::default()
    };
    let error = failure(order.advance(response));
    assert_eq!((error.code, error.retry_after), ("ACME004", Some(7200)));
    assert!(error.message.contains("too many"));
    assert!(order.is_over());
    // An order that ended answers every further call with a failure.
    assert_eq!(failure(order.resume()).code, "ACME006");
    assert_eq!(failure(order.presented()).code, "ACME006");
    assert_eq!(failure(order.advance(Response::default())).code, "ACME006");
}

#[test]
fn answers_that_break_a_bound_end_the_order() {
    let directory = |new_nonce: &str| {
        format!(r#"{{"newNonce":"{new_nonce}","newAccount":"{BASE}/a","newOrder":"{BASE}/o"}}"#)
            .into_bytes()
    };
    let cases: [(&str, Response); 6] = [
        (
            "a downgrade to http",
            Response {
                status: 200,
                body: directory("http://ca.example/n"),
                ..Response::default()
            },
        ),
        (
            "a URL with a space",
            Response {
                status: 200,
                body: directory("https://ca.example/n n"),
                ..Response::default()
            },
        ),
        (
            "a body that is no JSON",
            Response { status: 200, body: b"<html>".to_vec(), ..Response::default() },
        ),
        (
            "a body that is no object",
            Response { status: 200, body: b"[1]".to_vec(), ..Response::default() },
        ),
        (
            "a body over the bound",
            Response { status: 200, body: vec![b' '; MAX_BODY + 1], ..Response::default() },
        ),
        (
            "a nonce with a line feed",
            Response {
                status: 200,
                nonce: Some("a\nb".to_owned()),
                body: directory("https://ca.example/n"),
                ..Response::default()
            },
        ),
    ];
    for (what, response) in cases {
        let mut account = Account::new(KeyPair::generate().unwrap());
        let mut order = first_request(&mut account);
        assert_eq!(failure(order.advance(response)).code, "ACME006", "{what}");
    }
}

#[test]
fn a_plain_directory_may_name_plain_urls() {
    let mut account = Account::new(KeyPair::generate().unwrap());
    let plain = OrderOptions { directory: "http://127.0.0.1:1/dir".to_owned(), ..options() };
    let (mut order, _) = Order::begin(&mut account, plain);
    let body = br#"{"newNonce":"http://127.0.0.1:1/n","newAccount":"http://127.0.0.1:1/a",
        "newOrder":"http://127.0.0.1:1/o"}"#;
    let action =
        order.advance(Response { status: 200, body: body.to_vec(), ..Response::default() });
    assert!(matches!(action, Action::Send(Request { method: Method::Head, .. })));
}

#[test]
fn a_failing_transport_ends_the_one_call_path() {
    let mut account = Account::new(KeyPair::generate().unwrap());
    let result = obtain(
        &mut account,
        options(),
        |_| Err(Error::unreachable("no route")),
        |_| Ok(()),
        |_| {},
    );
    assert_eq!(result.unwrap_err().code, "ACME002");
}

const MAC_KEY: &[u8] = b"a key of the authority, 32 bytes";

fn bound(kid: &str, key: &[u8]) -> OrderOptions {
    let binding = jws::Binding { kid: kid.to_owned(), key: key.to_vec() };
    OrderOptions { binding: Some(binding), ..options() }
}

#[test]
fn a_registration_carries_the_binding_that_the_authority_wants() {
    let script = || Script { binding: Some(("kid-1", MAC_KEY)), ..Script::default() };
    let mut account = Account::new(KeyPair::generate().unwrap());
    let run = run_with(&mut account, bound("kid-1", MAC_KEY), script());
    assert!(run.result.is_ok());
    assert!(run.log.contains(&"/new-account".to_owned()));

    // Another key: the authority refuses, and the failure names the binding.
    let mut account = Account::new(KeyPair::generate().unwrap());
    let run = run_with(&mut account, bound("kid-1", b"another key"), script());
    let error = run.result.unwrap_err();
    assert_eq!((error.code, error.title), ("ACME012", "ACCOUNT BINDING REFUSED"));
    assert!(error.message.contains("bad MAC"), "{}", error.message);
    assert_eq!(run.log.last().map(String::as_str), Some("/new-account"));
}

#[test]
fn a_required_binding_that_is_missing_fails_before_any_signed_request() {
    let script = Script { binding: Some(("kid-1", MAC_KEY)), ..Script::default() };
    let run = run(script);
    let error = run.result.unwrap_err();
    assert_eq!(error.code, "ACME012");
    assert!(error.message.contains("https://ca.example/directory"), "{}", error.message);
    assert!(error.hint.contains("eab"));
    assert_eq!(run.log, ["/directory"]);
}

#[test]
fn the_binding_reads_its_key_file_and_hides_the_key() {
    let binding = jws::Binding::parse("kid-1", " YSBrZXk=\n").unwrap();
    assert_eq!(binding.key, b"a key");
    assert_eq!(jws::Binding::parse("kid-1", "YSBrZXk").unwrap().key, b"a key");
    assert!(jws::Binding::parse("", "YSBrZXk").is_none());
    assert!(jws::Binding::parse("kid-1", "").is_none());
    assert!(jws::Binding::parse("kid-1", "not base64!").is_none());
    let shown = format!("{binding:?}");
    assert!(shown.contains("kid-1") && !shown.contains("97"), "{shown}");
}

#[test]
fn a_renewal_names_the_certificate_it_replaces_when_the_directory_takes_it() {
    let replacing = || OrderOptions { replaces: Some("aaa.bbb".to_owned()), ..options() };
    let mut account = Account::new(KeyPair::generate().unwrap());
    let script = Script { renewal_info: true, ..Script::default() };
    let run = run_with(&mut account, replacing(), script);
    assert!(run.result.is_ok());
    assert_eq!(run.replaces, ["aaa.bbb"]);

    // A directory without renewal information does not know the member.
    let mut account = Account::new(KeyPair::generate().unwrap());
    let run = run_with(&mut account, replacing(), Script::default());
    assert!(run.result.is_ok());
    assert_eq!(run.replaces, [""]);

    // An authority that refuses the member gets the order again without it.
    let mut account = Account::new(KeyPair::generate().unwrap());
    let script = Script { renewal_info: true, refuse_replaces: true, ..Script::default() };
    let run = run_with(&mut account, replacing(), script);
    assert!(run.result.is_ok());
    assert_eq!(run.replaces, ["aaa.bbb", ""]);
}

#![allow(clippy::unwrap_used)]
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use sibuna_json::Value;

use super::*;
use crate::order::{Method, Request, Response};
use crate::{Account, Challenge, KeyPair, OrderOptions, der, obtain, pem, x509};

const NOW: u64 = 1_795_516_496;
const BASE: &str = "https://ca.internal/acme";

/// A storage directory of one test, removed with it.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SERIAL: AtomicU32 = AtomicU32::new(0);
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-acme-server-{}-{serial}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The key authorizations that the responder serves, by token.
type Answers = Arc<Mutex<Vec<(String, String)>>>;

/// Serves key authorizations on a loopback port, as a host under validation does.
/// The thread lives as long as the test process.
fn responder() -> (u16, Answers) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answers = Answers::default();
    let served = Arc::clone(&answers);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0; 2048];
            let count = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..count]).into_owned();
            let path = request.split(' ').nth(1).unwrap_or_default();
            let token = path.rsplit('/').next().unwrap_or_default();
            let known = served.lock().unwrap().iter().find(|(t, _)| t == token).cloned();
            let response = match known {
                Some((_, body)) => {
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                }
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, answers)
}

fn options(port: u16) -> ServerOptions {
    ServerOptions {
        url: BASE.to_owned(),
        names: vec!["localhost".to_owned(), "lab.internal".to_owned()],
        ranges: vec![(Ipv4Addr::new(127, 0, 0, 0).into(), 8)],
        constraints: Vec::new(),
        http_port: port,
    }
}

fn header<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
    reply.headers.iter().find(|(key, _)| *key == name).map(|(_, value)| value.as_str())
}

/// A client that speaks to a server with no socket in between.
struct Client<'a> {
    server: &'a Server,
    key: KeyPair,
    nonce: String,
    account: Option<String>,
}

impl<'a> Client<'a> {
    fn new(server: &'a Server) -> Self {
        let exchange = Exchange { method: "HEAD", path: "/new-nonce", body: b"" };
        let nonce = header(&server.handle(&exchange, NOW), "Replay-Nonce").unwrap().to_owned();
        Self { server, key: KeyPair::generate().unwrap(), nonce, account: None }
    }

    /// Sends a signed POST and keeps the new nonce.
    fn post_at(&mut self, path: &str, payload: &str, now: u64) -> Reply {
        let url = format!("{BASE}{path}");
        let body =
            jws::sign(&self.key, self.account.as_deref(), &self.nonce, &url, payload).unwrap();
        let exchange = Exchange { method: "POST", path, body: body.as_bytes() };
        let reply = self.server.handle(&exchange, now);
        self.nonce = header(&reply, "Replay-Nonce").unwrap().to_owned();
        reply
    }

    fn post(&mut self, path: &str, payload: &str) -> Reply {
        self.post_at(path, payload, NOW)
    }

    fn register(&mut self) {
        let reply = self.post("/new-account", r#"{"termsOfServiceAgreed":true}"#);
        assert_eq!(reply.status, 201, "{}", text(&reply));
        self.account = Some(header(&reply, "Location").unwrap().to_owned());
    }

    /// Places an order and returns its path, for example `/order/ID`.
    fn order(&mut self, names: &[&str]) -> String {
        let reply = self.post("/new-order", &identifiers(names));
        assert_eq!(reply.status, 201, "{}", text(&reply));
        header(&reply, "Location").unwrap().strip_prefix(BASE).unwrap().to_owned()
    }
}

fn identifiers(names: &[&str]) -> String {
    let list: Vec<String> =
        names.iter().map(|name| format!(r#"{{"type":"dns","value":"{name}"}}"#)).collect();
    format!(r#"{{"identifiers":[{}]}}"#, list.join(","))
}

fn text(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}

/// The string member `name` of the JSON body of a reply.
fn member(reply: &Reply, name: &str) -> String {
    let value = sibuna_json::parse(&reply.body).unwrap();
    value.as_object().unwrap().get(name).and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// The ACME error type of a problem reply, without its prefix.
fn problem_of(reply: &Reply) -> String {
    assert_eq!(reply.content_type, "application/problem+json", "{}", text(reply));
    member(reply, "type").trim_start_matches("urn:ietf:params:acme:error:").to_owned()
}

/// Runs every queued task.
fn work(server: &Server, authority: &LocalAuthority) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    while let Some(task) = server.next_task(Duration::ZERO) {
        outcomes.push(server.perform(task, authority, 43_200, NOW));
    }
    outcomes
}

/// Sends a request of the crate's own client to the server.
fn send(server: &Server, request: &Request) -> Result<Response, crate::Error> {
    let method = match request.method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
    };
    let path = request.url.strip_prefix(BASE).unwrap();
    let reply = server.handle(&Exchange { method, path, body: request.body.as_bytes() }, NOW);
    Ok(Response {
        status: reply.status,
        location: header(&reply, "Location").map(str::to_owned),
        nonce: header(&reply, "Replay-Nonce").map(str::to_owned),
        retry_after: None,
        body: reply.body,
    })
}

#[test]
fn the_client_of_the_crate_obtains_a_certificate_of_the_local_authority() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let (port, answers) = responder();
    let server = Server::new(options(port)).unwrap();
    let mut account = Account::new(KeyPair::generate().unwrap());
    let order = OrderOptions {
        directory: format!("{BASE}/directory"),
        name: "localhost".to_owned(),
        any_challenge: false,
        ..OrderOptions::default()
    };
    let present = |challenge: &Challenge| {
        let answer = (challenge.token.clone(), challenge.key_authorization.clone());
        answers.lock().unwrap().push(answer);
        Ok(())
    };
    let mut outcomes = Vec::new();
    let issued = obtain(
        &mut account,
        order,
        |request| {
            let response = send(&server, request);
            outcomes.extend(work(&server, &authority));
            response
        },
        present,
        |_seconds| {},
    )
    .unwrap();
    let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
    assert_eq!(blocks.len(), 2);
    let leaf = x509::read(&blocks[0]).unwrap();
    assert_eq!(leaf.names, ["localhost"]);
    assert_eq!(leaf.not_after, NOW + 43_200);
    // The leaf carries the key of the client and chains to the intermediate.
    let own = authority.issue(&["localhost"], 60, NOW).unwrap();
    let own_blocks = pem::decode("CERTIFICATE", &own.chain_pem).unwrap();
    assert_eq!(blocks[1], own_blocks[1]);
    let parts = x509::parts(&blocks[0]).unwrap();
    assert_eq!(parts.spki, issued.key.subject_public_key_info());
    let validated = Outcome::Validated { name: "localhost".to_owned(), failure: None };
    let signed = Outcome::Issued { names: vec!["localhost".to_owned()] };
    assert_eq!(outcomes, [validated, signed]);
}

#[test]
fn the_directory_the_nonce_and_the_list_answer_without_a_signature() {
    let server = Server::new(options(80)).unwrap();
    let get = |path| server.handle(&Exchange { method: "GET", path, body: b"" }, NOW);
    let directory = get("/directory");
    assert_eq!(directory.status, 200);
    assert_eq!(member(&directory, "newNonce"), format!("{BASE}/new-nonce"));
    assert_eq!(member(&directory, "newAccount"), format!("{BASE}/new-account"));
    assert_eq!(member(&directory, "newOrder"), format!("{BASE}/new-order"));
    assert_eq!(
        header(&directory, "Link"),
        Some("<https://ca.internal/acme/directory>;rel=\"index\"")
    );
    assert!(header(&directory, "Replay-Nonce").is_none());
    let first = get("/new-nonce");
    let second = server.handle(&Exchange { method: "HEAD", path: "/new-nonce", body: b"" }, NOW);
    let nonce = |reply: &Reply| header(reply, "Replay-Nonce").unwrap().to_owned();
    assert!(nonce(&first).len() == 22 && nonce(&first) != nonce(&second));
    assert_eq!(get("/crl").status, 404);
    server.set_crl(vec![0x30, 0]);
    let list = get("/crl");
    assert_eq!((list.status, list.content_type), (200, "application/pkix-crl"));
    assert_eq!(list.body, [0x30, 0]);
    for (method, path) in [("GET", "/"), ("GET", "/order/x"), ("PUT", "/directory"), ("GET", "")] {
        let reply = server.handle(&Exchange { method, path, body: b"" }, NOW);
        assert_eq!(reply.status, 404, "{method} {path}");
    }
    let long = format!("/{}", "a".repeat(MAX_PATH));
    assert_eq!(get(&long).status, 404);
    assert!(Server::new(ServerOptions { url: "https://x/\"".to_owned(), ..options(80) }).is_err());
    assert!(Server::new(ServerOptions { url: "https://x/".to_owned(), ..options(80) }).is_err());
}

#[test]
fn a_nonce_is_accepted_once_and_not_after_its_hour() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    let used = client.nonce.clone();
    client.register();
    // The same nonce again: refused, and the refusal carries a fresh one.
    client.nonce = used;
    let reply = client.post("/new-order", &identifiers(&["localhost"]));
    assert_eq!((reply.status, problem_of(&reply).as_str()), (400, "badNonce"));
    assert_eq!(client.post("/new-order", &identifiers(&["localhost"])).status, 201);
    // A nonce that the server never made, and no nonce.
    for nonce in ["AAAAAAAAAAAAAAAAAAAAAA", "", &"n".repeat(65)] {
        client.nonce = nonce.to_owned();
        let reply = client.post("/new-order", &identifiers(&["localhost"]));
        assert_eq!(problem_of(&reply), "badNonce", "{nonce}");
    }
    // A nonce is good for an hour.
    let reply = client.post_at("/new-order", &identifiers(&["localhost"]), NOW + NONCE_LIFETIME);
    assert_eq!(reply.status, 201);
    let reply =
        client.post_at("/new-order", &identifiers(&["localhost"]), NOW + 2 * NONCE_LIFETIME + 1);
    assert_eq!(problem_of(&reply), "badNonce");
}

#[test]
fn the_nonces_are_bounded_and_the_oldest_leave() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    let oldest = client.nonce.clone();
    for _ in 0..MAX_NONCES {
        let _ = server.handle(&Exchange { method: "HEAD", path: "/new-nonce", body: b"" }, NOW);
    }
    assert_eq!(server.state().nonces.len(), MAX_NONCES);
    client.nonce = oldest;
    let reply = client.post("/new-account", "{}");
    assert_eq!(problem_of(&reply), "badNonce");
    assert_eq!(client.post("/new-account", "{}").status, 201);
}

#[test]
fn a_request_must_be_signed_for_this_url_by_a_known_kind_of_key() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    let raw = |client: &mut Client<'_>, body: &[u8]| {
        let reply = server.handle(&Exchange { method: "POST", path: "/new-account", body }, NOW);
        client.nonce = header(&reply, "Replay-Nonce").unwrap().to_owned();
        reply
    };
    for body in [
        &b""[..],
        b"{",
        b"[]",
        b"{\"protected\":1}",
        b"{\"protected\":\"!\",\"payload\":\"\",\"signature\":\"\"}",
    ] {
        let reply = raw(&mut client, body);
        assert_eq!((reply.status, problem_of(&reply).as_str()), (400, "malformed"));
    }
    let big = vec![b' '; MAX_BODY + 1];
    assert_eq!(raw(&mut client, &big).status, 413);
    // Signed for another URL.
    let other = jws::sign(&client.key, None, &client.nonce, "https://elsewhere/new-account", "{}");
    let reply = raw(&mut client, other.unwrap().as_bytes());
    assert_eq!((reply.status, problem_of(&reply).as_str()), (403, "unauthorized"));
    // A signature that does not verify: one character of the payload is changed.
    let good = jws::sign(&client.key, None, &client.nonce, &format!("{BASE}/new-account"), "{}");
    let bad = good.unwrap().replace(r#""payload":"e30""#, r#""payload":"e31""#);
    let nonce = client.nonce.clone();
    let reply = raw(&mut client, bad.as_bytes());
    assert_eq!((reply.status, problem_of(&reply).as_str()), (403, "unauthorized"));
    // The refused request did not use up its nonce.
    client.nonce = nonce;
    assert_eq!(client.post("/new-account", "{}").status, 201);
    // A registration with `kid`, and an order with `jwk`.
    let reply = client.post("/new-order", &identifiers(&["localhost"]));
    assert_eq!(problem_of(&reply), "malformed");
    client.register();
    assert_eq!(problem_of(&client.post("/new-account", "{}")), "malformed");
    // A `kid` of another server, and one that holds no key.
    for kid in ["https://elsewhere/acme/account/e30", "https://ca.internal/acme/account/e30"] {
        client.account = Some(kid.to_owned());
        let reply = client.post("/new-order", &identifiers(&["localhost"]));
        assert_eq!(problem_of(&reply), "accountDoesNotExist", "{kid}");
    }
}

#[test]
fn an_account_is_its_key_and_keeps_no_state() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    let first = client.post("/new-account", "{}");
    let again = client.post("/new-account", r#"{"onlyReturnExisting":true}"#);
    assert_eq!((first.status, again.status), (201, 200));
    assert_eq!(header(&first, "Location"), header(&again, "Location"));
    let url = header(&first, "Location").unwrap().to_owned();
    let id = url.strip_prefix("https://ca.internal/acme/account/").unwrap();
    assert_eq!(jose::decode(id).unwrap(), jws::jwk(&client.key).into_bytes());
    client.account = Some(url.clone());
    let path = url.strip_prefix(BASE).unwrap().to_owned();
    assert_eq!(member(&client.post(&path, ""), "status"), "valid");
    let reply = client.post(&path, r#"{"status":"deactivated"}"#);
    assert_eq!((reply.status, problem_of(&reply).as_str()), (403, "unauthorized"));
    // The account URL of another key is not this account's.
    let other = Client::new(&server);
    let foreign = format!("/account/{}", jws::base64url(jws::jwk(&other.key).as_bytes()));
    assert_eq!(client.post(&foreign, "").status, 400);
}

#[test]
fn an_order_takes_only_names_that_the_server_may_issue() {
    let constrained = ServerOptions {
        constraints: vec!["internal".to_owned(), "10.0.0.0/8".to_owned()],
        ..options(80)
    };
    let server = Server::new(constrained).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let refused = |client: &mut Client<'_>, payload: &str| {
        let reply = client.post("/new-order", payload);
        (reply.status, problem_of(&reply))
    };
    let rejected = (400, "rejectedIdentifier".to_owned());
    for name in [
        "*.lab.internal",
        "example.com",
        "xlab.internal",
        "lab.internal.",
        "a b.lab.internal",
        "-a.lab.internal",
        "10.0.0.1",
        "\\\"x.lab.internal",
    ] {
        assert_eq!(refused(&mut client, &identifiers(&[name])), rejected, "{name}");
    }
    // `localhost` is allowed by the server and outside the constraints of the root.
    assert_eq!(refused(&mut client, &identifiers(&["localhost"])), rejected);
    let address = r#"{"identifiers":[{"type":"ip","value":"10.0.0.1"}]}"#;
    assert_eq!(refused(&mut client, address), (400, "unsupportedIdentifier".to_owned()));
    for payload in [
        "",
        "{}",
        r#"{"identifiers":[]}"#,
        r#"{"identifiers":[{"type":"dns"}]}"#,
        r#"{"identifiers":[1]}"#,
    ] {
        assert_eq!(refused(&mut client, payload), (400, "malformed".to_owned()), "{payload}");
    }
    let many: Vec<String> = (0..=MAX_NAMES).map(|n| format!("h{n}.lab.internal")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(refused(&mut client, &identifiers(&many)), (400, "malformed".to_owned()));
    // Upper case is folded, and a name that is given twice counts once.
    let reply = client.post("/new-order", &identifiers(&["A.Lab.Internal", "a.lab.internal"]));
    assert_eq!(reply.status, 201);
    assert_eq!(member(&reply, "status"), "pending");
    let body = text(&reply);
    assert_eq!(body.matches("a.lab.internal").count(), 1, "{body}");
    assert!(body.contains("/authz/") && body.contains("/finalize/"), "{body}");
}

#[test]
fn the_orders_are_bounded_for_an_account_and_expire_after_an_hour() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let first = client.order(&["localhost"]);
    for _ in 1..MAX_ACCOUNT_ORDERS {
        client.order(&["localhost"]);
    }
    let reply = client.post("/new-order", &identifiers(&["localhost"]));
    assert_eq!((reply.status, problem_of(&reply).as_str()), (429, "rateLimited"));
    assert_eq!(header(&reply, "Retry-After"), Some("60"));
    // Another account still has room, and cannot read the orders of the first.
    let mut other = Client::new(&server);
    other.register();
    other.order(&["localhost"]);
    assert_eq!(other.post(&first, "").status, 400);
    assert_eq!(client.post(&first, "").status, 200);
    // After the hour the orders are gone and there is room again.
    let reply = client.post_at(&first, "", NOW + ORDER_LIFETIME);
    assert_eq!(reply.status, 400);
    assert_eq!(server.state().orders.len(), 0);
    let reply = client.post_at("/new-order", &identifiers(&["localhost"]), NOW + ORDER_LIFETIME);
    assert_eq!(reply.status, 201);
}

/// The paths of the first authorization and of its challenge, and the token.
fn challenge_of(client: &mut Client<'_>, order: &str) -> (String, String, String) {
    let id = order.strip_prefix("/order/").unwrap();
    let authz = format!("/authz/{id}.0");
    let reply = client.post(&authz, "");
    assert_eq!(reply.status, 200, "{}", text(&reply));
    let body = text(&reply);
    let token = body.split(r#""token":""#).nth(1).unwrap().split('"').next().unwrap().to_owned();
    (authz, format!("/chall/{id}.0"), token)
}

#[test]
fn a_failed_validation_makes_the_order_invalid_and_says_why() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let (port, _answers) = responder();
    let server = Server::new(options(port)).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let order = client.order(&["localhost"]);
    let (authz, challenge, _token) = challenge_of(&mut client, &order);
    // Finalizing before the proof is refused.
    let finalize = order.replace("/order/", "/finalize/");
    let reply = client.post(&finalize, r#"{"csr":"AAAA"}"#);
    assert_eq!((reply.status, problem_of(&reply).as_str()), (400, "orderNotReady"));
    assert_eq!(member(&client.post(&challenge, "{}"), "status"), "processing");
    // A second answer does not queue a second validation.
    assert_eq!(member(&client.post(&challenge, "{}"), "status"), "processing");
    let outcomes = work(&server, &authority);
    assert_eq!(outcomes.len(), 1);
    let Outcome::Validated { failure: Some(reason), .. } = &outcomes[0] else {
        panic!("{outcomes:?}");
    };
    assert!(reason.contains("status 404"), "{reason}");
    let body = text(&client.post(&authz, ""));
    assert!(body.contains(r#""status":"invalid""#) && body.contains("status 404"), "{body}");
    assert!(body.contains("incorrectResponse"), "{body}");
    assert_eq!(member(&client.post(&order, ""), "status"), "invalid");
    assert_eq!(problem_of(&client.post(&finalize, r#"{"csr":"AAAA"}"#)), "orderNotReady");
    assert_eq!(member(&client.post(&challenge, "{}"), "status"), "invalid");
    assert!(server.next_task(Duration::ZERO).is_none());
}

/// An order of `names` whose names are all proved: its path and its finalize path.
fn ready_order(
    client: &mut Client<'_>,
    authority: &LocalAuthority,
    answers: &Answers,
    names: &[&str],
) -> (String, String) {
    let order = client.order(names);
    let id = order.strip_prefix("/order/").unwrap().to_owned();
    let thumbprint = jws::thumbprint(&client.key);
    for index in 0..names.len() {
        let body = text(&client.post(&format!("/authz/{id}.{index}"), ""));
        let token = body.split(r#""token":""#).nth(1).unwrap().split('"').next().unwrap();
        answers.lock().unwrap().push((token.to_owned(), format!("{token}.{thumbprint}")));
        assert_eq!(client.post(&format!("/chall/{id}.{index}"), "{}").status, 200);
    }
    let outcomes = work(client.server, authority);
    assert_eq!(outcomes.len(), names.len(), "{outcomes:?}");
    assert_eq!(member(&client.post(&order, ""), "status"), "ready");
    (order.clone(), order.replace("/order/", "/finalize/"))
}

fn csr_payload(key: &KeyPair, names: &[&str]) -> String {
    format!(r#"{{"csr":"{}"}}"#, jws::base64url(&csr::write(key, names).unwrap()))
}

#[test]
fn finalize_takes_only_a_request_for_the_names_of_the_order() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let (port, answers) = responder();
    let server = Server::new(options(port)).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let (order, finalize) = ready_order(&mut client, &authority, &answers, &["localhost"]);
    let key = KeyPair::generate().unwrap();
    let mut damaged = csr::write(&key, &["localhost"]).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let long = jws::base64url(&vec![0x30; MAX_REQUEST + 1]);
    let payloads = [
        String::new(),
        "{}".to_owned(),
        r#"{"csr":"!"}"#.to_owned(),
        format!(r#"{{"csr":"{long}"}}"#),
        format!(r#"{{"csr":"{}"}}"#, jws::base64url(&damaged)),
        csr_payload(&key, &["other.lab.internal"]),
        csr_payload(&key, &["localhost", "other.lab.internal"]),
        csr_payload(&key, &["localhost", "127.0.0.1"]),
    ];
    for payload in &payloads {
        let reply = client.post(&finalize, payload);
        assert_eq!((reply.status, problem_of(&reply).as_str()), (400, "badCSR"), "{payload}");
    }
    assert_eq!(member(&client.post(&order, ""), "status"), "ready");
    let certificate = order.replace("/order/", "/cert/");
    assert_eq!(client.post(&certificate, "").status, 400);
    let reply = client.post(&finalize, &csr_payload(&key, &["LOCALHOST"]));
    assert_eq!((reply.status, member(&reply, "status").as_str()), (200, "processing"));
    // An order is finalized once.
    let again = client.post(&finalize, &csr_payload(&key, &["localhost"]));
    assert_eq!(problem_of(&again), "orderNotReady");
    let signed = Outcome::Issued { names: vec!["localhost".to_owned()] };
    assert_eq!(work(&server, &authority), [signed]);
    let done = client.post(&order, "");
    assert_eq!(member(&done, "status"), "valid");
    assert_eq!(member(&done, "certificate"), format!("{BASE}{certificate}"));
    let chain = client.post(&certificate, "");
    assert_eq!(chain.content_type, "application/pem-certificate-chain");
    let blocks = pem::decode("CERTIFICATE", &text(&chain)).unwrap();
    assert_eq!(x509::parts(&blocks[0]).unwrap().spki, key.subject_public_key_info());
    // Another account does not get the certificate.
    let mut other = Client::new(&server);
    other.register();
    assert_eq!(other.post(&certificate, "").status, 400);
}

#[test]
fn a_failed_signing_makes_the_order_invalid_and_keeps_the_reason_from_the_client() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let (port, answers) = responder();
    let server = Server::new(options(port)).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let (order, finalize) = ready_order(&mut client, &authority, &answers, &["localhost"]);
    let key = KeyPair::generate().unwrap();
    assert_eq!(client.post(&finalize, &csr_payload(&key, &["localhost"])).status, 200);
    // The storage is lost before the signing: a file stands where the directory was.
    std::fs::remove_dir_all(&scratch.0).unwrap();
    std::fs::write(&scratch.0, "").unwrap();
    let outcomes = work(&server, &authority);
    std::fs::remove_file(&scratch.0).unwrap();
    let [Outcome::NotIssued { error, .. }] = outcomes.as_slice() else { panic!("{outcomes:?}") };
    assert_eq!(error.code, "ACME011");
    let body = text(&client.post(&order, ""));
    assert!(body.contains(r#""status":"invalid""#) && body.contains("serverInternal"), "{body}");
    // The reason of the authority is for the operator, not for the client.
    assert!(!body.contains("ACME011") && !body.contains(scratch.0.to_str().unwrap()), "{body}");
}

#[test]
fn the_queue_of_work_is_bounded() {
    let server = Server::new(options(80)).unwrap();
    let mut refused = None;
    let mut queued = 0;
    'clients: for _ in 0..=MAX_TASKS / MAX_ACCOUNT_ORDERS {
        let mut client = Client::new(&server);
        client.register();
        for _ in 0..MAX_ACCOUNT_ORDERS {
            let order = client.order(&["localhost"]);
            let (_, challenge, _) = challenge_of(&mut client, &order);
            let reply = client.post(&challenge, "{}");
            if reply.status != 200 {
                refused = Some((reply.status, problem_of(&reply), challenge, client));
                break 'clients;
            }
            queued += 1;
        }
    }
    assert_eq!(queued, MAX_TASKS);
    let (status, kind, challenge, mut client) = refused.unwrap();
    assert_eq!((status, kind.as_str()), (429, "rateLimited"));
    // The refused challenge is still pending, so the client may try again.
    assert_eq!(server.next_task(Duration::ZERO).iter().count(), 1);
    assert_eq!(member(&client.post(&challenge, "{}"), "status"), "processing");
}

/// A JWS with RS256 and the key as `jwk`, as a client with an RSA account key sends.
fn rs256(key: &KeyPair, nonce: &str, url: &str, payload: &str) -> String {
    let (_, public, _) = der::read(key.public_point()).unwrap();
    let mut parts = der::children(public);
    let strip = |bytes: &[u8]| jws::base64url(bytes.strip_prefix(&[0]).unwrap_or(bytes));
    let (n, e) = (strip(parts.next().unwrap().1), strip(parts.next().unwrap().1));
    let jwk = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    let header = format!(r#"{{"alg":"RS256","jwk":{jwk},"nonce":"{nonce}","url":"{url}"}}"#);
    let protected = jws::base64url(header.as_bytes());
    let payload = jws::base64url(payload.as_bytes());
    let signed = key.sign_der(format!("{protected}.{payload}").as_bytes()).unwrap();
    // The message is no DER element, so the signature is found by its length: the
    // last 256 bytes of what a key of 2048 bits signs.
    let signature = &signed[signed.len() - 256..];
    format!(
        r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
        jws::base64url(signature)
    )
}

#[test]
fn an_rsa_account_key_signs_with_rs256() {
    let Some(key) = crate::key::test_rsa_key() else { return };
    let server = Server::new(options(80)).unwrap();
    let client = Client::new(&server);
    let url = format!("{BASE}/new-account");
    let body = rs256(&key, &client.nonce, &url, "{}");
    let reply = server
        .handle(&Exchange { method: "POST", path: "/new-account", body: body.as_bytes() }, NOW);
    assert_eq!(reply.status, 201, "{}", text(&reply));
    let account = header(&reply, "Location").unwrap();
    let id = account.strip_prefix("https://ca.internal/acme/account/").unwrap();
    assert!(jose::AccountKey::from_account_id(id).is_some());
    // The same key with the algorithm of another kind of key is refused.
    let nonce = header(&reply, "Replay-Nonce").unwrap();
    let wrong = rs256(&key, nonce, &url, "{}");
    let (_, rest) = wrong.split_once(r#""protected":""#).unwrap();
    let protected = rest.split('"').next().unwrap();
    let header_text = String::from_utf8(jose::decode(protected).unwrap()).unwrap();
    let forged = jws::base64url(header_text.replace("RS256", "ES256").as_bytes());
    let body = wrong.replace(protected, &forged);
    let reply = server
        .handle(&Exchange { method: "POST", path: "/new-account", body: body.as_bytes() }, NOW);
    assert_eq!(problem_of(&reply), "badSignatureAlgorithm");
}

#[test]
fn no_request_makes_the_server_panic() {
    let server = Server::new(options(80)).unwrap();
    let mut client = Client::new(&server);
    client.register();
    let order = client.order(&["localhost"]);
    let id = order.strip_prefix("/order/").unwrap().to_owned();
    let paths = [
        "/order/".to_owned(),
        "/order".to_owned(),
        format!("/order/{id}.0"),
        format!("/authz/{id}"),
        format!("/authz/{id}.1"),
        format!("/authz/{id}.99999999999999999999"),
        format!("/authz/{id}.-1"),
        format!("/chall/{id}"),
        format!("/chall/{id}.7"),
        format!("/finalize/{id}.0"),
        format!("/cert/{id}"),
        format!("/cert/{id}/x"),
        "/account/".to_owned(),
        "/account/e30".to_owned(),
        "/nothing".to_owned(),
        "/".to_owned(),
        "/\u{e9}".to_owned(),
    ];
    for path in &paths {
        for payload in ["", "{}", "[]", "null", r#"{"csr":7,"status":[],"identifiers":{}}"#] {
            let reply = client.post(path, payload);
            assert!((400..500).contains(&reply.status), "{path} {payload}: {}", reply.status);
            assert_eq!(reply.content_type, "application/problem+json", "{path}");
        }
    }
    assert_eq!(client.post(&order, "").status, 200);
}

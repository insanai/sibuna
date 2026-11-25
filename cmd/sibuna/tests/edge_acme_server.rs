//! The ACME server of the local authority through the binary (SID 0021): the ACME
//! client of the crate obtains a certificate from a running edge over TLS, with the
//! HTTP-01 validation against a responder inside the test. Everything is on loopback.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/acme_authority.rs"]
#[allow(dead_code)]
mod authority;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use authority::connect_trusting;
use sibuna_acme::{Account, Challenge, KeyPair, Method, OrderOptions, Request, Response};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// A running edge. Dropping it stops the process.
struct Daemon {
    child: Child,
    tls: SocketAddr,
    plain: SocketAddr,
    socket: PathBuf,
    log: Arc<Mutex<String>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("the daemon wrote:\n{}", self.log());
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    fn ctl(&self, command: &str) -> String {
        let output = Command::new(BIN)
            .arg("ctl")
            .arg(&self.socket)
            .args(command.split(' '))
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The base URL of the ACME server.
    fn url(&self) -> String {
        format!("https://localhost:{}/acme", self.tls.port())
    }
}

/// A directory of this test alone.
fn home(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("sibuna-acme-server-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// A server that answers every request with `ok` and closes.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            let mut buffer = [0; 4096];
            let _ = socket.read(&mut buffer);
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    address
}

/// The key authorizations that the responder serves, by token.
type Answers = Arc<Mutex<Vec<(String, String)>>>;

/// The host under validation: serves key authorizations on a loopback port that the
/// test holds for its whole life.
fn responder() -> (u16, Answers) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answers = Answers::default();
    let served = Arc::clone(&answers);
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            let mut buffer = [0; 2048];
            let count = socket.read(&mut buffer).unwrap_or(0);
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
            let _ = socket.write_all(response.as_bytes());
        }
    });
    (port, answers)
}

/// Starts the edge with the ACME server at `https://localhost:TLS/acme`. A port that
/// was free a moment ago may be taken by a test beside this one: the listeners are
/// then chosen again.
fn start(home: &Path, origin: SocketAddr, http_port: u16) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(home, origin, http_port) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(home: &Path, origin: SocketAddr, http_port: u16) -> Result<Daemon, String> {
    let (tls, plain) = (free_address(), free_address());
    let file = home.join("edge.json");
    let socket = home.join("admin.sock");
    let server = format!(
        r#"{{"url":"https://localhost:{}/acme","allow":["localhost","127.0.0.0/8"],
            "http_port":{http_port}}}"#,
        tls.port()
    );
    let text = format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{"storage":"{storage}","internal":{{"server":{server}}}}}}},
        "http":{{"surface":"off"}},
        "observability":{{"access_log":{{"output":"{log}"}}}},
        "frontends":{{"web":{{"proto":"http","binds":["{tls}"],
          "tls":{{"auto":["localhost","127.0.0.1"]}},"default_backend":"app"}},
          "plain":{{"proto":"http","binds":["{plain}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = socket.display(),
        storage = home.join("acme").display(),
        log = home.join("access.log").display(),
    );
    fs::write(&file, text).unwrap();
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&file).stderr(Stdio::piped()).spawn().unwrap();
    let mut reader = BufReader::new(child.stderr.take().unwrap());
    let mut text = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(text);
        }
        text.push_str(&line);
        if line.contains("listeners ready") {
            break;
        }
    }
    let log = Arc::new(Mutex::new(text));
    let sink = Arc::clone(&log);
    std::thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            sink.lock().unwrap().push_str(&line);
            line.clear();
        }
    });
    Ok(Daemon { child, tls, plain, socket, log })
}

/// Waits until `check` returns a value, for at most `seconds`.
fn wait_for<T>(what: &str, seconds: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The root of the local authority, as `show ca` prints it.
fn local_root(daemon: &Daemon) -> String {
    let text = daemon.ctl("show ca");
    text.lines().filter(|line| !line.starts_with('#')).collect::<Vec<_>>().join("\n")
}

/// The parts of an answer of the edge.
struct Answer {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<String> {
        let prefix = format!("{}:", name.to_ascii_lowercase());
        let line = self.head.lines().find(|line| line.to_ascii_lowercase().starts_with(&prefix));
        line.and_then(|line| line.split_once(':')).map(|(_, value)| value.trim().to_owned())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn parse_answer(bytes: &[u8]) -> Answer {
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n").unwrap_or(bytes.len());
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let status = head.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    Answer { status, head, body: bytes.get(end + 4..).unwrap_or_default().to_vec() }
}

/// One request inside TLS, from a client that trusts `root` alone.
fn exchange(
    daemon: &Daemon,
    root: &str,
    host: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Answer {
    let name = host.split(':').next().unwrap();
    let (mut session, mut socket) = connect_trusting(daemon.tls, name, root).unwrap();
    let mut stream = rustls::Stream::new(&mut session, &mut socket);
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/jose+json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    parse_answer(&bytes)
}

/// Sends a request of the ACME client of the crate to the edge.
fn send(daemon: &Daemon, root: &str, request: &Request) -> Response {
    let method = match request.method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
    };
    let host = format!("localhost:{}", daemon.tls.port());
    let path = request.url.strip_prefix(&format!("https://{host}")).unwrap();
    let answer = exchange(daemon, root, &host, method, path, &request.body);
    Response {
        status: answer.status,
        location: answer.header("location"),
        nonce: answer.header("replay-nonce"),
        retry_after: None,
        body: answer.body,
    }
}

/// Orders a certificate for `name` with the client of the crate. `answering` says
/// whether the challenge is published at the responder.
fn order(
    daemon: &Daemon,
    root: &str,
    answers: &Answers,
    name: &str,
    answering: bool,
    sent: &mut Vec<Request>,
) -> Result<sibuna_acme::Issued, sibuna_acme::Error> {
    let mut account = Account::new(KeyPair::generate().unwrap());
    let options = OrderOptions {
        directory: format!("{}/directory", daemon.url()),
        name: name.to_owned(),
        any_challenge: false,
        ..OrderOptions::default()
    };
    let present = |challenge: &Challenge| {
        if answering {
            let answer = (challenge.token.clone(), challenge.key_authorization.clone());
            answers.lock().unwrap().push(answer);
        }
        Ok(())
    };
    sibuna_acme::obtain(
        &mut account,
        options,
        |request| {
            sent.push(request.clone());
            Ok(send(daemon, root, request))
        },
        present,
        |seconds| std::thread::sleep(Duration::from_millis(200 * seconds.clamp(1, 5))),
    )
}

/// OpenSSL accepts the chain with the root, when it is installed.
fn openssl_accepts(home: &Path, root: &str, chain_pem: &str) {
    let blocks = sibuna_acme::pem::decode("CERTIFICATE", chain_pem).unwrap();
    let write = |name: &str, text: String| {
        let path = home.join(name);
        fs::write(&path, text).unwrap();
        path
    };
    let leaf = write("client-leaf.pem", sibuna_acme::pem::encode("CERTIFICATE", &blocks[0]));
    let middle = write("client-middle.pem", sibuna_acme::pem::encode("CERTIFICATE", &blocks[1]));
    let root = write("client-root.pem", root.to_owned());
    let verified = Command::new("openssl")
        .args(["verify", "-x509_strict", "-CAfile"])
        .arg(&root)
        .arg("-untrusted")
        .arg(&middle)
        .arg(&leaf)
        .output();
    if let Ok(output) = verified {
        let text = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{text}");
    }
}

/// What the edge answers outside the protocol: the list, other hosts, the plain
/// frontend, a replayed request and a body that is too long.
fn the_edges_of_the_server(daemon: &Daemon, root: &str, replayed: &Request) {
    let host = format!("localhost:{}", daemon.tls.port());
    let get = |host: &str, path: &str| exchange(daemon, root, host, "GET", path, "");
    let directory = get(&host, "/acme/directory");
    assert_eq!(directory.status, 200, "{}", directory.head);
    assert!(directory.text().contains(&format!("{}/new-order", daemon.url())));
    assert!(directory.header("link").unwrap().contains("rel=\"index\""));
    // The revocation list of the authority, as DER.
    let list = wait_for("the revocation list", 30, || {
        let list = get(&host, "/acme/crl");
        (list.status == 200).then_some(list)
    });
    assert_eq!(list.header("content-type").as_deref(), Some("application/pkix-crl"));
    assert!(sibuna_acme::crl::read(&list.body, None).is_some());
    // Another host and another path are not the server: the backend answers.
    assert_eq!(get("127.0.0.1", "/acme/directory").text(), "ok");
    assert_eq!(get(&host, "/other/directory").text(), "ok");
    assert_eq!(get(&host, "/acme/nothing").status, 404);
    // An https URL is not answered on the plain frontend.
    let mut plain = std::net::TcpStream::connect(daemon.plain).unwrap();
    let request =
        format!("GET /acme/directory HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    plain.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = plain.read_to_string(&mut answer);
    assert!(!answer.contains("newNonce"), "{answer}");
    // A request that was accepted once is refused the second time, with a new nonce.
    let again = send(daemon, root, replayed);
    assert_eq!(again.status, 400);
    assert!(String::from_utf8_lossy(&again.body).contains("badNonce"));
    assert!(again.nonce.is_some());
    // A body over the bound is refused and closes the connection.
    let long = "x".repeat(40 * 1024);
    let refused = exchange(daemon, root, &host, "POST", "/acme/new-account", &long);
    assert_eq!(refused.status, 413, "{}", refused.head);
    assert!(refused.head.to_ascii_lowercase().contains("connection: close"), "{}", refused.head);
}

#[test]
fn a_client_obtains_a_certificate_of_the_local_authority_from_the_edge() {
    let home = home("order");
    let (http_port, answers) = responder();
    let daemon = start(&home, origin(), http_port);
    wait_for("the certificate of the edge", 30, || {
        let table = daemon.ctl("show certs");
        let ready = |name: &str| {
            table.lines().any(|line| line.starts_with(name) && line.contains("ready"))
        };
        (ready("localhost") && ready("127.0.0.1")).then_some(())
    });
    let root = local_root(&daemon);
    let mut sent = Vec::new();
    let issued = order(&daemon, &root, &answers, "localhost", true, &mut sent).unwrap();
    let blocks = sibuna_acme::pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
    assert_eq!(blocks.len(), 2);
    let leaf = sibuna_acme::x509::read(&blocks[0]).unwrap();
    assert_eq!(leaf.names, ["localhost"]);
    // The intermediate is the one that signs the certificate of the edge itself.
    let own = fs::read_to_string(home.join("acme/local/certs/localhost/cert.pem")).unwrap();
    let own = sibuna_acme::pem::decode("CERTIFICATE", &own).unwrap();
    assert_eq!(blocks[1], own[1]);
    assert_ne!(blocks[0], own[0]);
    openssl_accepts(&home, &root, &issued.chain_pem);
    // The key never left the client: the storage of the edge holds no order of it.
    assert!(!home.join("acme/local/certs/client").exists());
    let log = daemon.log();
    assert!(log.contains("ACME server: localhost validated for a client"), "{log}");
    assert!(log.contains("ACME server: certificate issued to a client for localhost"), "{log}");

    // A name outside `allow` is refused at the order.
    let error = order(&daemon, &root, &answers, "example.org", true, &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("under no name that this server issues for"), "{error}");
    // A challenge that the host does not answer fails the order, and the log says why.
    let error = order(&daemon, &root, &answers, "localhost", false, &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("status 404"), "{error}");
    let log = wait_for("the failed validation in the log", 10, || {
        let log = daemon.log();
        log.contains("localhost not validated for a client").then_some(log)
    });
    assert!(log.contains("status 404"), "{log}");

    let replayed = sent.iter().rev().find(|request| request.method == Method::Post).unwrap();
    the_edges_of_the_server(&daemon, &root, replayed);
}

//! OCSP stapling for automatic certificates (SID 0021) through the binary, against a
//! certificate authority and a responder inside the test.
//!
//! Every server listens on a loopback port. No name is resolved and no real responder
//! is asked.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/acme_authority.rs"]
#[allow(dead_code)]
mod authority;
#[path = "support/ocsp_responder.rs"]
mod responder;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authority::{Authority, stapled};
use responder::Responder;
use sibuna_acme::ocsp::{self, Status};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const NAME: &str = "staple.example.org";

/// A number that no other file of this test binary has.
fn serial() -> usize {
    use std::sync::atomic::AtomicUsize as Counter;
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A server that answers every request with `ok` and closes.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 2 {
                line.clear();
            }
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    address
}

/// A running edge. Dropping it stops the process.
struct Daemon {
    child: Child,
    tls: SocketAddr,
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

    /// The columns of the line of `show certs` for [`NAME`].
    fn row(&self) -> Vec<String> {
        let output = Command::new(BIN)
            .arg("ctl")
            .arg(&self.socket)
            .args(["show", "certs"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let table = String::from_utf8_lossy(&output.stdout).into_owned();
        let line = table.lines().find(|line| line.split_whitespace().next() == Some(NAME));
        line.unwrap_or_default().split_whitespace().map(str::to_owned).collect()
    }

    /// Waits until the name is `ready`.
    fn ready(&self) {
        wait_for("a served certificate", 20, || {
            (self.row().get(5).map(String::as_str) == Some("ready")).then_some(())
        });
    }

    /// The leaf and the stapled response of a new handshake. The response is empty
    /// when none is stapled.
    fn handshake(&self) -> (Vec<u8>, Vec<u8>) {
        stapled(self.tls, NAME).unwrap()
    }

    /// Waits for a handshake with a stapled response and checks it as a client would:
    /// the authority or its delegate signed it, it names the served leaf, and its
    /// window is open. Returns the response and its answer.
    fn good_staple(&self, authority: &Authority) -> (Vec<u8>, ocsp::Answer) {
        let (leaf, response) = wait_for("a stapled response", 20, || {
            Some(self.handshake()).filter(|(_, response)| !response.is_empty())
        });
        let checker = ocsp::Responder::find(&leaf, &authority.root_der()).unwrap();
        let answer = checker.check(&response, now()).unwrap();
        assert_eq!(answer.status, Status::Good);
        (response, answer)
    }
}

/// A directory of one test alone.
fn home(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-ocsp-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// Starts the edge with a TLS frontend for [`NAME`] and a plain frontend. `acme` holds
/// more members of `global.acme`, each with a leading comma.
fn start(authority: &Authority, home: &Path, acme: &str) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(authority, home, acme) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(authority: &Authority, home: &Path, acme: &str) -> Result<Daemon, String> {
    let (bind, plain) = (free_address(), free_address());
    authority.tls_port.store(bind.port(), Ordering::Relaxed);
    authority.http_port.store(plain.port(), Ordering::Relaxed);
    let file = home.join(format!("edge-{}.json", serial()));
    let socket = home.join("admin.sock");
    let text = format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{"storage":"{storage}","challenge":"http-01","ari":false,
            "directory":"{directory}"{acme}}}}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{bind}"],
          "tls":{{"auto":["{NAME}"]}},"default_backend":"app"}},
          "plain":{{"proto":"http","binds":["{plain}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = socket.display(),
        storage = home.join("acme").display(),
        directory = authority.directory,
        origin = origin(),
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
    Ok(Daemon { child, tls: bind, socket, log })
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

fn asked(responder: &Responder) -> usize {
    responder.asked.load(Ordering::Relaxed)
}

/// What `openssl s_client -status` prints for the edge. `None`: no `openssl`.
fn openssl_status(address: SocketAddr) -> Option<String> {
    let output = Command::new("openssl")
        .args(["s_client", "-status", "-servername", NAME, "-connect"])
        .arg(address.to_string())
        .stdin(Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn a_response_is_stapled_refreshed_and_loaded_after_a_restart() {
    let authority = Authority::start();
    let responder = Responder::start(&authority);
    responder.validity.store(8, Ordering::Relaxed);
    let home = home("staple");
    let daemon = start(&authority, &home, "");
    daemon.ready();
    let (first, answer) = daemon.good_staple(&authority);
    assert_eq!(daemon.row()[7], "good", "{:?}", daemon.row());
    let line = format!("OCSP response stapled to the certificate for {NAME}");
    assert!(daemon.log().contains(&line), "{}", daemon.log());
    if let Some(text) = openssl_status(daemon.tls) {
        assert!(text.contains("OCSP Response Status: successful"), "{text}");
        assert!(text.contains("Cert Status: good"), "{text}");
    }

    // The responder is asked again at half of the window, with no restart. The next
    // answer lives long, so the restart below finds it in the storage.
    responder.validity.store(3600, Ordering::Relaxed);
    let before = asked(&responder);
    let (second, later) = wait_for("a refreshed response", 20, || {
        Some(daemon.good_staple(&authority)).filter(|(response, _)| *response != first)
    });
    assert!(asked(&responder) > before);
    assert!(later.next_update > answer.next_update + 1000, "{answer:?} {later:?}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    drop(daemon);

    // A restart staples the stored response and asks nobody.
    let before = asked(&responder);
    let daemon = start(&authority, &home, "");
    daemon.ready();
    let (restored, _) = daemon.good_staple(&authority);
    assert_eq!(restored, second);
    assert!(daemon.log().contains("loaded from storage"), "{}", daemon.log());
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(asked(&responder), before);
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
}

#[test]
fn a_revoked_certificate_gets_no_staple_and_is_renewed() {
    let authority = Authority::start();
    // A certificate of one minute may be renewed six seconds after it was obtained.
    authority.lifetime.store(60, Ordering::Relaxed);
    let responder = Responder::start(&authority);
    *responder.status.lock().unwrap() = Status::Revoked;
    let daemon = start(&authority, &home("revoked"), "");
    let line = format!("the certificate for {NAME} is revoked");
    wait_for("the revocation", 20, || daemon.log().contains(&line).then_some(()));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    let (old, response) = daemon.handshake();
    assert!(response.is_empty(), "a response is stapled to a revoked certificate");
    assert_eq!(daemon.row()[7], "revoked", "{:?}", daemon.row());

    // The next certificate is good. It is ordered after the floor, with no restart.
    *responder.status.lock().unwrap() = Status::Good;
    wait_for("the renewal", 30, || {
        (authority.order_count.load(Ordering::Relaxed) == 2).then_some(())
    });
    daemon.good_staple(&authority);
    let (new, _) = daemon.handshake();
    assert_ne!(old, new);
    assert!(daemon.log().contains(&format!("certificate for {NAME} renewed")), "{}", daemon.log());
    // The revocation did not put the daemon into a loop of orders.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 2);
}

#[test]
fn a_delegated_signer_is_accepted_and_a_silent_responder_staples_nothing() {
    let authority = Authority::start();
    let responder = Responder::start(&authority);
    responder.delegated.store(true, Ordering::Relaxed);
    let daemon = start(&authority, &home("delegate"), "");
    daemon.ready();
    daemon.good_staple(&authority);
    drop(daemon);

    // The responder answers 503: the certificate is served, without a response.
    responder.down.store(true, Ordering::Relaxed);
    let daemon = start(&authority, &home("silent"), "");
    daemon.ready();
    // The stderr reader publishes one line at a time. The hint completes the diagnostic.
    let log = wait_for("the OCSP diagnostic and its hint", 20, || {
        Some(daemon.log()).filter(|log| {
            log.split_once("NO OCSP RESPONSE (ACME013)")
                .is_some_and(|(_, body)| body.contains("\nHint: "))
        })
    });
    assert!(log.contains(&format!("No OCSP response for the certificate of `{NAME}`")), "{log}");
    assert!(log.contains("the responder answered 503"), "{log}");
    let (leaf, response) = daemon.handshake();
    assert!(!leaf.is_empty() && response.is_empty());
    assert_eq!(daemon.row()[5..8], ["ready", "listed", "-"], "{:?}", daemon.row());
}

#[test]
fn nobody_is_asked_without_a_responder_or_with_ocsp_off() {
    let authority = Authority::start();
    // The leaf names no responder.
    let daemon = start(&authority, &home("none"), "");
    daemon.ready();
    std::thread::sleep(Duration::from_secs(2));
    assert!(daemon.handshake().1.is_empty());
    assert!(!daemon.log().contains("OCSP"), "{}", daemon.log());
    drop(daemon);

    // The leaf names one, and the file turns stapling off.
    let responder = Responder::start(&authority);
    let daemon = start(&authority, &home("off"), r#","ocsp":false"#);
    daemon.ready();
    std::thread::sleep(Duration::from_secs(2));
    assert!(daemon.handshake().1.is_empty());
    assert_eq!(asked(&responder), 0);
    assert_eq!(daemon.row()[7], "-");
}

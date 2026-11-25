//! Issuance on demand (SID 0021) through the binary, against a certificate authority
//! and an `ask` server inside the test: the first handshake for a name that is not
//! listed obtains its certificate, and the guards stop every other name before an order.
//!
//! Every server listens on a loopback port. No name is resolved.
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
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use authority::{Authority, ISSUER, connect_trusting, peer_certificate};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// A number that no other file of this test binary has.
fn serial() -> usize {
    use std::sync::atomic::AtomicUsize as Counter;
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
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

/// The `ask` server of a test: it allows the names that start with `yes`, and records
/// every name it was asked for.
struct Ask {
    url: String,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Ask {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/allowed", listener.local_addr().unwrap());
        let asked = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        std::thread::spawn(move || {
            for mut socket in listener.incoming().flatten() {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let target = first.split(' ').nth(1).unwrap_or_default();
                let name = target.strip_prefix("/allowed?domain=").unwrap_or_default().to_owned();
                let status = if name.starts_with("yes") { "204 No Content" } else { "403 No" };
                record.lock().unwrap().push(name);
                let answer =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = socket.write_all(answer.as_bytes());
            }
        });
        Self { url, asked }
    }

    /// How often the server was asked for `name`.
    fn count(&self, name: &str) -> usize {
        self.asked.lock().unwrap().iter().filter(|asked| *asked == name).count()
    }
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

    /// The columns of the line of `show certs` for `name`, when it has one.
    fn row(&self, name: &str) -> Option<Vec<String>> {
        let table = self.ctl("show certs");
        let line = table.lines().find(|line| line.split_whitespace().next() == Some(name))?;
        Some(line.split_whitespace().map(str::to_owned).collect())
    }
}

/// A directory of one test alone.
fn home(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-demand-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// Starts the edge with a TLS frontend that obtains on demand and a plain frontend.
/// `acme` holds the members of `global.acme` beside the storage, each with a leading
/// comma. `tls` holds more members of the `tls` object, each with a leading comma.
fn start(authority: &Authority, home: &Path, acme: &str, tls: &str) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(authority, home, acme, tls) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(authority: &Authority, home: &Path, acme: &str, tls: &str) -> Result<Daemon, String> {
    let (bind, plain) = (free_address(), free_address());
    authority.tls_port.store(bind.port(), Ordering::Relaxed);
    authority.http_port.store(plain.port(), Ordering::Relaxed);
    let file = home.join(format!("edge-{}.json", serial()));
    let socket = home.join("admin.sock");
    let text = format!(
        r#"{{"global":{{"admin_socket":"{socket}","acme":{{"storage":"{storage}"{acme}}}}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{bind}"],
          "tls":{{"on_demand":true{tls}}},"default_backend":"app"}},
          "plain":{{"proto":"http","binds":["{plain}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = socket.display(),
        storage = home.join("acme").display(),
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

/// One handshake for `name`. Returns the leaf that the edge served, when it is a
/// certificate of the test authority for that name.
fn handshake(daemon: &Daemon, name: &str) -> Option<Vec<u8>> {
    let leaf = peer_certificate(daemon.tls, name, None)?;
    let fields = sibuna_acme::x509::read(&leaf)?;
    (fields.issuer == ISSUER && fields.names_host(name)).then_some(leaf)
}

/// The members of `global.acme` that name the test authority, HTTP-01 and the guards.
fn guarded(authority: &Authority, guards: &str) -> String {
    challenged(authority, "http-01", guards)
}

/// The members of `global.acme` that name the test authority, a challenge and the
/// guards.
fn challenged(authority: &Authority, challenge: &str, guards: &str) -> String {
    format!(
        r#","directory":"{}","challenge":"{challenge}","on_demand":{{{guards}}}"#,
        authority.directory
    )
}

#[test]
fn the_first_handshake_obtains_a_certificate_and_the_guards_refuse_other_names() {
    let authority = Authority::start();
    let ask = Ask::start();
    let home = home("first");
    let guards = format!(r#""ask":"{}","allow":["apps.example.test"],"wait":4"#, ask.url);
    let acme = guarded(&authority, &guards);
    let daemon = start(&authority, &home, &acme, "");
    assert!(daemon.log().contains("names on demand"), "{}", daemon.log());
    assert_eq!(daemon.ctl("show certs").lines().count(), 1);

    // The first handshake waits for the order and is served the new certificate.
    let name = "yes.apps.example.test";
    let first = handshake(&daemon, name).expect("the first handshake has the certificate");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    assert_eq!(ask.count(name), 1);
    let row = daemon.row(name).unwrap();
    assert_eq!(row[1..3], ["http-01", "Sibuna_Test_Authority"], "{row:?}");
    assert_eq!(row[5..], ["ready", "on-demand", "-"], "{row:?}");
    // The second handshake finds it. Nothing is asked again.
    assert_eq!(handshake(&daemon, name), Some(first.clone()));
    assert_eq!((authority.order_count.load(Ordering::Relaxed), ask.count(name)), (1, 1));

    // A name that `ask` refuses gets no order. The handshake ends at once with an
    // alert, because the frontend has no certificate from a file. The refusal is
    // remembered: a second handshake does not ask again.
    let refused = "no.apps.example.test";
    let begun = Instant::now();
    assert_eq!(peer_certificate(daemon.tls, refused, None), None);
    assert_eq!(peer_certificate(daemon.tls, refused, None), None);
    assert!(begun.elapsed() < Duration::from_secs(4), "{:?}", begun.elapsed());
    assert_eq!(ask.count(refused), 1);
    let log = daemon.log();
    assert!(log.contains(&format!("no certificate on demand for {refused}")), "{log}");
    assert!(log.contains("the ask URL did not allow it"), "{log}");

    // A name outside `allow`, a wildcard and an address are not even queued.
    for outside in ["yes.other.example.test", "yes-apps.example.test"] {
        assert_eq!(peer_certificate(daemon.tls, outside, None), None);
        assert_eq!(ask.count(outside), 0);
    }
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    assert_eq!(daemon.ctl("show certs").lines().count(), 2);

    // A restart finds the certificate in the storage: no order, and no question.
    drop(daemon);
    let daemon = start(&authority, &home, &acme, "");
    assert_eq!(handshake(&daemon, name), Some(first));
    assert_eq!((authority.order_count.load(Ordering::Relaxed), ask.count(name)), (1, 1));
    let log = daemon.log();
    assert!(log.contains(&format!("certificate for {name} loaded from storage")), "{log}");
}

#[test]
fn the_rate_stops_the_next_new_name() {
    let authority = Authority::start();
    let home = home("rate");
    let acme = guarded(&authority, r#""allow":["apps.example.test"],"rate":2,"wait":4"#);
    let daemon = start(&authority, &home, &acme, "");
    for name in ["one.apps.example.test", "two.apps.example.test"] {
        assert!(handshake(&daemon, name).is_some(), "{name}");
    }
    assert_eq!(peer_certificate(daemon.tls, "three.apps.example.test", None), None);
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 2);
    let log = wait_for("the refusal", 5, || {
        Some(daemon.log()).filter(|log| log.contains("three.apps.example.test"))
    });
    assert!(log.contains("the rate of new certificates is spent"), "{log}");
    // The name is denied until the next token, half an hour away: no order follows.
    assert_eq!(peer_certificate(daemon.tls, "three.apps.example.test", None), None);
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 2);
    assert!(daemon.row("three.apps.example.test").is_none());
}

#[test]
fn the_bound_on_held_names_stops_the_next_name_and_a_failed_order_frees_its_place() {
    let authority = Authority::start();
    let home = home("names");
    let acme = guarded(&authority, r#""allow":["apps.example.test"],"names":1,"wait":4"#);
    let daemon = start(&authority, &home, &acme, "");
    // An order that the authority refuses holds no place afterwards.
    authority.refuse.store(true, Ordering::Relaxed);
    assert_eq!(peer_certificate(daemon.tls, "bad.apps.example.test", None), None);
    let log = wait_for("the failure", 5, || {
        Some(daemon.log()).filter(|log| log.contains("No new certificate for `bad.apps"))
    });
    assert!(log.contains("ACME"), "{log}");
    assert!(daemon.row("bad.apps.example.test").is_none());
    authority.refuse.store(false, Ordering::Relaxed);
    // The failed name is denied for its retry delay. Another name takes the place.
    assert_eq!(peer_certificate(daemon.tls, "bad.apps.example.test", None), None);
    assert!(handshake(&daemon, "one.apps.example.test").is_some());
    let orders = authority.order_count.load(Ordering::Relaxed);
    // The table is full now.
    assert_eq!(peer_certificate(daemon.tls, "two.apps.example.test", None), None);
    assert_eq!(authority.order_count.load(Ordering::Relaxed), orders);
    assert_eq!(daemon.ctl("show certs").lines().count(), 2);
    assert!(handshake(&daemon, "one.apps.example.test").is_some());
}

#[test]
fn a_used_name_is_renewed_and_an_unused_one_is_released() {
    let authority = Authority::start();
    // A certificate of nine seconds is due after six.
    authority.lifetime.store(9, Ordering::Relaxed);
    let home = home("release");
    let acme = guarded(&authority, r#""allow":["apps.example.test"],"wait":4"#);
    let daemon = start(&authority, &home, &acme, "");
    let (used, unused) = ("used.apps.example.test", "unused.apps.example.test");
    let first = handshake(&daemon, used).expect("the certificate of the used name");
    assert!(handshake(&daemon, unused).is_some());
    authority.lifetime.store(3600, Ordering::Relaxed);
    // Only one of the two is named again after it has its certificate.
    assert_eq!(handshake(&daemon, used), Some(first.clone()));
    let renewed = wait_for("the renewal of the used name", 30, || {
        let row = daemon.row(used)?;
        (row[5] == "ready" && authority.order_count.load(Ordering::Relaxed) == 3).then_some(row)
    });
    assert_eq!(renewed[6], "on-demand", "{renewed:?}");
    wait_for("the release of the unused name", 10, || daemon.row(unused).is_none().then_some(()));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 3);
    let leaf = handshake(&daemon, used).expect("the renewed certificate");
    assert_ne!(leaf, first);
    // The released name is asked for again by its next handshake. Its stored
    // certificate has expired by then or is due, so the order is a new one.
    std::thread::sleep(Duration::from_secs(1));
    assert!(handshake(&daemon, unused).is_some());
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 4);
}

#[test]
fn a_name_on_demand_is_proved_with_tls_alpn_01_and_a_file_certificate_serves_meanwhile() {
    let authority = Authority::start();
    let home = home("alpn");
    let acme = challenged(&authority, "tls-alpn-01", r#""allow":["example.test"],"wait":4"#);
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/tls/tests/data");
    let tls = format!(
        r#","cert_file":"{}","key_file":"{}""#,
        data.join("localhost.pem").display(),
        data.join("localhost.key").display()
    );
    let daemon = start(&authority, &home, &acme, &tls);
    // A name that the guards refuse gets the certificate of the file, as any unknown
    // name on a frontend without `strict_sni`.
    let other = peer_certificate(daemon.tls, "www.example.org", None).expect("the default");
    assert!(sibuna_acme::x509::read(&other).is_some_and(|fields| fields.issuer != ISSUER));
    // The name of the file is served from the file and asks for nothing.
    assert_eq!(peer_certificate(daemon.tls, "localhost", None), Some(other));
    assert_eq!(daemon.ctl("show certs").lines().count(), 1);
    let name = "alpn.example.test";
    assert!(handshake(&daemon, name).is_some());
    assert_eq!(*authority.validated.lock().unwrap(), ["tls-alpn-01"]);
    assert_eq!(daemon.row(name).unwrap()[1], "tls-alpn-01");
}

#[test]
fn an_internal_name_on_demand_comes_from_the_local_authority() {
    let authority = Authority::start();
    let home = home("local");
    // No directory: the default is Let's Encrypt, which is never contacted, because
    // every admitted name is internal.
    let acme = r#","on_demand":{"allow":["localhost"],"wait":4}"#;
    let daemon = start(&authority, &home, acme, "");
    let name = "app.localhost";
    let leaf = peer_certificate(daemon.tls, name, None).expect("a certificate at once");
    let fields = sibuna_acme::x509::read(&leaf).unwrap();
    assert!(fields.names_host(name) && fields.issuer.contains("Sibuna Local Authority"));
    let text = daemon.ctl("show ca");
    let root: String =
        text.lines().filter(|line| !line.starts_with('#')).collect::<Vec<_>>().join("\n");
    let (mut session, mut socket) = connect_trusting(daemon.tls, name, &root).unwrap();
    let mut stream = rustls::Stream::new(&mut session, &mut socket);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: app.localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert!(answer.ends_with("ok"), "{answer}");
    let row = daemon.row(name).unwrap();
    assert_eq!((row[1].as_str(), row[6].as_str()), ("local", "on-demand"), "{row:?}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 0);
    assert!(!home.join("acme").join("acme-v02.api.letsencrypt.org-directory").exists());
}

#[test]
fn the_check_refuses_on_demand_without_a_guard() {
    let home = home("check");
    let check = |global: &str| {
        let file = home.join(format!("edge-{}.json", serial()));
        let text = format!(
            r#"{{{global}"frontends":{{"web":{{"binds":["127.0.0.1:8443"],
               "tls":{{"on_demand":true}}}}}},
               "backends":{{"app":{{"servers":["127.0.0.1:8080"]}}}}}}"#
        );
        fs::write(&file, text).unwrap();
        let output = Command::new(BIN).arg("check").arg("-f").arg(&file).output().unwrap();
        (output.status.success(), String::from_utf8_lossy(&output.stderr).into_owned())
    };
    for global in ["", r#""global":{"acme":{"on_demand":{"rate":3}}},"#] {
        let (ok, text) = check(global);
        assert!(!ok && text.contains("ON DEMAND NEEDS A GUARD"), "{text}");
        assert!(text.contains("Hint: ") && text.contains("on_demand: { allow:"), "{text}");
    }
    let (ok, text) = check(r#""global":{"acme":{"on_demand":{"allow":["example.org"]}}},"#);
    assert!(ok, "{text}");
}

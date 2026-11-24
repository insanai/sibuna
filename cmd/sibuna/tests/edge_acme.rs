//! Automatic HTTPS of the edge against a certificate authority inside the test
//! (SID 0021): the daemon obtains, serves, renews and keeps certificates, with no
//! restart and no reload in between.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/acme_authority.rs"]
mod authority;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use authority::{Authority, ISSUER, peer_certificate};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const SITE: &str = "site.example.test";

/// A server that answers every request with `ok` and closes.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let _ = socket.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    address
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// What a test chooses about the topology.
struct Setup<'a> {
    authority: &'a Authority,
    origin: SocketAddr,
    /// The directory of the storage, the file, the socket and the log.
    home: &'a Path,
    /// The `auto` names.
    names: &'a [&'a str],
    /// The plain HTTP frontend, when the file has one: more members of it, each with a
    /// trailing comma.
    plain: Option<&'a str>,
    /// More members of `global.acme`, each with a leading comma.
    acme: &'a str,
}

/// A running edge. Dropping it stops the process.
struct Daemon {
    child: Child,
    tls: SocketAddr,
    plain: SocketAddr,
    file: PathBuf,
    socket: PathBuf,
    /// Everything the daemon wrote to standard error.
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

    /// Runs an admin command that must succeed and returns its output.
    fn ctl(&self, command: &str) -> String {
        let output = Command::new(BIN)
            .arg("ctl")
            .arg(&self.socket)
            .args(command.split(' '))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "`{command}`: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        text
    }

    /// The columns of the line of `show certs` for `name`.
    fn row(&self, name: &str) -> Vec<String> {
        let table = self.ctl("show certs");
        let line = table.lines().find(|line| line.split_whitespace().next() == Some(name));
        let line = line.unwrap_or_else(|| panic!("no certificate {name} in\n{table}"));
        line.split_whitespace().map(str::to_owned).collect()
    }
}

/// The topology as a file: a TLS frontend with `auto` names, and a plain one on demand.
fn topology(setup: &Setup<'_>, tls: SocketAddr, plain: SocketAddr, socket: &Path) -> String {
    let names: Vec<String> = setup.names.iter().map(|name| format!("\"{name}\"")).collect();
    let plain_frontend = match setup.plain {
        Some(members) => {
            let rest = format!(r#"{members}"default_backend":"app""#);
            format!(r#","plain":{{"proto":"http","binds":["{plain}"],{rest}}}"#)
        }
        None => String::new(),
    };
    format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{"directory":"{directory}","storage":"{storage}"{acme}}}}},
        "http":{{"surface":"off"}},
        "observability":{{"access_log":{{"output":"{log}"}}}},
        "frontends":{{"web":{{"proto":"http","binds":["{tls}"],
          "tls":{{"auto":[{names}]}},"default_backend":"app"}}{plain_frontend}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = socket.display(),
        directory = setup.authority.directory,
        storage = setup.home.join("acme").display(),
        acme = setup.acme,
        log = setup.home.join("access.log").display(),
        names = names.join(","),
        origin = setup.origin,
    )
}

/// Starts the edge. A port that was free a moment ago may be taken by a test that runs
/// beside this one. The listeners are then chosen again.
fn start(setup: &Setup<'_>) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(setup) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(setup: &Setup<'_>) -> Result<Daemon, String> {
    let (tls, plain) = (free_address(), free_address());
    setup.authority.tls_port.store(tls.port(), Ordering::Relaxed);
    setup.authority.http_port.store(plain.port(), Ordering::Relaxed);
    let file = setup.home.join("edge.json");
    let socket = setup.home.join("admin.sock");
    fs::write(&file, topology(setup, tls, plain, &socket)).unwrap();
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
    Ok(Daemon { child, tls, plain, file, socket, log })
}

/// A directory of this test alone.
fn home(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-acme-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
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

/// The certificate the edge serves for `name`, once the test authority issued it.
fn issued(daemon: &Daemon, name: &str) -> Option<Vec<u8>> {
    let leaf = peer_certificate(daemon.tls, name, None)?;
    let fields = sibuna_acme::x509::read(&leaf)?;
    (fields.issuer == ISSUER && fields.names_host(name)).then_some(leaf)
}

/// One plain HTTP request. Returns the whole answer.
fn get(address: SocketAddr, host: &str, target: &str) -> String {
    let mut socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = socket.read_to_string(&mut answer);
    answer
}

/// One request inside TLS. Returns the whole answer.
fn get_secure(address: SocketAddr, host: &str) -> String {
    let (mut session, mut socket) = authority::connect(address, host, None).unwrap();
    let mut stream = rustls::Stream::new(&mut session, &mut socket);
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}

/// Every file below `directory`.
fn files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_certificate_is_obtained_served_renewed_and_kept_through_a_failure() {
    let authority = Authority::start();
    // The first certificate is due after eight of its twelve seconds.
    authority.lifetime.store(12, Ordering::Relaxed);
    let home = home("http01");
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[SITE],
        plain: Some(""),
        acme: r#","challenge":"http-01""#,
    };
    let daemon = start(&setup);
    let first = wait_for("the first certificate", 30, || issued(&daemon, SITE));
    authority.lifetime.store(3600, Ordering::Relaxed);
    assert_eq!(*authority.validated.lock().unwrap(), ["http-01"]);
    assert!(get_secure(daemon.tls, SITE).ends_with("ok"));

    // Plain HTTP for the managed name goes to HTTPS. Another host is served as before.
    let moved = get(daemon.plain, SITE, "/some/path?x=1");
    assert!(moved.starts_with("HTTP/1.1 308 "), "{moved}");
    let location = format!("Location: https://{SITE}:{}/some/path?x=1\r\n", daemon.tls.port());
    assert!(moved.contains(&location), "{moved}");
    assert!(get(daemon.plain, "other.example.test", "/").ends_with("ok"));
    // A token of no order is answered for the managed name, as another node would need.
    let foreign = get(daemon.plain, SITE, "/.well-known/acme-challenge/abc_DEF-1");
    assert!(foreign.starts_with("HTTP/1.1 200 ") && foreign.contains("\r\n\r\nabc_DEF-1."));

    // The renewal arrives with no restart and no reload.
    let second = wait_for("the renewal", 40, || issued(&daemon, SITE).filter(|c| *c != first));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 2);
    let log = wait_for("the log line", 5, || Some(daemon.log()).filter(|l| l.contains("renewed")));
    assert!(log.contains(&format!("certificate for {SITE} obtained")), "{log}");
    let row =
        wait_for("the ready state", 10, || Some(daemon.row(SITE)).filter(|row| row[4] == "ready"));
    assert_eq!((row[1].as_str(), row[5].as_str()), ("Sibuna_Test_Authority", "-"), "{row:?}");
    let stats = daemon.ctl("show stats");
    assert!(stats.contains("sibuna_edge_acme_certificates_managed 1\n"), "{stats}");
    assert!(stats.contains("sibuna_edge_acme_certificates_served 1\n"), "{stats}");
    assert!(stats.contains("sibuna_edge_acme_nearest_expiry_seconds "), "{stats}");

    // Keys are private, and the answers of automatic HTTPS are in the access log.
    let mut stored = Vec::new();
    files(&home.join("acme"), &mut stored);
    let keys: Vec<_> =
        stored.iter().filter(|path| path.to_string_lossy().ends_with("key.pem")).collect();
    assert!(!keys.is_empty() && keys.iter().all(|path| mode(path) == 0o600), "{stored:?}");
    assert!(stored.iter().any(|path| path.ends_with("account.key") && mode(path) == 0o600));
    assert_eq!(mode(&home.join("acme")), 0o700);
    let access = wait_for("the access log", 10, || {
        let text = fs::read_to_string(home.join("access.log")).unwrap_or_default();
        (text.contains("\"status\":308") && text.contains("/.well-known/acme-challenge/"))
            .then_some(text)
    });
    assert!(access.contains("/some/path"), "{access}");

    // A reload adds a name that the authority refuses. The failure is reported with a
    // hint, the listener stays, and the first name keeps its certificate.
    authority.refuse.store(true, Ordering::Relaxed);
    let grown = Setup { names: &[SITE, "refused.example.test"], ..setup };
    fs::write(&daemon.file, topology(&grown, daemon.tls, daemon.plain, &daemon.socket)).unwrap();
    daemon.ctl("reload");
    let row = wait_for("the failure", 30, || {
        Some(daemon.row("refused.example.test")).filter(|row| row[4] == "retry")
    });
    assert!(row[5..].join(" ").contains("ACME"), "{row:?}");
    let log = daemon.log();
    assert!(log.contains("Hint: ") && log.contains("refused.example.test"), "{log}");
    assert_eq!(issued(&daemon, SITE), Some(second));
    // The refused name has no certificate of its own.
    assert_eq!(issued(&daemon, "refused.example.test"), None);
    assert!(daemon.ctl("show stats").contains("sibuna_edge_acme_failures_total 1\n"));
}

#[test]
fn tls_alpn_01_needs_no_plain_frontend_and_a_restart_reuses_the_certificate() {
    let authority = Authority::start();
    let home = home("alpn01");
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[SITE],
        plain: None,
        acme: "",
    };
    let daemon = start(&setup);
    let first = wait_for("the certificate", 30, || issued(&daemon, SITE));
    assert_eq!(*authority.validated.lock().unwrap(), ["tls-alpn-01"]);
    assert!(get_secure(daemon.tls, SITE).ends_with("ok"));
    // Outside an order nobody gets a challenge certificate.
    assert!(peer_certificate(daemon.tls, SITE, Some(b"acme-tls/1")).is_none());
    drop(daemon);

    let daemon = start(&setup);
    let again = wait_for("the stored certificate", 30, || issued(&daemon, SITE));
    assert_eq!(again, first);
    let log = wait_for("the log line", 5, || {
        Some(daemon.log()).filter(|log| log.contains("loaded from storage"))
    });
    assert!(!log.contains("obtained"), "{log}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
}

#[test]
fn the_redirect_of_the_traffic_policy_and_the_automatic_one_compose() {
    let authority = Authority::start();
    let home = home("redirects");
    // The plain frontend redirects everything with 301 (SID 0019), except two prefixes.
    let members = r#""redirect_https":301,
        "routes":[{"path_prefix":"/keep","backend":"app","redirect_https":false},
                  {"path_prefix":"/auto","backend":"app","max_body":"1m"}],"#;
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[SITE],
        plain: Some(members),
        acme: r#","challenge":"http-01""#,
    };
    let daemon = start(&setup);
    // The authority validates over the frontend that redirects: the challenge is
    // answered before the redirect of the traffic policy.
    wait_for("the certificate", 30, || issued(&daemon, SITE));
    assert_eq!(*authority.validated.lock().unwrap(), ["http-01"]);
    let foreign = get(daemon.plain, SITE, "/.well-known/acme-challenge/abc");
    assert!(foreign.starts_with("HTTP/1.1 200 "), "{foreign}");

    // A stated redirect answers once, with its own status and port.
    let stated = get(daemon.plain, SITE, "/x?y=1");
    assert!(stated.starts_with("HTTP/1.1 301 "), "{stated}");
    assert!(stated.contains(&format!("Location: https://{SITE}/x?y=1\r\n")), "{stated}");
    assert_eq!(stated.matches("Location:").count(), 1);
    // `redirect_https: false` is the operator's choice: the request stays on HTTP.
    assert!(get(daemon.plain, SITE, "/keep/it").ends_with("ok"));
    // A route that states nothing about the redirect inherits the one of its frontend.
    assert!(get(daemon.plain, SITE, "/auto/x").starts_with("HTTP/1.1 301 "));
    // Another host has the stated redirect only.
    assert!(get(daemon.plain, "other.example.test", "/").starts_with("HTTP/1.1 301 "));
}

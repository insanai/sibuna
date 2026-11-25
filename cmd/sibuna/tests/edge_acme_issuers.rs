//! Several authorities, the external account binding and renewal information
//! (SID 0021) through the binary, against certificate authorities inside the test.
//!
//! Every server listens on a loopback port. No name is resolved.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/acme_authority.rs"]
#[allow(dead_code)]
mod authority;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use authority::{Authority, ISSUER, peer_certificate};
use sibuna_acme::store::authority_id;
use sibuna_acme::{ari, x509};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const NAME: &str = "one.example.org";

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

    /// The columns of the line of `show certs` for `name`.
    fn row(&self, name: &str) -> Vec<String> {
        let output = Command::new(BIN)
            .arg("ctl")
            .arg(&self.socket)
            .args(["show", "certs"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let table = String::from_utf8_lossy(&output.stdout).into_owned();
        let line = table.lines().find(|line| line.split_whitespace().next() == Some(name));
        line.unwrap_or_default().split_whitespace().map(str::to_owned).collect()
    }

    /// Waits until the name is `ready` and returns its line.
    fn ready(&self, name: &str) -> Vec<String> {
        wait_for("a served certificate", 20, || {
            Some(self.row(name)).filter(|row| row.get(5).map(String::as_str) == Some("ready"))
        })
    }

    /// The leaf that the edge serves for `name`, a certificate of a test authority.
    fn leaf(&self, name: &str) -> x509::Certificate {
        let leaf = peer_certificate(self.tls, name, None).unwrap();
        let fields = x509::read(&leaf).unwrap();
        assert!(fields.issuer == ISSUER && fields.names_host(name), "{fields:?}");
        fields
    }
}

/// A directory of one test alone.
fn home(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-issuers-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// Starts the edge with a TLS frontend for [`NAME`] and a plain frontend. `acme` holds
/// the members of `global.acme` beside the storage and the challenge, each with a
/// leading comma. Every authority of `authorities` validates at the new frontends.
fn start(authorities: &[&Authority], home: &Path, acme: &str) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(authorities, home, acme) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(authorities: &[&Authority], home: &Path, acme: &str) -> Result<Daemon, String> {
    let (bind, plain) = (free_address(), free_address());
    for authority in authorities {
        authority.tls_port.store(bind.port(), Ordering::Relaxed);
        authority.http_port.store(plain.port(), Ordering::Relaxed);
    }
    let file = home.join(format!("edge-{}.json", serial()));
    let socket = home.join("admin.sock");
    let text = format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{"storage":"{storage}","challenge":"http-01"{acme}}}}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{bind}"],
          "tls":{{"auto":["{NAME}"]}},"default_backend":"app"}},
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

fn orders(authority: &Authority) -> usize {
    authority.order_count.load(Ordering::Relaxed)
}

/// The members of `global.acme` that name `first` and then `others` as the fallback.
fn listed(first: &str, others: &[&str]) -> String {
    let fallback: Vec<String> =
        others.iter().map(|directory| format!(r#"{{"directory":"{directory}"}}"#)).collect();
    format!(r#","directory":"{first}","fallback":[{}]"#, fallback.join(","))
}

/// Whether the store of `directory` under `home` holds a certificate for [`NAME`].
fn stored(home: &Path, directory: &str) -> bool {
    home.join("acme").join(authority_id(directory)).join("certs").join(NAME).is_dir()
}

#[test]
fn the_next_authority_issues_when_the_first_fails_and_rests_when_it_works() {
    let (first, second) = (Authority::start(), Authority::start());
    let acme = listed(&first.directory, &[&second.directory]);

    // The first authority works: the second one is never asked.
    let working = home("working");
    let daemon = start(&[&first, &second], &working, &acme);
    daemon.ready(NAME);
    assert_eq!((orders(&first), orders(&second)), (1, 0));
    assert_eq!(second.signed_count.load(Ordering::Relaxed), 0);
    let line = format!("for 1 name(s) from {} (then 1 more)", first.directory);
    assert!(daemon.log().contains(&line), "{}", daemon.log());
    assert!(stored(&working, &first.directory) && !stored(&working, &second.directory));
    assert!(!daemon.log().contains("No certificate for"), "{}", daemon.log());
    drop(daemon);

    // The first authority refuses the order: the second one issues in the same attempt.
    first.refuse.store(true, Ordering::Relaxed);
    let refused = home("refused");
    let daemon = start(&[&first, &second], &refused, &acme);
    let row = daemon.ready(NAME);
    assert_eq!(row[7], "-", "{row:?}");
    assert_eq!((orders(&first), orders(&second)), (1, 1));
    assert!(!stored(&refused, &first.directory) && stored(&refused, &second.directory));
    let log = daemon.log();
    let line = format!("No certificate for `{NAME}` from {}.", first.directory);
    assert!(log.contains(&line), "{log}");
    assert!(log.contains("the test refuses this name"), "{log}");
    assert!(log.contains(&format!("The daemon asks {} now.", second.directory)), "{log}");
    assert!(!log.contains("No new certificate"), "{log}");
    daemon.leaf(NAME);
    // A restart serves the certificate of the second authority from its store.
    drop(daemon);
    let daemon = start(&[&first, &second], &refused, &acme);
    daemon.ready(NAME);
    assert!(daemon.log().contains("loaded from storage"), "{}", daemon.log());
    assert_eq!((orders(&first), orders(&second)), (1, 1));
    drop(daemon);

    // Every authority fails: the attempt fails once, with the failure of the last one.
    second.refuse.store(true, Ordering::Relaxed);
    let failing = home("failing");
    let daemon = start(&[&first, &second], &failing, &acme);
    let log = wait_for("the failure", 20, || {
        Some(daemon.log()).filter(|log| log.contains("No new certificate"))
    });
    assert!(log.contains(&line), "{log}");
    assert_eq!(daemon.row(NAME)[5], "retry");
    assert_eq!((orders(&first), orders(&second)), (1, 1));
}

#[test]
fn an_authority_that_does_not_answer_is_followed_by_the_next() {
    let second = Authority::start();
    // A loopback port that nobody listens on.
    let silent = format!("http://{}/dir", free_address());
    let home = home("silent");
    let daemon = start(&[&second], &home, &listed(&silent, &[&second.directory]));
    daemon.ready(NAME);
    assert_eq!(orders(&second), 1);
    let log = daemon.log();
    assert!(log.contains(&format!("No certificate for `{NAME}` from {silent}.")), "{log}");
    assert!(log.contains("AUTHORITY UNREACHABLE") || log.contains("ACME002"), "{log}");
}

#[test]
fn an_account_is_bound_with_the_key_of_the_authority() {
    let authority = Authority::start();
    let key = b"the MAC key of the test authority".to_vec();
    *authority.binding.lock().unwrap() = Some(("kid-7".to_owned(), key.clone()));
    let member = |file: &Path| {
        let eab = format!(r#""eab":{{"kid":"kid-7","key_file":"{}"}}"#, file.display());
        format!(r#","directory":"{}",{eab}"#, authority.directory)
    };

    // No binding in the file: the daemon stops before it signs a request.
    let missing = home("unbound");
    let unbound = format!(r#","directory":"{}""#, authority.directory);
    let daemon = start(&[&authority], &missing, &unbound);
    let log =
        wait_for("the refusal", 20, || Some(daemon.log()).filter(|log| log.contains("ACME012")));
    assert!(log.contains("ACCOUNT NOT BOUND (ACME012)"), "{log}");
    assert!(log.contains("registers an account only with an external account binding"), "{log}");
    assert!(log.contains("Hint: Set `eab: { kid, key_file }`"), "{log}");
    assert_eq!(authority.signed_count.load(Ordering::Relaxed), 0);
    drop(daemon);

    // Another key: the authority refuses the registration, and no order is placed.
    let wrong = home("wrong-key");
    let file = wrong.join("eab.key");
    fs::write(&file, sibuna_acme::jws::base64url(b"another key")).unwrap();
    let daemon = start(&[&authority], &wrong, &member(&file));
    let log =
        wait_for("the refusal", 20, || Some(daemon.log()).filter(|log| log.contains("ACME012")));
    assert!(log.contains("the binding does not verify"), "{log}");
    assert_eq!(orders(&authority), 0);
    assert!(!log.contains("another key") && !log.contains("YW5vdGhlciBrZXk"), "{log}");
    drop(daemon);

    // A file that holds no key is reported with its path.
    let empty = home("no-key");
    let file = empty.join("eab.key");
    fs::write(&file, "not base64!\n").unwrap();
    let daemon = start(&[&authority], &empty, &member(&file));
    let log = wait_for("the failure", 20, || {
        Some(daemon.log()).filter(|log| log.contains("holds no key"))
    });
    assert!(log.contains(&file.display().to_string()), "{log}");
    drop(daemon);

    // The key of the authority, with a line end as an editor leaves it.
    let bound = home("bound");
    let file = bound.join("eab.key");
    fs::write(&file, sibuna_acme::jws::base64url(&key) + "\n").unwrap();
    let daemon = start(&[&authority], &bound, &member(&file));
    daemon.ready(NAME);
    assert_eq!(orders(&authority), 1);
}

#[test]
fn the_authority_moves_the_renewal_and_learns_which_certificate_is_replaced() {
    let authority = Authority::start();
    authority.renewal_info.store(true, Ordering::Relaxed);
    // A certificate of a minute is due after 40 seconds by the rule of two thirds.
    authority.lifetime.store(60, Ordering::Relaxed);
    // The first answer asks for a renewal in the past, every later one for a day ahead.
    let past_then_far = || [(-20, -10), (86_400, 90_000)].into_iter().collect();
    *authority.windows.lock().unwrap() = past_then_far();
    let home = home("ari");
    let acme = format!(r#","directory":"{}""#, authority.directory);
    let daemon = start(&[&authority], &home, &acme);
    daemon.ready(NAME);
    let begun = Instant::now();
    let first = ari::certificate_id(&daemon.leaf(NAME)).unwrap();

    // The certificate was just obtained, so the renewal waits for the floor, a tenth of
    // the lifetime, and then names the certificate that it replaces.
    wait_for("the early renewal", 25, || (orders(&authority) == 2).then_some(()));
    let elapsed = begun.elapsed();
    assert!(elapsed >= Duration::from_secs(3), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(25), "{elapsed:?}");
    wait_for("the new certificate", 10, || {
        (ari::certificate_id(&daemon.leaf(NAME)).unwrap() != first).then_some(())
    });
    assert_eq!(*authority.replaces.lock().unwrap(), [String::new(), first.clone()]);
    assert_eq!(authority.asked_renewal.lock().unwrap()[0], first);
    let second = ari::certificate_id(&daemon.leaf(NAME)).unwrap();
    assert!(daemon.log().contains(&format!("certificate for {NAME} renewed")));

    // The second answer lies a day ahead: the renewal is capped at four fifths of the
    // lifetime, 48 seconds, and nothing is ordered meanwhile.
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(orders(&authority), 2);
    assert!(authority.asked_renewal.lock().unwrap().contains(&second));
    drop(daemon);

    // A restart loads the certificate. The authority now asks for a renewal in the
    // past, and a loaded certificate has no floor: it is renewed at once.
    *authority.windows.lock().unwrap() = past_then_far();
    let daemon = start(&[&authority], &home, &acme);
    let begun = Instant::now();
    wait_for("the renewal after the restart", 10, || (orders(&authority) == 3).then_some(()));
    assert!(begun.elapsed() < Duration::from_secs(6), "{:?}", begun.elapsed());
    assert_eq!(authority.replaces.lock().unwrap()[2], second);
    assert!(daemon.log().contains("loaded from storage"), "{}", daemon.log());
}

#[test]
fn without_ari_the_authority_is_not_asked() {
    let authority = Authority::start();
    authority.renewal_info.store(true, Ordering::Relaxed);
    *authority.windows.lock().unwrap() = [(-20, -10)].into_iter().collect();
    let home = home("no-ari");
    let acme = format!(r#","directory":"{}","ari":false"#, authority.directory);
    let daemon = start(&[&authority], &home, &acme);
    daemon.ready(NAME);
    std::thread::sleep(Duration::from_secs(3));
    assert!(authority.asked_renewal.lock().unwrap().is_empty());
    assert_eq!(orders(&authority), 1);
    assert_eq!(*authority.replaces.lock().unwrap(), [String::new()]);
}

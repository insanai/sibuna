//! The Cloudflare provider of DNS-01 and the delegation of a challenge to another zone
//! (SID 0021) through the binary, against a certificate authority, a DNS server and an
//! API inside the test.
//!
//! Every server listens on a loopback port. The resolver of each topology is the DNS
//! server of the test: no name is asked of the system, and no request goes to
//! Cloudflare. The hook is a shell script that the test writes into its own directory.
//! It is test data, not a tool of the repository.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/cloudflare_api.rs"]
mod api;
#[path = "support/acme_authority.rs"]
#[allow(dead_code)]
mod authority;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api::Api;
use authority::{Authority, ISSUER, peer_certificate};
use sibuna_acme::dns::server::{Entry, Server};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const TOKEN: &str = "cf-test-token-Zm9vYmFyMDEyMzQ1Njc4OQ";

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

    /// Waits until `name` is in `retry` and returns its error column.
    fn failure(&self, name: &str) -> String {
        let row = wait_for("the failure", 60, || {
            Some(self.row(name)).filter(|row| row.get(5).map(String::as_str) == Some("retry"))
        });
        row[8..].join(" ")
    }

    /// Waits until the edge serves a certificate of the test authority for `host` and
    /// returns its names.
    fn served(&self, host: &str) -> Vec<String> {
        wait_for("the certificate", 60, || {
            let fields = sibuna_acme::x509::read(&peer_certificate(self.tls, host, None)?)?;
            (fields.issuer == ISSUER).then_some(fields.names)
        })
    }
}

/// A directory of one test alone.
fn home(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-cf-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// The topology: a TLS frontend with the `auto` name `name`, the test authority, and
/// the members `dns` of `global.acme.dns`.
fn topology(
    authority: &Authority,
    home: &Path,
    name: &str,
    dns: &str,
    bind: SocketAddr,
) -> String {
    format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{"storage":"{storage}","challenge":"dns-01","ari":false,"ocsp":false,
            "directory":"{directory}","dns":{{{dns}}}}}}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{bind}"],
          "tls":{{"auto":["{name}"]}},"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = home.join("admin.sock").display(),
        storage = home.join("acme").display(),
        directory = authority.directory,
        origin = origin(),
    )
}

/// Starts the edge. A port that was free a moment ago may be taken by a test that runs
/// beside this one. The listener is then chosen again.
fn start(authority: &Authority, home: &Path, name: &str, dns: &str) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(authority, home, name, dns) {
            Ok(daemon) => return daemon,
            Err(text) => failure = text,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(authority: &Authority, home: &Path, name: &str, dns: &str) -> Result<Daemon, String> {
    let bind = free_address();
    authority.tls_port.store(bind.port(), Ordering::Relaxed);
    let file = home.join(format!("edge-{}.json", serial()));
    fs::write(&file, topology(authority, home, name, dns, bind)).unwrap();
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
    Ok(Daemon { child, tls: bind, socket: home.join("admin.sock"), log })
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

/// The test authority and the DNS server that it asks. The server is also the resolver
/// of every topology.
fn world() -> (Arc<Authority>, Server) {
    let authority = Authority::start();
    let dns = Server::start_local().unwrap();
    *authority.dns_server.lock().unwrap() = Some(dns.address);
    (authority, dns)
}

/// The members of `global.acme.dns` after the provider: the resolver and the servers.
fn asking(dns: &Server, timeout: u64) -> String {
    format!(
        r#""resolver":"{address}","servers":["{address}"],"timeout":{timeout}"#,
        address = dns.address
    )
}

#[test]
fn a_wildcard_is_proved_through_the_cloudflare_provider_and_the_record_is_removed() {
    let (authority, dns) = world();
    let api = Api::start(TOKEN, &[("example.test", "zone0001")], Arc::clone(&dns.table));
    let home = home("wildcard");
    let token_file = home.join("cf.token");
    fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
    let members = format!(
        r#""cloudflare":{{"token_file":"{}","api":"{}"}},{}"#,
        token_file.display(),
        api.url,
        asking(&dns, 20)
    );
    let wildcard = "*.cf.example.test";
    let daemon = start(&authority, &home, wildcard, &members);
    assert_eq!(daemon.served("a.cf.example.test"), [wildcard]);
    assert_eq!(*authority.validated.lock().unwrap(), ["dns-01"]);
    // The zone was searched from the owner upwards, the record was created in it, and
    // the cleanup found the zone again, listed the record and deleted it.
    let owner = "_acme-challenge.cf.example.test";
    let calls = wait_for("the cleanup", 10, || {
        Some(api.calls.lock().unwrap().clone()).filter(|calls| calls.len() == 9)
    });
    let search = [
        format!("GET /client/v4/zones?name={owner}"),
        "GET /client/v4/zones?name=cf.example.test".to_owned(),
        "GET /client/v4/zones?name=example.test".to_owned(),
    ];
    assert_eq!(calls[..3], search, "{calls:?}");
    assert_eq!(calls[3], "POST /client/v4/zones/zone0001/dns_records");
    assert_eq!(calls[4..7], search, "{calls:?}");
    assert_eq!(
        calls[7],
        format!("GET /client/v4/zones/zone0001/dns_records?type=TXT&name={owner}")
    );
    assert_eq!(calls[8], "DELETE /client/v4/zones/zone0001/dns_records/rec0001");
    assert!(api.records().is_empty());
    assert!(dns.with(|table| table.texts(owner)).is_empty());
    assert_eq!(*api.denied.lock().unwrap(), 0);
    let row = daemon.row(wildcard);
    assert_eq!(row[1..3], ["dns-01", "Sibuna_Test_Authority"], "{row:?}");
    // The token is in no line of the log.
    assert!(!daemon.log().contains(TOKEN));
}

#[test]
fn a_named_zone_is_asked_alone_and_a_wrong_token_is_reported_without_the_token() {
    let (authority, dns) = world();
    let api = Api::start(TOKEN, &[("example.test", "zone0001")], Arc::clone(&dns.table));
    let home = home("token");
    let token_file = home.join("cf.token");
    let wrong = "another-token-QUJDREVGR0hJSktMTU5PUA";
    fs::write(&token_file, wrong).unwrap();
    let members = format!(
        r#""cloudflare":{{"token_file":"{}","zone":"example.test","api":"{}"}},{}"#,
        token_file.display(),
        api.url,
        asking(&dns, 20)
    );
    let wildcard = "*.denied.example.test";
    let daemon = start(&authority, &home, wildcard, &members);
    assert_eq!(daemon.failure(wildcard), "DNS PROVIDER FAILED (ACME009)");
    let log = wait_for("the diagnostic", 10, || {
        Some(daemon.log()).filter(|log| log.contains("DNS PROVIDER FAILED"))
    });
    assert!(log.contains("Cloudflare did not find the zone"), "{log}");
    assert!(log.contains("answered 403 with Authentication error (10000)"), "{log}");
    assert!(log.contains("Hint: Check the token in `global.acme.dns.cloudflare.token_file`"));
    // Neither the token of the file nor the one of the API is in a line of the log.
    assert!(!log.contains(wrong) && !log.contains(TOKEN), "{log}");
    assert!(*api.denied.lock().unwrap() >= 1);
    // With `zone`, only that zone is asked about.
    let calls = api.calls.lock().unwrap().clone();
    assert!(
        calls.iter().all(|call| call == "GET /client/v4/zones?name=example.test"),
        "{calls:?}"
    );
    assert!(api.records().is_empty());
    assert!(authority.validated.lock().unwrap().is_empty());
}

/// Writes an executable script into `home` and returns its path.
fn script(home: &Path, name: &str, body: &str) -> PathBuf {
    let path = home.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn a_delegated_challenge_is_written_at_its_target_by_the_hook_and_by_the_update() {
    let (authority, dns) = world();
    // The challenges of two names are delegated into the zone `example.net`.
    let (hooked, updated) = ("www.deleg.example.test", "api.deleg.example.test");
    let (hook_target, update_target) =
        ("www.validation.example.net", "api.validation.example.net");
    dns.with(|table| {
        table.add("example.net", Entry::Soa);
        table.add(&format!("_acme-challenge.{hooked}"), Entry::Cname(hook_target.to_owned()));
        table.add(&format!("_acme-challenge.{updated}"), Entry::Cname(update_target.to_owned()));
    });

    // The hook keeps the records in a file that the DNS server of the test reads.
    let home_one = home("deleg-hook");
    let (records, log) = (home_one.join("records"), home_one.join("hook.log"));
    dns.with(|table| table.txt_file = Some(records.clone()));
    let body = format!(
        "echo \"$1 $2 $SIBUNA_ACME_CHALLENGE $SIBUNA_ACME_NAME\" >> {log}\ncase \"$1\" in\n  \
         present) echo \"$2 $3\" >> {records} ;;\n  \
         cleanup) grep -v -F \"$2 $3\" {records} > {records}.new; mv {records}.new {records} ;;\n\
         esac",
        log = log.display(),
        records = records.display()
    );
    let hook = script(&home_one, "dns-hook", &body);
    let members = format!(r#""hook":"{}",{}"#, hook.display(), asking(&dns, 20));
    let daemon = start(&authority, &home_one, hooked, &members);
    assert_eq!(daemon.served(hooked), [hooked]);
    assert_eq!(*authority.validated.lock().unwrap(), ["dns-01"]);
    let lines = wait_for("the cleanup", 10, || {
        Some(fs::read_to_string(&log).unwrap_or_default()).filter(|text| text.lines().count() == 2)
    });
    // The record is the target. The owner that the authority asks is in the environment.
    let rest = format!("{hook_target}. _acme-challenge.{hooked}. {hooked}");
    assert_eq!(lines, format!("present {rest}\ncleanup {rest}\n"));
    assert_eq!(fs::read_to_string(&records).unwrap(), "");
    drop(daemon);

    // The dynamic update finds the zone of the target and writes there.
    let home_two = home("deleg-update");
    let members = format!(r#""rfc2136":{{"server":"{}"}},{}"#, dns.address, asking(&dns, 20));
    let daemon = start(&authority, &home_two, updated, &members);
    assert_eq!(daemon.served(updated), [updated]);
    let updates = wait_for("the cleanup", 10, || {
        Some(dns.with(|table| table.updates.clone())).filter(|updates| updates.len() == 2)
    });
    assert_eq!((updates[0].0.as_str(), updates[0].2), (update_target, false));
    assert_eq!((updates[1].0.as_str(), updates[1].2), (update_target, true));
    assert!(dns.with(|table| table.texts(update_target)).is_empty());
    drop(daemon);

    // With `follow_cname: false` the hook gets the first owner. The server follows the
    // alias when the authority asks, and finds nothing at the target: no certificate.
    let home_three = home("deleg-off");
    let log = home_three.join("hook.log");
    let hook = script(&home_three, "dns-hook", &format!("echo \"$1 $2\" >> {}", log.display()));
    let members = format!(r#""hook":"{}","follow_cname":false,"check":false,"#, hook.display())
        + &asking(&dns, 5);
    let daemon = start(&authority, &home_three, hooked, &members);
    assert!(daemon.failure(hooked).contains("ACME"));
    let text = fs::read_to_string(&log).unwrap();
    assert!(text.starts_with(&format!("present _acme-challenge.{hooked}.\n")), "{text}");
}

#[test]
fn a_resolver_that_does_not_answer_fails_the_attempt_before_the_provider_runs() {
    let (authority, dns) = world();
    let home = home("silent");
    let log = home.join("hook.log");
    let hook = script(&home, "dns-hook", &format!("echo \"$1 $2\" >> {}", log.display()));
    // Nobody listens on the port of the resolver.
    let members = format!(
        r#""hook":"{}","resolver":"127.0.0.1:9","servers":["{}"],"timeout":3"#,
        hook.display(),
        dns.address
    );
    let name = "www.silent.example.test";
    let daemon = start(&authority, &home, name, &members);
    assert_eq!(daemon.failure(name), "RECORD NOT VISIBLE (ACME010)");
    let text = wait_for("the diagnostic", 10, || {
        Some(daemon.log()).filter(|log| log.contains("RECORD NOT VISIBLE"))
    });
    assert!(text.contains("No resolver answered the question for a CNAME record"), "{text}");
    assert!(text.contains(&format!("_acme-challenge.{name}")), "{text}");
    // The provider wrote nothing, so nothing is left to remove.
    assert!(!log.exists());
    assert!(authority.validated.lock().unwrap().is_empty());
}

#[test]
fn check_refuses_an_api_that_is_not_http_on_a_loopback_address() {
    let (authority, dns) = world();
    let home = home("check");
    let verdict = |api: &str| {
        let members = format!(
            r#""cloudflare":{{"token_file":"/nonexistent/cf.token","api":"{api}"}},{}"#,
            asking(&dns, 20)
        );
        let file = home.join(format!("edge-{}.json", serial()));
        let text = topology(&authority, &home, "*.check.example.test", &members, free_address());
        fs::write(&file, text).unwrap();
        let output = Command::new(BIN).arg("check").arg("-f").arg(&file).output().unwrap();
        (output.status.success(), String::from_utf8_lossy(&output.stderr).into_owned())
    };
    // `check` opens no socket and reads no token file.
    let (accepted, text) = verdict("http://127.0.0.1:20443/client/v4");
    assert!(accepted, "{text}");
    for api in [
        "https://api.cloudflare.com/client/v4",
        "http://api.cloudflare.com/client/v4",
        "https://127.0.0.1:20443/client/v4",
        "http://192.0.2.7:20443/client/v4",
        "http://127.0.0.1@example.org/client/v4",
    ] {
        let (accepted, text) = verdict(api);
        assert!(!accepted, "{api} was accepted");
        assert!(text.contains("global.acme.dns.cloudflare.api"), "{api}: {text}");
        assert!(text.contains("an http URL on a loopback address"), "{api}: {text}");
    }
}

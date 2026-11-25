//! Automatic HTTPS of the edge against a certificate authority inside the test
//! (SID 0021): the daemon obtains, serves, renews and keeps certificates, with no
//! restart and no reload in between. A wildcard is proved with DNS-01 at a DNS server
//! inside the test. Internal names and addresses come from the local authority.
//!
//! The hook of the DNS-01 tests is a shell script that the test writes into its own
//! directory. It is test data, not a tool of the repository.
#![cfg(all(feature = "https", unix))]
#![allow(clippy::unwrap_used)]

#[path = "support/acme_authority.rs"]
#[allow(dead_code)]
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

use authority::{Authority, ISSUER, connect_trusting, peer_certificate};
use sibuna_acme::dns::TsigKey;
use sibuna_acme::dns::server::{Entry, Server};

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
#[derive(Clone, Copy)]
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
    /// More members of the `tls` object, each with a leading comma.
    tls: &'a str,
    /// Name the test authority as `global.acme.directory`. Without it the directory is
    /// the default, Let's Encrypt, which a test never contacts: every name must then go
    /// to the local authority.
    directory: bool,
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
    let local = |name: &&str| sibuna_lb::is_address(name) || sibuna_lb::is_internal_name(name);
    let never_public =
        setup.tls.contains(r#""issuer":"internal""#) || setup.names.iter().all(local);
    assert!(setup.directory || never_public, "a test must not ask a public authority");
    let directory = match setup.directory {
        true => format!(r#""directory":"{}","#, setup.authority.directory),
        false => String::new(),
    };
    let plain_frontend = match setup.plain {
        Some(members) => {
            let rest = format!(r#"{members}"default_backend":"app""#);
            format!(r#","plain":{{"proto":"http","binds":["{plain}"],{rest}}}"#)
        }
        None => String::new(),
    };
    format!(
        r#"{{"global":{{"admin_socket":"{socket}",
          "acme":{{{directory}"storage":"{storage}"{acme}}}}},
        "http":{{"surface":"off"}},
        "observability":{{"access_log":{{"output":"{log}"}}}},
        "frontends":{{"web":{{"proto":"http","binds":["{tls}"],
          "tls":{{"auto":[{names}]{more}}},"default_backend":"app"}}{plain_frontend}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket = socket.display(),
        more = setup.tls,
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
        tls: "",
        directory: true,
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
        wait_for("the ready state", 10, || Some(daemon.row(SITE)).filter(|row| row[5] == "ready"));
    assert_eq!(row[1..3], ["http-01", "Sibuna_Test_Authority"], "{row:?}");
    assert_eq!(row[8], "-", "{row:?}");
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
        Some(daemon.row("refused.example.test")).filter(|row| row[5] == "retry")
    });
    assert!(row[8..].join(" ").contains("ACME"), "{row:?}");
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
        tls: "",
        directory: true,
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
        tls: "",
        directory: true,
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

/// Writes an executable script into `home` and returns its path.
fn script(home: &Path, name: &str, body: &str) -> PathBuf {
    let path = home.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The issuer and the names of the certificate that the edge serves for `host`.
fn served(daemon: &Daemon, host: &str) -> Option<(String, Vec<String>)> {
    let fields = sibuna_acme::x509::read(&peer_certificate(daemon.tls, host, None)?)?;
    Some((fields.issuer, fields.names))
}

#[test]
fn a_wildcard_is_proved_with_dns_01_through_a_hook_and_serves_one_label() {
    let authority = Authority::start();
    let dns = Server::start_local().unwrap();
    *authority.dns_server.lock().unwrap() = Some(dns.address);
    let home = home("dns-hook");
    // The hook keeps the records in a file that the DNS server of the test reads.
    let (records, log) = (home.join("records"), home.join("hook.log"));
    dns.with(|table| table.txt_file = Some(records.clone()));
    let body = format!(
        "echo \"$1 $2\" >> {log}\ncase \"$1\" in\n  present) echo \"$2 $3\" >> {records} ;;\n  \
         cleanup) grep -v -F \"$2 $3\" {records} > {records}.new; mv {records}.new {records} ;;\n\
         esac",
        log = log.display(),
        records = records.display()
    );
    let hook = script(&home, "dns-hook", &body);
    let acme = format!(
        r#","challenge":"dns-01","dns":{{"hook":"{}","resolver":"{address}",
            "servers":["{address}"],"timeout":20}}"#,
        hook.display(),
        address = dns.address
    );
    // The name and its wildcard share the record `_acme-challenge.apex.example.test`.
    let (apex, wildcard) = ("apex.example.test", "*.apex.example.test");
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[apex, wildcard],
        plain: None,
        acme: &acme,
        tls: "",
        directory: true,
    };
    let daemon = start(&setup);
    let wild = (ISSUER.to_owned(), vec![wildcard.to_owned()]);
    let found = wait_for("the wildcard certificate", 60, || {
        served(&daemon, "a.apex.example.test").filter(|found| *found == wild)
    });
    assert_eq!(found.1, [wildcard]);
    // The wildcard serves one label. The name itself has its own certificate, and two
    // labels fall to the certificate of the first name: not to the wildcard.
    let exact = wait_for("the exact certificate", 60, || {
        served(&daemon, apex).filter(|found| found.1 == [apex])
    });
    assert_eq!(served(&daemon, "a.b.apex.example.test"), Some(exact));
    assert_eq!(served(&daemon, "B.Apex.Example.Test"), Some(wild));
    assert!(get_secure(daemon.tls, "www.apex.example.test").ends_with("ok"));
    assert_eq!(*authority.validated.lock().unwrap(), ["dns-01", "dns-01"]);
    // Each order presented its value and removed it: no record is left.
    let owner = "_acme-challenge.apex.example.test.";
    let expected = format!("present {owner}\ncleanup {owner}\n").repeat(2);
    assert_eq!(fs::read_to_string(&log).unwrap(), expected);
    assert_eq!(fs::read_to_string(&records).unwrap(), "");
    let mut stored = Vec::new();
    files(&home.join("acme"), &mut stored);
    assert!(!stored.iter().any(|path| path.ends_with("dns")), "{stored:?}");
    assert!(stored.iter().any(|path| path.ends_with("certs/_.apex.example.test/cert.pem")));
    let row = daemon.row(wildcard);
    assert_eq!(row[1..3], ["dns-01", "Sibuna_Test_Authority"], "{row:?}");
}

#[test]
fn a_dynamic_update_signed_with_tsig_proves_a_wildcard() {
    let authority = Authority::start();
    let dns = Server::start_local().unwrap();
    *authority.dns_server.lock().unwrap() = Some(dns.address);
    let home = home("dns-update");
    let secret = "c2lidW5hLXRzaWctdGVzdC1zZWNyZXQtMDEyMzQ1Njc=";
    let key_file = home.join("tsig.key");
    fs::write(&key_file, format!("{secret}\n")).unwrap();
    dns.with(|table| {
        table.add("example.test", Entry::Soa);
        table.key = TsigKey::parse("sibuna-key", secret);
    });
    let acme = format!(
        r#","dns":{{"rfc2136":{{"server":"{address}","key_name":"sibuna-key.",
            "key_file":"{key}","zone":"example.test"}},"resolver":"{address}",
            "servers":["{address}"],"timeout":20}}"#,
        address = dns.address,
        key = key_file.display()
    );
    let wildcard = "*.dyn.example.test";
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[wildcard],
        plain: None,
        acme: &acme,
        tls: "",
        directory: true,
    };
    let daemon = start(&setup);
    let found = wait_for("the wildcard certificate", 60, || {
        served(&daemon, "a.dyn.example.test").filter(|found| found.0 == ISSUER)
    });
    assert_eq!(found.1, [wildcard]);
    assert_eq!(*authority.validated.lock().unwrap(), ["dns-01"]);
    // One signed update added the record and one removed it.
    let owner = "_acme-challenge.dyn.example.test";
    let updates = wait_for("the cleanup", 10, || {
        Some(dns.with(|table| table.updates.clone())).filter(|updates| updates.len() == 2)
    });
    assert_eq!((updates[0].0.as_str(), updates[0].2), (owner, false));
    assert_eq!((updates[1].0.as_str(), updates[1].2), (owner, true));
    assert_eq!(updates[0].1, updates[1].1);
    assert!(dns.with(|table| table.texts(owner)).is_empty());
    // The secret of the key is in no line of the log.
    assert!(!daemon.log().contains(secret));
}

#[test]
fn a_failing_provider_and_an_invisible_record_are_reported_with_hints() {
    let authority = Authority::start();
    let dns = Server::start_local().unwrap();
    *authority.dns_server.lock().unwrap() = Some(dns.address);
    let wildcard = "*.fail.example.test";
    let row_of = |daemon: &Daemon| {
        wait_for("the failure", 60, || Some(daemon.row(wildcard)).filter(|row| row[5] == "retry"))
    };

    // A hook that fails: its status and the end of its output are in the diagnostic.
    let home_one = home("dns-fail");
    let hook = script(&home_one, "dns-hook", "echo 'the token is wrong' >&2\nexit 7");
    // The resolver is the DNS server of the test: no test asks that of the system.
    let acme = format!(
        r#","dns":{{"hook":"{}","resolver":"{address}","servers":["{address}"]}}"#,
        hook.display(),
        address = dns.address
    );
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home_one,
        names: &[wildcard],
        plain: None,
        acme: &acme,
        tls: "",
        directory: true,
    };
    let daemon = start(&setup);
    let row = row_of(&daemon);
    assert_eq!(row[8..].join(" "), "DNS PROVIDER FAILED (ACME009)", "{row:?}");
    let log = wait_for("the diagnostic", 10, || {
        Some(daemon.log()).filter(|log| log.contains("ended with the status 7"))
    });
    assert!(log.contains("the token is wrong") && log.contains("Hint: Run the hook by hand"));
    assert!(log.contains("present _acme-challenge.fail.example.test."), "{log}");
    // The cleanup of the failed order ran and failed too. It is reported on its own.
    assert!(log.contains("was not removed"), "{log}");
    assert!(authority.validated.lock().unwrap().is_empty());
    drop(daemon);

    // A hook that writes nothing: the record never shows at the server, and the
    // daemon says so after the timeout, without asking the authority to validate.
    let home_two = home("dns-invisible");
    let log_file = home_two.join("hook.log");
    let hook = script(&home_two, "dns-hook", &format!("echo \"$1\" >> {}", log_file.display()));
    let acme = format!(
        r#","dns":{{"hook":"{}","resolver":"{address}","servers":["{address}"],"timeout":3}}"#,
        hook.display(),
        address = dns.address
    );
    let setup = Setup { home: &home_two, acme: &acme, ..setup };
    let daemon = start(&setup);
    let row = row_of(&daemon);
    assert_eq!(row[8..].join(" "), "RECORD NOT VISIBLE (ACME010)", "{row:?}");
    let log = wait_for("the diagnostic", 10, || {
        Some(daemon.log()).filter(|log| log.contains("RECORD NOT VISIBLE"))
    });
    assert!(log.contains(&dns.address.to_string()), "{log}");
    assert!(log.contains("Hint: Raise `global.acme.dns.timeout`"), "{log}");
    // The record was removed after the failure as well.
    assert_eq!(fs::read_to_string(&log_file).unwrap(), "present\ncleanup\n");
    assert!(authority.validated.lock().unwrap().is_empty());
}

/// The PEM text of `show ca`, and the path in its comment lines.
fn local_root(daemon: &Daemon) -> (String, PathBuf) {
    let text = daemon.ctl("show ca");
    let path = text.lines().find_map(|line| line.strip_prefix("# file: "));
    let path = PathBuf::from(path.unwrap_or_else(|| panic!("no root in\n{text}")));
    let pem: String =
        text.lines().filter(|line| !line.starts_with('#')).collect::<Vec<_>>().join("\n");
    (pem, path)
}

/// One request inside TLS from a client that trusts `root` alone. `name` is a host
/// name or an address. Returns the answer, or the reason the handshake failed.
fn get_trusting(address: SocketAddr, name: &str, root: &str) -> Result<String, String> {
    let (mut session, mut socket) = connect_trusting(address, name, root)?;
    let mut stream = rustls::Stream::new(&mut session, &mut socket);
    let request = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|error| error.to_string())?;
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    Ok(answer)
}

/// The leaf that the edge serves to a client that trusts `root` alone.
fn trusted_leaf(address: SocketAddr, name: &str, root: &str) -> Option<Vec<u8>> {
    let (session, _socket) = connect_trusting(address, name, root).ok()?;
    Some(session.peer_certificates()?.first()?.to_vec())
}

#[test]
fn internal_names_and_addresses_are_served_from_the_local_authority() {
    let authority = Authority::start();
    let (other_home, home) = (home("local-second"), home("local"));
    // No directory, no issuer: the names alone choose the local authority.
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &["localhost", "127.0.0.1", "*.corp.internal"],
        plain: Some(""),
        acme: "",
        tls: "",
        directory: false,
    };
    let daemon = start(&setup);
    wait_for("the certificates", 30, || {
        let ready = |name: &str| daemon.row(name)[5] == "ready";
        (ready("localhost") && ready("127.0.0.1") && ready("*.corp.internal")).then_some(())
    });
    let (root, path) = local_root(&daemon);
    assert_eq!(path, home.join("acme/local/root.crt"));
    assert_eq!(fs::read_to_string(&path).unwrap().trim_end(), root.trim_end());
    assert_eq!(mode(&home.join("acme/local/root.pem")), 0o600);
    assert_eq!(mode(&home.join("acme/local/intermediate.pem")), 0o600);
    // A client that trusts the root alone accepts the name, the address, which it
    // names without a server name, and one label under the wildcard.
    for name in ["localhost", "127.0.0.1", "db.corp.internal"] {
        let answer = get_trusting(daemon.tls, name, &root);
        assert!(answer.as_ref().is_ok_and(|answer| answer.ends_with("ok")), "{name}: {answer:?}");
    }
    // Another name is not in the certificate, and another root does not verify.
    assert!(get_trusting(daemon.tls, "other.internal", &root).is_err());
    let foreign = sibuna_acme::local::LocalAuthority::open(&other_home.join("foreign"), 0, &[]);
    let foreign = foreign.unwrap().root_pem().unwrap();
    assert!(get_trusting(daemon.tls, "localhost", &foreign).is_err());
    let line = "automatic HTTPS for 3 name(s) from the local authority, storage";
    assert!(daemon.log().contains(line), "{}", daemon.log());
    let row = daemon.row("localhost");
    assert_eq!(row[1..3], ["local", "Sibuna_Local_Authority_-_Intermediate"], "{row:?}");
    // The redirect and the metrics are those of any managed name.
    let moved = get(daemon.plain, "localhost", "/x");
    assert!(moved.starts_with("HTTP/1.1 308 "), "{moved}");
    assert!(daemon.ctl("show stats").contains("sibuna_edge_acme_certificates_served 3\n"));
    // No account and no directory of a public authority exist: nobody was asked.
    let entries: Vec<_> = fs::read_dir(home.join("acme")).unwrap().flatten().collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 0);

    // A second node on the same storage uses the same root and the stored leaves.
    let leaf = trusted_leaf(daemon.tls, "localhost", &root).unwrap();
    std::os::unix::fs::symlink(home.join("acme"), other_home.join("acme")).unwrap();
    let second = start(&Setup { home: &other_home, ..setup });
    wait_for("the second node", 30, || {
        (second.row("localhost")[5] == "ready" && second.row("127.0.0.1")[5] == "ready")
            .then_some(())
    });
    assert_eq!(local_root(&second).0, root);
    assert_eq!(trusted_leaf(second.tls, "localhost", &root), Some(leaf.clone()));
    assert!(get_trusting(second.tls, "127.0.0.1", &root).is_ok());
    drop(second);
    drop(daemon);

    // A restart reuses the root and the leaf.
    let daemon = start(&setup);
    let again =
        wait_for("the stored certificate", 30, || trusted_leaf(daemon.tls, "localhost", &root));
    assert_eq!(again, leaf);
    assert_eq!(local_root(&daemon).0, root);
    let log = wait_for("the log line", 5, || {
        Some(daemon.log()).filter(|log| log.contains("localhost loaded from storage"))
    });
    assert!(!log.contains("obtained"), "{log}");
}

#[test]
fn a_local_certificate_is_renewed_without_a_restart_and_an_address_is_added_by_a_reload() {
    let authority = Authority::start();
    let home = home("local-renew");
    // A leaf of twelve seconds is due after two thirds of its validity.
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &["127.0.0.1"],
        plain: None,
        acme: r#","internal":{"lifetime":12}"#,
        tls: "",
        directory: false,
    };
    let daemon = start(&setup);
    wait_for("the certificate", 30, || (daemon.row("127.0.0.1")[5] == "ready").then_some(()));
    let (root, _) = local_root(&daemon);
    let first = trusted_leaf(daemon.tls, "127.0.0.1", &root).unwrap();
    let second = wait_for("the renewal", 40, || {
        trusted_leaf(daemon.tls, "127.0.0.1", &root).filter(|leaf| *leaf != first)
    });
    assert_eq!(local_root(&daemon).0, root);
    let log = wait_for("the log line", 5, || Some(daemon.log()).filter(|l| l.contains("renewed")));
    assert!(log.contains("certificate for 127.0.0.1 obtained"), "{log}");

    // A reload adds an address. The certificate without a server name lists both.
    let grown = Setup { names: &["127.0.0.1", "127.0.0.2"], ..setup };
    fs::write(&daemon.file, topology(&grown, daemon.tls, daemon.plain, &daemon.socket)).unwrap();
    daemon.ctl("reload");
    let both = wait_for("the certificate of both addresses", 40, || {
        let leaf = trusted_leaf(daemon.tls, "127.0.0.1", &root).filter(|leaf| *leaf != second)?;
        let names = sibuna_acme::x509::read(&leaf)?.names;
        (names.contains(&"127.0.0.1".to_owned()) && names.contains(&"127.0.0.2".to_owned()))
            .then_some(leaf)
    });
    assert!(!both.is_empty());
    assert!(connect_trusting(daemon.tls, "127.0.0.2", &root).is_ok());
}

#[test]
fn one_frontend_mixes_both_issuers_and_a_public_name_can_be_forced_internal() {
    // The test authority issues for the name, the local authority for the address.
    let authority = Authority::start();
    let home_one = home("mixed");
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home_one,
        names: &[SITE, "127.0.0.1"],
        plain: None,
        acme: "",
        tls: "",
        directory: true,
    };
    let daemon = start(&setup);
    wait_for("the certificate of the authority", 30, || issued(&daemon, SITE));
    wait_for("the local certificate", 30, || {
        (daemon.row("127.0.0.1")[5] == "ready").then_some(())
    });
    let (root, _) = local_root(&daemon);
    assert!(
        get_trusting(daemon.tls, "127.0.0.1", &root).is_ok_and(|answer| answer.ends_with("ok"))
    );
    // The local root does not vouch for the certificate of the other authority.
    assert!(get_trusting(daemon.tls, SITE, &root).is_err());
    assert_eq!(daemon.row(SITE)[1..3], ["tls-alpn-01", "Sibuna_Test_Authority"]);
    assert_eq!(daemon.row("127.0.0.1")[1], "local");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    drop(daemon);

    // `issuer: "internal"` sends a public name to the local authority.
    let home_two = home("forced");
    let forced = Setup {
        home: &home_two,
        names: &["www.example.org"],
        tls: r#","issuer":"internal""#,
        directory: false,
        ..setup
    };
    let daemon = start(&forced);
    wait_for("the certificate", 30, || {
        (daemon.row("www.example.org")[5] == "ready").then_some(())
    });
    let (root, _) = local_root(&daemon);
    let answer = get_trusting(daemon.tls, "www.example.org", &root);
    assert!(answer.is_ok_and(|answer| answer.ends_with("ok")));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
}

#[test]
fn the_check_refuses_an_internal_name_for_acme_and_a_wildcard_without_dns() {
    let home = home("check");
    let check = |tls: &str| {
        let file = home.join("edge.json");
        let text = format!(
            r#"{{"frontends":{{"web":{{"binds":["127.0.0.1:8443"],"tls":{tls}}}}},
               "backends":{{"app":{{"servers":["127.0.0.1:8080"]}}}}}}"#
        );
        fs::write(&file, text).unwrap();
        let output = Command::new(BIN).arg("check").arg("-f").arg(&file).output().unwrap();
        (output.status.success(), String::from_utf8_lossy(&output.stderr).into_owned())
    };
    let (ok, text) = check(r#"{"auto":["localhost"],"issuer":"acme"}"#);
    assert!(!ok && text.contains("NAME NOT PUBLIC"), "{text}");
    assert!(text.contains("Hint: ") && text.contains("issuer: \"internal\""), "{text}");
    let (ok, text) = check(r#"{"auto":["*.example.org"]}"#);
    assert!(!ok && text.contains("WILDCARD NEEDS DNS"), "{text}");
    assert!(text.contains("dns: { hook:"), "{text}");
    let (ok, text) = check(r#"{"auto":["localhost","10.1.2.3","*.corp.internal"]}"#);
    assert!(ok, "{text}");
}

/// Whether a rustls verifier that trusts `root` alone accepts `chain_pem` for `name`.
fn rustls_accepts(chain_pem: &str, name: &str, root: &str) -> bool {
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    let mut roots = rustls::RootCertStore::empty();
    for root in sibuna_acme::pem::decode("CERTIFICATE", root).unwrap() {
        roots.add(CertificateDer::from(root)).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .unwrap();
    let chain = sibuna_acme::pem::decode("CERTIFICATE", chain_pem).unwrap();
    let chain: Vec<_> = chain.into_iter().map(CertificateDer::from).collect();
    let name = ServerName::try_from(name.to_owned()).unwrap();
    verifier.verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now()).is_ok()
}

/// The keys of the storage in `home` sign leaves inside and outside the constraints
/// of their root: whoever holds the storage can do that. A client that trusts the root
/// refuses the leaves outside.
fn a_client_refuses_a_leaf_outside_the_constraints(home: &Path, root: &str) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let list = ["127.0.0.0/8".to_owned(), "localhost".to_owned()];
    let keys = sibuna_acme::local::LocalAuthority::open(&home.join("acme"), now.as_secs(), &list);
    let keys = keys.unwrap();
    let issue = |name: &str| keys.issue(&[name], 600, now.as_secs()).unwrap().chain_pem;
    assert!(rustls_accepts(&issue("a.localhost"), "a.localhost", root));
    assert!(rustls_accepts(&issue("127.9.9.9"), "127.9.9.9", root));
    assert!(!rustls_accepts(&issue("bank.example"), "bank.example", root));
    assert!(!rustls_accepts(&issue("10.0.0.1"), "10.0.0.1", root));
}

#[test]
fn the_root_keeps_its_constraints_and_a_lost_root_is_replaced_at_the_start() {
    let authority = Authority::start();
    let home = home("local-constraints");
    let constraints = r#","internal":{"constraints":["localhost","127.0.0.0/8"]}"#;
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &["localhost", "127.0.0.1"],
        plain: None,
        acme: constraints,
        tls: "",
        directory: false,
    };
    let ready = |daemon: &Daemon| {
        wait_for("the certificates", 30, || {
            let ready = |name: &str| daemon.row(name)[5] == "ready";
            (ready("localhost") && ready("127.0.0.1")).then_some(())
        });
    };
    let daemon = start(&setup);
    ready(&daemon);
    let (root, path) = local_root(&daemon);
    // Every user may read the root. The keys stay private.
    assert_eq!((mode(&path), mode(&home.join("acme/local"))), (0o644, 0o755));
    assert_eq!(mode(&home.join("acme/local/root.pem")), 0o600);
    assert_eq!(mode(&home.join("acme/local/certs")), 0o700);
    // A rustls client accepts a name and an address inside the constraints.
    for name in ["localhost", "127.0.0.1"] {
        let answer = get_trusting(daemon.tls, name, &root);
        assert!(answer.as_ref().is_ok_and(|answer| answer.ends_with("ok")), "{name}: {answer:?}");
    }
    drop(daemon);

    a_client_refuses_a_leaf_outside_the_constraints(&home, &root);

    // The check refuses a local name outside the list, and a start with another list
    // reports the root and serves nothing new.
    let file = home.join("check.json");
    let socket = home.join("check.sock");
    let outside = Setup { names: &["db.internal"], ..setup };
    let address: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    fs::write(&file, topology(&outside, address, address, &socket)).unwrap();
    let output = Command::new(BIN).arg("check").arg("-f").arg(&file).output().unwrap();
    let text = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success() && text.contains("NAME OUTSIDE CONSTRAINTS"), "{text}");
    assert!(text.contains("`db.internal`") && text.contains("Hint: "), "{text}");
    let other = r#","internal":{"constraints":["localhost","127.0.0.0/8","10.0.0.0/8"]}"#;
    let daemon = start(&Setup { acme: other, ..setup });
    let log = wait_for("the refusal of the root", 20, || {
        Some(daemon.log()).filter(|log| log.contains("other name constraints"))
    });
    assert!(log.contains("ACME011") && log.contains("internal.constraints"), "{log}");
    assert_ne!(daemon.row("localhost")[5], "ready");
    drop(daemon);

    // The storage loses its root. The next start makes a new one, does not serve the
    // stored leaves of the old one, and issues once for each name.
    for lost in ["root.pem", "root.crt", "intermediate.pem"] {
        fs::remove_file(home.join("acme/local").join(lost)).unwrap();
    }
    let daemon = start(&setup);
    ready(&daemon);
    let (new_root, _) = local_root(&daemon);
    assert_ne!(new_root, root);
    for name in ["localhost", "127.0.0.1"] {
        assert!(get_trusting(daemon.tls, name, &new_root).is_ok(), "{name}");
        assert!(get_trusting(daemon.tls, name, &root).is_err(), "{name}");
    }
    let log = daemon.log();
    assert!(!log.contains("loaded from storage"), "{log}");
    assert_eq!(log.matches("certificate for localhost obtained").count(), 1, "{log}");
    assert_eq!(log.matches("certificate for 127.0.0.1 obtained").count(), 1, "{log}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 0);
}

/// The files `dns` under the storage of `home`: the DNS-01 records that the daemon
/// remembers as presented.
fn remembered_records(home: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for authority in fs::read_dir(home.join("acme")).unwrap().flatten() {
        let Ok(names) = fs::read_dir(authority.path().join("certs")) else { continue };
        found.extend(names.flatten().map(|name| name.path().join("dns")).filter(|p| p.exists()));
    }
    found
}

#[test]
fn the_record_of_a_name_that_left_the_file_is_cleaned_at_once_and_at_the_start() {
    let authority = Authority::start();
    let dns = Server::start_local().unwrap();
    *authority.dns_server.lock().unwrap() = Some(dns.address);
    let wildcard = "*.gone.example.test";
    let record = "cleanup _acme-challenge.gone.example.test.";
    for (tag, restart) in [("sweep-reload", false), ("sweep-start", true)] {
        let home = home(tag);
        // The hook fails, also at the cleanup: the record stays remembered.
        let hook = script(&home, "dns-hook", "exit 7");
        let acme = format!(
            r#","dns":{{"hook":"{}","resolver":"{address}","servers":["{address}"]}}"#,
            hook.display(),
            address = dns.address
        );
        let setup = Setup {
            authority: &authority,
            origin: origin(),
            home: &home,
            names: &[wildcard],
            plain: None,
            acme: &acme,
            tls: "",
            directory: true,
        };
        let daemon = start(&setup);
        wait_for("the failure", 60, || Some(daemon.row(wildcard)).filter(|row| row[5] == "retry"));
        assert_eq!(remembered_records(&home).len(), 1);
        // The hook works again, and the wildcard leaves the file for another name.
        let log = home.join("hook.log");
        script(&home, "dns-hook", &format!("echo \"$1 $2\" >> {}", log.display()));
        let kept = Setup { names: &["kept.gone.example.test"], ..setup };
        let daemon = match restart {
            true => {
                drop(daemon);
                start(&kept)
            }
            false => {
                let file = topology(&kept, daemon.tls, daemon.plain, &daemon.socket);
                fs::write(&daemon.file, file).unwrap();
                daemon.ctl("reload");
                daemon
            }
        };
        let hook_log = wait_for("the cleanup", 20, || {
            fs::read_to_string(&log).ok().filter(|text| text.contains(record))
        });
        assert_eq!(hook_log.matches(record).count(), 1, "{tag}: {hook_log}");
        wait_for("the forgotten record", 10, || {
            remembered_records(&home).is_empty().then_some(())
        });
        assert!(!daemon.ctl("show certs").contains(wildcard), "{tag}");
    }
}

#[test]
fn a_certificate_key_on_p384_is_ordered_issued_stored_and_served() {
    /// The object identifier of the curve P-384, as the key of a certificate names it.
    const SECP384R1: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    let authority = Authority::start();
    let home = home("p384");
    let name = "p384.example.test";
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[name, "127.0.0.1"],
        plain: Some(""),
        acme: r#","key":"p384""#,
        tls: "",
        directory: true,
    };
    let on_p384 = |daemon: &Daemon, host: &str| {
        // A rustls client completes the handshake, so the daemon signed with the key.
        let leaf = peer_certificate(daemon.tls, host, None).unwrap();
        leaf.windows(SECP384R1.len()).any(|window| window == SECP384R1)
    };
    let ready = |daemon: &Daemon| {
        wait_for("the certificates", 30, || {
            let ready = |name: &str| daemon.row(name)[5] == "ready";
            (ready(name) && ready("127.0.0.1")).then_some(())
        });
    };
    let daemon = start(&setup);
    ready(&daemon);
    // One certificate from the authority of the test, one from the local authority.
    assert_eq!(daemon.row(name)[1], "http-01");
    assert_eq!(daemon.row("127.0.0.1")[1], "local");
    assert!(on_p384(&daemon, name) && on_p384(&daemon, "127.0.0.1"));
    assert!(get(daemon.plain, name, "/").starts_with("HTTP/1.1 308 "));
    let (root, _) = local_root(&daemon);
    let answer = get_trusting(daemon.tls, "127.0.0.1", &root);
    assert!(answer.is_ok_and(|answer| answer.ends_with("ok")));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    drop(daemon);

    // The stored keys load after a restart, and nothing is ordered again.
    let daemon = start(&setup);
    ready(&daemon);
    assert!(on_p384(&daemon, name) && on_p384(&daemon, "127.0.0.1"));
    let log = daemon.log();
    assert!(log.contains(&format!("certificate for {name} loaded from storage")), "{log}");
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
}

#[test]
fn a_certificate_key_of_rsa_is_ordered_issued_stored_and_served() {
    /// The object identifier `rsaEncryption`, as the key of a certificate names it.
    const RSA: [u8; 11] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    if sibuna_acme::keygen::probe().is_err() {
        eprintln!("openssl is not installed; no RSA key is made");
        return;
    }
    let authority = Authority::start();
    let home = home("rsa");
    let name = "rsa.example.test";
    let setup = Setup {
        authority: &authority,
        origin: origin(),
        home: &home,
        names: &[name, "127.0.0.1"],
        plain: Some(""),
        acme: r#","key":"rsa2048""#,
        tls: "",
        directory: true,
    };
    let with_rsa = |daemon: &Daemon, host: &str| {
        // A rustls client completes the handshake, so the daemon signed with the key.
        let leaf = peer_certificate(daemon.tls, host, None).unwrap();
        leaf.windows(RSA.len()).any(|window| window == RSA)
    };
    let ready = |daemon: &Daemon| {
        wait_for("the certificates", 60, || {
            let ready = |name: &str| daemon.row(name)[5] == "ready";
            (ready(name) && ready("127.0.0.1")).then_some(())
        });
    };
    let daemon = start(&setup);
    ready(&daemon);
    // One certificate from the authority of the test, one from the local authority.
    assert_eq!(daemon.row(name)[1], "http-01");
    assert_eq!(daemon.row("127.0.0.1")[1], "local");
    assert!(with_rsa(&daemon, name) && with_rsa(&daemon, "127.0.0.1"));
    let (root, _) = local_root(&daemon);
    let answer = get_trusting(daemon.tls, "127.0.0.1", &root);
    assert!(answer.is_ok_and(|answer| answer.ends_with("ok")));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
    let key = home.join("acme/local/certs/127.0.0.1/key.pem");
    let key = sibuna_acme::KeyPair::from_pem(&fs::read_to_string(key).unwrap()).unwrap();
    assert_eq!(key.key_type(), sibuna_acme::KeyType::Rsa2048);
    drop(daemon);

    // The stored keys load after a restart, and nothing is ordered again.
    let daemon = start(&setup);
    ready(&daemon);
    assert!(with_rsa(&daemon, name) && with_rsa(&daemon, "127.0.0.1"));
    assert_eq!(authority.order_count.load(Ordering::Relaxed), 1);
}

/// With an RSA key and no `openssl` in the `PATH`, the check and the start both fail
/// at once, with the code and the hint of the key tool.
#[test]
fn an_rsa_key_without_openssl_fails_the_check_and_the_start() {
    let home = home("no-openssl");
    let file = home.join("edge.json");
    let storage = home.join("acme");
    let text = format!(
        r#"{{"global":{{"acme":{{"key":"rsa2048","storage":"{}"}}}},
           "frontends":{{"web":{{"binds":["127.0.0.1:8443"],"tls":{{"auto":["localhost"]}}}}}},
           "backends":{{"app":{{"servers":["127.0.0.1:8080"]}}}}}}"#,
        storage.display()
    );
    fs::write(&file, text).unwrap();
    let empty = home.join("empty-path");
    fs::create_dir_all(&empty).unwrap();
    for arguments in [vec!["check", "-f"], vec!["--config-file"]] {
        let output =
            Command::new(BIN).args(&arguments).arg(&file).env("PATH", &empty).output().unwrap();
        let text = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{arguments:?}: {text}");
        assert!(text.contains("KEY TOOL FAILED (ACME015)"), "{arguments:?}: {text}");
        assert!(text.contains("could not be started"), "{arguments:?}: {text}");
        assert!(text.contains("Hint: ") && text.contains("\"p256\""), "{arguments:?}: {text}");
    }
    // Nothing was created: the failure came before the storage was touched.
    assert!(!storage.exists());
    // With an ECDSA key the same file needs no program.
    let text = fs::read_to_string(&file).unwrap().replace("rsa2048", "p384");
    fs::write(&file, text).unwrap();
    let output =
        Command::new(BIN).arg("check").arg("-f").arg(&file).env("PATH", &empty).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

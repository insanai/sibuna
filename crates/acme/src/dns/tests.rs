#![allow(clippy::unwrap_used)]
//! Tests of DNS-01 against the test server and a hook program.
//!
//! The hook of these tests is a shell script that each test writes into its own
//! directory. It is test data, not a tool of the repository.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::server::{Entry, Server};
use super::*;
use crate::order::ChallengeKind;

/// A directory of one test, removed with it.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SERIAL: AtomicU32 = AtomicU32::new(0);
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("sibuna-dns-{}-{serial}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// Writes an executable script and returns its path.
    #[cfg(unix)]
    fn script(&self, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn log(&self) -> String {
        fs::read_to_string(self.0.join("log")).unwrap_or_default()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn challenge(name: &str) -> Challenge {
    Challenge {
        kind: ChallengeKind::Dns01,
        name: name.to_owned(),
        token: "token".to_owned(),
        key_authorization: "token.thumbprint".to_owned(),
    }
}

/// The value of [`challenge`]: base64url of SHA-256 of `token.thumbprint`.
fn value() -> String {
    challenge("x").dns_value()
}

fn hook_run<'a>(program: &'a Path, action: &'a str, timeout: Duration) -> hook::Run<'a> {
    let owner = "_acme-challenge.example.org";
    hook::Run { program, action, owner, value: "abc", name: "*.example.org", timeout }
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// A server that is the resolver and the only name server of `example.org` and of
/// `example.net`, and a lookup that asks it.
fn world() -> (Server, Lookup) {
    let server = Server::start_local().unwrap();
    server.with(|table| {
        for zone in ["example.org", "example.net"] {
            table.add(zone, Entry::Soa);
            table.add(zone, Entry::Ns("ns1.example.org".to_owned()));
        }
        table.add("ns1.example.org", Entry::A(Ipv4Addr::LOCALHOST));
        table.add("www.example.org", Entry::A(Ipv4Addr::new(192, 0, 2, 1)));
    });
    let lookup = Lookup {
        resolver: Some(server.address),
        servers: Vec::new(),
        port: server.address.port(),
    };
    (server, lookup)
}

#[test]
fn the_challenge_names_its_record_and_its_value() {
    assert_eq!(challenge("example.org").dns_owner(), "_acme-challenge.example.org");
    assert_eq!(challenge("*.example.org").dns_owner(), "_acme-challenge.example.org");
    // RFC 8555, section 8.4: base64url of the SHA-256 digest, 43 characters.
    assert_eq!(value().len(), 43);
    assert!(value().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}

#[cfg(unix)]
#[test]
fn the_hook_receives_the_action_the_record_and_the_value() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = Scratch::new();
    let log = scratch.0.join("log");
    let body = format!(
        "echo \"$# $1 $2 $3 | $SIBUNA_ACME_ACTION $SIBUNA_ACME_RECORD $SIBUNA_ACME_VALUE \
         $SIBUNA_ACME_NAME\" >> {}\nread line && echo \"stdin open\" >> {}\nexit 0",
        log.display(),
        log.display()
    );
    let program = scratch.script("hook", &body);
    hook::run(hook_run(&program, "present", HOOK_TIMEOUT)).unwrap();
    hook::run(hook_run(&program, "cleanup", HOOK_TIMEOUT)).unwrap();
    let record = "_acme-challenge.example.org.";
    let expected = format!(
        "3 present {record} abc | present {record} abc *.example.org\n\
         3 cleanup {record} abc | cleanup {record} abc *.example.org\n"
    );
    assert_eq!(scratch.log(), expected);
}

#[cfg(unix)]
#[test]
fn a_failing_hook_is_reported_with_the_end_of_its_output() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = Scratch::new();
    let noisy = "i=0; while [ $i -lt 400 ]; do echo \"line $i of output\"; i=$((i+1)); done\n\
                 printf 'bad \\033[31mcredentials\\n' >&2; exit 3";
    let program = scratch.script("hook", noisy);
    let error = hook::run(hook_run(&program, "present", HOOK_TIMEOUT)).unwrap_err();
    assert_eq!((error.code, error.title), ("ACME009", "DNS PROVIDER FAILED"));
    let message = &error.message;
    assert!(message.contains("ended with the status 3"), "{message}");
    assert!(message.contains("credentials") && message.contains("line 399"), "{message}");
    assert!(!message.contains("line 0 of") && !message.contains('\u{1b}'), "{message}");
    assert!(message.len() < 2 * hook::MAX_OUTPUT + 400, "{}", message.len());
    assert!(error.hint.contains("by hand"));
}

#[cfg(unix)]
#[test]
fn a_hook_that_runs_too_long_is_stopped() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = Scratch::new();
    let program = scratch.script("hook", "echo started; exec sleep 30");
    let begun = Instant::now();
    let error = hook::run(hook_run(&program, "present", Duration::from_millis(300))).unwrap_err();
    assert!(begun.elapsed() < Duration::from_secs(5));
    assert!(error.message.contains("ran longer than 0 seconds"), "{}", error.message);
    assert!(error.message.contains("started"), "{}", error.message);
    let missing = scratch.0.join("no-such-program");
    let error = hook::run(hook_run(&missing, "present", HOOK_TIMEOUT)).unwrap_err();
    assert!(error.message.contains("could not be started"), "{}", error.message);
}

#[cfg(unix)]
#[test]
fn the_solver_remembers_the_record_until_its_cleanup_succeeded() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let scratch = Scratch::new();
    let log = scratch.0.join("log");
    let fail = scratch.0.join("fail");
    let body = format!(
        "echo \"$1 $2 $3\" >> {}\nif [ -e {} ]; then echo no >&2; exit 1; fi",
        log.display(),
        fail.display()
    );
    let options = DnsOptions { check: false, ..DnsOptions::hook(scratch.script("hook", &body)) };
    let store = Store::open(&scratch.0, "https://ca.test/dir").unwrap();
    let solver = Solver { options: &options, store: &store };
    let pauses = std::cell::RefCell::new(Vec::new());
    let mut pause = |time: Duration| {
        pauses.borrow_mut().push(time);
        true
    };
    let name = "*.example.org";
    let record = "_acme-challenge.example.org";
    // Nothing presented: nothing to clean.
    assert!(!solver.cleanup(name).unwrap());
    solver.present(name, &challenge(name), &mut pause).unwrap();
    assert_eq!(store.load_presented(name), Some((record.to_owned(), value())));
    // The cleanup fails: the record stays remembered. Then it succeeds.
    fs::write(&fail, "").unwrap();
    assert_eq!(solver.cleanup(name).unwrap_err().code, "ACME009");
    assert!(store.load_presented(name).is_some());
    fs::remove_file(&fail).unwrap();
    assert!(solver.cleanup(name).unwrap());
    assert_eq!(store.load_presented(name), None);
    // A present that fails leaves the record remembered, for the cleanup after it.
    fs::write(&fail, "").unwrap();
    assert_eq!(solver.present(name, &challenge(name), &mut pause).unwrap_err().code, "ACME009");
    assert!(store.load_presented(name).is_some());
    fs::remove_file(&fail).unwrap();
    // A new process finds the record of the dead one and removes it.
    let again = Store::open(&scratch.0, "https://ca.test/dir").unwrap();
    assert!(Solver { options: &options, store: &again }.cleanup(name).unwrap());
    let line = |action: &str| format!("{action} {record}. {}\n", value());
    let expected =
        [line("present"), line("cleanup"), line("cleanup"), line("present"), line("cleanup")];
    assert_eq!(scratch.log(), expected.concat());
    assert!(pauses.borrow().is_empty());
    // With `wait`, the solver pauses once; a stop during the pause fails the attempt.
    let waiting = DnsOptions { wait: Duration::from_secs(7), ..options.clone() };
    let solver = Solver { options: &waiting, store: &store };
    solver.present(name, &challenge(name), &mut pause).unwrap();
    assert_eq!(*pauses.borrow(), [Duration::from_secs(7)]);
    let error = solver.present(name, &challenge(name), &mut |_| false).unwrap_err();
    assert_eq!(error.code, "ACME010");
}

#[test]
fn the_zone_and_its_servers_are_found_through_the_resolver() {
    let (server, lookup) = world();
    assert_eq!(lookup.zone_of("_acme-challenge.www.example.org.", far()).unwrap(), "example.org");
    assert_eq!(lookup.zone_of("Example.Net", far()).unwrap(), "example.net");
    let error = lookup.zone_of("_acme-challenge.other.test", far()).unwrap_err();
    assert_eq!(error.code, "ACME010");
    let servers = lookup.servers_of("example.org", far()).unwrap();
    assert_eq!(servers, [("ns1.example.org".to_owned(), server.address)]);
    // A zone whose name server has no address, and no resolver at all.
    server.with(|table| {
        table.add("example.com", Entry::Soa);
        table.add("example.com", Entry::Ns("ns.nowhere.test".to_owned()));
    });
    assert!(
        lookup.servers_of("example.com", far()).unwrap_err().message.contains("no name server")
    );
    let error = Lookup::default().zone_of("example.org", far()).unwrap_err();
    assert!(error.message.contains("resolv.conf"), "{}", error.message);
    // Given servers replace the search.
    let given = Lookup { servers: vec![server.address], ..Lookup::default() };
    assert_eq!(given.servers_of("", far()).unwrap()[0].1, server.address);
    assert_eq!(given.zone_of("a.example.org", far()).unwrap(), "example.org");
}

#[test]
fn the_record_is_visible_when_the_server_shows_it() {
    let (server, lookup) = world();
    let owner = "_acme-challenge.example.org";
    let mut rounds = 0;
    let mut pause = |_: Duration| {
        rounds += 1;
        if rounds == 2 {
            server.with(|table| table.add(owner, Entry::Txt("the-value".to_owned())));
        }
        true
    };
    // Another value of the same owner does not count.
    server.with(|table| table.add(owner, Entry::Txt("other".to_owned())));
    lookup::wait_visible(&lookup, owner, "the-value", Duration::from_secs(20), &mut pause)
        .unwrap();
    assert_eq!(rounds, 2);
    // Over TCP when the answer over UDP is cut.
    server.with(|table| table.truncate_udp = true);
    lookup::wait_visible(&lookup, owner, "the-value", Duration::from_secs(20), &mut |_| true)
        .unwrap();
    assert!(server.with(|table| table.tcp_count) >= 4);
}

#[test]
fn a_delegated_challenge_is_checked_at_its_target() {
    let (server, lookup) = world();
    let owner = "_acme-challenge.www.example.org";
    server.with(|table| {
        table.add(owner, Entry::Cname("www.validation.example.net".to_owned()));
        table.add("www.validation.example.net", Entry::Txt("delegated".to_owned()));
    });
    assert_eq!(lookup.final_owner(owner, far()), "www.validation.example.net");
    assert_eq!(
        lookup.final_owner("_acme-challenge.example.org.", far()),
        "_acme-challenge.example.org"
    );
    lookup::wait_visible(&lookup, owner, "delegated", Duration::from_secs(20), &mut |_| true)
        .unwrap();
    // A loop of aliases ends.
    server.with(|table| {
        table.add("a.example.org", Entry::Cname("b.example.org".to_owned()));
        table.add("b.example.org", Entry::Cname("a.example.org".to_owned()));
    });
    let last = lookup.final_owner("a.example.org", far());
    assert!(last == "a.example.org" || last == "b.example.org");
}

#[test]
fn a_record_that_never_shows_fails_with_the_servers_named() {
    let (server, lookup) = world();
    let owner = "_acme-challenge.example.org";
    let mut rounds = 0;
    let mut pause = |_: Duration| {
        rounds += 1;
        rounds < 3
    };
    let error = lookup::wait_visible(&lookup, owner, "v", Duration::from_secs(20), &mut pause)
        .unwrap_err();
    assert_eq!((error.code, error.title), ("ACME010", "RECORD NOT VISIBLE"));
    let named = format!("ns1.example.org ({})", server.address);
    assert!(error.message.contains(&named), "{}", error.message);
    assert!(error.hint.contains("check") && error.hint.contains("timeout"));
    // One server of two has the record, the other not: not visible. Then the other is
    // silent: the one that answers decides.
    let second = Server::start_local().unwrap();
    server.with(|table| table.add(owner, Entry::Txt("v".to_owned())));
    let both = Lookup { servers: vec![server.address, second.address], ..lookup.clone() };
    let error = lookup::wait_visible(&both, owner, "v", Duration::from_secs(20), &mut |_| false)
        .unwrap_err();
    assert!(error.message.contains(&second.address.to_string()), "{}", error.message);
    assert!(!error.message.contains(&format!("{},", server.address)), "{}", error.message);
    second.with(|table| table.silent = true);
    lookup::wait_visible(&both, owner, "v", Duration::from_secs(20), &mut |_| false).unwrap();
    // No server answers at all.
    server.with(|table| table.silent = true);
    let error = lookup::wait_visible(&both, owner, "v", Duration::from_secs(8), &mut |_| false)
        .unwrap_err();
    assert!(error.message.contains("no name server"), "{}", error.message);
}

#[test]
fn an_answer_to_another_question_is_no_answer() {
    // A server that answers every datagram with a fixed message about another name.
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = socket.local_addr().unwrap();
    let liar = std::thread::spawn(move || {
        let mut buffer = [0; 512];
        let (_, peer) = socket.recv_from(&mut buffer).unwrap();
        let mut forged = wire::query(0, "other.example", wire::TYPE_TXT, false).unwrap();
        forged[..2].copy_from_slice(&buffer[..2]);
        forged[2] = 0x84;
        socket.send_to(&forged, peer).unwrap();
        socket.send_to(&[0xff; 700], peer).unwrap();
    });
    let lookup = Lookup { servers: vec![address], ..Lookup::default() };
    let error =
        lookup::wait_visible(&lookup, "a.example.org", "v", Duration::from_secs(4), &mut |_| {
            false
        })
        .unwrap_err();
    assert!(error.message.contains("no name server"), "{}", error.message);
    liar.join().unwrap();
}

#[test]
fn the_resolver_of_the_system_is_the_first_nameserver() {
    let text = "# comment\nsearch example.org\nnameserver fe80::1%eth0\nnameserver 192.0.2.53\n";
    assert_eq!(lookup::system_resolver(text), Some("[fe80::1]:53".parse().unwrap()));
    assert_eq!(
        lookup::system_resolver("nameserver 192.0.2.53"),
        Some("192.0.2.53:53".parse().unwrap())
    );
    assert_eq!(lookup::system_resolver("nameserver nonsense\noptions x"), None);
}

fn key() -> TsigKey {
    TsigKey::parse("sibuna-key.", "c2lidW5hLXRzaWctdGVzdC1zZWNyZXQtMDEyMzQ1Njc=").unwrap()
}

fn change<'a>(owner: &'a str, value: &'a str, delete: bool) -> update::Change<'a> {
    update::Change { zone: "example.org", owner, value, delete }
}

#[test]
fn a_signed_update_adds_and_deletes_one_value() {
    let (server, _) = world();
    server.with(|table| table.key = Some(key()));
    let owner = "_acme-challenge.example.org";
    let texts = || server.with(|table| table.texts(owner));
    update::send(server.address, Some(&key()), change(owner, "one", false)).unwrap();
    update::send(server.address, Some(&key()), change(owner, "two", false)).unwrap();
    assert_eq!(texts(), ["one", "two"]);
    // A delete removes its own value only: the value of another order stays.
    update::send(server.address, Some(&key()), change(owner, "one", true)).unwrap();
    assert_eq!(texts(), ["two"]);
    // Over TCP as well.
    server.with(|table| table.truncate_udp = true);
    update::send(server.address, Some(&key()), change(owner, "two", true)).unwrap();
    assert!(texts().is_empty());
    assert_eq!(server.with(|table| table.updates.len()), 4);
}

#[test]
fn a_refused_update_is_reported() {
    let (server, _) = world();
    let owner = "_acme-challenge.example.org";
    // An unsigned update to a server without a key is taken.
    update::send(server.address, None, change(owner, "v", false)).unwrap();
    // A zone the server does not hold.
    let foreign = update::Change { zone: "example.com", ..change("a.example.com", "v", false) };
    let error = update::send(server.address, None, foreign).unwrap_err();
    assert_eq!(error.code, "ACME009");
    assert!(error.message.contains("REFUSED") && error.message.contains("example.com"));
    // The server wants a key: an unsigned update and a wrong secret are refused, and
    // nothing changes.
    server.with(|table| table.key = Some(key()));
    let error = update::send(server.address, None, change(owner, "w", false)).unwrap_err();
    assert!(error.message.contains("NOTAUTH"), "{}", error.message);
    let mut wrong = key();
    wrong.secret[3] ^= 0x40;
    let error = update::send(server.address, Some(&wrong), change(owner, "w", false)).unwrap_err();
    assert!(error.message.contains("not signed"), "{}", error.message);
    assert_eq!(server.with(|table| table.texts(owner)), ["v"]);
    // We sign, the server answers unsigned: the answer is not trusted.
    server.with(|table| table.key = None);
    let error = update::send(server.address, Some(&key()), change(owner, "w", false)).unwrap_err();
    assert!(error.message.contains("not signed"), "{}", error.message);
}

#[test]
fn the_solver_updates_the_zone_it_finds_and_checks_the_record() {
    let (server, lookup) = world();
    server.with(|table| table.key = Some(key()));
    let scratch = Scratch::new();
    let store = Store::open(&scratch.0, "https://ca.test/dir").unwrap();
    let provider = Provider::Rfc2136 { server: server.address, key: Some(key()), zone: None };
    let options = DnsOptions { provider, lookup, ..DnsOptions::hook("") };
    let solver = Solver { options: &options, store: &store };
    let name = "*.www.example.org";
    solver.present(name, &challenge(name), &mut |_| true).unwrap();
    let owner = "_acme-challenge.www.example.org";
    assert_eq!(server.with(|table| table.texts(owner)), [value()]);
    assert!(solver.cleanup(name).unwrap());
    assert!(server.with(|table| table.texts(owner)).is_empty());
    let updates = server.with(|table| table.updates.clone());
    assert_eq!(updates.len(), 2);
    assert!(!updates[0].2 && updates[1].2);
    // A server that does not answer: three tries, then ACME009.
    let dead: SocketAddr = "127.0.0.9:9".parse().unwrap();
    let error = update::send(dead, None, change(owner, "v", false)).unwrap_err();
    assert!(error.message.contains("did not answer"), "{}", error.message);
}

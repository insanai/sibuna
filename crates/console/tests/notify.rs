//! Notifications through a running console (unit U6): target rules, sealed secrets, a real
//! webhook delivery with an HMAC signature, UDP and framed TCP syslog lines, audit records
//! without secret bytes, and the durable queue's cooldowns, retries and identities (Zig's
//! `console_notify_test.py` and `console_delivery_test.py`, in process; a ban is raised by
//! counting one on the daemon's metrics, as the honeypot did).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod signin;
mod support;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_console::{Config, ConsoleKey, Keys};
use sibuna_console_protocol::Role;
use sibuna_core::Metrics;
use sibuna_crypto::hmac;
use signin::{json, member, text};
use support::{Harness, Response, Session};

/// One request a receiver took.
#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    at: Instant,
}

/// A plain HTTP receiver on loopback that answers by path: `/small-error` and
/// `/large-error` (9,000 bytes) with 500, `/retry` with an empty 500, anything else 204.
struct Receiver {
    address: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Receiver {
    fn start() -> Receiver {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, flag) = (Arc::clone(&received), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &log),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Receiver { address, received, stop, thread: Some(thread) }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn all(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    fn count(&self, path: &str) -> usize {
        self.all().iter().filter(|row| row.path == path).count()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, log: &Mutex<Vec<Received>>) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => raw.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers.get("content-length").map_or(0, |value| value.parse().unwrap());
    let mut body = raw[end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => body.extend_from_slice(&chunk[..count]),
        }
    }
    let reply = match path.as_str() {
        "/small-error" => b"HTTP/1.1 500 Error\r\nContent-Length: 5\r\n\r\nerror".to_vec(),
        "/large-error" => {
            let mut reply = b"HTTP/1.1 500 Error\r\nContent-Length: 9000\r\n\r\n".to_vec();
            reply.extend_from_slice(&b"error".repeat(1800));
            reply
        }
        "/retry" => b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n".to_vec(),
        _ => b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
    };
    log.lock().unwrap().push(Received { path, headers, body, at: Instant::now() });
    let _ = stream.write_all(&reply);
}

/// Starts a console with a console key and metrics the test counts bans on, and signs in
/// an administrator.
fn start(name: &str) -> (Harness, Arc<Metrics>, Session) {
    let metrics = Arc::new(Metrics::default());
    let shared = Arc::clone(&metrics);
    let harness = Harness::start_with(name, Config::default(), move |inputs| {
        inputs.keys = Keys { totp: Some(ConsoleKey::new([0x0f; 32])), peer: None };
        inputs.metrics = shared;
    });
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    (harness, metrics, session)
}

/// Posts `body` to `notifications/<endpoint>` and checks the status.
fn call(
    harness: &Harness,
    session: &Session,
    endpoint: &str,
    body: &str,
    status: u16,
) -> Response {
    let reply = post(harness, session, &format!("/console/api/notifications/{endpoint}"), body);
    assert_eq!(reply.status, status, "{endpoint} {body}: {}", reply.text());
    reply
}

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

/// Saves a destination and returns its id.
fn save(harness: &Harness, session: &Session, body: &str) -> u64 {
    let reply = call(harness, session, "save", body, 200);
    text(&json(&reply), "id").parse().unwrap()
}

/// Waits up to `seconds` for `done`.
fn wait(seconds: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

/// Returns every audit row of `action` as JSON text (following the pages), and the
/// replies' bodies.
fn audit(harness: &Harness, session: &Session, action: &str) -> (Vec<String>, String) {
    let (mut rows, mut bodies) = (Vec::new(), String::new());
    let mut before = String::new();
    for _ in 0..8 {
        let query = format!("{{\"action\":\"{action}\"{before}}}");
        let reply = post(harness, session, "/console/api/audit/query", &query);
        assert_eq!(reply.status, 200, "{}", reply.text());
        bodies.push_str(&reply.text());
        let page = json(&reply);
        rows.extend(member(&page, "rows").as_array().unwrap().iter().map(ToString::to_string));
        match member(&page, "next") {
            sibuna_json::Value::Null => break,
            next => {
                before = format!(
                    ",\"before\":\"{}\"",
                    next.as_str().map_or(next.to_string(), str::to_owned)
                )
            }
        }
    }
    (rows, bodies)
}

/// The TCP syslog receiver: reads one octet-counted frame per connection.
fn syslog_receiver() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&lines);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut raw = Vec::new();
            let _ = stream.read_to_end(&mut raw);
            let text = String::from_utf8_lossy(&raw).into_owned();
            let (length, line) = text.split_once(' ').unwrap();
            let length: usize = length.parse().unwrap();
            assert!(0 < length && length <= 1024);
            assert_eq!(line.len(), length);
            log.lock().unwrap().push(line.to_owned());
        }
    });
    (address, lines)
}

/// Targets the rule refuses are answered 400 `CONSOLENOTIFYTARGET` before storage.
fn refuses_targets(harness: &Harness, admin: &Session) {
    for target in [
        "https://10.0.0.1/hook",
        "https://user@hooks.example/x",
        "ftp://x/y",
        "http://hooks.example/x",
        "https://169.254.169.254/latest",
        "https://hooks.example:9443/x",
        "http://127.0.0.1:80/hook",
        "http://8.8.8.8:8080/hook",
    ] {
        let body = format!(
            "{{\"kind\":\"webhook\",\"label\":\"bad\",\"target\":\"{target}\",\"events\":15,\
             \"cooldown_seconds\":0}}"
        );
        let reply = call(harness, admin, "save", &body, 400);
        assert_eq!(reply.code(), "CONSOLENOTIFYTARGET", "{target}");
    }
}

#[test]
fn targets_secrets_signatures_and_syslog() {
    let (harness, metrics, admin) = start("notify");
    refuses_targets(&harness, &admin);
    let receiver = Receiver::start();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let (tcp, tcp_lines) = syslog_receiver();
    let hook = receiver.url("/hook");
    let webhook = save(
        &harness,
        &admin,
        &format!(
            "{{\"kind\":\"webhook\",\"label\":\"lobby\",\"target\":\"{hook}\",\
             \"secret\":\"shared hook secret\",\"events\":15,\"cooldown_seconds\":0}}"
        ),
    );
    let datagram = save(
        &harness,
        &admin,
        &format!(
            "{{\"kind\":\"syslog\",\"label\":\"collector-udp\",\"transport\":\"udp\",\
             \"target\":\"{}\",\"events\":2,\"cooldown_seconds\":0}}",
            udp.local_addr().unwrap()
        ),
    );
    let stream = save(
        &harness,
        &admin,
        &format!(
            "{{\"kind\":\"syslog\",\"label\":\"framed collector\",\"transport\":\"tcp\",\
             \"target\":\"{tcp}\",\"events\":2,\"cooldown_seconds\":0}}"
        ),
    );
    lists_without_secrets(&harness, &admin, [webhook, datagram, stream]);

    tests_deliver_and_report(&harness, &admin, &receiver, webhook);

    // A ban raises an event that the notifier delivers to all three destinations.
    metrics.bans_issued.add(1);
    let banned = |row: &Received| text(&sibuna_json::parse(&row.body).unwrap(), "event") == "ban";
    assert!(wait(30, || receiver.all().iter().any(banned)), "ban never reached the webhook");
    let mut line = [0u8; 2048];
    let (length, _) = udp.recv_from(&mut line).unwrap();
    let line = String::from_utf8_lossy(&line[..length]).into_owned();
    assert!(line.starts_with("<132>1 ") && line.contains(" sibuna - ban - "), "{line}");
    assert!(wait(15, || !tcp_lines.lock().unwrap().is_empty()), "no framed TCP line");
    assert!(tcp_lines.lock().unwrap()[0].contains(" sibuna - ban - "));
    let delivered = receiver.all().into_iter().find(banned).unwrap();
    assert!(delivered.headers.get("idempotency-key").unwrap().starts_with("sibuna/"));

    call(
        &harness,
        &admin,
        "remove",
        &format!("{{\"id\":{webhook},\"expected_revision\":99}}"),
        409,
    );
    call(
        &harness,
        &admin,
        "remove",
        &format!("{{\"id\":{webhook},\"expected_revision\":1}}"),
        200,
    );
    let (created, body) = audit(&harness, &admin, "notification.create");
    assert_eq!(created.len(), 5);
    assert!(!body.contains("shared hook secret"));
}

/// The destination page shows whether a secret is set and the transport, never the secret.
fn lists_without_secrets(
    harness: &Harness,
    admin: &Session,
    [webhook, datagram, stream]: [u64; 3],
) {
    let page = call(harness, admin, "query", "{}", 200);
    assert!(!page.text().contains("shared hook secret"));
    let rows = json(&page);
    let rows = member(&rows, "rows").as_array().unwrap();
    let row = |id: u64| rows.iter().find(|row| text(row, "id") == id.to_string()).unwrap();
    assert_eq!(text(row(webhook), "secret_set"), "true");
    assert_eq!(text(row(datagram), "secret_set"), "false");
    assert_eq!(text(row(datagram), "transport"), "udp");
    assert_eq!(text(row(stream), "transport"), "tcp");
}

/// Test deliveries: a signed webhook, then a small and an oversized 500, each audited
/// before and after.
fn tests_deliver_and_report(
    harness: &Harness,
    admin: &Session,
    receiver: &Receiver,
    webhook: u64,
) {
    let reply = call(harness, admin, "test", &format!("{{\"id\":{webhook}}}"), 200);
    let result = json(&reply);
    assert_eq!(
        (text(&result, "delivered"), text(&result, "audit_recorded")),
        ("true".into(), "true".into())
    );
    assert_eq!(text(&result, "detail"), "status 204");
    let delivery = receiver.all().pop().unwrap();
    let mac = hmac::hmac_sha256(b"shared hook secret", &delivery.body);
    let expected = format!("sha256={}", sibuna_encoding::hex::encode(&mac));
    assert_eq!(delivery.headers.get("x-sibuna-signature"), Some(&expected));
    assert_eq!(delivery.headers.get("x-sibuna-event").map(String::as_str), Some("denial_spike"));
    assert!(!delivery.headers.contains_key("idempotency-key"));
    let body = sibuna_json::parse(&delivery.body).unwrap();
    assert_eq!(text(&body, "event"), "denial_spike");
    assert_eq!(text(&body, "detail"), "test delivery from the console");
    assert_eq!(text(&body, "console"), harness.origin());
    for path in ["/small-error", "/large-error"] {
        let target = receiver.url(path);
        let id = save(
            harness,
            admin,
            &format!(
                "{{\"kind\":\"webhook\",\"label\":\"failure probe\",\"target\":\"{target}\",\
                 \"events\":1,\"cooldown_seconds\":0}}"
            ),
        );
        let reply = call(harness, admin, "test", &format!("{{\"id\":{id}}}"), 200);
        let result = json(&reply);
        assert_eq!(text(&result, "delivered"), "false");
        assert_eq!(text(&result, "detail"), "status 500");
        assert_eq!(text(&result, "audit_recorded"), "true");
        call(harness, admin, "remove", &format!("{{\"id\":{id},\"expected_revision\":1}}"), 200);
    }
    let (started, _) = audit(harness, admin, "notification.test");
    let (results, body) = audit(harness, admin, "notification.test_result");
    assert_eq!((started.len(), results.len()), (3, 3));
    assert!(!body.contains("shared hook secret"));
}

#[test]
fn deliveries_keep_cooldowns_retries_and_identities() {
    let (harness, metrics, admin) = start("deliveries");
    let receiver = Receiver::start();
    for (path, cooldown) in [("/fast", 0), ("/slow", 10), ("/retry", 0)] {
        let target = receiver.url(path);
        save(
            &harness,
            &admin,
            &format!(
                "{{\"kind\":\"webhook\",\"label\":\"{}\",\"events\":2,\"target\":\"{target}\",\
                 \"cooldown_seconds\":{cooldown}}}",
                &path[1..]
            ),
        );
    }
    metrics.bans_issued.add(1);
    assert!(wait(35, || receiver.count("/fast") >= 1 && receiver.count("/slow") >= 1));
    metrics.bans_issued.add(1);
    let all = || {
        receiver.count("/fast") >= 2
            && receiver.count("/slow") >= 2
            && receiver.count("/retry") >= 6
    };
    assert!(
        wait(40, all),
        "{:?}",
        receiver.all().iter().map(|row| row.path.clone()).collect::<Vec<_>>()
    );
    // Longer than the first backoff, to catch unintended extra sends.
    std::thread::sleep(Duration::from_secs(3));
    let rows = receiver.all();
    for (path, count, attempts) in [("/fast", 2, 1), ("/slow", 2, 1), ("/retry", 6, 3)] {
        let selected: Vec<&Received> = rows.iter().filter(|row| row.path == path).collect();
        assert_eq!(selected.len(), count, "{path}");
        let mut identities: HashMap<&str, usize> = HashMap::new();
        for row in &selected {
            *identities
                .entry(row.headers.get("idempotency-key").unwrap().as_str())
                .or_default() += 1;
        }
        assert_eq!(identities.len(), 2, "{path}");
        assert!(identities.values().all(|&seen| seen == attempts), "{path}: {identities:?}");
    }
    let slow: Vec<&Received> = rows.iter().filter(|row| row.path == "/slow").collect();
    // Storage keeps whole seconds; allow the fractional boundary.
    assert!(slow[1].at.duration_since(slow[0].at) >= Duration::from_secs(9));
    let (audited, _) = audit(&harness, &admin, "notification.delivery");
    assert_eq!(audited.len(), 10);
}

/// A server that accepts connections and never answers; returns its address and a channel
/// that receives one message per accepted connection.
fn stalled() -> (SocketAddr, std::sync::mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, accepted) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            held.push(stream);
            if sender.send(()).is_err() {
                return;
            }
        }
    });
    (address, accepted)
}

#[test]
fn stopping_ends_stalled_deliveries_at_once() {
    let (mut harness, metrics, admin) = start("notify-stop");
    let (queued, queued_accepted) = stalled();
    let (tested, tested_accepted) = stalled();
    for (label, address, events) in [("queued", queued, 2), ("tested", tested, 1)] {
        save(
            &harness,
            &admin,
            &format!(
                "{{\"kind\":\"webhook\",\"label\":\"{label}\",\"events\":{events},\
                 \"target\":\"http://{address}/hook\",\"cooldown_seconds\":0}}"
            ),
        );
    }
    // The notifier delivers a ban to the first; a test delivery waits on the second.
    metrics.bans_issued.add(1);
    queued_accepted.recv_timeout(Duration::from_secs(30)).expect("the notifier connects");
    let address = harness.address();
    let origin = harness.origin();
    let headers = [
        ("Cookie".to_owned(), admin.cookie.clone()),
        ("X-Console-CSRF".to_owned(), admin.csrf.clone()),
        ("Origin".to_owned(), origin),
        ("Content-Type".to_owned(), "application/json".to_owned()),
    ];
    let test = std::thread::spawn(move || {
        let headers: Vec<(&str, &str)> =
            headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        support::request(
            address,
            "POST",
            "/console/api/notifications/test",
            &headers,
            b"{\"id\":2}",
        )
    });
    tested_accepted.recv_timeout(Duration::from_secs(10)).expect("the test connects");
    let started = Instant::now();
    harness.console.take().unwrap().stop();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(1), "stop took {elapsed:?}");
    let _ = test.join();
}

//! Differential tests against the Zig daemon, run when `SIBUNA_ZIG_BINARY` names a Zig build
//! (they pass trivially otherwise).
//!
//! Both daemons start with the same seed, flags and policy file in front of the same stub
//! origin, receive the same requests in the same order, and must answer with the same bytes
//! once the values that are random or time-dependent by design (challenge identifiers,
//! tickets, request references, token texts, expiry times) are masked. Tokens and tickets
//! minted by one daemon are then accepted by the other (SID 0010, acceptance criterion 2).

#![allow(clippy::unwrap_used)]

mod support;

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use support::*;

const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const POLICY: &str = r#"{"rules":[
  {"name":"exact-route","path":"^/exact$","action":"CHALLENGE","challenge":{"difficulty":10}},
  {"name":"robots-txt","path":"/robots.txt","action":"ALLOW"},
  {"name":"private","path":"/private*","action":"CHALLENGE"},
  {"name":"quota","path":"/quota","action":"ALLOW",
   "limits":{"rate":1,"window_seconds":60,"ban_seconds":30}},
  {"name":"bots","user_agent":"*Scrapy*","action":"DENY"}
]}"#;

struct Process {
    child: Child,
    port: u16,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn spawn(binary: &str, extra: &[&str], policy: &str) -> Process {
    let port = free_port();
    let origin = origin_port().to_string();
    let port_text = port.to_string();
    let mut args = vec![
        "--host",
        "127.0.0.1",
        "--port",
        &port_text,
        "--upstream-port",
        &origin,
        "--trust-forwarded",
        "--rate-limit",
        "6",
        "--workers",
        "2",
        "--policy-file",
        policy,
    ];
    args.extend_from_slice(extra);
    let child = Command::new(binary)
        .args(&args)
        .env("SIBUNA_SECRET", SEED)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(address(port)).is_err() {
        assert!(Instant::now() < deadline, "{binary} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Process { child, port }
}

fn pair(extra: &[&str]) -> Option<(Process, Process)> {
    let zig = std::env::var("SIBUNA_ZIG_BINARY").ok().filter(|path| !path.is_empty())?;
    let dir =
        std::env::temp_dir().join(format!("sibuna-parity-{}-{}", std::process::id(), extra.len()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, POLICY).unwrap();
    let policy = policy.to_str().unwrap().to_owned();
    Some((spawn(&zig, extra, &policy), spawn(env!("CARGO_BIN_EXE_sibuna"), extra, &policy)))
}

/// Replaces the value after each `marker` up to the next byte in `ends` by `#`.
fn mask(text: &str, marker: &str, ends: &[char]) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(marker) {
        let start = at + marker.len();
        out.push_str(&rest[..start]);
        out.push('#');
        let tail = &rest[start..];
        let end = tail.find(|c: char| ends.contains(&c)).unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Masks the values that are random or time-dependent by design, and the length of bodies
/// that carry them.
fn normalize(response: &Response) -> String {
    let mut text = response.text();
    for (marker, ends) in [
        ("\"id\":\"", &['"'][..]),
        ("\"expires_at\":", &['}'][..]),
        ("need=", &['"', '&'][..]),
        ("data-ticket=\"", &['"'][..]),
        (" ref ", &['<', ' '][..]),
        ("Reference ", &[' '][..]),
        ("__sibuna_token=", &[';'][..]),
    ] {
        text = mask(&text, marker, ends);
    }
    let volatile = ["\"id\":\"", "need=", "data-ticket", "Reference ", " ref "];
    if volatile.iter().any(|marker| response.text().contains(marker)) {
        text = mask(&text, "Content-Length: ", &['\r']);
    }
    text
}

fn compare(zig: &Process, rust: &Process, raw: &str) {
    let theirs = round_trip(zig.port, raw.as_bytes());
    let ours = round_trip(rust.port, raw.as_bytes());
    assert_eq!(normalize(&ours), normalize(&theirs), "request:\n{raw}");
}

fn request(path: &str, ip: &str, ua: &str, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\n\
         User-Agent: {ua}\r\n{extra}\r\n"
    )
}

#[test]
fn reverse_proxy_answers_are_byte_identical() {
    let Some((zig, rust)) = pair(&["-a", "hashcash", "-d", "8"]) else { return };
    let html = BROWSER_ACCEPT;
    let json = "Accept: application/json\r\n";
    let cases = [
        request("/blog/post-1", "198.51.100.1", BROWSER_UA, html),
        request("/blog/post-1", "198.51.100.1", BROWSER_UA, json),
        request("/robots.txt", "198.51.100.2", "GPTBot/1.0", ""),
        request("/exact?view=1", "198.51.100.3", BROWSER_UA, json),
        request("/__sibuna/health", "198.51.100.4", "curl", ""),
        request("/__sibuna/nope", "198.51.100.4", "curl", ""),
        request("/__sibuna/challenge.json?path=/exact", "198.51.100.5", "curl", ""),
        request("/__sibuna/challenge.json?path=/blog", "198.51.100.5", "curl", ""),
        request("/search?q=1%27%20union%20select%20null--", "198.51.100.6", "curl", ""),
        request("/search?q=%3Cscript%3E", "198.51.100.6", BROWSER_UA, html),
        request("/", "198.51.100.7", "Scrapy/2.0", ""),
        request("/", "198.51.100.7", "Scrapy/2.0", html),
        request("/__sibuna/honeypot", "198.51.100.8", "curl", ""),
        request("/robots.txt", "198.51.100.8", "curl", ""),
        request("/robots.txt", "198.51.100.8", "curl", html),
        request("/quota", "198.51.100.9", "curl", ""),
        request("/quota", "198.51.100.9", "curl", ""),
        request("/quota", "198.51.100.9", "curl", html),
        request("/robots.txt", "198.51.100.9", "curl", ""),
        "GARBAGE\r\n\r\n".to_owned(),
        "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_owned(),
        "POST / HTTP/1.1\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\nabc".to_owned(),
        "POST / HTTP/1.1\r\nContent-Length: 3\r\nExpect: nothing\r\n\r\nabc".to_owned(),
        "POST /incomplete HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort".to_owned(),
        format!("GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(20_000)),
        "POST /__sibuna/verify HTTP/1.1\r\nContent-Length: 13\r\n\r\n{\"nonce\":\"1\"}".to_owned(),
        "POST /__sibuna/verify HTTP/1.1\r\nContent-Length: 36\r\n\r\n\
         {\"challenge_id\":\"zzz\",\"nonce\":\"1\"}"
            .to_owned(),
        "POST /__sibuna/verify HTTP/1.1\r\nContent-Length: 34\r\n\r\n\
         {\"challenge_id\":\"z\",\"nonce\":\"x1\"}"
            .to_owned(),
    ];
    for raw in &cases {
        compare(&zig, &rust, raw);
    }
    for _ in 0..8 {
        compare(&zig, &rust, &request("/robots.txt", "198.51.100.10", "curl", ""));
    }
    compare_metrics(&zig, &rust);
}

/// The Zig daemon's counters read the same; the port's security counters follow them, all
/// zero here (so only the body and its length differ).
fn compare_metrics(zig: &Process, rust: &Process) {
    let raw = request("/__sibuna/metrics", "198.51.100.11", "curl", "");
    let theirs = round_trip(zig.port, raw.as_bytes());
    let ours = round_trip(rust.port, raw.as_bytes());
    assert_eq!(ours.status(), theirs.status());
    let (ours, theirs) = (ours.body_text(), theirs.body_text());
    let added = ours.strip_prefix(theirs.as_str()).expect("the Zig counters come first");
    let names = ["bans_refused", "forwarded_invalid", "honeypot_refused", "rate_evictions"];
    let expected: String = names
        .iter()
        .map(|name| format!("# TYPE sibuna_{name}_total counter\nsibuna_{name}_total 0\n"))
        .collect();
    assert_eq!(added, expected);
}

#[test]
fn sessions_and_tickets_cross_between_the_implementations() {
    let Some((zig, rust)) = pair(&["-a", "hashcash", "-d", "8", "--token-scheme", "mac"]) else {
        return;
    };
    for (issuer, verifier) in [(&zig, &rust), (&rust, &zig)] {
        let ip = "198.51.100.20";
        // A ticket sealed by one daemon sets the work issuance at the other.
        let page = get(issuer.port, "/exact?view=1", ip, BROWSER_UA, BROWSER_ACCEPT);
        let ticket = ticket_of(&page).unwrap();
        let challenge = issue(verifier.port, ip, BROWSER_UA, &format!("need={ticket}"));
        assert_eq!(challenge.difficulty, 10);
        // A session minted by one daemon admits at the other.
        let cookie = solve_session(
            issuer.port,
            ip,
            &fetch_challenge(issuer.port, ip, BROWSER_UA, "/private"),
        );
        let response = get(verifier.port, "/private", ip, BROWSER_UA, &cookie);
        assert_eq!(response.status(), 200, "{}", response.text());
        assert!(response.contains("X-Sibuna-Rule: session"));
    }
}

#[test]
fn forward_authorization_answers_are_byte_identical() {
    let Some((zig, rust)) =
        pair(&["--mode", "forward_auth", "-a", "posw", "-d", "9", "--posw-challenges", "4"])
    else {
        return;
    };
    let original = "X-Forwarded-Uri: /private?a=1\r\nX-Forwarded-Method: GET\r\n";
    let cases = [
        request("/auth", "198.51.100.30", BROWSER_UA, &format!("{original}{BROWSER_ACCEPT}")),
        request("/auth", "198.51.100.30", "curl", original),
        request("/auth", "198.51.100.31", "curl", "X-Forwarded-Uri: /robots.txt\r\n"),
        request("/auth", "198.51.100.31", "curl", "X-Forwarded-Uri: //bad\r\n"),
        request("/__sibuna/challenge", "198.51.100.32", BROWSER_UA, BROWSER_ACCEPT),
        request(
            "/__sibuna/challenge",
            "198.51.100.32",
            BROWSER_UA,
            &format!("X-Original-URI: /private\r\n{BROWSER_ACCEPT}"),
        ),
        request("/__sibuna/health", "198.51.100.33", "curl", ""),
    ];
    for raw in &cases {
        compare(&zig, &rust, raw);
    }
}

/// The verification failures each daemon explains, for a challenge it issued itself.
fn verify_failures(port: u16) -> Vec<String> {
    let ip = "198.51.100.40";
    let challenge = fetch_challenge(port, ip, BROWSER_UA, "/private");
    let nonce = solve_hashcash(&challenge);
    let body = nonce_body(&challenge, nonce);
    let tampered = format!("{}A", &challenge.id[..challenge.id.len() - 1]);
    let tampered = format!("{{\"challenge_id\":\"{tampered}\",\"nonce\":\"1\"}}");
    let proof = format!("{{\"challenge_id\":\"{}\",\"proof\":\"AAAA\"}}", challenge.id);
    // An invalid session cookie is never explained: it falls through to the challenge.
    let bogus_page = format!("Cookie: __sibuna_token=bogus\r\n{BROWSER_ACCEPT}");
    let bogus_api = "Cookie: __sibuna_token=bogus\r\nAccept: application/json\r\n";
    let answers = [
        post(port, "/__sibuna/verify", "198.51.100.41", BROWSER_UA, &body),
        post(port, "/__sibuna/verify", ip, "other-agent", &body),
        post(port, "/__sibuna/verify", ip, BROWSER_UA, &body),
        post(port, "/__sibuna/verify", ip, BROWSER_UA, &body),
        post(port, "/__sibuna/verify", ip, BROWSER_UA, &tampered),
        post(port, "/__sibuna/verify", ip, BROWSER_UA, &proof),
        get(port, "/private", ip, BROWSER_UA, &bogus_page),
        get(port, "/private", ip, BROWSER_UA, bogus_api),
    ];
    answers.iter().map(normalize).collect()
}

#[test]
fn verification_explanations_are_the_zig_texts() {
    let Some((zig, rust)) = pair(&["-a", "hashcash", "-d", "8", "--secure-cookie"]) else {
        return;
    };
    let theirs = verify_failures(zig.port);
    let ours = verify_failures(rust.port);
    for (ours, theirs) in ours.iter().zip(&theirs) {
        assert_eq!(ours, theirs);
    }
    assert!(ours[0].contains("FINGERPRINT MISMATCH"), "{}", ours[0]);
    assert!(ours[3].contains("DOUBLE SPEND"), "{}", ours[3]);
}

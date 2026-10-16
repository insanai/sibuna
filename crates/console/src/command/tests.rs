//! The command client against a controlled peer (Zig's `console_client_test.py` and the
//! transport part of `console_token_cli_test.py`): exact requests, session cleanup,
//! refused redirects, bounded replies, private credential files, and output that never
//! carries a credential or an unexpected member.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::*;

/// One request the peer received: path, header lines, body.
type Seen = (String, Vec<String>, Vec<u8>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Private,
    Redirect,
    Oversize,
}

/// A peer that answers sign-in, the users page and sign-out like a console, misbehaving
/// as `mode` says, until `count` requests were served.
fn peer(mode: Mode, count: usize) -> (u16, Arc<Mutex<Vec<Seen>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let thread = std::thread::spawn(move || {
        for _ in 0..count {
            let Ok((socket, _)) = listener.accept() else { return };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = line.split(' ').nth(1).unwrap().to_owned();
            let mut headers = Vec::new();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end().to_owned();
                if header.is_empty() {
                    break;
                }
                if let Some(value) = header.strip_prefix("Content-Length: ") {
                    length = value.parse().unwrap();
                }
                headers.push(header);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut socket = reader.into_inner();
            let reply = answer(mode, &path);
            log.lock().unwrap().push((path, headers, body));
            let _ = socket.write_all(&reply);
        }
    });
    (port, seen, thread)
}

fn answer(mode: Mode, path: &str) -> Vec<u8> {
    if mode == Mode::Redirect {
        return b"HTTP/1.1 302 Found\r\nLocation: /credential-trap\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
    }
    let (cookie, payload) = match path {
        "/console/api/login" => (
            format!("Set-Cookie: __sibuna_console={}; HttpOnly\r\n", "a".repeat(64)),
            format!(
                "{{\"user\":\"9007199254740993\",\"role\":\"admin\",\"must_change\":false,\
                 \"totp_required\":false,\"csrf\":\"{}\"}}",
                "b".repeat(64)
            ),
        ),
        "/console/api/users/query" if mode == Mode::Private => (
            String::new(),
            "{\"version\":1,\"rows\":[],\"next\":null,\"internal_trace\":\"secret\"}".into(),
        ),
        "/console/api/users/query" => {
            (String::new(), "{\"version\":1,\"rows\":[],\"next\":null}".into())
        }
        _ => (String::new(), "{\"signed_out\":true}".into()),
    };
    let length = if mode == Mode::Oversize { 16_385 } else { payload.len() };
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cookie}Content-Length: {length}\
         \r\n\r\n{payload}"
    )
    .into_bytes()
}

/// Writes `value` and a line end to a private file and returns its path.
fn private(name: &str, value: &str, mode: u32) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sibuna-u2-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, format!("{value}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
    path
}

fn words(port: u16, credential: &[&str]) -> Vec<String> {
    let origin = format!("http://127.0.0.1:{port}");
    let mut words = vec!["users".to_owned(), "--origin".to_owned(), origin];
    words.extend(credential.iter().map(|word| (*word).to_owned()));
    words
}

#[test]
fn the_client_signs_in_queries_and_signs_out() {
    let password = private("password", "client boundary test password", 0o600);
    let path = password.to_str().unwrap().to_owned();
    for (mode, failure) in [
        (Mode::Normal, None),
        (Mode::Private, Some("InvalidResponse")),
        (Mode::Redirect, Some("Transport")),
        (Mode::Oversize, Some("ResponseTooLarge")),
    ] {
        let count = if matches!(mode, Mode::Normal | Mode::Private) { 3 } else { 1 };
        let (port, seen, thread) = peer(mode, count);
        let credential = ["--username", "admin", "--password-file", path.as_str()];
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let result = run_with(&words(port, &credential), &mut out, &mut notes);
        thread.join().unwrap();
        let output = String::from_utf8(out).unwrap() + &String::from_utf8(notes).unwrap();
        assert!(!output.contains("client boundary test password"));
        assert!(!output.contains("secret"));
        match failure {
            None => {
                result.unwrap();
                assert_eq!(output, "{\"version\":1,\"rows\":[],\"next\":null}\n");
            }
            Some(name) => {
                let error = result.unwrap_err();
                assert_eq!(error.name(), name);
                assert!(output.is_empty(), "{output}");
            }
        }
        let seen = seen.lock().unwrap();
        let paths: Vec<&str> = seen.iter().map(|(path, _, _)| path.as_str()).collect();
        if count == 3 {
            assert_eq!(
                paths,
                ["/console/api/login", "/console/api/users/query", "/console/api/logout"]
            );
            for (_, headers, _) in &seen[1..] {
                assert!(headers.contains(&format!("Cookie: __sibuna_console={}", "a".repeat(64))));
                assert!(headers.contains(&format!("X-Console-CSRF: {}", "b".repeat(64))));
            }
            let login = String::from_utf8(seen[0].2.clone()).unwrap();
            assert_eq!(
                login,
                "{\"username\":\"admin\",\"password\":\"client boundary test password\",\
                 \"code\":\"\"}"
            );
            assert!(seen[0].1.iter().all(|header| !header.starts_with("Cookie")));
        } else {
            assert_eq!(paths, ["/console/api/login"]);
        }
    }
    let _ = std::fs::remove_file(password);
}

#[test]
fn bearer_commands_send_only_the_token() {
    let token = private("token", &"c".repeat(64), 0o600);
    let path = token.to_str().unwrap().to_owned();
    let (port, seen, thread) = peer(Mode::Normal, 1);
    let (mut out, mut notes) = (Vec::new(), Vec::new());
    let result = run_with(&words(port, &["--token-file", path.as_str()]), &mut out, &mut notes);
    thread.join().unwrap();
    result.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "a bearer command neither signs in nor out");
    let (path, headers, _) = &seen[0];
    assert_eq!(path, "/console/api/users/query");
    assert!(headers.contains(&format!("Authorization: Bearer {}", "c".repeat(64))));
    assert!(headers.iter().all(|header| !header.starts_with("Cookie")));
    assert!(headers.iter().all(|header| !header.starts_with("X-Console-CSRF")));
    let _ = std::fs::remove_file(token);
}

#[test]
fn credential_files_must_be_private_regular_and_bounded() {
    let open = private("open", "a password", 0o644);
    let open_path = open.to_str().unwrap();
    assert!(matches!(read_secret(open_path, 131), Err(CommandError::CredentialPermissions)));
    let empty = private("empty", "", 0o600);
    assert!(matches!(
        read_secret(empty.to_str().unwrap(), 131),
        Err(CommandError::InvalidCredential)
    ));
    let long = private("long", &"x".repeat(200), 0o600);
    assert!(matches!(read_secret(long.to_str().unwrap(), 131), Err(CommandError::CredentialFile)));
    let crlf = private("crlf", "secret\r", 0o600);
    assert_eq!(read_secret(crlf.to_str().unwrap(), 131).unwrap(), "secret");
    let directory = std::env::temp_dir();
    assert!(matches!(
        read_secret(directory.to_str().unwrap(), 131),
        Err(CommandError::CredentialFile)
    ));
    assert!(matches!(
        read_secret("/nonexistent/password", 131),
        Err(CommandError::CredentialFile)
    ));
    let token = private("short-token", "abc", 0o600);
    let mut session = Session::open("http://127.0.0.1:1").unwrap();
    assert!(matches!(
        session.authenticate(token.to_str().unwrap()),
        Err(CommandError::InvalidCredential)
    ));
    for path in [open, empty, long, crlf, token] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn errors_name_zig_diagnostics() {
    let arguments = run(&["users".to_owned()], &mut Vec::new()).unwrap_err();
    assert_eq!((arguments.code(), arguments.name()), ("CONSOLECLI002", "AuthenticationRequired"));
    assert_eq!(arguments.to_string(), "invalid management command (AuthenticationRequired)");
    let remote = ["users", "--origin", "http://192.0.2.1:9443", "--token-file", "x"];
    let remote: Vec<String> = remote.iter().map(|word| (*word).to_owned()).collect();
    let insecure = run(&remote, &mut Vec::new()).unwrap_err();
    assert_eq!(insecure.name(), "InsecureOrigin");
    assert_eq!(insecure.hint(), "Use HTTPS or literal loopback HTTP.");
    assert_eq!(CommandError::Unauthorized.to_string(), "management command failed (Unauthorized)");
    assert_eq!(require_ok(302).unwrap_err().name(), "Transport");
    assert!(matches!(require_ok(429), Err(CommandError::RateLimited)));
    assert!(matches!(require_ok(500), Err(CommandError::InvalidResponse)));
}

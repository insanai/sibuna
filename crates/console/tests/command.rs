//! The `sibuna console` commands against a running console (unit U2): account and token
//! commands with private credential files, revisions, roles, sign-in restrictions, bearer
//! automation and restart persistence (Zig's `console_cli_test.py`,
//! `console_token_cli_test.py` and the factor part of `console_totp_test.py`). The
//! commands never open storage; they speak HTTP to the console like any client.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use std::path::{Path, PathBuf};

use sibuna_console::Config;
use sibuna_console::command::{CommandError, run_with};
use signin::{Browser, json, login, member, restart, rotate, text};
use support::{Harness, unix_now};

/// A private file in the test's directory.
fn private(dir: &Path, name: &str, value: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("{value}\n")).unwrap();
    chmod(&path, 0o600);
    path.to_str().unwrap().to_owned()
}

fn chmod(path: &impl AsRef<Path>, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn directory(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sibuna-u2-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs a command with `--origin` and the credential words; returns its output, or the
/// error. The output never carries the credential, and nothing is printed on failure.
fn invoke(
    harness: &Harness,
    command: &[&str],
    credential: &[&str],
) -> Result<String, CommandError> {
    let origin = harness.origin();
    let mut words: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
    words.extend(["--origin".to_owned(), origin]);
    words.extend(credential.iter().map(|word| (*word).to_owned()));
    let (mut out, mut notes) = (Vec::new(), Vec::new());
    let result = run_with(&words, &mut out, &mut notes);
    let notes = String::from_utf8(notes).unwrap();
    assert!(!notes.contains("CONSOLECLICLOSE"), "{notes}");
    let output = String::from_utf8(out).unwrap();
    for word in credential.iter().filter(|word| !word.starts_with("--")) {
        if let Ok(secret) = std::fs::read_to_string(word) {
            assert!(!output.contains(secret.trim()) || secret.trim().is_empty());
        }
    }
    match result {
        Ok(()) => {
            assert!(output.ends_with('\n') && output.len() <= 16 * 1024 + 1);
            Ok(output)
        }
        Err(error) => {
            assert!(output.is_empty(), "{output}");
            Err(error)
        }
    }
}

fn failure(result: Result<String, CommandError>) -> &'static str {
    result.unwrap_err().name()
}

fn parse(output: &str) -> String {
    output.trim_end().to_owned()
}

fn rows(output: &str) -> Vec<String> {
    let page = sibuna_json::parse(output.as_bytes()).unwrap();
    member(&page, "rows").as_array().unwrap().iter().map(ToString::to_string).collect()
}

fn field(row: &str, name: &str) -> String {
    text(&sibuna_json::parse(row.as_bytes()).unwrap(), name)
}

const ADMIN: &str = "CLI administrator permanent passphrase";

// console_cli_test.py: native account commands, permissions, revisions and restart.
#[test]
fn account_commands_run_against_the_console() {
    let dir = directory("accounts");
    let mut harness = Harness::start("u2-cli-accounts");
    signin::bootstrap(&harness, "admin", "temporary CLI passphrase", true);
    let first = Browser::from(&login(&harness, "admin", "temporary CLI passphrase", ""));
    rotate(&harness, &first, "temporary CLI passphrase", ADMIN);
    let password = private(&dir, "password", ADMIN);
    let admin = ["--username", "admin", "--password-file", password.as_str()];
    chmod(&password, 0o644);
    assert_eq!(failure(invoke(&harness, &["users"], &admin)), "CredentialPermissions");
    chmod(&password, 0o600);
    let page = invoke(&harness, &["users"], &admin).unwrap();
    assert_eq!(field(&rows(&page)[0], "username"), "admin");
    let created = invoke(&harness, &["add-user", "cli-viewer"], &admin).unwrap();
    let temporary = text(&sibuna_json::parse(created.as_bytes()).unwrap(), "temporary_password");
    assert_eq!(temporary.len(), 64);
    restart(&mut harness, Config::default(), false);
    let restricted = private(&dir, "restricted", &temporary);
    let viewer = ["--username", "cli-viewer", "--password-file", restricted.as_str()];
    assert_eq!(failure(invoke(&harness, &["users"], &viewer)), "PasswordChangeRequired");
    let browser = Browser::from(&login(&harness, "cli-viewer", &temporary, ""));
    let permanent = "CLI viewer permanent passphrase";
    rotate(&harness, &browser, &temporary, permanent);
    private(&dir, "restricted", permanent);
    assert_eq!(failure(invoke(&harness, &["add-user", "forbidden"], &viewer)), "Forbidden");
    restart(&mut harness, Config::default(), false);
    let row = rows(&invoke(&harness, &["users"], &admin).unwrap())
        .into_iter()
        .find(|row| field(row, "username") == "cli-viewer")
        .unwrap();
    let (id, revision) = (field(&row, "id"), field(&row, "revision"));
    let access =
        ["set-user", &id, "--revision", &revision, "--role", "operator", "--disabled", "false"];
    let changed = invoke(&harness, &access, &admin).unwrap();
    assert_eq!(
        parse(&changed),
        "{\"saved\":true,\"temporary_password\":null,\"password_expires\":\"0\"}"
    );
    let stale = ["revoke-sessions", &id, "--revision", &revision];
    assert_eq!(failure(invoke(&harness, &stale, &admin)), "Conflict");
    let current = rows(&invoke(&harness, &["users"], &admin).unwrap())
        .into_iter()
        .find(|row| field(row, "username") == "cli-viewer")
        .unwrap();
    assert_eq!(field(&current, "role"), "operator");
    assert_ne!(field(&current, "last_login"), "null");
    let revision = field(&current, "revision");
    let revoked = invoke(&harness, &["revoke-sessions", &id, "--revision", &revision], &admin);
    assert!(revoked.unwrap().contains("\"saved\":true"));
    // Five sign-ins since the last restart: the limiter would refuse the sixth.
    restart(&mut harness, Config::default(), false);
    let next = (revision.parse::<u64>().unwrap() + 1).to_string();
    let reset = invoke(&harness, &["reset-password", &id, "--revision", &next], &admin).unwrap();
    let reset = text(&sibuna_json::parse(reset.as_bytes()).unwrap(), "temporary_password");
    assert_eq!(reset.len(), 64);
    restart(&mut harness, Config::default(), false);
    let after = invoke(&harness, &["users", "--after", &id], &admin).unwrap();
    assert_eq!(parse(&after), "{\"version\":1,\"rows\":[],\"next\":null}");
    harness.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// The tokens minted by [`mint_tokens`]: ids and private token files.
struct Minted {
    reader_id: String,
    reader_file: String,
    writer_id: String,
    writer_file: String,
}

/// Mints a reader and an administrator writer with the password sign-in, and checks what
/// a bearer may and may not run.
fn mint_tokens(harness: &Harness, dir: &Path, admin: &[&str]) -> Minted {
    let expiry = (unix_now() + 3600).to_string();
    let scopes = ["--scope", "users_read", "--scope", "geoip_read", "--expires", &expiry];
    let mint = [&["mint-token", "CLI observer"][..], &scopes].concat();
    let reader = invoke(harness, &mint, admin).unwrap();
    let reader = sibuna_json::parse(reader.as_bytes()).unwrap();
    let (reader_token, reader_id) = (text(&reader, "token"), text(&reader, "id"));
    assert_eq!((text(&reader, "expires"), reader_token.len()), (expiry.clone(), 64));
    let reader_file = private(dir, "reader", &reader_token);
    let bearer = ["--token-file", reader_file.as_str()];
    chmod(&reader_file, 0o644);
    assert_eq!(failure(invoke(harness, &["users"], &bearer)), "CredentialPermissions");
    chmod(&reader_file, 0o600);
    let users = invoke(harness, &["users"], &bearer).unwrap();
    assert_eq!(field(&rows(&users)[0], "username"), "admin");
    assert_eq!(failure(invoke(harness, &["add-user", "forbidden"], &bearer)), "Forbidden");
    assert_eq!(failure(invoke(harness, &["tokens"], &bearer)), "UnexpectedOption");
    let mixed = [&bearer[..], admin].concat();
    assert_eq!(failure(invoke(harness, &["users"], &mixed)), "UnexpectedOption");
    let scopes = ["--scope", "users_write", "--scope", "users_read"];
    let writer_mint =
        [&["mint-token", "account maintenance", "--role", "admin"][..], &scopes].concat();
    let writer = invoke(harness, &writer_mint, admin).unwrap();
    let writer = sibuna_json::parse(writer.as_bytes()).unwrap();
    assert_eq!(text(&writer, "expires"), "null");
    let writer_file = private(dir, "writer", &text(&writer, "token"));
    let automation = ["--token-file", writer_file.as_str()];
    let created = invoke(harness, &["add-user", "automated"], &automation).unwrap();
    let created = sibuna_json::parse(created.as_bytes()).unwrap();
    assert_eq!(text(&created, "temporary_password").len(), 64);
    let page = invoke(harness, &["tokens"], admin).unwrap();
    assert_eq!(rows(&page).len(), 2);
    assert!(page.contains("\"next\":null"));
    assert!(!page.contains("digest") && !page.contains("\"token\""));
    assert!(rows(&page).iter().all(|row| field(row, "active") == "true"));
    let remove = ["remove-token", reader_id.as_str(), "--revision", "1"];
    assert_eq!(failure(invoke(harness, &remove, admin)), "Conflict");
    Minted { reader_id, reader_file, writer_id: text(&writer, "id"), writer_file }
}

/// Revokes the reader (twice: the second conflicts) and removes it.
fn revoke_reader(harness: &Harness, admin: &[&str], minted: &Minted) {
    let bearer = ["--token-file", minted.reader_file.as_str()];
    let id = minted.reader_id.as_str();
    assert!(!rows(&invoke(harness, &["users"], &bearer).unwrap()).is_empty());
    let revoke = ["revoke-token", id, "--revision", "1"];
    let revoked = invoke(harness, &revoke, admin).unwrap();
    assert_eq!(parse(&revoked), format!("{{\"saved\":true,\"id\":{id}}}"));
    assert_eq!(failure(invoke(harness, &revoke, admin)), "Conflict");
    assert_eq!(failure(invoke(harness, &["users"], &bearer)), "Unauthorized");
    let page = invoke(harness, &["tokens"], admin).unwrap();
    let row = rows(&page).into_iter().find(|row| field(row, "id") == id).unwrap();
    assert_eq!(field(&row, "disabled"), "true");
    assert_eq!((field(&row, "active"), field(&row, "revision")), ("false".into(), "2".into()));
    assert!(invoke(harness, &["remove-token", id, "--revision", "2"], admin).is_ok());
}

// console_token_cli_test.py: native token lifecycle, bearer commands and restart.
#[test]
fn token_commands_run_against_the_console() {
    let dir = directory("tokens");
    let mut harness = Harness::start("u2-cli-tokens");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let password = private(&dir, "password", ADMIN);
    let admin = ["--username", "admin", "--password-file", password.as_str()];
    let minted = mint_tokens(&harness, &dir, &admin);
    restart(&mut harness, Config::default(), false);
    revoke_reader(&harness, &admin, &minted);
    restart(&mut harness, Config::default(), false);
    let page = invoke(&harness, &["tokens", "--after", &minted.reader_id], &admin).unwrap();
    let remaining = rows(&page);
    assert_eq!(remaining.len(), 1);
    assert_eq!(field(&remaining[0], "id"), minted.writer_id);
    let automation = ["--token-file", minted.writer_file.as_str()];
    let owner = rows(&invoke(&harness, &["users"], &automation).unwrap())[0].clone();
    let (id, revision) = (field(&owner, "id"), field(&owner, "revision"));
    let revoke = ["revoke-sessions", id.as_str(), "--revision", revision.as_str()];
    assert!(invoke(&harness, &revoke, &automation).unwrap().contains("\"saved\":true"));
    assert_eq!(failure(invoke(&harness, &["users"], &automation)), "Unauthorized");
    restart(&mut harness, Config::default(), false);
    let page = invoke(&harness, &["tokens"], &admin).unwrap();
    assert_eq!(field(&rows(&page)[0], "active"), "false");
    harness.stop();
    let _ = std::fs::remove_dir_all(dir);
}

// console_totp_test.py through console_cli_test.factor_input: a password alone is refused
// for an account with a factor; a recovery code works once.
#[test]
fn commands_take_the_second_factor_from_a_file() {
    let dir = directory("factor");
    let mut harness = signin::start_with_key("u2-cli-factor", Config::default());
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let browser = signin::sign_in(&harness, "admin", ADMIN);
    let body = format!("{{\"password\":\"{ADMIN}\",\"revision\":0}}");
    let secret = text(&json(&browser.post(&harness, "/console/api/totp/enroll", &body)), "secret");
    let code = signin::totp_code(&secret, unix_now() / 30);
    let confirm = format!("{{\"password\":\"{ADMIN}\",\"revision\":1,\"code\":\"{code}\"}}");
    let confirmed = browser.post(&harness, "/console/api/totp/confirm", &confirm);
    let reply = json(&confirmed);
    let recovery =
        member(&reply, "recovery_codes").as_array().unwrap()[2].as_str().unwrap().to_owned();
    restart(&mut harness, Config::default(), true);
    let password = private(&dir, "password", ADMIN);
    let factor = private(&dir, "factor", &recovery);
    let plain = ["--username", "admin", "--password-file", password.as_str()];
    assert_eq!(failure(invoke(&harness, &["users"], &plain)), "Unauthorized");
    let with_factor = [
        "--username",
        "admin",
        "--password-file",
        password.as_str(),
        "--factor-file",
        factor.as_str(),
    ];
    let page = invoke(&harness, &["users"], &with_factor).unwrap();
    assert_eq!(field(&rows(&page)[0], "totp_enabled"), "true");
    assert_eq!(failure(invoke(&harness, &["users"], &with_factor)), "Unauthorized");
    harness.stop();
    let _ = std::fs::remove_dir_all(dir);
}

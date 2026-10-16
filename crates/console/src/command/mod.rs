//! The `sibuna console ...` subcommands (unit U2; Zig's `console_command*.zig`): account,
//! token, GeoIP and policy commands against a running console through its HTTP API. They
//! never open the console's storage.
//!
//! A command signs in with a password (and a second-factor code when the account has one)
//! read from private files, or presents a bearer token read from a private file; it never
//! takes a credential as an argument. It runs one operation, checks the reply against the
//! exact contract (the `reply` module) and prints the reply's bytes, then signs out. Expected
//! revisions stay explicit, and a lost reply never implies a rollback: the hints say to
//! query the state before retrying.
//!
//! ```text
//! sibuna console users --origin https://console.example --username admin \
//!     --password-file ~/.sibuna-password
//! sibuna console mint-token deploy --role operator --scope policy_read \
//!     --scope policy_write --origin ... --username admin --password-file ...
//! sibuna console policies import --file set.json --origin ... --token-file ~/.token
//! ```
//!
//! The daemon's command line hands everything after `console` to [`run`] (or to
//! [`run_with`], which also receives progress lines and the sign-out warning) and renders a
//! failure with [`CommandError::code`], its `Display` text and [`CommandError::hint`].
//!
//! # Changes from Zig
//!
//! - The library never prints: output goes to the caller's writer, progress and the
//!   sign-out warning to a second writer (Zig printed them to standard error itself).
//! - `policies import` sends the whole set in one `policies/import` request (SID 0013)
//!   instead of staging chunks and committing them.
//! - The client is `crate::client` (one deadline per request through socket timeouts)
//!   instead of `std.http.Client` raced against a sleeping task.

mod accounts;
mod args;
mod geoip;
mod policies;
mod reply;
mod tokens;

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use sibuna_console_protocol::Role;
use sibuna_crypto::ct;
use sibuna_tls::{Connector, Trust};

pub use args::ArgsError;

use crate::client::{self, ClientError, Endpoint, Limits, Method, Origin, Request, Response};
use args::Args;

/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest reply a command reads.
pub const MAX_RESPONSE: usize = 16 * 1024;
/// A password file holds at most 128 bytes and a line end.
const PASSWORD_FILE: usize = 131;
/// A code or token file holds at most 64 bytes and a line end.
const CODE_FILE: usize = 67;

/// Why a console command failed.
#[derive(Debug)]
pub enum CommandError {
    /// The command line was refused.
    Arguments(ArgsError),
    /// The request could not be made or its reply not read.
    Client(ClientError),
    /// A credential file is missing, not a regular file, or too large.
    CredentialFile,
    /// A credential file may be read by the group or others.
    CredentialPermissions,
    /// A credential file is empty, too long, or not of the expected form.
    InvalidCredential,
    /// The policy set file cannot be read.
    PolicyFile,
    /// The policy set file is not a JSON array of 1 to 128 rule objects within the bounds.
    InvalidPolicySet,
    /// The reply broke its contract.
    InvalidResponse,
    /// The console refused the credential (401).
    Unauthorized,
    /// The credential does not allow the command (403).
    Forbidden,
    /// Capacity or the expected revision conflicted (409).
    Conflict,
    /// Too many attempts (429).
    RateLimited,
    /// The console cannot answer now (503).
    Unavailable,
    /// The account must change its temporary password in the browser first.
    PasswordChangeRequired,
    /// The account must enroll a second factor in the browser first.
    FactorEnrollmentRequired,
    /// The GeoIP import failed.
    ImportFailed,
    /// The output could not be written.
    Write(io::Error),
}

impl CommandError {
    /// Returns the error's name, as Zig printed it in its diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            CommandError::Arguments(error) => error.name(),
            CommandError::Client(error) => match error {
                ClientError::InvalidOrigin => "InvalidOrigin",
                ClientError::InsecureOrigin => "InsecureOrigin",
                ClientError::InvalidRequest => "InvalidRequest",
                ClientError::Deadline => "Deadline",
                ClientError::TooLarge => "ResponseTooLarge",
                ClientError::InvalidResponse => "InvalidResponse",
                ClientError::TlsRequired | ClientError::Tls(_) | ClientError::Transport(_) => {
                    "Transport"
                }
            },
            CommandError::CredentialFile => "CredentialFile",
            CommandError::CredentialPermissions => "CredentialPermissions",
            CommandError::InvalidCredential => "InvalidCredential",
            CommandError::PolicyFile => "PolicyFile",
            CommandError::InvalidPolicySet => "InvalidPolicySet",
            CommandError::InvalidResponse => "InvalidResponse",
            CommandError::Unauthorized => "Unauthorized",
            CommandError::Forbidden => "Forbidden",
            CommandError::Conflict => "Conflict",
            CommandError::RateLimited => "RateLimited",
            CommandError::Unavailable => "Unavailable",
            CommandError::PasswordChangeRequired => "PasswordChangeRequired",
            CommandError::FactorEnrollmentRequired => "FactorEnrollmentRequired",
            CommandError::ImportFailed => "ImportFailed",
            CommandError::Write(_) => "WriteFailed",
        }
    }

    /// Returns the diagnostic code: `CONSOLECLI002` for a refused command line,
    /// `CONSOLECLIWRITE` when the output was not delivered, `CONSOLECLI` otherwise.
    pub fn code(&self) -> &'static str {
        match self {
            CommandError::Arguments(_) => "CONSOLECLI002",
            CommandError::Write(_) => "CONSOLECLIWRITE",
            _ => "CONSOLECLI",
        }
    }

    /// Returns a sentence that tells the operator how to proceed (Zig's `diagnose`).
    pub fn hint(&self) -> &'static str {
        const UNKNOWN: &str = "Outcome unknown. Query the affected resource before retrying.";
        match self {
            CommandError::Arguments(_) => {
                "Use sibuna --help for management commands and required options."
            }
            CommandError::Client(ClientError::InvalidOrigin | ClientError::InsecureOrigin) => {
                "Use HTTPS or literal loopback HTTP."
            }
            CommandError::Client(ClientError::Tls(error)) => error.hint(),
            CommandError::Client(_) | CommandError::InvalidResponse => UNKNOWN,
            CommandError::Unavailable => UNKNOWN,
            CommandError::Conflict => {
                "Refresh the resource: capacity or the expected revision conflicted."
            }
            CommandError::ImportFailed => {
                "Inspect GeoIP status and daemon diagnostics before retrying."
            }
            CommandError::Forbidden => {
                "Check role and scope; token management requires administrator login."
            }
            CommandError::Unauthorized => {
                "Check credential expiry, revocation, password and second factor."
            }
            CommandError::PasswordChangeRequired => {
                "Change the temporary password in the browser first."
            }
            CommandError::FactorEnrollmentRequired => {
                "Complete required two-factor enrollment in Account."
            }
            CommandError::RateLimited => {
                "Wait a minute before another login or management operation."
            }
            CommandError::CredentialPermissions => {
                "Remove group and other permissions from credential files."
            }
            CommandError::CredentialFile | CommandError::InvalidCredential => {
                "Use private regular credential files."
            }
            CommandError::PolicyFile => "Check the path of the policy set file.",
            CommandError::InvalidPolicySet => {
                "Write a JSON array of 1 to 128 rule objects, each at most 4 KiB compact and \
                 256 KiB together."
            }
            CommandError::Write(_) => {
                "Query current state; reset a temporary password or revoke an undisclosed \
                 token if needed."
            }
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Arguments(error) => write!(f, "invalid management command ({error})"),
            CommandError::Write(_) => f.write_str("output was not delivered"),
            other => write!(f, "management command failed ({})", other.name()),
        }
    }
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CommandError::Arguments(error) => Some(error),
            CommandError::Client(error) => Some(error),
            CommandError::Write(error) => Some(error),
            _ => None,
        }
    }
}

/// Runs the console command `args` (the words after `sibuna console`), writing its output
/// to `out`. Progress lines and the sign-out warning are dropped; see [`run_with`]. The
/// library never prints; the daemon renders a failure as a diagnostic.
///
/// Fails with the [`CommandError`] of the first failed step.
pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), CommandError> {
    run_with(args, out, &mut io::sink())
}

/// Runs the console command `args` like [`run`], writing progress lines (GeoIP status
/// changes) and a warning when the sign-out was not confirmed to `notes`, typically
/// standard error.
///
/// Fails with the [`CommandError`] of the first failed step.
pub fn run_with(
    args: &[String],
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CommandError> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let args = args::parse(&words).map_err(CommandError::Arguments)?;
    let mut session = Session::open(args.origin)?;
    let result = execute(&mut session, &args, out, notes);
    session.close(notes);
    result
}

fn execute(
    session: &mut Session,
    args: &Args<'_>,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CommandError> {
    match args.token_file {
        Some(path) => session.authenticate(path)?,
        None => login(session, args)?,
    }
    if args.kind.manages_tokens() {
        return tokens::run(session, args, out);
    }
    match args.kind {
        args::Kind::GeoStatus | args::Kind::GeoUpdate => geoip::run(session, args, out, notes),
        args::Kind::PoliciesExport | args::Kind::PoliciesImport => {
            policies::run(session, args, out)
        }
        _ => accounts::run(session, args, out),
    }
}

/// One command's connection to the console: its origin, the TLS configuration for an
/// `https` origin, and the credential, wiped when dropped.
pub(crate) struct Session {
    origin: Origin,
    connector: Option<Connector>,
    /// `__sibuna_console=<hex>` after a password sign-in.
    cookie: String,
    /// The session's CSRF token.
    csrf: String,
    /// `Bearer <hex>` for a token.
    bearer: String,
}

impl Session {
    /// Checks the origin and loads the system trust store for `https`.
    fn open(origin: &str) -> Result<Session, CommandError> {
        let origin = Origin::parse(origin).map_err(CommandError::Client)?;
        let connector = match origin.scheme() {
            client::Scheme::Https => {
                let loaded = Connector::load(&Trust::default());
                Some(loaded.map_err(|error| CommandError::Client(ClientError::Tls(error)))?)
            }
            client::Scheme::Http => None,
        };
        let empty = String::new;
        Ok(Session { origin, connector, cookie: empty(), csrf: empty(), bearer: empty() })
    }

    /// Sends one request with the session's credential before `deadline`.
    fn request_until(
        &self,
        method: Method,
        target: &str,
        body: &[u8],
        deadline: Instant,
    ) -> Result<Response, CommandError> {
        let mut fields = vec![("Origin", self.origin.as_str())];
        if !self.bearer.is_empty() {
            fields.push(("Authorization", self.bearer.as_str()));
        } else if !self.cookie.is_empty() {
            fields.push(("Cookie", self.cookie.as_str()));
            fields.push(("X-Console-CSRF", self.csrf.as_str()));
        }
        let endpoint =
            Endpoint { origin: &self.origin, address: None, connector: self.connector.as_ref() };
        let request = Request { method, target, fields: &fields, body, ..Request::default() };
        let limits = Limits { deadline, max_body: MAX_RESPONSE };
        client::send(&endpoint, &request, &limits).map_err(CommandError::Client)
    }

    /// Posts `body` to `target` within [`REQUEST_TIMEOUT`] and returns a 200 reply.
    ///
    /// Fails with the transport's error, or [`require_ok`]'s for another status.
    fn post(&self, target: &str, body: &[u8]) -> Result<Response, CommandError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let response = self.request_until(Method::Post, target, body, deadline)?;
        require_ok(response.status)?;
        Ok(response)
    }

    /// Presents the bearer token in the private file `path`.
    ///
    /// Fails like [`read_secret`], and with [`CommandError::InvalidCredential`] unless the
    /// file holds 64 hexadecimal digits.
    fn authenticate(&mut self, path: &str) -> Result<(), CommandError> {
        let mut token = read_secret(path, CODE_FILE)?;
        let valid = token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit());
        if valid {
            self.bearer = format!("Bearer {token}");
        }
        wipe(&mut token);
        if valid { Ok(()) } else { Err(CommandError::InvalidCredential) }
    }

    /// Signs out a password session; a sign-out that is not confirmed is reported to
    /// `notes`, not as the command's failure (the operation itself already completed).
    fn close(&mut self, notes: &mut dyn Write) {
        if self.cookie.is_empty() {
            return;
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let reply = self.request_until(Method::Post, "/console/api/logout", b"", deadline);
        if !reply.is_ok_and(|reply| reply.status == 200 || reply.status == 401) {
            let _ = writeln!(
                notes,
                "CONSOLECLICLOSE: CLI session closure was not confirmed. Hint: revoke sessions \
                 through Users if necessary."
            );
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        wipe(&mut self.cookie);
        wipe(&mut self.csrf);
        wipe(&mut self.bearer);
    }
}

/// Maps a reply status to the command's error; 200 passes. A redirect is refused as a
/// transport failure, as Zig's client refused to follow it.
///
/// Fails with the error the status stands for.
pub(crate) fn require_ok(status: u16) -> Result<(), CommandError> {
    match status {
        200 => Ok(()),
        300..=399 => Err(CommandError::Client(ClientError::Transport(io::Error::other(
            "the console answered with a redirect, which is refused",
        )))),
        401 => Err(CommandError::Unauthorized),
        403 => Err(CommandError::Forbidden),
        409 => Err(CommandError::Conflict),
        429 => Err(CommandError::RateLimited),
        503 => Err(CommandError::Unavailable),
        _ => Err(CommandError::InvalidResponse),
    }
}

/// Signs in with the password file and the optional factor file, keeps the session's
/// cookie and CSRF token, and checks that the account may run the command.
fn login(session: &mut Session, args: &Args<'_>) -> Result<(), CommandError> {
    let mut body = credentials(args)?;
    let sent = session.post("/console/api/login", body.as_bytes());
    wipe(&mut body);
    let reply = sent?;
    capture_cookie(session, &reply)?;
    let login = reply::login(&reply.body)?;
    session.csrf = login.csrf;
    if login.must_change {
        return Err(CommandError::PasswordChangeRequired);
    }
    if login.totp_required {
        return Err(CommandError::FactorEnrollmentRequired);
    }
    let operator_import = args.kind == args::Kind::PoliciesImport && login.role == Role::Operator;
    if !args.kind.is_read_only() && !operator_import && login.role != Role::Admin {
        return Err(CommandError::Forbidden);
    }
    Ok(())
}

/// Reads the password and the optional code and returns the sign-in body; every
/// intermediate copy is wiped.
fn credentials(args: &Args<'_>) -> Result<String, CommandError> {
    let mut password = read_secret(args.password_file, PASSWORD_FILE)?;
    let code = match args.factor_file {
        Some(path) => read_secret(path, CODE_FILE),
        None => Ok(String::new()),
    };
    let mut code = match code {
        Ok(code) => code,
        Err(error) => {
            wipe(&mut password);
            return Err(error);
        }
    };
    let body = if password.len() <= 128 && code.len() <= 64 {
        Ok(login_body(args.actor, &password, &code))
    } else {
        Err(CommandError::InvalidCredential)
    };
    wipe(&mut password);
    wipe(&mut code);
    body
}

fn login_body(username: &str, password: &str, code: &str) -> String {
    // Sized so the text never moves while it is written, leaving no unwiped copy behind.
    let capacity = 64 + 6 * (username.len() + password.len() + code.len());
    let mut json = sibuna_json::Writer::new(String::with_capacity(capacity));
    // Writing into a String cannot fail.
    let _ = json
        .begin_object()
        .and_then(|()| json.key("username"))
        .and_then(|()| json.string(username))
        .and_then(|()| json.key("password"))
        .and_then(|()| json.string(password))
        .and_then(|()| json.key("code"))
        .and_then(|()| json.string(code))
        .and_then(|()| json.end_object());
    json.into_inner()
}

/// Keeps the one session cookie of a sign-in reply: `__sibuna_console=` and 64
/// hexadecimal digits.
fn capture_cookie(session: &mut Session, reply: &Response) -> Result<(), CommandError> {
    const PREFIX: &str = "__sibuna_console=";
    let mut found = None;
    for value in reply.headers("Set-Cookie") {
        let Some(cookie) = value.split(';').next().filter(|cookie| cookie.starts_with(PREFIX))
        else {
            continue;
        };
        let token = cookie.get(PREFIX.len()..).unwrap_or_default();
        let valid = token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit());
        if found.is_some() || !valid {
            return Err(CommandError::InvalidResponse);
        }
        found = Some(cookie.to_owned());
    }
    session.cookie = found.ok_or(CommandError::InvalidResponse)?;
    Ok(())
}

/// Reads a credential from the private file at `path`: a regular file smaller than
/// `capacity` bytes that neither the group nor others may access. One line end is
/// trimmed. The caller wipes the result.
///
/// Fails with [`CommandError::CredentialFile`] when the file is missing, not a regular file
/// or too large, [`CommandError::CredentialPermissions`] when others may access it, and
/// [`CommandError::InvalidCredential`] when it is empty, too long or not UTF-8.
///
/// The permission check needs Unix mode bits. On Windows the file's ACL is not inspected:
/// keeping credential files readable only by their user is the operator's job there.
fn read_secret(path: &str, capacity: usize) -> Result<String, CommandError> {
    check_file(&std::fs::metadata(path).map_err(|_| CommandError::CredentialFile)?, capacity)?;
    let mut file = File::open(path).map_err(|_| CommandError::CredentialFile)?;
    check_file(&file.metadata().map_err(|_| CommandError::CredentialFile)?, capacity)?;
    let mut buffer = vec![0u8; capacity];
    let mut length = 0;
    let read = loop {
        match file.read(buffer.get_mut(length..).unwrap_or_default()) {
            Ok(0) => break Ok(()),
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break Err(CommandError::CredentialFile),
        }
        if length == capacity {
            break Err(CommandError::InvalidCredential);
        }
    };
    let text = read.and_then(|()| {
        let bytes = buffer.get(..length).unwrap_or_default();
        let end =
            bytes.iter().rposition(|byte| !matches!(byte, b'\r' | b'\n')).map_or(0, |at| at + 1);
        let value = std::str::from_utf8(bytes.get(..end).unwrap_or_default());
        value
            .ok()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(CommandError::InvalidCredential)
    });
    ct::zeroize(&mut buffer);
    text
}

fn check_file(metadata: &std::fs::Metadata, capacity: usize) -> Result<(), CommandError> {
    if !metadata.is_file() || metadata.len() >= capacity as u64 {
        return Err(CommandError::CredentialFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CommandError::CredentialPermissions);
        }
    }
    Ok(())
}

/// Wipes and empties `text`.
fn wipe(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    ct::zeroize(&mut bytes);
}

/// Writes a validated reply and a line end, and flushes.
///
/// Fails with [`CommandError::Write`].
fn emit(out: &mut dyn Write, bytes: &[u8]) -> Result<(), CommandError> {
    out.write_all(bytes)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(CommandError::Write)
}

/// A member value of a request body.
#[derive(Clone, Copy, Debug)]
enum Field<'a> {
    /// A JSON string.
    Text(&'a str),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// An array of strings.
    Texts(&'a [&'a str]),
}

/// Writes the JSON object of `members`, in order.
fn body(members: &[(&str, Field<'_>)]) -> String {
    let mut json = sibuna_json::Writer::new(String::new());
    let mut write = || -> fmt::Result {
        json.begin_object()?;
        for (name, value) in members {
            json.key(name)?;
            match value {
                Field::Text(text) => json.string(text)?,
                Field::Bool(flag) => json.bool(*flag)?,
                Field::Null => json.null()?,
                Field::Texts(texts) => {
                    json.begin_array()?;
                    for text in *texts {
                        json.string(text)?;
                    }
                    json.end_array()?;
                }
            }
        }
        json.end_object()
    };
    // Writing into a String cannot fail.
    let _ = write();
    json.into_inner()
}

#[cfg(test)]
mod tests;

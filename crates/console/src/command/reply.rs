//! Reply validation (Zig's `console_command_reply.zig` and
//! `console_command_token_reply.zig`): a command prints a reply only after it decoded as
//! exactly the expected contract. Error pages, unexpected members and anything that could
//! smuggle a credential or digest into redirected output never reach the output; the one
//! secret a successful reply may carry (a temporary password or a new token) is the reason
//! the command ran. Large counters stay decimal strings, because the reply's bytes are
//! printed, not re-encoded.

use sibuna_console_protocol::codec::{self, Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::{Role, tokens, users, valid_username};
use sibuna_json::Value;

use super::CommandError;
use super::args::{Args, Kind};

/// The largest id or revision a reply may carry.
const MAX: u64 = i64::MAX as u64;

fn positive(value: u64) -> bool {
    value != 0 && value <= MAX
}

fn decode<T: Decode>(bytes: &[u8]) -> Result<T, CommandError> {
    codec::from_json(bytes).map_err(|_| CommandError::InvalidResponse)
}

fn ensure(condition: bool) -> Result<(), CommandError> {
    if condition { Ok(()) } else { Err(CommandError::InvalidResponse) }
}

/// The reply of a sign-in.
#[derive(Debug)]
pub struct Login {
    /// The account id.
    pub user: u64,
    /// The account's role.
    pub role: Role,
    /// The password must be changed first.
    pub must_change: bool,
    /// A second factor must be enrolled first.
    pub totp_required: bool,
    /// The session's CSRF token, 64 hexadecimal digits.
    pub csrf: String,
}

impl Decode for Login {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Login, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let user = fields.required("user")?;
        let _: Option<u32> = fields.or_default("node")?;
        let login = Login {
            user,
            role: fields.required("role")?,
            must_change: fields.required("must_change")?,
            totp_required: fields.required("totp_required")?,
            csrf: fields.required("csrf")?,
        };
        fields.finish()?;
        Ok(login)
    }
}

/// Decodes a sign-in reply and checks the account id and CSRF token.
///
/// Fails with [`CommandError::InvalidResponse`] for anything else.
pub fn login(bytes: &[u8]) -> Result<Login, CommandError> {
    let login: Login = decode(bytes)?;
    let hex = login.csrf.len() == 64 && login.csrf.bytes().all(|byte| byte.is_ascii_hexdigit());
    ensure(hex && login.user != 0)?;
    Ok(login)
}

/// `{"saved":<bool>,"temporary_password":<text>|null,"password_expires":<n>}`.
struct Saved {
    saved: bool,
    temporary_password: Option<String>,
    password_expires: u64,
}

impl Decode for Saved {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Saved, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let saved = Saved {
            saved: fields.required("saved")?,
            temporary_password: fields.required("temporary_password")?,
            password_expires: fields.required("password_expires")?,
        };
        fields.finish()?;
        Ok(saved)
    }
}

/// Checks the reply of an account command (Zig's `console_command_reply.validate`).
///
/// Fails with [`CommandError::InvalidResponse`] when the reply breaks its contract.
pub fn account(args: &Args<'_>, bytes: &[u8]) -> Result<(), CommandError> {
    if args.kind == Kind::Users {
        let page: users::Page = decode(bytes)?;
        let mut previous = args.after;
        for row in &page.rows {
            let valid = row.id > previous && row.id <= MAX && row.revision != 0;
            ensure(valid && valid_username(row.username.as_str()))?;
            previous = row.id;
        }
        return ensure(page.next.is_none_or(|next| !page.rows.is_empty() && next == previous));
    }
    let saved: Saved = decode(bytes)?;
    ensure(saved.saved)?;
    if !matches!(args.kind, Kind::Add | Kind::Password) {
        return ensure(saved.temporary_password.is_none() && saved.password_expires == 0);
    }
    let secret = saved.temporary_password.ok_or(CommandError::InvalidResponse)?;
    let hex = secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit());
    ensure(hex && saved.password_expires != 0)
}

/// `{"saved":<bool>,"id":<id>,"token":"<hex>","expires":<seconds>|null}`.
struct Created {
    saved: bool,
    id: u64,
    token: String,
    expires: Option<u64>,
}

impl Decode for Created {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Created, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let created = Created {
            saved: fields.required("saved")?,
            id: fields.required("id")?,
            token: fields.required("token")?,
            expires: fields.required("expires")?,
        };
        fields.finish()?;
        Ok(created)
    }
}

/// `{"saved":<bool>,"id":<id>}`.
struct TokenSaved {
    saved: bool,
    id: u64,
}

impl Decode for TokenSaved {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<TokenSaved, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let saved = TokenSaved { saved: fields.required("saved")?, id: fields.required("id")? };
        fields.finish()?;
        Ok(saved)
    }
}

/// Checks the reply of a token command (Zig's `console_command_token_reply.validate`):
/// catalog rows with consistent authority and distinct scopes, a new token shown once with
/// the requested expiry, or the revoked token's id.
///
/// Fails with [`CommandError::InvalidResponse`] when the reply breaks its contract.
pub fn token(args: &Args<'_>, bytes: &[u8]) -> Result<(), CommandError> {
    match args.kind {
        Kind::Tokens => token_page(args, &decode(bytes)?),
        Kind::MintToken => {
            let created: Created = decode(bytes)?;
            let hex = created.token.len() == 64
                && created.token.bytes().all(|byte| byte.is_ascii_hexdigit());
            ensure(created.saved && positive(created.id) && hex && created.expires == args.expires)
        }
        _ => {
            let saved: TokenSaved = decode(bytes)?;
            ensure(saved.saved && saved.id == args.target)
        }
    }
}

fn token_page(args: &Args<'_>, page: &tokens::Page) -> Result<(), CommandError> {
    let mut previous = args.after;
    for row in &page.rows {
        let authority = row.id > previous
            && positive(row.id)
            && positive(row.revision)
            && positive(row.created_by)
            && row.created_at <= MAX
            && tokens::valid_label(row.label.as_str())
            && !(row.disabled && row.active);
        let expiry =
            row.expires.is_none_or(|expires| expires > row.created_at && positive(expires));
        ensure(authority && expiry && tokens::valid_scopes(row.scopes, row.role))?;
        previous = row.id;
    }
    let full = page.rows.len() == tokens::PAGE_ROWS;
    ensure(page.next.is_none_or(|next| full && next == previous))
}

/// Checks the reply of `policies import`: `{"committed":<revision>}`, optionally with the
/// applied revision, as decimal strings or numbers.
///
/// Fails with [`CommandError::InvalidResponse`] for anything else.
pub fn import(bytes: &[u8]) -> Result<(), CommandError> {
    struct Imported;
    impl Decode for Imported {
        fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Imported, DecodeError> {
            let mut fields = Fields::new(value, path)?;
            let _: u64 = fields.required("committed")?;
            let _: Option<u64> = fields.or_default("applied")?;
            fields.finish()?;
            Ok(Imported)
        }
    }
    decode::<Imported>(bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::args::parse;

    fn args(kind: &[&'static str], extra: &[&'static str]) -> Args<'static> {
        let mut words = kind.to_vec();
        words.extend_from_slice(&["--origin", "http://127.0.0.1:1", "--username", "admin"]);
        words.extend_from_slice(&["--password-file", "p"]);
        words.extend_from_slice(extra);
        parse(&words).unwrap()
    }

    // console_command_reply.zig: "CLI replies retain decimal counters and refuse unexpected
    // sensitive fields".
    #[test]
    fn account_replies_keep_counters_and_refuse_unexpected_fields() {
        let users = args(&["users"], &[]);
        let row = r#"{"id":"9007199254740993","username":"viewer","role":"viewer",
            "revision":"9007199254740995","disabled":false,"must_change":false,
            "totp_enabled":false,"password_expires":0,"last_login":null}"#;
        let page = format!("{{\"version\":1,\"rows\":[{row}],\"next\":null}}");
        assert!(account(&users, page.as_bytes()).is_ok());
        let unsupported = br#"{"version":2,"rows":[],"next":null}"#;
        assert!(account(&users, unsupported).is_err());
        let sensitive = br#"{"version":1,"rows":[],"next":null,"password_hash":"private"}"#;
        assert!(account(&users, sensitive).is_err());
        let repeated = format!("{{\"version\":1,\"rows\":[{row},{row}],\"next\":null}}");
        assert!(account(&users, repeated.as_bytes()).is_err());
        let saved = br#"{"saved":true,"temporary_password":null,"password_expires":"0"}"#;
        let tail = ["--revision", "1", "--role", "viewer", "--disabled", "false"];
        let access = args(&["set-user", "2"], &tail);
        assert!(account(&access, saved).is_ok());
        let password = args(&["reset-password", "2"], &["--revision", "1"]);
        assert!(account(&password, saved).is_err());
        let minted = format!(
            "{{\"saved\":true,\"temporary_password\":\"{}\",\"password_expires\":\"7\"}}",
            "a".repeat(64)
        );
        assert!(account(&password, minted.as_bytes()).is_ok());
        assert!(account(&access, minted.as_bytes()).is_err());
    }

    // console_command_token_reply.zig: "token CLI output checks authority, scope uniqueness
    // and one-time disclosure".
    #[test]
    fn token_replies_check_authority_scopes_and_one_time_disclosure() {
        let catalog = args(&["tokens"], &[]);
        let row = r#"{"id":"9007199254740993","revision":"2","label":"deploy","role":"operator",
            "scopes":["policy_read","policy_write"],"created_by":"1","created_at":"12",
            "expires":null,"disabled":false,"active":true}"#;
        let page = format!("{{\"version\":1,\"rows\":[{row}],\"next\":null}}");
        assert!(token(&catalog, page.as_bytes()).is_ok());
        let sensitive = br#"{"version":1,"rows":[],"next":null,"digest":"redacted"}"#;
        assert!(token(&catalog, sensitive).is_err());
        let repeated = format!("{{\"version\":1,\"rows\":[{row},{row}],\"next\":null}}");
        assert!(token(&catalog, repeated.as_bytes()).is_err());
        let created = format!(
            "{{\"saved\":true,\"id\":\"1\",\"token\":\"{}\",\"expires\":null}}",
            "a".repeat(64)
        );
        let mint = args(&["mint-token", "deploy"], &["--scope", "stats_read"]);
        assert!(token(&mint, created.as_bytes()).is_ok());
        assert!(token(&catalog, created.as_bytes()).is_err());
        let expiring = Args { expires: Some(999), ..mint.clone() };
        assert!(token(&expiring, created.as_bytes()).is_err());
        let saved = br#"{"saved":true,"id":"2"}"#;
        let revoke = args(&["revoke-token", "2"], &["--revision", "1"]);
        assert!(token(&revoke, saved).is_ok());
        let other = Args { target: 3, ..revoke };
        assert!(token(&other, saved).is_err());
    }

    #[test]
    fn login_and_import_replies_are_exact() {
        let csrf = "b".repeat(64);
        let reply = format!(
            "{{\"user\":\"9007199254740993\",\"role\":\"admin\",\"must_change\":false,\
             \"totp_required\":false,\"csrf\":\"{csrf}\"}}"
        );
        let parsed = login(reply.as_bytes()).unwrap();
        assert_eq!((parsed.user, parsed.role), (9_007_199_254_740_993, Role::Admin));
        let with_node = reply.replace("{\"user\"", "{\"node\":1,\"user\"");
        assert!(login(with_node.as_bytes()).is_ok());
        assert!(login(reply.replace(&csrf, "short").as_bytes()).is_err());
        assert!(login(reply.replace("\"9007199254740993\"", "0").as_bytes()).is_err());
        assert!(login(reply.replace("}", ",\"x\":1}").as_bytes()).is_err());
        assert!(import(br#"{"committed":"9"}"#).is_ok());
        assert!(import(br#"{"committed":"9","applied":"8"}"#).is_ok());
        assert!(import(br#"{"ok":true}"#).is_err());
    }
}

//! Command arguments (Zig's `console_command_args.zig`). They borrow the words of the
//! command line for the length of the command. No credential is accepted as an argument:
//! passwords, second-factor codes and tokens come from private files, which keeps them out
//! of process listings and shell histories.

use std::fmt;

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{Role, valid_username};
use sibuna_geoip::Provider;

/// The most words a command takes.
pub const MAX_WORDS: usize = 32;
/// The longest option value.
pub const MAX_VALUE: usize = 1024;
/// The longest GeoIP wait, in seconds.
pub const MAX_TIMEOUT: u32 = 86_400;

/// Which command runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `users`: one page of accounts.
    Users,
    /// `add-user <name>`: creates an account with a temporary password.
    Add,
    /// `set-user <id>`: sets the role and the disabled flag.
    Access,
    /// `reset-password <id>`: sets a temporary password.
    Password,
    /// `revoke-sessions <id>`: ends every session of the account.
    Revoke,
    /// `geoip status`.
    GeoStatus,
    /// `geoip update`: imports a publisher version and waits for it.
    GeoUpdate,
    /// `tokens`: one page of tokens.
    Tokens,
    /// `mint-token <label>`.
    MintToken,
    /// `revoke-token <id>`.
    RevokeToken,
    /// `remove-token <id>`.
    RemoveToken,
    /// `policies export`: every managed rule document as one JSON array.
    PoliciesExport,
    /// `policies import --file <path>`: replaces every managed rule with the file's array.
    PoliciesImport,
}

impl Kind {
    /// Returns true for the token commands, which need an administrator's password sign-in.
    pub fn manages_tokens(self) -> bool {
        matches!(self, Kind::Tokens | Kind::MintToken | Kind::RevokeToken | Kind::RemoveToken)
    }

    /// Returns true for the commands that change one row at a known revision.
    fn needs_revision(self) -> bool {
        matches!(
            self,
            Kind::Access | Kind::Password | Kind::Revoke | Kind::RevokeToken | Kind::RemoveToken
        )
    }

    /// Returns true for commands that only read.
    pub fn is_read_only(self) -> bool {
        matches!(self, Kind::Users | Kind::GeoStatus | Kind::PoliciesExport)
    }

    /// Returns the operation name `users/change` takes for an account change.
    pub fn operation(self) -> &'static str {
        match self {
            Kind::Access => "access",
            Kind::Password => "password",
            _ => "revoke",
        }
    }
}

/// A parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args<'a> {
    /// The command.
    pub kind: Kind,
    /// The console's origin, `--origin`.
    pub origin: &'a str,
    /// The signing-in account, `--username`.
    pub actor: &'a str,
    /// The private file holding the password, `--password-file`.
    pub password_file: &'a str,
    /// The private file holding a TOTP or recovery code, `--factor-file`.
    pub factor_file: Option<&'a str>,
    /// The private file holding a bearer token, `--token-file`.
    pub token_file: Option<&'a str>,
    /// Scope bits of `mint-token`, `--scope` (repeated).
    pub scopes: u32,
    /// The expiry of `mint-token`, `--expires`, Unix seconds.
    pub expires: Option<u64>,
    /// The new account's name, or the new token's label.
    pub username: &'a str,
    /// The account or token a change names.
    pub target: u64,
    /// The revision a change expects, `--revision`.
    pub revision: u64,
    /// The page cursor, `--after`.
    pub after: u64,
    /// The role, `--role`.
    pub role: Role,
    /// The disabled flag of `set-user`, `--disabled`.
    pub disabled: bool,
    /// The GeoIP publisher, `--provider` (or `dbip` through `--month`).
    pub provider: &'a str,
    /// The publisher version, `--version` or `--month`.
    pub version: &'a str,
    /// `--month` was given.
    pub month_alias: bool,
    /// The operator's SHA-256 of the source, `--checksum`.
    pub checksum: &'a str,
    /// How long `geoip update` waits, in seconds, `--timeout`.
    pub timeout: u32,
    /// The policy set of `policies import`, `--file`.
    pub file: &'a str,
}

impl Args<'_> {
    fn new(kind: Kind) -> Args<'static> {
        Args {
            kind,
            origin: "",
            actor: "",
            password_file: "",
            factor_file: None,
            token_file: None,
            scopes: 0,
            expires: None,
            username: "",
            target: 0,
            revision: 0,
            after: 0,
            role: Role::Viewer,
            disabled: false,
            provider: "user-country",
            version: "",
            month_alias: false,
            checksum: "",
            timeout: 1200,
            file: "",
        }
    }
}

/// Why a command line was refused (Zig's error names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArgsError {
    /// No words, or more than 32.
    InvalidArguments,
    /// The first word names no command.
    UnknownCommand,
    /// The command's operand is missing.
    MissingTarget,
    /// `add-user` names an invalid account name.
    InvalidUsername,
    /// `--origin`, or `--username` and `--password-file`, are missing.
    AuthenticationRequired,
    /// `set-user` needs both `--role` and `--disabled`.
    AccessFieldsRequired,
    /// The change needs `--revision`.
    RevisionRequired,
    /// An option has no value.
    MissingValue,
    /// An option is repeated.
    DuplicateOption,
    /// An option is unknown.
    UnknownOption,
    /// An option's value is invalid.
    InvalidValue,
    /// The origin is longer than 255 bytes.
    InvalidOrigin,
    /// The option does not belong to this command.
    UnexpectedOption,
    /// The role is not `viewer`, `operator` or `admin`.
    InvalidRole,
    /// A number is not 1 to 19 digits within the signed 64-bit range.
    InvalidNumber,
}

impl ArgsError {
    /// Returns the error's name, as Zig printed it.
    pub fn name(self) -> &'static str {
        match self {
            ArgsError::InvalidArguments => "InvalidArguments",
            ArgsError::UnknownCommand => "UnknownCommand",
            ArgsError::MissingTarget => "MissingTarget",
            ArgsError::InvalidUsername => "InvalidUsername",
            ArgsError::AuthenticationRequired => "AuthenticationRequired",
            ArgsError::AccessFieldsRequired => "AccessFieldsRequired",
            ArgsError::RevisionRequired => "RevisionRequired",
            ArgsError::MissingValue => "MissingValue",
            ArgsError::DuplicateOption => "DuplicateOption",
            ArgsError::UnknownOption => "UnknownOption",
            ArgsError::InvalidValue => "InvalidValue",
            ArgsError::InvalidOrigin => "InvalidOrigin",
            ArgsError::UnexpectedOption => "UnexpectedOption",
            ArgsError::InvalidRole => "InvalidRole",
            ArgsError::InvalidNumber => "InvalidNumber",
        }
    }
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for ArgsError {}

/// The options, in Zig's order; the index is the bit of the seen-set.
const OPTIONS: [&str; 17] = [
    "--origin",
    "--username",
    "--password-file",
    "--factor-file",
    "--role",
    "--disabled",
    "--revision",
    "--after",
    "--month",
    "--checksum",
    "--timeout",
    "--token-file",
    "--scope",
    "--expires",
    "--provider",
    "--version",
    "--file",
];
const ROLE: usize = 4;
const DISABLED: usize = 5;
const SCOPE: usize = 12;

/// Parses the words after `sibuna console`.
///
/// Fails with the [`ArgsError`] of the first problem found.
pub fn parse<'a>(words: &[&'a str]) -> Result<Args<'a>, ArgsError> {
    if words.is_empty() || words.len() > MAX_WORDS {
        return Err(ArgsError::InvalidArguments);
    }
    let kind = command(words)?;
    let mut args = Args::new(kind);
    let grouped = matches!(
        kind,
        Kind::GeoStatus | Kind::GeoUpdate | Kind::PoliciesExport | Kind::PoliciesImport
    );
    let mut index = if grouped { 2 } else { 1 };
    if kind == Kind::Add || kind == Kind::MintToken || kind.needs_revision() {
        let operand = *words.get(1).ok_or(ArgsError::MissingTarget)?;
        match kind {
            Kind::Add if !valid_username(operand) => return Err(ArgsError::InvalidUsername),
            Kind::MintToken if !tokens::valid_label(operand) => {
                return Err(ArgsError::InvalidValue);
            }
            Kind::Add | Kind::MintToken => args.username = operand,
            _ => args.target = number(operand, false)?,
        }
        index += 1;
    }
    let mut seen = 0u32;
    let mut options = words.get(index..).unwrap_or_default().chunks(2);
    for pair in &mut options {
        let [name, value] = *pair else { return Err(ArgsError::MissingValue) };
        let option = OPTIONS.iter().position(|known| *known == name);
        let option = option.ok_or(ArgsError::UnknownOption)?;
        let bit = 1u32 << option;
        if seen & bit != 0 && option != SCOPE {
            return Err(ArgsError::DuplicateOption);
        }
        seen |= bit;
        assign(&mut args, option, value)?;
    }
    check(&args, seen)?;
    Ok(args)
}

/// The checks that need every option.
fn check(args: &Args<'_>, seen: u32) -> Result<(), ArgsError> {
    authentication(args)?;
    if args.kind == Kind::MintToken && !tokens::valid_scopes(args.scopes, args.role) {
        return Err(ArgsError::InvalidValue);
    }
    let access = (1 << ROLE) | (1 << DISABLED);
    if args.kind == Kind::Access && seen & access != access {
        return Err(ArgsError::AccessFieldsRequired);
    }
    if args.kind.needs_revision() && args.revision == 0 {
        return Err(ArgsError::RevisionRequired);
    }
    if args.kind == Kind::GeoUpdate {
        geographic_version(args)?;
    }
    if args.kind == Kind::PoliciesImport && args.file.is_empty() {
        return Err(ArgsError::MissingTarget);
    }
    Ok(())
}

fn command(words: &[&str]) -> Result<Kind, ArgsError> {
    let first = *words.first().ok_or(ArgsError::InvalidArguments)?;
    let second = words.get(1).copied();
    match first {
        "geoip" => match second.ok_or(ArgsError::MissingTarget)? {
            "status" => Ok(Kind::GeoStatus),
            "update" => Ok(Kind::GeoUpdate),
            _ => Err(ArgsError::UnknownCommand),
        },
        "policies" => match second.ok_or(ArgsError::MissingTarget)? {
            "export" => Ok(Kind::PoliciesExport),
            "import" => Ok(Kind::PoliciesImport),
            _ => Err(ArgsError::UnknownCommand),
        },
        "users" => Ok(Kind::Users),
        "add-user" => Ok(Kind::Add),
        "set-user" => Ok(Kind::Access),
        "reset-password" => Ok(Kind::Password),
        "revoke-sessions" => Ok(Kind::Revoke),
        "tokens" => Ok(Kind::Tokens),
        "mint-token" => Ok(Kind::MintToken),
        "revoke-token" => Ok(Kind::RevokeToken),
        "remove-token" => Ok(Kind::RemoveToken),
        _ => Err(ArgsError::UnknownCommand),
    }
}

fn assign<'a>(args: &mut Args<'a>, option: usize, value: &'a str) -> Result<(), ArgsError> {
    if value.is_empty() || value.len() > MAX_VALUE {
        return Err(ArgsError::InvalidValue);
    }
    let kind = args.kind;
    match OPTIONS.get(option).copied().unwrap_or_default() {
        "--origin" if value.len() > 255 => return Err(ArgsError::InvalidOrigin),
        "--origin" => args.origin = value,
        "--username" => args.actor = value,
        "--password-file" => args.password_file = value,
        "--factor-file" => args.factor_file = Some(value),
        "--token-file" => args.token_file = Some(value),
        "--scope" | "--expires" => token_option(args, option == SCOPE, value)?,
        "--role" => {
            if !matches!(kind, Kind::Add | Kind::Access | Kind::MintToken) {
                return Err(ArgsError::UnexpectedOption);
            }
            args.role = Role::from_name(value).ok_or(ArgsError::InvalidRole)?;
        }
        "--disabled" => {
            if kind != Kind::Access {
                return Err(ArgsError::UnexpectedOption);
            }
            args.disabled = match value {
                "true" => true,
                "false" => false,
                _ => return Err(ArgsError::InvalidValue),
            };
        }
        "--revision" => {
            if !kind.needs_revision() {
                return Err(ArgsError::UnexpectedOption);
            }
            args.revision = number(value, false)?;
            if args.revision == i64::MAX as u64 {
                return Err(ArgsError::InvalidNumber);
            }
        }
        "--after" => {
            if !matches!(kind, Kind::Users | Kind::Tokens) {
                return Err(ArgsError::UnexpectedOption);
            }
            args.after = number(value, true)?;
        }
        "--file" if kind != Kind::PoliciesImport => return Err(ArgsError::UnexpectedOption),
        "--file" => args.file = value,
        name => geographic(args, name, value)?,
    }
    Ok(())
}

/// Parses 1 to 19 digits within the signed 64-bit range; zero only when `zero` allows it.
fn number(value: &str, zero: bool) -> Result<u64, ArgsError> {
    if value.is_empty() || value.len() > 19 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArgsError::InvalidNumber);
    }
    let parsed = value.parse::<u64>().map_err(|_| ArgsError::InvalidNumber)?;
    if (!zero && parsed == 0) || parsed > i64::MAX as u64 {
        return Err(ArgsError::InvalidNumber);
    }
    Ok(parsed)
}

fn geographic<'a>(args: &mut Args<'a>, name: &str, value: &'a str) -> Result<(), ArgsError> {
    if args.kind != Kind::GeoUpdate {
        return Err(ArgsError::UnexpectedOption);
    }
    match name {
        "--month" => {
            if !Provider::Dbip.is_version_valid(value) {
                return Err(ArgsError::InvalidValue);
            }
            (args.version, args.provider, args.month_alias) = (value, "dbip", true);
        }
        "--version" => args.version = value,
        "--provider" => {
            Provider::parse(value).ok_or(ArgsError::InvalidValue)?;
            args.provider = value;
        }
        "--checksum" => {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ArgsError::InvalidValue);
            }
            args.checksum = value;
        }
        "--timeout" => {
            let seconds = number(value, false)?;
            args.timeout = u32::try_from(seconds)
                .ok()
                .filter(|&seconds| seconds <= MAX_TIMEOUT)
                .ok_or(ArgsError::InvalidValue)?;
        }
        _ => return Err(ArgsError::UnknownOption),
    }
    Ok(())
}

/// `--month` is the DB-IP alias; it cannot be combined with another provider.
fn geographic_version(args: &Args<'_>) -> Result<(), ArgsError> {
    if args.version.is_empty() {
        return Err(ArgsError::MissingValue);
    }
    let provider = Provider::parse(args.provider).ok_or(ArgsError::InvalidValue)?;
    if (args.month_alias && provider != Provider::Dbip) || !provider.is_version_valid(args.version)
    {
        return Err(ArgsError::InvalidValue);
    }
    Ok(())
}

/// A token file excludes a password sign-in and the token commands; otherwise an account
/// name and a password file are required.
fn authentication(args: &Args<'_>) -> Result<(), ArgsError> {
    if args.origin.is_empty() {
        return Err(ArgsError::AuthenticationRequired);
    }
    if args.token_file.is_some() {
        if !args.actor.is_empty() || !args.password_file.is_empty() || args.factor_file.is_some() {
            return Err(ArgsError::UnexpectedOption);
        }
        if args.kind.manages_tokens() {
            return Err(ArgsError::UnexpectedOption);
        }
        return Ok(());
    }
    if !valid_username(args.actor) || args.password_file.is_empty() {
        return Err(ArgsError::AuthenticationRequired);
    }
    Ok(())
}

fn token_option(args: &mut Args<'_>, scope: bool, value: &str) -> Result<(), ArgsError> {
    if args.kind != Kind::MintToken {
        return Err(ArgsError::UnexpectedOption);
    }
    if !scope {
        args.expires = Some(number(value, false)?);
        return Ok(());
    }
    let scope = Scope::from_name(value).ok_or(ArgsError::InvalidValue)?;
    if args.scopes & scope.bit() != 0 {
        return Err(ArgsError::DuplicateOption);
    }
    args.scopes |= scope.bit();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: [&str; 6] =
        ["--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private"];

    fn words<'a>(head: &[&'a str], tail: &[&'a str]) -> Vec<&'a str> {
        let mut all = head.to_vec();
        all.extend_from_slice(&AUTH);
        all.extend_from_slice(tail);
        all
    }

    // console_command_args.zig: "account CLI requires explicit authority, exact revisions
    // and complete access edits".
    #[test]
    fn account_commands_require_authority_revisions_and_complete_edits() {
        let tail = ["--revision", "9007199254740995", "--role", "operator", "--disabled", "false"];
        let args = parse(&words(&["set-user", "9007199254740993"], &tail)).unwrap();
        assert_eq!((args.target, args.revision), (9_007_199_254_740_993, 9_007_199_254_740_995));
        assert_eq!(args.role, Role::Operator);
        let parse = |head: &[&str], tail: &[&str]| parse(&words(head, tail)).map(|_| ());
        assert_eq!(parse(&["reset-password", "2"], &[]), Err(ArgsError::RevisionRequired));
        assert_eq!(parse(&["set-user", "2"], &[]), Err(ArgsError::AccessFieldsRequired));
        assert_eq!(parse(&["users"], &["--role", "admin"]), Err(ArgsError::UnexpectedOption));
        assert_eq!(parse(&["users"], &["--username", "x"]), Err(ArgsError::DuplicateOption));
        assert_eq!(parse(&["reset-password", "-1"], &[]), Err(ArgsError::InvalidNumber));
        assert_eq!(parse(&["users"], &["--after", "1e3"]), Err(ArgsError::InvalidNumber));
        assert_eq!(parse(&["users"], &["--after"]), Err(ArgsError::MissingValue));
        assert_eq!(parse(&["users"], &["--colour", "x"]), Err(ArgsError::UnknownOption));
        assert_eq!(parse(&["delete"], &[]), Err(ArgsError::UnknownCommand));
        assert_eq!(parse(&["add-user", "a b"], &[]), Err(ArgsError::InvalidUsername));
        let revision = ["--revision", "9223372036854775807"];
        assert_eq!(parse(&["revoke-sessions", "2"], &revision), Err(ArgsError::InvalidNumber));
        assert_eq!(super::parse(&["users"]), Err(ArgsError::AuthenticationRequired));
        assert_eq!(super::parse(&[]), Err(ArgsError::InvalidArguments));
    }

    // console_command_args.zig: "GeoIP CLI requires a bounded explicit publisher version and
    // scoped options".
    #[test]
    fn geoip_commands_require_a_bounded_explicit_version() {
        let parse = |tail: &[&'static str]| parse(&words(&["geoip", "update"], tail));
        let args = parse(&["--month", "2026-09", "--timeout", "60"]).unwrap();
        assert_eq!((args.kind, args.timeout, args.provider), (Kind::GeoUpdate, 60, "dbip"));
        let status = super::parse(&words(&["geoip", "status"], &[])).unwrap();
        assert_eq!(status.kind, Kind::GeoStatus);
        assert_eq!(parse(&[]), Err(ArgsError::MissingValue));
        assert_eq!(parse(&["--month", "2026-13"]), Err(ArgsError::InvalidValue));
        let daily = parse(&["--provider", "user-country", "--version", "2026-09-09"]).unwrap();
        assert_eq!((daily.provider, daily.version), ("user-country", "2026-09-09"));
        assert_eq!(parse(&["--version", "2026-09"]), Err(ArgsError::InvalidValue));
        let mixed = ["--month", "2026-09", "--provider", "user-country"];
        assert_eq!(parse(&mixed), Err(ArgsError::InvalidValue));
        let unknown = ["--provider", "maxmind", "--version", "2026-09-09"];
        assert_eq!(parse(&unknown), Err(ArgsError::InvalidValue));
        let month = ["--month", "2026-09"];
        assert_eq!(super::parse(&words(&["users"], &month)), Err(ArgsError::UnexpectedOption));
        assert_eq!(parse(&["--revision", "1"]), Err(ArgsError::UnexpectedOption));
        assert_eq!(
            parse(&["--month", "2026-09", "--timeout", "86401"]),
            Err(ArgsError::InvalidValue)
        );
    }

    // console_command_args.zig: "token CLI rejects delegation, mixed credentials and
    // ambiguous capabilities".
    #[test]
    fn token_commands_reject_delegation_mixed_credentials_and_ambiguity() {
        let tail =
            ["--scope", "policy_read", "--scope", "policy_write", "--expires", "9007199254740993"];
        let args = parse(&words(&["mint-token", "deploy", "--role", "operator"], &tail)).unwrap();
        assert_eq!(args.expires, Some(9_007_199_254_740_993));
        assert_eq!(args.scopes, Scope::PolicyRead.bit() | Scope::PolicyWrite.bit());
        let parse = |head: &[&str], tail: &[&str]| parse(&words(head, tail)).map(|_| ());
        assert_eq!(parse(&["mint-token", "empty"], &[]), Err(ArgsError::InvalidValue));
        let above = ["--scope", "users_write"];
        assert_eq!(parse(&["mint-token", "above-role"], &above), Err(ArgsError::InvalidValue));
        let twice = ["--scope", "stats_read", "--scope", "stats_read"];
        assert_eq!(parse(&["mint-token", "duplicate"], &twice), Err(ArgsError::DuplicateOption));
        let mixed = ["--token-file", "private-token"];
        assert_eq!(parse(&["users"], &mixed), Err(ArgsError::UnexpectedOption));
        let bearer =
            ["users", "--origin", "http://127.0.0.1:9443", "--token-file", "private-token"];
        assert_eq!(super::parse(&bearer).unwrap().token_file, Some("private-token"));
        let tokens = ["tokens", "--origin", "http://127.0.0.1:9443", "--token-file", "t"];
        assert_eq!(super::parse(&tokens), Err(ArgsError::UnexpectedOption));
        assert_eq!(parse(&["revoke-token", "1"], &[]), Err(ArgsError::RevisionRequired));
    }

    #[test]
    fn policy_commands_need_a_file_for_import() {
        let import = parse(&words(&["policies", "import"], &["--file", "set.json"]));
        assert_eq!(import.unwrap().file, "set.json");
        let missing = parse(&words(&["policies", "import"], &[]));
        assert_eq!(missing, Err(ArgsError::MissingTarget));
        let export = parse(&words(&["policies", "export"], &["--file", "x"]));
        assert_eq!(export, Err(ArgsError::UnexpectedOption));
        assert_eq!(parse(&["policies"]), Err(ArgsError::MissingTarget));
        assert_eq!(parse(&["policies", "delete"]), Err(ArgsError::UnknownCommand));
        let many = vec!["users"; 33];
        assert_eq!(parse(&many), Err(ArgsError::InvalidArguments));
    }
}

//! Command-line parsing for [`Config`].
//!
//! Every option is either recognised and valid or the whole command line is rejected: a
//! misspelled flag or an out-of-range value never silently keeps the default. A rejection
//! names the option, the value and what was expected, and renders as the daemon's
//! `INVALID COMMAND LINE` diagnostic.

use std::fmt;

use super::{Config, Mode, PowAlgorithm, TokenScheme};
use crate::diagnostic;
use crate::incident_heads::REDACTED;

/// Why a command line was rejected. The names are the Zig daemon's error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArgErrorKind {
    /// `--mode` names no mode, or was written as `--mode=<value>`.
    InvalidMode,
    /// `--mode` is the last argument.
    MissingMode,
    /// `--mode` (or `-m`) appears twice.
    DuplicateMode,
    /// The option is not recognised, or a flag was followed by a value.
    UnknownOption,
    /// An option that takes a value is the last argument.
    MissingValue,
    /// The value is malformed or out of range.
    InvalidValue,
    /// A Zaxonlite cluster option that SID 0011 removed.
    RemovedOption,
    /// Two options that exclude each other were both given.
    ConflictingOptions,
    /// An option requires another one that was not given.
    MissingOption,
}

impl ArgErrorKind {
    /// Returns the name the report shows after `Error:`, such as `UnknownOption`.
    pub fn name(self) -> &'static str {
        match self {
            ArgErrorKind::InvalidMode => "InvalidMode",
            ArgErrorKind::MissingMode => "MissingMode",
            ArgErrorKind::DuplicateMode => "DuplicateMode",
            ArgErrorKind::UnknownOption => "UnknownOption",
            ArgErrorKind::MissingValue => "MissingValue",
            ArgErrorKind::InvalidValue => "InvalidValue",
            ArgErrorKind::RemovedOption => "RemovedOption",
            ArgErrorKind::ConflictingOptions => "ConflictingOptions",
            ArgErrorKind::MissingOption => "MissingOption",
        }
    }

    /// Returns the hint the report ends with.
    pub fn hint(self) -> &'static str {
        match self {
            ArgErrorKind::UnknownOption => {
                "Check the spelling against sibuna --help; every option must be recognised, \
                 and flags take no value."
            }
            ArgErrorKind::MissingValue | ArgErrorKind::MissingMode => {
                "Supply a value after the option."
            }
            ArgErrorKind::DuplicateMode => "Give --mode once.",
            ArgErrorKind::RemovedOption => {
                "SID 0011 removed Zaxonlite clustering. Point every node at one PostgreSQL \
                 database with --database-url <url> and give each node a unique \
                 --cluster-node <id>."
            }
            ArgErrorKind::ConflictingOptions => {
                "Keep one of them: --data-dir stores one node's state in SQLite; \
                 --database-url or --database-url-file connects a cluster to PostgreSQL \
                 (SID 0011)."
            }
            ArgErrorKind::MissingOption => {
                "Give every node that shares the database a unique --cluster-node <id> \
                 (SID 0011)."
            }
            ArgErrorKind::InvalidMode | ArgErrorKind::InvalidValue => {
                "Correct the value; see sibuna --help for each option's range."
            }
        }
    }
}

impl fmt::Display for ArgErrorKind {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.name())
    }
}

/// A rejected command line: what went wrong and where.
///
/// `Display` renders the daemon's `INVALID COMMAND LINE` diagnostic, byte for byte as the
/// Zig daemon printed it (before its final newline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgError {
    /// What went wrong.
    pub kind: ArgErrorKind,
    /// The option at fault, as given.
    pub option: String,
    /// The value at fault; empty when there was none. A database URL is shown as
    /// `[redacted]`, because connection strings carry passwords.
    pub value: String,
    /// What the option accepts; empty when that says nothing useful.
    pub expected: &'static str,
}

impl fmt::Display for ArgError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut body = format!(
            "The daemon cannot start with this command line.\n\nOption:   {}\n",
            self.option
        );
        if !self.value.is_empty() {
            body.push_str(&format!("Value:    {}\n", self.value));
        }
        if !self.expected.is_empty() {
            body.push_str(&format!("Expected: {}\n", self.expected));
        }
        body.push_str(&format!("Error:    {}\n", self.kind.name()));
        diagnostic::render(out, "INVALID COMMAND LINE", &body, self.kind.hint())
    }
}

impl std::error::Error for ArgError {}

/// A fault found while applying one value, before the option and value are attached.
struct Fault {
    kind: ArgErrorKind,
    expected: &'static str,
}

impl Fault {
    fn invalid(expected: &'static str) -> Fault {
        Fault { kind: ArgErrorKind::InvalidValue, expected }
    }
}

/// Options that take a value. Flags are recognised by `Config::apply_flag` instead.
const VALUED_OPTIONS: &[&str] = &[
    "--port",
    "-p",
    "--host",
    "-h",
    "--upstream-host",
    "--upstream-port",
    "-u",
    "--difficulty",
    "-d",
    "--algorithm",
    "-a",
    "--posw-challenges",
    "--token-scheme",
    "--token-ttl",
    "--challenge-ttl",
    "--cookie-name",
    "--secret-file",
    "-s",
    "--policy-file",
    "-P",
    "--workers",
    "-w",
    "--max-connections",
    "--max-connections-per-ip",
    "--idle-timeout",
    "--websocket-idle-timeout",
    "--rate-limit",
    "--rate-window",
    "--challenge-rate-limit",
    "--ban-seconds",
    "--trusted-hops",
    "--ipv6-prefix",
    "--rate-table-cells",
    "--ban-table-slots",
    "--spent-tags",
    "--data-dir",
    "-D",
    "--database-url",
    "--database-url-file",
    "--cluster-node",
    "--storage-poll-ms",
];

/// Zaxonlite cluster options removed by SID 0011.
const REMOVED_OPTIONS: [&str; 6] = [
    "--cluster-listen",
    "--cluster-peer",
    "--cluster-secret-file",
    "--cluster-tls-cert",
    "--cluster-tls-key",
    "--cluster-tls-ca",
];

const EXPECTED_MODE: &str = "reverse_proxy or forward_auth";
const EXPECTED_CLUSTER: &str = "--database-url <url> with --cluster-node <id> (SID 0011)";
const EXPECTED_DATABASE_URL: &str = "a postgres:// or postgresql:// URL";

impl Config {
    /// Parses the daemon's command line (without the program name) into a configuration,
    /// starting from [`Config::default`]. It borrows `args` and copies the strings it keeps.
    ///
    /// Fails at the first fault with an [`ArgError`] naming the option and value: an
    /// unknown option, a missing or invalid value, a repeated `--mode`, a removed cluster
    /// option, or a storage combination that [`Config::check_storage`] rejects.
    pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<Config, ArgError> {
        let mut config = Config::default();
        let mut mode_seen = false;
        let mut args = args.iter().map(AsRef::as_ref);
        while let Some(option) = args.next() {
            let fail = |kind, value: &str, expected| ArgError {
                kind,
                option: option.to_owned(),
                value: value.to_owned(),
                expected,
            };
            if option.starts_with("--mode=") {
                return Err(fail(ArgErrorKind::InvalidMode, "", ""));
            }
            if option == "--mode" || option == "-m" {
                if mode_seen {
                    return Err(fail(ArgErrorKind::DuplicateMode, "", ""));
                }
                let value = args.next().ok_or_else(|| fail(ArgErrorKind::MissingMode, "", ""))?;
                config.mode = Mode::parse(value)
                    .ok_or_else(|| fail(ArgErrorKind::InvalidMode, value, EXPECTED_MODE))?;
                mode_seen = true;
                continue;
            }
            if config.apply_flag(option) {
                continue;
            }
            if REMOVED_OPTIONS.contains(&option) {
                return Err(fail(ArgErrorKind::RemovedOption, "", EXPECTED_CLUSTER));
            }
            if !VALUED_OPTIONS.contains(&option) {
                return Err(fail(ArgErrorKind::UnknownOption, "", ""));
            }
            let value = args.next().ok_or_else(|| fail(ArgErrorKind::MissingValue, "", ""))?;
            config.apply_option(option, value).map_err(|fault| {
                let shown = if option == "--database-url" { REDACTED } else { value };
                fail(fault.kind, shown, fault.expected)
            })?;
        }
        config.check_storage()?;
        Ok(config)
    }

    /// Checks the storage options together (SID 0011): at most one of `database_url` and
    /// `database_url_file`; no data directory beside a database; and a `cluster_node` with
    /// a database.
    ///
    /// Fails with [`ArgErrorKind::ConflictingOptions`] or [`ArgErrorKind::MissingOption`],
    /// naming the database option.
    pub fn check_storage(&self) -> Result<(), ArgError> {
        let database = match (&self.database_url, &self.database_url_file) {
            (Some(_), Some(_)) => {
                return Err(storage_error(
                    ArgErrorKind::ConflictingOptions,
                    "--database-url-file",
                    "--database-url or --database-url-file, not both",
                ));
            }
            (Some(_), None) => "--database-url",
            (None, Some(_)) => "--database-url-file",
            (None, None) => return Ok(()),
        };
        if self.data_dir.is_some() {
            let expected = "--data-dir or a database URL, not both";
            return Err(storage_error(ArgErrorKind::ConflictingOptions, database, expected));
        }
        if self.cluster_node.is_none() {
            let expected = "--cluster-node <id> beside a database URL";
            return Err(storage_error(ArgErrorKind::MissingOption, database, expected));
        }
        Ok(())
    }

    /// Applies `option` when it is a flag; returns false when it is not one.
    fn apply_flag(&mut self, option: &str) -> bool {
        match option {
            "--verbose" | "-v" => self.verbose = true,
            "--trust-forwarded" => self.trust_forwarded = Some(true),
            "--no-trust-forwarded" => self.trust_forwarded = Some(false),
            "--no-waf" | "--gate" => self.waf = false,
            "--waf" | "--shield" => self.waf = true,
            "--secure-cookie" => self.secure_cookie = true,
            _ => return false,
        }
        true
    }

    /// Applies one valued option. Every range is the Zig daemon's.
    fn apply_option(&mut self, option: &str, value: &str) -> Result<(), Fault> {
        const PORT: &str = "a port 1-65535";
        const HOST: &str = "a host name or address";
        const PATH: &str = "a file path";
        const REQUESTS: &str = "requests 1 or more";
        let max_u32 = u64::from(u32::MAX);
        match option {
            "--port" | "-p" => self.listen_port = number(value, 1, 65_535, PORT)?,
            "--host" | "-h" => self.listen_host = text(value, HOST)?,
            "--upstream-host" => self.upstream_host = text(value, HOST)?,
            "--upstream-port" | "-u" => self.upstream_port = number(value, 1, 65_535, PORT)?,
            "--difficulty" | "-d" => {
                self.default_difficulty = number(value, 1, 64, "work bits 1-64")?;
            }
            "--algorithm" | "-a" => {
                self.algorithm =
                    PowAlgorithm::parse(value).ok_or(Fault::invalid("posw or hashcash"))?;
            }
            "--posw-challenges" => self.posw_challenges = number(value, 1, 32, "openings 1-32")?,
            "--token-scheme" => {
                self.token_scheme =
                    TokenScheme::parse(value).ok_or(Fault::invalid("mac or ed25519"))?;
            }
            "--token-ttl" => {
                self.token_ttl_seconds = number(value, 1, 31_536_000, "seconds 1-31536000")?;
            }
            "--challenge-ttl" => {
                self.challenge_ttl_seconds = number(value, 1, 86_400, "seconds 1-86400")?;
            }
            "--cookie-name" => self.cookie_name = cookie_name(value)?,
            "--secret-file" | "-s" => self.secret_file = Some(text(value, PATH)?),
            "--policy-file" | "-P" => self.policy_file = Some(text(value, PATH)?),
            "--workers" | "-w" => {
                self.workers = number(value, 0, 64, "0 for one per CPU, or 1-64")?;
            }
            "--max-connections" => {
                let limit = u64::from(Config::MAX_CONNECTIONS_LIMIT);
                self.max_connections = number(value, 1, limit, "1-8192")?;
            }
            "--max-connections-per-ip" => {
                let limit = u64::from(Config::MAX_CONNECTIONS_LIMIT);
                self.max_connections_per_ip =
                    number(value, 0, limit, "0 for no bound, or 1-8192")?;
            }
            "--idle-timeout" => {
                self.idle_timeout_seconds = number(value, 0, 86_400, "seconds 0-86400")?;
            }
            "--websocket-idle-timeout" => {
                let seconds = number(value, 0, 86_400, "seconds 0-86400")?;
                self.websocket_idle_timeout_seconds = seconds;
            }
            "--rate-limit" => self.rate_limit = number(value, 1, max_u32, REQUESTS)?,
            "--rate-window" => {
                self.rate_window_seconds = number(value, 1, 86_400, "seconds 1-86400")?;
            }
            "--challenge-rate-limit" => {
                self.challenge_rate_limit = number(value, 1, max_u32, REQUESTS)?;
            }
            "--ban-seconds" => {
                self.ban_seconds = number(value, 0, 31_536_000, "seconds 0-31536000")?;
            }
            _ => return self.apply_storage_option(option, value),
        }
        Ok(())
    }

    fn apply_storage_option(&mut self, option: &str, value: &str) -> Result<(), Fault> {
        match option {
            "--data-dir" | "-D" => self.data_dir = Some(text(value, "a directory path")?),
            "--database-url" => self.database_url = Some(database_url(value)?),
            "--database-url-file" => self.database_url_file = Some(text(value, "a file path")?),
            "--cluster-node" => {
                // Zig accepted 0, which storage then numbered as node 1 (SID 0011).
                let max = u64::from(Config::MAX_NODE_ID);
                self.cluster_node = Some(number(value, 1, max, "a node id 1-8388607")?);
            }
            "--storage-poll-ms" => {
                self.storage_poll_ms = number(value, 1, 60_000, "milliseconds 1-60000")?;
            }
            _ => return self.apply_identity_option(option, value),
        }
        Ok(())
    }

    /// Applies the client identity and state table options.
    fn apply_identity_option(&mut self, option: &str, value: &str) -> Result<(), Fault> {
        match option {
            "--trusted-hops" => self.trusted_hops = number(value, 1, 8, "proxies 1-8")?,
            "--ipv6-prefix" => self.ipv6_prefix = number(value, 32, 128, "a length 32-128")?,
            "--rate-table-cells" => {
                self.rate_table_cells = number(value, 4096, 1 << 24, "cells 4096-16777216")?;
            }
            "--ban-table-slots" => {
                self.ban_table_slots = number(value, 1024, 1 << 24, "slots 1024-16777216")?;
            }
            "--spent-tags" => {
                self.spent_tags = number(value, 65_536, 1 << 24, "tags 65536-16777216")?;
            }
            // Every option in VALUED_OPTIONS is handled above or here.
            _ => return Err(Fault { kind: ArgErrorKind::UnknownOption, expected: "" }),
        }
        Ok(())
    }
}

fn storage_error(kind: ArgErrorKind, option: &str, expected: &'static str) -> ArgError {
    ArgError { kind, option: option.to_owned(), value: String::new(), expected }
}

/// Parses a decimal integer in `min..=max` with the syntax of Zig's
/// `std.fmt.parseInt(T, text, 10)`, which existing deployments may rely on: an optional
/// `+` or `-` sign, and `_` separators anywhere but at the ends. A negative value is
/// accepted only when it is zero (`-0`).
fn number<T: TryFrom<u64>>(
    text: &str,
    min: u64,
    max: u64,
    expected: &'static str,
) -> Result<T, Fault> {
    let invalid = || Fault::invalid(expected);
    let (negative, digits) = match text.as_bytes() {
        [b'+', rest @ ..] => (false, rest),
        [b'-', rest @ ..] => (true, rest),
        all => (false, all),
    };
    if digits.is_empty() || digits.first() == Some(&b'_') || digits.last() == Some(&b'_') {
        return Err(invalid());
    }
    let mut value: u64 = 0;
    for &byte in digits.iter().filter(|&&byte| byte != b'_') {
        if !byte.is_ascii_digit() {
            return Err(invalid());
        }
        let digit = u64::from(byte - b'0');
        value = value.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or_else(invalid)?;
    }
    if (negative && value != 0) || value < min || value > max {
        return Err(invalid());
    }
    T::try_from(value).map_err(|_| invalid())
}

/// Accepts 1 to 4096 bytes without control characters, and copies them.
fn text(value: &str, expected: &'static str) -> Result<String, Fault> {
    let control = value.bytes().any(|byte| byte < 32 || byte == 127);
    if value.is_empty() || value.len() > 4096 || control {
        return Err(Fault::invalid(expected));
    }
    Ok(value.to_owned())
}

/// RFC 6265 cookie names: 1 to 64 token characters.
fn cookie_name(value: &str) -> Result<String, Fault> {
    let token = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
    if value.is_empty() || value.len() > 64 || !value.bytes().all(token) {
        return Err(Fault::invalid("a cookie name of 1-64 token characters"));
    }
    Ok(value.to_owned())
}

/// A PostgreSQL connection string, as sqlx accepts it.
fn database_url(value: &str) -> Result<String, Fault> {
    let url = text(value, EXPECTED_DATABASE_URL)?;
    let scheme_end = url.find("://").ok_or(Fault::invalid(EXPECTED_DATABASE_URL))?;
    let scheme = &url[..scheme_end];
    if !scheme.eq_ignore_ascii_case("postgres") && !scheme.eq_ignore_ascii_case("postgresql") {
        return Err(Fault::invalid(EXPECTED_DATABASE_URL));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_number(text: &str) -> Option<u64> {
        number::<u64>(text, 0, u64::MAX, "").ok()
    }

    #[test]
    fn numbers_follow_zig_parse_int() {
        assert_eq!(parse_number("10"), Some(10));
        assert_eq!(parse_number("+10"), Some(10));
        assert_eq!(parse_number("-0"), Some(0));
        assert_eq!(parse_number("+0"), Some(0));
        assert_eq!(parse_number("-0_0"), Some(0));
        assert_eq!(parse_number("1_000"), Some(1000));
        assert_eq!(parse_number("1__0"), Some(10));
        assert_eq!(parse_number("18446744073709551615"), Some(u64::MAX));
        for bad in ["", "+", "-", "-10", "-01", " 10", "10 ", "_10", "10_", "0x10", "1e3"] {
            assert_eq!(parse_number(bad), None, "{bad:?}");
        }
        assert_eq!(parse_number("18446744073709551616"), None);
        assert!(number::<u8>("255", 0, 255, "").is_ok());
        assert!(number::<u8>("256", 0, 255, "").is_err());
    }

    #[test]
    fn database_urls_must_name_postgres() {
        assert!(database_url("postgres://u:p@db/sibuna").is_ok());
        assert!(database_url("PostgreSQL://db").is_ok());
        for bad in ["", "db", "sqlite://x.db", "postgres:/db", "postgres://\n"] {
            assert!(database_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_per_client_connection_bound_takes_zero_to_the_global_limit() {
        assert_eq!(Config::default().max_connections_per_ip, 64);
        let parse = |value: &str| Config::parse_args(&["--max-connections-per-ip", value]);
        assert_eq!(parse("0").map(|config| config.max_connections_per_ip).ok(), Some(0));
        assert_eq!(parse("8192").map(|config| config.max_connections_per_ip).ok(), Some(8192));
        assert!(parse("8193").is_err() && parse("-1").is_err());
    }

    #[test]
    fn identity_and_table_options_take_their_ranges() {
        let config = Config::default();
        assert_eq!((config.trusted_hops, config.ipv6_prefix), (1, 64));
        assert_eq!((config.rate_table_cells, config.ban_table_slots), (1 << 18, 1 << 16));
        assert_eq!(config.spent_tags, 1 << 20);
        let parse = |option: &str, value: &str| Config::parse_args(&[option, value]);
        let hops = parse("--trusted-hops", "3").map(|config| config.trusted_hops);
        assert_eq!(hops.ok(), Some(3));
        let prefix = parse("--ipv6-prefix", "48").map(|config| config.ipv6_prefix);
        assert_eq!(prefix.ok(), Some(48));
        let cells = parse("--rate-table-cells", "1000000").map(|config| config.rate_table_cells);
        assert_eq!(cells.ok(), Some(1_000_000));
        let slots = parse("--ban-table-slots", "1024").map(|config| config.ban_table_slots);
        assert_eq!(slots.ok(), Some(1024));
        let tags = parse("--spent-tags", "16777216").map(|config| config.spent_tags);
        assert_eq!(tags.ok(), Some(1 << 24));
        for (option, bad) in [
            ("--trusted-hops", "0"),
            ("--trusted-hops", "9"),
            ("--ipv6-prefix", "31"),
            ("--ipv6-prefix", "129"),
            ("--rate-table-cells", "4095"),
            ("--ban-table-slots", "16777217"),
            ("--spent-tags", "65535"),
        ] {
            assert!(parse(option, bad).is_err(), "{option} {bad}");
        }
    }

    #[test]
    fn every_option_and_flag_is_in_the_help() {
        for option in VALUED_OPTIONS.iter().chain(&["--trust-forwarded", "--no-waf"]) {
            assert!(super::super::HELP.contains(option), "{option}");
        }
        for option in REMOVED_OPTIONS {
            assert!(!super::super::HELP.contains(option), "{option}");
        }
    }
}

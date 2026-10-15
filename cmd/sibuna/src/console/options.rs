//! The `--console*` options (Zig's `console_start.zig` parser).
//!
//! The console's flags are split off before the data plane's parser sees the arguments, so
//! `sibuna_core::Config::parse_args` never learns them: [`parse`] returns the console's
//! configuration and the remaining arguments in their order. `init-admin <username>` as
//! the first argument asks for the offline bootstrap instead of a daemon.
//!
//! Every refusal is a [`OptionError`] whose name is Zig's error name; the command line
//! prints it in the `CONSOLE002` diagnostic.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use sibuna_console::Config;
use sibuna_console::config::{MAX_PROBES, MAX_PROXIES, PeerTarget, Probe, peers::MAX_PEERS};
pub use sibuna_console::config::{MAX_QUERY_STEPS, MIN_QUERY_STEPS};
use sibuna_console_protocol::Location;
use sibuna_console_protocol::valid_username;
use sibuna_core::incident_heads::{Extra, ExtraError};

/// The console options of one command line.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    /// The console's configuration; meaningful only when `enabled`.
    pub config: Config,
    /// `--console` was given.
    pub enabled: bool,
    /// `--console-query-steps`, when given; also in `config.query_steps`.
    pub query_steps: Option<u64>,
    /// `--console-capture-heads` was given.
    pub capture_heads: bool,
    /// The `--console-capture-header` names.
    pub capture_headers: Extra,
    /// The arguments that are not console options, in their order.
    pub data_args: Vec<String>,
    /// `init-admin <username>`: the account to bootstrap offline.
    pub initial_admin: Option<String>,
}

/// Why the console options were refused. The names are Zig's error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OptionError {
    /// `init-admin` without a valid user name.
    InvalidUsername,
    /// An option without its value.
    MissingValue,
    /// An option that is not one of the console's.
    UnknownConsoleOption,
    /// `--console` given twice.
    DuplicateConsole,
    /// `--console` is not `<ip>:<port>` with a nonzero port.
    InvalidAddress,
    /// `--console-cookie-secure` given twice.
    DuplicateCookieSecure,
    /// `--console-key-file` given twice.
    DuplicateConsoleKey,
    /// `--console-origin` given twice.
    DuplicateOrigin,
    /// More than sixteen `--console-trusted-proxy`.
    TooManyProxies,
    /// `--console-advertise` given twice.
    DuplicateAdvertise,
    /// More than eight `--console-probe`.
    TooManyProbes,
    /// A probe that is not `<node>=<url>` with a nonzero node.
    InvalidProbe,
    /// `--console-location` given twice.
    DuplicateLocation,
    /// A location that is not `<latitude>,<longitude>` in range.
    InvalidLocation,
    /// More than eight `--console-peer`.
    TooManyPeers,
    /// A peer that is not `<node>=<origin>`.
    InvalidPeer,
    /// `--console-peer-key-file` given twice.
    DuplicatePeerKey,
    /// `--console-peer-ca-file` given twice.
    DuplicatePeerTrust,
    /// `--console-query-steps` given twice.
    DuplicateQuerySteps,
    /// Query steps outside 100,000 to 50,000,000, or not plain decimal digits.
    InvalidQuerySteps,
    /// A capture header that is not a header name.
    InvalidCaptureHeader,
    /// More than sixteen capture headers.
    TooManyCaptureHeaders,
    /// `--console-capture-header` without `--console-capture-heads`.
    CaptureHeaderWithoutCapture,
    /// Console options beside `init-admin`, which runs without a console.
    UnexpectedConsoleOptions,
    /// Console options without `--console`.
    ConsoleRequired,
}

impl OptionError {
    /// Returns Zig's error name, which the `CONSOLE002` diagnostic shows.
    pub fn name(self) -> &'static str {
        match self {
            OptionError::InvalidUsername => "InvalidUsername",
            OptionError::MissingValue => "MissingValue",
            OptionError::UnknownConsoleOption => "UnknownConsoleOption",
            OptionError::DuplicateConsole => "DuplicateConsole",
            OptionError::InvalidAddress => "InvalidAddress",
            OptionError::DuplicateCookieSecure => "DuplicateCookieSecure",
            OptionError::DuplicateConsoleKey => "DuplicateConsoleKey",
            OptionError::DuplicateOrigin => "DuplicateOrigin",
            OptionError::TooManyProxies => "TooManyProxies",
            OptionError::DuplicateAdvertise => "DuplicateAdvertise",
            OptionError::TooManyProbes => "TooManyProbes",
            OptionError::InvalidProbe => "InvalidProbe",
            OptionError::DuplicateLocation => "DuplicateLocation",
            OptionError::InvalidLocation => "InvalidLocation",
            OptionError::TooManyPeers => "TooManyPeers",
            OptionError::InvalidPeer => "InvalidPeer",
            OptionError::DuplicatePeerKey => "DuplicatePeerKey",
            OptionError::DuplicatePeerTrust => "DuplicatePeerTrust",
            OptionError::DuplicateQuerySteps => "DuplicateQuerySteps",
            OptionError::InvalidQuerySteps => "InvalidQuerySteps",
            OptionError::InvalidCaptureHeader => "InvalidCaptureHeader",
            OptionError::TooManyCaptureHeaders => "TooManyCaptureHeaders",
            OptionError::CaptureHeaderWithoutCapture => "CaptureHeaderWithoutCapture",
            OptionError::UnexpectedConsoleOptions => "UnexpectedConsoleOptions",
            OptionError::ConsoleRequired => "ConsoleRequired",
        }
    }
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for OptionError {}

/// Splits the console options off `args` (the words after the program name, and after
/// `console` for `sibuna console init-admin`).
///
/// Fails with the first [`OptionError`], in the order Zig checked.
pub fn parse(args: &[String]) -> Result<Parsed, OptionError> {
    let mut parsed = Parsed::default();
    let mut options_seen = false;
    let mut words = args.iter().enumerate();
    while let Some((index, flag)) = words.next() {
        if index == 0 && flag == "init-admin" {
            let username = words.next().map(|(_, word)| word);
            match username {
                Some(name) if valid_username(name) => parsed.initial_admin = Some(name.clone()),
                _ => return Err(OptionError::InvalidUsername),
            }
            continue;
        }
        if !flag.starts_with("--console") {
            parsed.data_args.push(flag.clone());
            continue;
        }
        options_seen = true;
        if switch(&mut parsed, flag)? {
            continue;
        }
        let value = match words.next() {
            Some((_, value)) if !value.starts_with("--") => value,
            _ => return Err(OptionError::MissingValue),
        };
        option(&mut parsed, flag, value)?;
    }
    if parsed.initial_admin.is_some() && options_seen {
        return Err(OptionError::UnexpectedConsoleOptions);
    }
    if options_seen && !parsed.enabled {
        return Err(OptionError::ConsoleRequired);
    }
    if !parsed.capture_headers.is_empty() && !parsed.capture_heads {
        return Err(OptionError::CaptureHeaderWithoutCapture);
    }
    Ok(parsed)
}

/// Applies a console flag that takes no value and returns true, or returns false for a
/// flag that takes one.
fn switch(parsed: &mut Parsed, flag: &str) -> Result<bool, OptionError> {
    match flag {
        "--console-behind-proxy" => parsed.config.behind_proxy = true,
        "--console-capture-heads" => parsed.capture_heads = true,
        "--console-cookie-secure" => {
            if parsed.config.cookie_secure {
                return Err(OptionError::DuplicateCookieSecure);
            }
            parsed.config.cookie_secure = true;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Applies a console flag with its value.
fn option(parsed: &mut Parsed, flag: &str, value: &str) -> Result<(), OptionError> {
    let config = &mut parsed.config;
    match flag {
        "--console-query-steps" => {
            if parsed.query_steps.is_some() {
                return Err(OptionError::DuplicateQuerySteps);
            }
            let steps = parse_query_steps(value)?;
            parsed.query_steps = Some(steps);
            parsed.config.query_steps = steps;
        }
        "--console-capture-header" => {
            parsed.capture_headers.add(value).map_err(|error| match error {
                ExtraError::InvalidHeaderName => OptionError::InvalidCaptureHeader,
                ExtraError::TooManyHeaders => OptionError::TooManyCaptureHeaders,
            })?;
        }
        "--console" => {
            if parsed.enabled {
                return Err(OptionError::DuplicateConsole);
            }
            config.listen = parse_endpoint(value)?;
            parsed.enabled = true;
        }
        "--console-key-file" => set_path(&mut config.key_file, value, DUPLICATE_KEY)?,
        "--console-origin" => set_text(&mut config.origin, value, OptionError::DuplicateOrigin)?,
        "--console-trusted-proxy" => {
            if config.trusted_proxies.len() == MAX_PROXIES {
                return Err(OptionError::TooManyProxies);
            }
            config.trusted_proxies.push(value.to_owned());
        }
        "--console-advertise" => {
            set_text(&mut config.advertise, value, OptionError::DuplicateAdvertise)?;
        }
        "--console-probe" => config.probes.push(parse_probe(config.probes.len(), value)?),
        "--console-location" => {
            if config.server_location.is_some() {
                return Err(OptionError::DuplicateLocation);
            }
            let location = Location::parse(value).map_err(|_| OptionError::InvalidLocation)?;
            config.server_location = Some(location);
        }
        "--console-peer" => {
            let peers = &mut config.peers.targets;
            peers.push(parse_peer(peers.len(), value)?);
        }
        "--console-peer-key-file" => {
            set_path(&mut config.peers.key_file, value, OptionError::DuplicatePeerKey)?;
        }
        "--console-peer-ca-file" => {
            set_path(&mut config.peers.ca_file, value, OptionError::DuplicatePeerTrust)?;
        }
        _ => return Err(OptionError::UnknownConsoleOption),
    }
    Ok(())
}

const DUPLICATE_KEY: OptionError = OptionError::DuplicateConsoleKey;

fn set_path(
    slot: &mut Option<PathBuf>,
    value: &str,
    duplicate: OptionError,
) -> Result<(), OptionError> {
    if slot.is_some() {
        return Err(duplicate);
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn set_text(slot: &mut String, value: &str, duplicate: OptionError) -> Result<(), OptionError> {
    if !slot.is_empty() {
        return Err(duplicate);
    }
    value.clone_into(slot);
    Ok(())
}

/// `<ip>:<port>`, IPv6 in brackets (or bare: the port follows the last colon), with a
/// nonzero port.
fn parse_endpoint(value: &str) -> Result<SocketAddr, OptionError> {
    let (host, port) = value.rsplit_once(':').ok_or(OptionError::InvalidAddress)?;
    let host = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host);
    let address = host.parse::<IpAddr>().map_err(|_| OptionError::InvalidAddress)?;
    match parse_decimal(port).and_then(|port| u16::try_from(port).ok()) {
        Some(port) if port != 0 => Ok(SocketAddr::new(address, port)),
        _ => Err(OptionError::InvalidAddress),
    }
}

/// `<node>=<url>`: a probed data-plane listener, never a discovered address. The URL is
/// checked by the console's configuration.
fn parse_probe(count: usize, value: &str) -> Result<Probe, OptionError> {
    if count == MAX_PROBES {
        return Err(OptionError::TooManyProbes);
    }
    let (node, url) = value.split_once('=').ok_or(OptionError::InvalidProbe)?;
    let node = parse_decimal(node).filter(|&node| node != 0).ok_or(OptionError::InvalidProbe)?;
    Ok(Probe { node, url: url.to_owned() })
}

/// `<node>=<https origin>`: a management peer. The origin is checked by the console's
/// configuration.
fn parse_peer(count: usize, value: &str) -> Result<PeerTarget, OptionError> {
    if count == MAX_PEERS {
        return Err(OptionError::TooManyPeers);
    }
    let (node, origin) = value.split_once('=').ok_or(OptionError::InvalidPeer)?;
    let node = parse_decimal(node).ok_or(OptionError::InvalidPeer)?;
    Ok(PeerTarget { node, origin: origin.to_owned() })
}

/// A `u32` written as plain decimal digits.
fn parse_decimal(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Query steps: plain decimal digits from 100,000 to 50,000,000.
fn parse_query_steps(value: &str) -> Result<u64, OptionError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OptionError::InvalidQuerySteps);
    }
    match value.parse::<u64>() {
        Ok(steps) if (MIN_QUERY_STEPS..=MAX_QUERY_STEPS).contains(&steps) => Ok(steps),
        _ => Err(OptionError::InvalidQuerySteps),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    fn parse_words(words: &[&str]) -> Result<Parsed, OptionError> {
        parse(&args(words))
    }

    // console_start.zig: "console parsing preserves data-plane arguments and rejects
    // unknown flags".
    #[test]
    fn data_plane_arguments_are_kept_and_unknown_flags_refused() {
        let parsed = parse_words(&["--port", "8081", "--console", "[::1]:9443"]).unwrap();
        assert_eq!(parsed.data_args, args(&["--port", "8081"]));
        assert_eq!(parsed.config.listen, "[::1]:9443".parse().unwrap());
        assert!(parsed.enabled);
        assert_eq!(
            parse_words(&["--console-mistake", "1"]).unwrap_err(),
            OptionError::UnknownConsoleOption
        );
        assert_eq!(parse_words(&["--console"]).unwrap_err(), OptionError::MissingValue);
        let peers = parse_words(&[
            "--console",
            "127.0.0.1:9443",
            "--console-advertise",
            "http://127.0.0.1:9443",
            "--console-probe",
            "2=http://127.0.0.1:8082",
            "--console-probe",
            "3=http://[::1]:8083",
        ])
        .unwrap();
        assert_eq!(peers.config.probes.len(), 2);
        assert_eq!(peers.config.probes[1].node, 3);
        assert_eq!(peers.config.advertise, "http://127.0.0.1:9443");
        let probe = ["--console", "127.0.0.1:9443", "--console-probe", "x=http://127.0.0.1:1"];
        assert_eq!(parse_words(&probe).unwrap_err(), OptionError::InvalidProbe);
        for endpoint in ["127.0.0.1", "localhost:9443", "127.0.0.1:0", "127.0.0.1:+1", ":1"] {
            let words = ["--console", endpoint];
            assert_eq!(parse_words(&words).unwrap_err(), OptionError::InvalidAddress);
        }
    }

    // console_start.zig: "console location is explicit, bounded and separate from
    // data-plane arguments".
    #[test]
    fn the_location_is_explicit_bounded_and_separate() {
        let words =
            ["--console", "127.0.0.1:9443", "--console-location", "1.3521,103.8198", "--gate"];
        let parsed = parse_words(&words).unwrap();
        assert_eq!(parsed.config.server_location.unwrap().lon, 103.8198);
        assert_eq!(parsed.data_args, args(&["--gate"]));
        let nan = ["--console", "127.0.0.1:9443", "--console-location", "nan,0"];
        assert_eq!(parse_words(&nan).unwrap_err(), OptionError::InvalidLocation);
        let twice = [
            "--console",
            "127.0.0.1:9443",
            "--console-location",
            "0,0",
            "--console-location",
            "0,0",
        ];
        assert_eq!(parse_words(&twice).unwrap_err(), OptionError::DuplicateLocation);
    }

    // console_start.zig: "management peer parsing owns origins and rejects self identity
    // after composition".
    #[test]
    fn peers_are_parsed_and_checked_against_this_node() {
        let parsed = parse_words(&[
            "--console",
            "127.0.0.1:9443",
            "--console-behind-proxy",
            "--console-origin",
            "https://console.test",
            "--console-trusted-proxy",
            "127.0.0.1/32",
            "--console-peer",
            "2=https://peer.test:443",
            "--console-peer-key-file",
            "peer.key",
            "--console-peer-ca-file",
            "ca.pem",
            "--gate",
        ])
        .unwrap();
        assert_eq!(parsed.data_args, args(&["--gate"]));
        assert_eq!(parsed.config.peers.ca_file, Some(PathBuf::from("ca.pem")));
        assert_eq!(parsed.config.validate(1), Ok(()));
        assert!(parsed.config.validate(2).is_err());
        let twice = [
            "--console",
            "127.0.0.1:9443",
            "--console-peer-key-file",
            "a",
            "--console-peer-key-file",
            "b",
        ];
        assert_eq!(parse_words(&twice).unwrap_err(), OptionError::DuplicatePeerKey);
    }

    // console_start.zig: "console query budget is bounded and never passed to the
    // data-plane parser".
    #[test]
    fn query_steps_are_bounded_and_kept_from_the_data_plane() {
        for value in ["100000", "4000000", "50000000"] {
            let words = ["--console", "127.0.0.1:9443", "--console-query-steps", value, "--gate"];
            let parsed = parse_words(&words).unwrap();
            assert_eq!(parsed.query_steps, Some(value.parse().unwrap()));
            assert_eq!(parsed.config.query_steps, value.parse::<u64>().unwrap());
            assert_eq!(parsed.data_args, args(&["--gate"]));
        }
        for value in ["99999", "50000001", "-1", "+100000", "4M", "", "18446744073709551616"] {
            let words = ["--console", "127.0.0.1:9443", "--console-query-steps", value];
            // A value that begins with a single `-` is a value, as in Zig.
            assert_eq!(parse_words(&words).unwrap_err(), OptionError::InvalidQuerySteps);
        }
        let twice = [
            "--console",
            "127.0.0.1:9443",
            "--console-query-steps",
            "100000",
            "--console-query-steps",
            "100000",
        ];
        assert_eq!(parse_words(&twice).unwrap_err(), OptionError::DuplicateQuerySteps);
        let alone = ["--console-query-steps", "100000"];
        assert_eq!(parse_words(&alone).unwrap_err(), OptionError::ConsoleRequired);
        let missing = ["--console-query-steps"];
        assert_eq!(parse_words(&missing).unwrap_err(), OptionError::MissingValue);
    }

    #[test]
    fn capture_headers_need_capture_and_valid_names() {
        let words = [
            "--console",
            "127.0.0.1:9443",
            "--console-capture-heads",
            "--console-capture-header",
            "X-Request-Id",
        ];
        let parsed = parse_words(&words).unwrap();
        assert!(parsed.capture_heads && parsed.capture_headers.contains(b"x-request-id"));
        let without = ["--console", "127.0.0.1:9443", "--console-capture-header", "X-Id"];
        assert_eq!(parse_words(&without).unwrap_err(), OptionError::CaptureHeaderWithoutCapture);
        let invalid = ["--console", "127.0.0.1:9443", "--console-capture-header", "bad name"];
        assert_eq!(parse_words(&invalid).unwrap_err(), OptionError::InvalidCaptureHeader);
    }

    #[test]
    fn init_admin_takes_a_valid_name_and_no_console_options() {
        let parsed = parse_words(&["init-admin", "admin", "--data-dir", "/tmp/x"]).unwrap();
        assert_eq!(parsed.initial_admin.as_deref(), Some("admin"));
        assert_eq!(parsed.data_args, args(&["--data-dir", "/tmp/x"]));
        assert!(!parsed.enabled);
        assert_eq!(parse_words(&["init-admin"]).unwrap_err(), OptionError::InvalidUsername);
        let with_console = ["init-admin", "admin", "--console", "127.0.0.1:9443"];
        assert_eq!(parse_words(&with_console).unwrap_err(), OptionError::UnexpectedConsoleOptions);
        // `init-admin` is a command only in the first position.
        let later = parse_words(&["--gate", "init-admin"]).unwrap();
        assert_eq!(later.data_args, args(&["--gate", "init-admin"]));
    }
}

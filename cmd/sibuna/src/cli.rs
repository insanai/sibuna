//! The command line: help and version, configuration, the master secret, the policy file,
//! the banner, the listener and the stop on SIGINT or SIGTERM.
//!
//! Every message goes to standard error, as the Zig daemon printed them with
//! `std.debug.print`, and keeps the Zig text.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::process::ExitCode;

use sibuna_challenge::{SEED_LEN, Seed};
use sibuna_core::config::HELP;
use sibuna_core::{Config, diagnostic};
use sibuna_policy::LoadError;
use sibuna_policy::loader::Diagnostic;

use crate::daemon::{Daemon, DaemonOptions, StartError};
use crate::recipe::{BuildError, Recipe};
use crate::server::{Hooks, VERSION};
use crate::signals::{self, Shutdown};

/// The most bytes read from `--secret-file`, as the Zig daemon's buffer.
const SECRET_FILE_BYTES: u64 = 256;
/// The most bytes read from `--policy-file`, as the Zig daemon's buffer.
const POLICY_FILE_BYTES: u64 = 256 * 1024;

/// Writes one line to standard error. Only the binary's code paths call it.
pub(crate) fn report(message: &str) {
    eprintln!("{message}");
}

/// Runs the daemon with `args` (without the program name) and `secret` (the value of
/// `SIBUNA_SECRET`, if set) until SIGINT or SIGTERM. Returns the process exit status.
pub fn run(args: &[String], secret: Option<&str>) -> ExitCode {
    for arg in args {
        match arg.as_str() {
            "--help" => {
                eprint!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                eprintln!("sibuna {VERSION}");
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    if args.first().is_some_and(|arg| arg == "console") {
        report(
            "CONSOLEBUILD: console support is not compiled. Hint: build with the console \
             feature enabled.",
        );
        return ExitCode::FAILURE;
    }
    let mut config = match Config::parse_args(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match start(&mut config, secret) {
        Ok(code) => code,
        Err(()) => ExitCode::FAILURE,
    }
}

/// Everything after parsing. `Err` means the failure was already reported.
fn start(config: &mut Config, secret: Option<&str>) -> Result<ExitCode, ()> {
    let seed = resolve_secret(config, secret)?;
    let shutdown = Shutdown::new();
    if let Err(error) = signals::install(std::sync::Arc::clone(&shutdown)) {
        report(&format!("Failed to install the signal handlers: {error}"));
        return Err(());
    }
    let policy_file = match &config.policy_file {
        Some(path) => Some(load_policy_file(config, path)?),
        None => None,
    };
    let recipe = Recipe::new(config, policy_file);
    let address = listen_address(config)?;
    let listener = bind(address, config.listen_port)?;
    let options = DaemonOptions { config: config.clone(), recipe, seed, hooks: Hooks::default() };
    let daemon = match Daemon::start(options, listener) {
        Ok(daemon) => daemon,
        Err(error) => {
            report_start_error(&error);
            return Err(());
        }
    };
    let mut banner = String::new();
    let _ = config.write_banner(&mut banner, VERSION);
    eprint!("{banner}");
    shutdown.wait();
    if !daemon.stop() {
        report("storage: shutdown could not confirm pending incidents");
    }
    Ok(ExitCode::SUCCESS)
}

fn report_start_error(error: &StartError) {
    match error {
        StartError::StorageDisabled => report(
            "Failed to start persistent storage: StorageDisabled. Hint: this build has no \
             storage; build with the sqlite or postgres feature, or omit the storage options.",
        ),
        #[cfg(feature = "storage")]
        StartError::Storage(error) => {
            report(&format!("Failed to start persistent storage: {error}"));
        }
        StartError::Engine(error) => {
            report(&format!("Failed to build the policy engine: {error}"))
        }
        StartError::Io(error) => report(&format!("Failed to start the server: {error}")),
    }
}

/// Secret precedence: `--secret-file`, then `SIBUNA_SECRET`, then a random per-process seed
/// (tokens then die with the process, which is fine for a single node but wrong for a
/// cluster, so the banner warns).
fn resolve_secret(config: &mut Config, secret: Option<&str>) -> Result<Seed, ()> {
    let seed = if let Some(path) = &config.secret_file {
        let content = read_bounded(path, SECRET_FILE_BYTES).map_err(|error| {
            report(&format!("Cannot open secret file {path}: {}", error_name(&error)));
        })?;
        Seed::parse(&content).map_err(|_| {
            report(&format!("Secret file {path} must hold 64 hex characters or 32 raw bytes"));
        })?
    } else if let Some(text) = secret {
        let seed = Seed::parse(text.as_bytes()).map_err(|_| {
            report("SIBUNA_SECRET must hold 64 hex characters");
        })?;
        config.secret_file = Some("env".to_owned());
        seed
    } else {
        Seed::new(random_seed().map_err(|error| {
            report(&format!("Cannot read random bytes for the master seed: {error}"));
        })?)
    };
    config.secret_seed = Some(*seed.as_bytes());
    Ok(seed)
}

/// Reads 32 bytes from the kernel's random source.
fn random_seed() -> io::Result<[u8; SEED_LEN]> {
    let mut seed = [0u8; SEED_LEN];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    Ok(seed)
}

/// Reads at most `limit` bytes of the file at `path`.
fn read_bounded(path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut content = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut content)?;
    Ok(content)
}

/// Loads and checks the policy file, reporting a rejected file with an Elm-style
/// diagnostic. A named file that cannot be read or compiled stops startup: serving with a
/// partial policy would admit traffic the operator meant to stop.
fn load_policy_file(config: &Config, path: &str) -> Result<Vec<u8>, ()> {
    let mut file = File::open(path).map_err(|error| {
        report(&format!(
            "POLICYFILE: unable to open policy file {path}: {}. Hint: check the path and \
             permissions, or omit --policy-file.",
            error_name(&error)
        ));
    })?;
    let mut content = Vec::new();
    if let Err(error) = (&mut file).take(POLICY_FILE_BYTES).read_to_end(&mut content) {
        report(&format!("POLICYFILE: failed to read policy file {path}: {}.", error_name(&error)));
        return Err(());
    }
    let recipe = Recipe::new(config, Some(content));
    let mut diagnostic = Diagnostic::default();
    match recipe.base_engine(&mut diagnostic) {
        Ok(_) => Ok(recipe.policy_file.unwrap_or_default()),
        Err(BuildError::File(error)) => {
            eprintln!("{}", explain_policy_error(error, path, &diagnostic));
            Err(())
        }
        Err(error) => {
            report(&format!("POLICYFILE: {error}"));
            Err(())
        }
    }
}

/// The diagnostic of a rejected policy file, byte for byte as the Zig daemon printed it.
pub fn explain_policy_error(error: LoadError, path: &str, diagnostic: &Diagnostic) -> String {
    let explanation = error.explain();
    let mut text =
        format!("{}\n\nFile:   {path}\nError:  {}\n", explanation.message, error.name());
    if !diagnostic.rule.is_empty() {
        let _ = writeln!(text, "Rule:   {}", diagnostic.rule);
    }
    if !diagnostic.field.is_empty() {
        let _ = writeln!(text, "Field:  {}", diagnostic.field);
    }
    if !diagnostic.value.is_empty() {
        let _ = writeln!(text, "Value:  {}", diagnostic.value);
    }
    let mut out = String::new();
    let _ = diagnostic::render(&mut out, explanation.title, &text, explanation.hint);
    out
}

fn listen_address(config: &Config) -> Result<SocketAddr, ()> {
    let host = &config.listen_host;
    let port = config.listen_port;
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(_) => {
            report(&format!(
                "Failed to parse listen address {host}:{port}: InvalidIpAddressFormat"
            ));
            Err(())
        }
    }
}

fn bind(address: SocketAddr, port: u16) -> Result<TcpListener, ()> {
    TcpListener::bind(address).map_err(|error| {
        report(&format!("Failed to bind socket on port {port}: {}", error_name(&error)));
    })
}

/// The Zig error name of an I/O failure where one corresponds, else the Rust description.
fn error_name(error: &io::Error) -> String {
    let name = match error.kind() {
        io::ErrorKind::NotFound => "FileNotFound",
        io::ErrorKind::PermissionDenied => "AccessDenied",
        io::ErrorKind::IsADirectory => "IsDir",
        io::ErrorKind::AddrInUse => "AddressInUse",
        io::ErrorKind::AddrNotAvailable => "AddressNotAvailable",
        _ => return error.to_string(),
    };
    name.to_owned()
}

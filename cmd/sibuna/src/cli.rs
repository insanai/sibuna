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
                #[cfg(feature = "console")]
                eprint!("{}", crate::console::HELP);
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
    let daemon_args = if args.first().is_some_and(|arg| arg == "console") {
        match console_subcommand(args.get(1..).unwrap_or_default()) {
            Ok(rest) => rest,
            Err(code) => return code,
        }
    } else {
        args
    };
    match console_options(daemon_args) {
        Ok(Some((mut config, console))) => match start(&mut config, secret, console) {
            Ok(code) => code,
            Err(()) => ExitCode::FAILURE,
        },
        Ok(None) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

/// `sibuna console <rest>`: without the console feature, refused.
#[cfg(not(feature = "console"))]
fn console_subcommand(_rest: &[String]) -> Result<&[String], ExitCode> {
    report(
        "CONSOLEBUILD: console support is not compiled. Hint: build with the console feature \
         enabled.",
    );
    Err(ExitCode::FAILURE)
}

/// `sibuna console <rest>`: `init-admin` continues as a daemon command line; any other
/// word is a console command, run here.
#[cfg(feature = "console")]
fn console_subcommand(rest: &[String]) -> Result<&[String], ExitCode> {
    if rest.first().is_some_and(|word| word == "init-admin") {
        return Ok(rest);
    }
    Err(console_command(rest))
}

/// The console's configuration when `--console` was given; nothing without the feature.
#[cfg(feature = "console")]
type ConsoleOption = Option<sibuna_console::Config>;
/// The console's configuration when `--console` was given; nothing without the feature.
#[cfg(not(feature = "console"))]
type ConsoleOption = Option<std::convert::Infallible>;

/// Parses the command line: the console's options are split off first, then the data
/// plane's are parsed. Returns the configuration and the console's, `Ok(None)` after an
/// offline `init-admin` succeeded, and `Err` when a failure was reported.
#[cfg(not(feature = "console"))]
fn console_options(args: &[String]) -> Result<Option<(Config, ConsoleOption)>, ()> {
    match Config::parse_args(args) {
        Ok(config) => Ok(Some((config, None))),
        Err(error) => {
            eprintln!("{error}");
            Err(())
        }
    }
}

/// Parses the command line: the console's options are split off first, then the data
/// plane's are parsed. Returns the configuration and the console's, `Ok(None)` after an
/// offline `init-admin` succeeded, and `Err` when a failure was reported.
#[cfg(feature = "console")]
fn console_options(args: &[String]) -> Result<Option<(Config, ConsoleOption)>, ()> {
    use crate::console::{init, options};
    let parsed = options::parse(args).map_err(|error| {
        report(&format!(
            "CONSOLE002: invalid console options ({error}). Hint: check --console host:port, \
             proxy settings, and query steps (100000-50000000, supplied once)."
        ));
    })?;
    let mut config = Config::parse_args(&parsed.data_args).map_err(|error| {
        eprintln!("{error}");
    })?;
    if let Some(steps) = parsed.query_steps {
        config.console_query_steps = steps;
    }
    if parsed.capture_heads {
        config.console_capture_heads = true;
        config.console_capture_headers = parsed.capture_headers.clone();
    }
    if parsed.enabled {
        validate_console(&parsed.config, &config)?;
    }
    if let Some(username) = &parsed.initial_admin {
        return match init::run(&config, username) {
            Ok(password) => {
                eprint!("{}", init::created_message(username, &password));
                Ok(None)
            }
            Err(error) => {
                report(&format!(
                    "CONSOLEBOOT: local initialization failed ({error}). Hint: use \
                     --data-dir with a stopped, uninitialized Sibuna instance."
                ));
                Err(())
            }
        };
    }
    Ok(Some((config, parsed.enabled.then_some(parsed.config))))
}

/// Refuses a console configuration with `CONSOLE001`: no storage, or a rule of the
/// console's configuration broken.
#[cfg(feature = "console")]
fn validate_console(console: &sibuna_console::Config, config: &Config) -> Result<(), ()> {
    use sibuna_console::ConfigError;
    let name = if config.storage_backend() == sibuna_core::StorageBackend::InMemory {
        String::from("StorageRequired")
    } else {
        match console.validate(crate::console::start::node_id(config)) {
            Ok(()) => return Ok(()),
            Err(ConfigError::Peers(error)) => format!("{error:?}"),
            Err(ConfigError::Budget(_)) => String::from("InvalidBudget"),
            Err(error) => format!("{error:?}"),
        }
    };
    report(&format!(
        "CONSOLE001: console configuration rejected ({name}). Hint: configure storage and a \
         trusted HTTPS ingress for remote access."
    ));
    Err(())
}

/// Runs `sibuna console <args>` against a running console and renders a failure. Progress
/// lines (GeoIP status changes) and a sign-out warning go to standard error.
#[cfg(feature = "console")]
fn console_command(args: &[String]) -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    match sibuna_console::command::run_with(args, &mut stdout, &mut stderr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut text = String::new();
            let _ =
                diagnostic::render(&mut text, "console command", &error.to_string(), error.hint());
            eprintln!("{text}");
            ExitCode::FAILURE
        }
    }
}

/// Everything after parsing. `Err` means the failure was already reported.
fn start(
    config: &mut Config,
    secret: Option<&str>,
    console: ConsoleOption,
) -> Result<ExitCode, ()> {
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
    let started = match console {
        #[cfg(feature = "console")]
        Some(console) => Daemon::start_with_console(options, console, listener),
        #[cfg(not(feature = "console"))]
        Some(never) => match never {},
        None => Daemon::start(options, listener),
    };
    let daemon = match started {
        Ok(daemon) => daemon,
        Err(error) => {
            report_start_error(&error);
            return Err(());
        }
    };
    #[cfg(feature = "console")]
    print_console_banner(&daemon);
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
        #[cfg(feature = "console")]
        StartError::Console(error) => {
            report(&format!("Failed to start the console: {error}. Hint: {}", error.hint()));
        }
    }
}

/// Prints the console's startup lines (Zig's `announce`).
#[cfg(feature = "console")]
fn print_console_banner(daemon: &Daemon) {
    let (Some(console), Some(storage)) = (daemon.console(), daemon.storage()) else { return };
    let uninitialized = crate::console::start::is_uninitialized(storage).unwrap_or(false);
    eprint!("{}", crate::console::start::banner(console, uninitialized));
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

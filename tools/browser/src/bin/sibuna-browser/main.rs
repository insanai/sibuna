//! `sibuna-browser`: browser checks of a running Sibuna daemon in headless Chromium.
//!
//! - `challenge --url <protected url> --out <dir> [--no-wasm]` loads a URL behind the
//!   challenge interstitial, waits until the browser has solved it and reached the origin,
//!   and reports which solver ran and how long it took.
//! - `screenshot --url <url> --out <file>` saves a screenshot, for ad-hoc checks.
//!
//! Run it with `cargo xtask browser <command> ...`.

mod arguments;
mod challenge;
mod screenshot;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use arguments::{Flags, UsageError};

/// The exit status for a usage error, as opposed to a failed check (1).
const EXIT_USAGE: u8 = 2;

const HELP: &str = "\
Browser checks of a running Sibuna daemon in headless Chromium.

Usage: sibuna-browser <COMMAND> [OPTIONS]

Commands:
  challenge   Solve the challenge interstitial in Chromium and reach the origin
  screenshot  Save a screenshot of a page
  help        Print this help

challenge options:
  --url <URL>          A URL the daemon protects with a challenge (required)
  --out <DIR>          Where screenshots and frames go (required)
  --no-wasm            Disable WebAssembly so the JavaScript fallback must solve
  --expect <TEXT>      Text the origin page must contain (default: any content)
  --cookie <NAME>      The session cookie's name (default: __sibuna_token)
  --timeout <SECONDS>  How long the browser may take to reach the origin (default: 60)

screenshot options:
  --url <URL>          The page (required)
  --out <FILE>         The PNG file to write (required)
  --width <PIXELS>     Viewport width (default: 1280)
  --height <PIXELS>    Viewport height (default: 800)
  --mobile             Emulate a phone
  --no-wasm            Disable WebAssembly

Chromium is found as `chromium` on PATH, or at $SIBUNA_CHROMIUM.
$SIBUNA_BROWSER_PROTOCOL_LOG names a file that receives every DevTools message.
";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        return print_help();
    };
    let outcome = match command.to_str() {
        Some("challenge") => Flags::parse(rest, challenge::FLAGS)
            .and_then(|flags| challenge::Settings::read(&flags))
            .map(|settings| challenge::run(&settings)),
        Some("screenshot") => Flags::parse(rest, screenshot::FLAGS)
            .and_then(|flags| screenshot::Settings::read(&flags))
            .map(|settings| screenshot::run(&settings)),
        Some("help" | "-h" | "--help") => return print_help(),
        _ => Err(UsageError::new(
            format!("There is no command named `{}`.", command.to_string_lossy()),
            "Run `sibuna-browser help` to list the commands.",
        )),
    };
    match outcome {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        Ok(Ok(false)) => ExitCode::FAILURE,
        Ok(Err(error)) => {
            let mut message = format!("sibuna-browser: {error}");
            if let Some(hint) = error.hint() {
                message.push_str(&format!("\nHint: {hint}"));
            }
            let _ = writeln!(io::stderr(), "{message}");
            ExitCode::FAILURE
        }
        Err(usage) => {
            let _ = writeln!(io::stderr(), "{usage}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn print_help() -> ExitCode {
    match io::stdout().lock().write_all(HELP.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(EXIT_USAGE),
    }
}

/// Browser options from the environment: `$SIBUNA_CHROMIUM` and
/// `$SIBUNA_BROWSER_PROTOCOL_LOG`.
fn browser_options() -> sibuna_browser::Options {
    let mut options = sibuna_browser::Options::default();
    if let Some(executable) = std::env::var_os("SIBUNA_CHROMIUM").filter(|path| !path.is_empty()) {
        options.executable = executable.into();
    }
    if let Some(log) =
        std::env::var_os("SIBUNA_BROWSER_PROTOCOL_LOG").filter(|path| !path.is_empty())
    {
        options.protocol_log = Some(log.into());
    }
    options
}

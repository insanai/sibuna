//! The `sibuna console ...` subcommands (unit U2; Zig's `console_command*.zig`): account,
//! token, GeoIP and policy commands against a running console through its HTTP API.
//! Credentials come only from files; replies are validated before they are printed.
//!
//! The daemon's command line hands everything after `console` to [`run`].

use std::fmt;
use std::io::Write;

/// Why a console command failed.
#[derive(Debug)]
pub enum CommandError {
    /// The command is not available in this build.
    Unavailable,
}

impl CommandError {
    /// Returns a sentence that tells the operator how to proceed.
    pub fn hint(&self) -> &'static str {
        match self {
            CommandError::Unavailable => "Use the console's web interface for now.",
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Unavailable => f.write_str("console commands are not available"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Runs the console command `args` (the words after `sibuna console`), writing its output
/// to `out`. The library never prints; the daemon renders a failure as a diagnostic.
///
/// Fails with the [`CommandError`] of the first failed step.
pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), CommandError> {
    let _ = (args, out);
    Err(CommandError::Unavailable)
}

//! A tiny leveled log line format.
//!
//! The Zig module printed `[LEVEL] message` lines straight to standard error. A library
//! must not print, so here the caller owns the sink: the daemon passes `std::io::stderr()`
//! (whose lock serialises lines), tests pass a `Vec<u8>`. The line format is unchanged.

use std::fmt;
use std::io;

/// The severity of a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Detail for developers.
    Debug,
    /// Normal operation.
    Info,
    /// Something the operator should look at.
    Warn,
    /// A failure.
    Error,
}

impl Level {
    /// Returns the fixed-width prefix of the level, such as `[INFO ]`.
    pub fn prefix(self) -> &'static str {
        match self {
            Level::Debug => "[DEBUG]",
            Level::Info => "[INFO ]",
            Level::Warn => "[WARN ]",
            Level::Error => "[ERROR]",
        }
    }
}

/// Writes one line, `<prefix> <message>\n`, into `out` with a single `write_all`, so lines
/// from several threads sharing a locked sink do not interleave.
///
/// Fails only when `out` fails. Format the message with `format_args!`.
pub fn write_line(
    out: &mut impl io::Write,
    level: Level,
    message: fmt::Arguments<'_>,
) -> io::Result<()> {
    let line = format!("{} {message}\n", level.prefix());
    out.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_prefixes() {
        assert_eq!(Level::Info.prefix(), "[INFO ]");
        assert_eq!(Level::Error.prefix(), "[ERROR]");
    }

    #[test]
    fn a_line_is_prefix_space_message_newline() {
        let mut out = Vec::new();
        write_line(&mut out, Level::Warn, format_args!("storage: {} queued", 3)).unwrap();
        assert_eq!(out, b"[WARN ] storage: 3 queued\n");
    }
}

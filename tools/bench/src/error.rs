//! The error of every benchmark step, printed as an Elm-style message.

use std::fmt;
use std::io;

/// A failure of a benchmark step: a short title, what went wrong, and how to fix it.
#[derive(Debug)]
pub struct Error {
    /// The title rule, in capitals (for example `WRK FAILED`).
    pub title: &'static str,
    /// A plain explanation of what went wrong.
    pub message: String,
    /// How to fix it, when we know.
    pub hint: Option<String>,
}

/// The result of a benchmark step.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Returns an error with `title` and `message` and no hint.
    pub fn new(title: &'static str, message: impl Into<String>) -> Error {
        Error { title, message: message.into(), hint: None }
    }

    /// Returns this error with `hint` attached.
    pub fn hint(mut self, hint: impl Into<String>) -> Error {
        self.hint = Some(hint.into());
        self
    }

    /// Returns an error for an I/O failure while doing `what`.
    pub fn io(what: impl fmt::Display, error: io::Error) -> Error {
        Error::new("I/O ERROR", format!("{what}: {error}."))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = 72usize.saturating_sub(self.title.len() + 4);
        writeln!(f, "-- {} {}", self.title, "-".repeat(rule))?;
        writeln!(f)?;
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\nHint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_has_a_title_rule_message_and_hint() {
        let error = Error::new("WRK FAILED", "wrk exited with status 1.").hint("Install wrk.");
        let text = error.to_string();
        assert!(text.starts_with("-- WRK FAILED ---"));
        assert!(text.contains("\n\nwrk exited with status 1.\nHint: Install wrk."));
        assert_eq!(text.lines().next().map(str::len), Some(72));
    }
}

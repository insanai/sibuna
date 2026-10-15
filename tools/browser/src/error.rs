//! The one error type of the crate.

use std::fmt;
use std::io;
use std::time::Duration;

use sibuna_http::websocket::FrameError;

/// Why a browser operation failed.
#[derive(Debug)]
pub enum Error {
    /// Chromium could not be started, or did not announce its DevTools port in time.
    Launch {
        /// What went wrong.
        message: String,
        /// The end of Chromium's standard error, when there is any.
        log_tail: String,
    },
    /// A file or socket operation failed.
    Io {
        /// What we were doing.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
    /// The WebSocket opening handshake was refused or malformed.
    Handshake(String),
    /// A WebSocket frame broke RFC 6455 or exceeded the message bound.
    WebSocket(FrameError),
    /// The DevTools connection closed.
    Closed,
    /// A DevTools message was not the JSON we expect.
    Protocol(String),
    /// Chromium answered a command with an error.
    Command {
        /// The command's method, such as `Page.navigate`.
        method: String,
        /// The DevTools error code.
        code: i64,
        /// The DevTools error message.
        message: String,
    },
    /// A JavaScript expression threw.
    Evaluation(String),
    /// Navigation failed before a document loaded (DNS, connection refused, ...).
    Navigation(String),
    /// No element matches a CSS selector.
    NotFound(String),
    /// A deadline passed first.
    Timeout {
        /// What we were waiting for.
        what: String,
        /// How long we waited.
        waited: Duration,
        /// The last error seen while polling, if any.
        last_error: Option<String>,
    },
}

impl Error {
    /// An [`Error::Io`] with a description of the operation.
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Error {
        Error::Io { context: context.into(), source }
    }

    /// The `Hint:` line that tells a person how to fix the cause, when we know one.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Error::Launch { .. } => {
                Some("Check that `chromium` is installed and on PATH, or set Options::executable.")
            }
            Error::Handshake(_) | Error::Closed => {
                Some("Chromium may have crashed; run with a visible log to see why.")
            }
            Error::NotFound(_) => Some("Wait for the element with Page::wait_for first."),
            Error::Timeout { .. } => Some(
                "Raise the timeout, or check the page in a screenshot to see where it stopped.",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Launch { message, log_tail } => {
                write!(f, "Chromium did not start: {message}")?;
                if !log_tail.is_empty() {
                    write!(f, "\nChromium's last output:\n{log_tail}")?;
                }
                Ok(())
            }
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Handshake(message) => write!(f, "WebSocket handshake failed: {message}"),
            Error::WebSocket(error) => write!(f, "DevTools connection: {error}"),
            Error::Closed => f.write_str("the DevTools connection closed"),
            Error::Protocol(message) => write!(f, "unexpected DevTools message: {message}"),
            Error::Command { method, code, message } => {
                write!(f, "{method} failed with code {code}: {message}")
            }
            Error::Evaluation(message) => write!(f, "the script threw: {message}"),
            Error::Navigation(message) => write!(f, "navigation failed: {message}"),
            Error::NotFound(selector) => write!(f, "no element matches `{selector}`"),
            Error::Timeout { what, waited, last_error } => {
                write!(f, "timed out after {:.1} s waiting for {what}", waited.as_secs_f64())?;
                if let Some(error) = last_error {
                    write!(f, " (last error: {error})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::WebSocket(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FrameError> for Error {
    fn from(error: FrameError) -> Self {
        Error::WebSocket(error)
    }
}

impl From<sibuna_json::Error> for Error {
    fn from(error: sibuna_json::Error) -> Self {
        Error::Protocol(format!("invalid JSON: {error}"))
    }
}

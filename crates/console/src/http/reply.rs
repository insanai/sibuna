//! JSON replies and failure bodies (Zig's `http.zig`), and [`RouteError`].
//!
//! A failure is `{"error":"<CODE>","hint":"<sentence>"}` with the hint texts of the Zig
//! console, which the interface shows. Every reply goes through `sibuna-serve`, which adds
//! the console's security fields and `Cache-Control: no-store`.

use std::fmt;

use sibuna_console_protocol::codec::{self, Encode};
use sibuna_http::Header;
use sibuna_serve::{Context, ServeError};

/// The content type of every API reply.
pub const JSON: &[u8] = b"application/json";

/// Why a route handler did not answer normally. The dispatcher turns each variant into its
/// reply ([`RouteError::reply`]); a handler that already answered returns `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteError {
    /// Answer `status` with the failure body of `code`.
    Fail {
        /// The HTTP status.
        status: u16,
        /// The failure code, such as `CONSOLE403`.
        code: &'static str,
    },
    /// The request is malformed, too large or not allowed in its form: 400 `CONSOLE002`.
    BadRequest,
    /// The storage job queue is full: 503 `CONSOLE003` (decision 8).
    StorageBusy,
    /// The password verifier is busy: 429 `CONSOLE003`, as in Zig.
    VerifierBusy,
    /// Storage did not answer within the request's wait: 503 `CONSOLEQUORUM`. The outcome is
    /// unknown, not proven failed.
    StorageTimeout,
    /// The service cannot answer (not available in this build, stopping, or an internal
    /// failure): 503 `CONSOLE004`.
    Unavailable,
    /// The connection failed, or a reply already started; nothing more can be sent.
    Serve(ServeError),
}

impl RouteError {
    /// Returns `Fail { status, code }`.
    pub const fn fail(status: u16, code: &'static str) -> RouteError {
        RouteError::Fail { status, code }
    }

    /// Returns the status and code this error answers with, or `None` when no reply can be
    /// sent ([`RouteError::Serve`]).
    pub fn reply(self) -> Option<(u16, &'static str)> {
        Some(match self {
            RouteError::Fail { status, code } => (status, code),
            RouteError::BadRequest => (400, "CONSOLE002"),
            RouteError::StorageBusy => (503, "CONSOLE003"),
            RouteError::VerifierBusy => (429, "CONSOLE003"),
            RouteError::StorageTimeout => (503, "CONSOLEQUORUM"),
            RouteError::Unavailable => (503, "CONSOLE004"),
            RouteError::Serve(_) => return None,
        })
    }
}

impl From<ServeError> for RouteError {
    /// Connection failures end the request; malformed input is a bad request (Zig answered
    /// `InvalidRequest` and `TooLarge` with 400); anything else is unavailable.
    fn from(error: ServeError) -> RouteError {
        match error {
            ServeError::WriteFailed | ServeError::ReadFailed | ServeError::EndOfStream => {
                RouteError::Serve(error)
            }
            ServeError::TooLarge
            | ServeError::InvalidRequest
            | ServeError::ExpectationFailed
            | ServeError::BodyConsumed => RouteError::BadRequest,
            ServeError::InvalidResponse | ServeError::Full | ServeError::Stopping => {
                RouteError::Unavailable
            }
        }
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, self.reply()) {
            (RouteError::Serve(error), _) => write!(f, "connection ended: {error}"),
            (_, Some((status, code))) => write!(f, "{status} {code}"),
            (_, None) => f.write_str("connection ended"),
        }
    }
}

impl std::error::Error for RouteError {}

/// Answers 200 with `value` as JSON. The value is encoded with its protocol encoder, so the
/// bytes are the Zig console's.
///
/// Fails with the listener's error when writing fails.
pub fn json<T: Encode + ?Sized>(context: &mut Context<'_>, value: &T) -> Result<(), ServeError> {
    json_bytes(context, codec::to_json(value).as_bytes(), &[])
}

/// Answers 200 with the JSON document `body` and the `extra` fields (a `Set-Cookie`, for
/// example).
///
/// Fails with the listener's error when writing fails or a field is invalid.
pub fn json_bytes(
    context: &mut Context<'_>,
    body: &[u8],
    extra: &[Header<'_>],
) -> Result<(), ServeError> {
    context.respond(200, JSON, body, extra)
}

/// Answers `status` with the failure body of `code`.
///
/// Fails with the listener's error when writing fails or `status` is invalid.
pub fn fail(context: &mut Context<'_>, status: u16, code: &str) -> Result<(), ServeError> {
    context.respond(status, JSON, failure_body(code).as_bytes(), &[])
}

/// Returns `{"error":"<code>","hint":"<hint>"}`. Codes and hints are ASCII without quotes or
/// backslashes, so no escaping is needed; a code that is not such text is escaped anyway.
pub fn failure_body(code: &str) -> String {
    let mut body = String::with_capacity(48 + code.len() + 160);
    body.push_str("{\"error\":");
    // Writing into a String cannot fail.
    let _ = sibuna_json::write_string(&mut body, code);
    body.push_str(",\"hint\":\"");
    body.push_str(hint(code));
    body.push_str("\"}");
    body
}

/// Returns the hint shown with failure `code`; the Zig console's texts.
pub fn hint(code: &str) -> &'static str {
    match code {
        "RANKHISTORY" => {
            "Retained ranking read failed. Check access, period and storage health, then \
             restart the scan. Missing archives are not zero traffic."
        }
        "CONSOLEPEERQUERY" => {
            "The selected node could not supply this view. Check peer health and retry. \
             Unavailable history is not zero traffic."
        }
        "TIMELINE001" => "History changed. Reload the latest page.",
        "CONSOLEQUORUM" => {
            "The database did not answer in time. The data plane continues from the last \
             applied policy. Check the database and retry."
        }
        "CONSOLENODE" => {
            "Refresh the node state and inspect the operation receipt before retrying. A \
             pending completion does not mean the local effect failed."
        }
        "CONSOLEAUDIT404" => {
            "This audit record is unavailable. Refresh; retention may have removed it."
        }
        "CONSOLESECURITY" => {
            "Narrow the findings period or select one node, then retry. If access changed, \
             sign in again."
        }
        "CONSOLEAUDIT" => "Narrow the audit filters or sign in again, then retry.",
        "CONSOLEMUTATION" => {
            "Wait up to one minute; a session permits sixty management mutations per minute."
        }
        "CONSOLETOKENFULL" => "Revoke unused credentials or remove inactive tokens, then retry.",
        "CONSOLETOKEN409" => "Refresh the token list and expected revision before retrying.",
        "CONSOLETOKEN403" => {
            "Use an administrator session and complete required two-factor setup."
        }
        "CONSOLETOKENS" => "Outcome unknown. Query the token list before retrying.",
        _ => "Check your input or sign in again.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_bodies_carry_the_zig_hints() {
        assert_eq!(
            failure_body("CONSOLE404"),
            "{\"error\":\"CONSOLE404\",\"hint\":\"Check your input or sign in again.\"}"
        );
        assert_eq!(
            failure_body("CONSOLEMUTATION"),
            "{\"error\":\"CONSOLEMUTATION\",\"hint\":\"Wait up to one minute; a session \
             permits sixty management mutations per minute.\"}"
        );
        // Without a consensus log the code means the database did not answer (SID 0007).
        assert!(hint("CONSOLEQUORUM").starts_with("The database did not answer in time."));
        assert!(hint("CONSOLEQUORUM").contains("policy. Check"));
        for code in ["RANKHISTORY", "CONSOLEPEERQUERY", "CONSOLENODE", "CONSOLESECURITY"] {
            let body = failure_body(code);
            assert!(sibuna_json::parse(body.as_bytes()).is_ok(), "{body}");
            assert!(!hint(code).contains("  "), "{code}");
        }
    }

    #[test]
    fn route_errors_answer_as_zig_did() {
        assert_eq!(RouteError::BadRequest.reply(), Some((400, "CONSOLE002")));
        assert_eq!(RouteError::StorageBusy.reply(), Some((503, "CONSOLE003")));
        assert_eq!(RouteError::VerifierBusy.reply(), Some((429, "CONSOLE003")));
        assert_eq!(RouteError::StorageTimeout.reply(), Some((503, "CONSOLEQUORUM")));
        assert_eq!(RouteError::Unavailable.reply(), Some((503, "CONSOLE004")));
        assert_eq!(RouteError::fail(404, "CONSOLE404").reply(), Some((404, "CONSOLE404")));
        assert_eq!(RouteError::from(ServeError::TooLarge), RouteError::BadRequest);
        assert_eq!(RouteError::from(ServeError::InvalidRequest), RouteError::BadRequest);
        let io = RouteError::from(ServeError::EndOfStream);
        assert_eq!(io.reply(), None);
        assert_eq!(RouteError::from(ServeError::InvalidResponse), RouteError::Unavailable);
    }
}

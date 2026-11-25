//! The failures of a handoff, as diagnostics with a code, a title and a hint.

use std::fmt;

/// Why a handoff ended. The giver decides by it what it may do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The peer runs as another user.
    Refused,
    /// The two ends share no version of the protocol.
    Version,
    /// The peer broke the protocol: a malformed, oversized or unexpected frame, or a
    /// descriptor that is not what the frame says.
    Protocol,
    /// The peer did not answer in time. Its connection is still open.
    Timeout,
    /// The peer closed the connection.
    Closed,
    /// The other end is busy or stopping and gave no descriptors.
    Busy,
    /// This platform cannot pass descriptors.
    Unsupported,
}

/// A handoff that ended without a cutover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeError {
    /// What kind of failure this is.
    pub failure: Failure,
    /// What happened, in one sentence.
    pub message: String,
}

impl UpgradeError {
    /// A failure of kind `failure` with the explanation `message`.
    pub fn new(failure: Failure, message: impl Into<String>) -> Self {
        Self { failure, message: message.into() }
    }

    /// The code of the diagnostic, from `UPG001`.
    pub fn code(&self) -> &'static str {
        match self.failure {
            Failure::Refused => "UPG001",
            Failure::Version => "UPG002",
            Failure::Protocol => "UPG003",
            Failure::Timeout => "UPG004",
            Failure::Closed => "UPG005",
            Failure::Busy => "UPG006",
            Failure::Unsupported => "UPG007",
        }
    }

    /// The title of the diagnostic, in lower case.
    pub fn title(&self) -> &'static str {
        match self.failure {
            Failure::Refused => "upgrade peer refused",
            Failure::Version => "upgrade version not shared",
            Failure::Protocol => "upgrade protocol error",
            Failure::Timeout => "upgrade timed out",
            Failure::Closed => "upgrade connection closed",
            Failure::Busy => "upgrade not possible now",
            Failure::Unsupported => "upgrade socket not supported",
        }
    }

    /// How the operator repairs the failure.
    pub fn hint(&self) -> &'static str {
        match self.failure {
            Failure::Refused => {
                "Start the replacement as the user of the running daemon. The upgrade socket \
                 serves that user only."
            }
            Failure::Version => {
                "The two binaries are too far apart for a handoff. Set `global.reuse_port` in \
                 the file, restart once, and replace the binary that way."
            }
            Failure::Protocol => {
                "Check that `global.upgrade_socket` names the socket of a running Sibuna edge \
                 and nothing else."
            }
            Failure::Timeout => {
                "The running daemon did not answer. Look at its log, and at its load. It keeps \
                 serving."
            }
            Failure::Closed => {
                "The running daemon ended the handoff. Its log says why, in a line with \
                 `UPG011` or `UPG012`. It keeps serving unless it was told to stop."
            }
            Failure::Busy => {
                "Another replacement is in progress, or the running daemon is stopping. Wait \
                 for it and start again."
            }
            Failure::Unsupported => {
                "Descriptor passing needs Linux. Remove `global.upgrade_socket`, and replace \
                 the binary with `global.reuse_port` or a restart."
            }
        }
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpgradeError {}

/// A protocol failure with the explanation `message`.
pub(crate) fn protocol(message: impl Into<String>) -> UpgradeError {
    UpgradeError::new(Failure::Protocol, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_has_its_own_code_and_a_hint() {
        let all = [
            Failure::Refused,
            Failure::Version,
            Failure::Protocol,
            Failure::Timeout,
            Failure::Closed,
            Failure::Busy,
            Failure::Unsupported,
        ];
        let mut codes: Vec<&str> =
            all.iter().map(|failure| UpgradeError::new(*failure, "x").code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        for failure in all {
            let error = UpgradeError::new(failure, "what happened");
            assert!(!error.hint().is_empty() && !error.title().is_empty());
            assert_eq!(error.to_string(), "what happened");
        }
    }
}

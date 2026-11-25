//! Verdicts, failures and the rule that joins them (SID 0030, "The failure rule").
//!
//! The Lean model `docs/sid/assets/plugin-tiers.lean` states [`outcome`] and [`chain`]
//! and proves that a chain with a failing authorization hook never admits.

/// What a hook answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The traffic goes on.
    Admit,
    /// The traffic is refused.
    Deny,
    /// The client must pass the proof-of-work challenge first. At the connection stage
    /// there is no challenge, and the caller denies.
    Challenge,
}

/// Why an invocation ended without a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The fuel of a Wasm hook was spent, or an agent did not answer in time.
    Timeout,
    /// The view did not fit the input buffer or a frame, or too many calls waited.
    Overload,
    /// A Wasm trap, a bound of the interpreter, or an answer outside the contract.
    Trap,
    /// The agent could not be reached, or its breaker is open.
    Unavailable,
}

impl Failure {
    /// Every failure, in the order of the counters.
    pub const ALL: [Failure; 4] =
        [Failure::Timeout, Failure::Overload, Failure::Trap, Failure::Unavailable];

    /// The name of the failure in the counters and in `show hooks`.
    pub fn name(self) -> &'static str {
        match self {
            Failure::Timeout => "timeout",
            Failure::Overload => "overload",
            Failure::Trap => "trap",
            Failure::Unavailable => "unavailable",
        }
    }

    /// The place of the failure in [`Failure::ALL`].
    pub(crate) fn index(self) -> usize {
        match self {
            Failure::Timeout => 0,
            Failure::Overload => 1,
            Failure::Trap => 2,
            Failure::Unavailable => 3,
        }
    }
}

/// The written choice `on_failure` of a plugin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OnFailure {
    /// A failure denies. This is an authorization hook.
    #[default]
    Deny,
    /// A failure admits. This is an advisory hook.
    Admit,
}

/// Where a hook is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// A new TCP connection or UDP mapping.
    Connection,
    /// An HTTP request that the firewall admitted.
    Request,
    /// An HTTP request whose answer ended.
    Telemetry,
}

impl Stage {
    /// Every stage, in the order of the wire form.
    pub const ALL: [Stage; 3] = [Stage::Connection, Stage::Request, Stage::Telemetry];

    /// The name of the stage in the configuration.
    pub fn name(self) -> &'static str {
        match self {
            Stage::Connection => "connection",
            Stage::Request => "request",
            Stage::Telemetry => "telemetry",
        }
    }

    /// The byte of the stage in the wire form of the view.
    pub fn wire(self) -> u8 {
        match self {
            Stage::Connection => 1,
            Stage::Request => 2,
            Stage::Telemetry => 3,
        }
    }

    /// The bit of the stage in [`crate::Slot::stages`].
    pub fn bit(self) -> u8 {
        1 << (self.wire() - 1)
    }
}

/// The outcome of one invocation that ended with `result` at `stage`, for a plugin whose
/// written choice is `on_failure`. A telemetry hook always admits: nothing is left to
/// refuse.
pub fn outcome(stage: Stage, on_failure: OnFailure, result: Result<Verdict, Failure>) -> Verdict {
    match (stage, result, on_failure) {
        (Stage::Telemetry, _, _) => Verdict::Admit,
        (_, Ok(verdict), _) => verdict,
        (_, Err(_), OnFailure::Deny) => Verdict::Deny,
        (_, Err(_), OnFailure::Admit) => Verdict::Admit,
    }
}

/// The verdict of a chain of outcomes in order: the first that is not an admission.
pub fn chain(outcomes: impl IntoIterator<Item = Verdict>) -> Verdict {
    outcomes.into_iter().find(|verdict| *verdict != Verdict::Admit).unwrap_or(Verdict::Admit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_authorization_hook_denies_at_both_deciding_stages() {
        for stage in [Stage::Connection, Stage::Request] {
            for failure in Failure::ALL {
                assert_eq!(outcome(stage, OnFailure::Deny, Err(failure)), Verdict::Deny);
                assert_eq!(outcome(stage, OnFailure::Admit, Err(failure)), Verdict::Admit);
            }
        }
    }

    #[test]
    fn a_verdict_is_kept_whatever_the_choice() {
        for choice in [OnFailure::Deny, OnFailure::Admit] {
            for verdict in [Verdict::Admit, Verdict::Deny, Verdict::Challenge] {
                assert_eq!(outcome(Stage::Request, choice, Ok(verdict)), verdict);
            }
        }
    }

    #[test]
    fn telemetry_never_refuses() {
        assert_eq!(outcome(Stage::Telemetry, OnFailure::Deny, Ok(Verdict::Deny)), Verdict::Admit);
        let failed = Err(Failure::Trap);
        assert_eq!(outcome(Stage::Telemetry, OnFailure::Deny, failed), Verdict::Admit);
    }

    #[test]
    fn a_chain_admits_only_when_every_hook_admits() {
        use Verdict::{Admit, Challenge, Deny};
        assert_eq!(chain([]), Admit);
        assert_eq!(chain([Admit, Admit]), Admit);
        assert_eq!(chain([Admit, Deny, Challenge]), Deny);
        assert_eq!(chain([Challenge, Deny]), Challenge);
        // The theorem of the model, exhaustively for chains of three.
        let all = [Admit, Deny, Challenge];
        for before in all {
            for after in all {
                let failed = outcome(Stage::Request, OnFailure::Deny, Err(Failure::Timeout));
                assert_ne!(chain([before, failed, after]), Admit);
            }
        }
    }
}

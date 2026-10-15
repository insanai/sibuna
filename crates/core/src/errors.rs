//! Elm-style explanations with recovery hints for the errors clients see.
//!
//! The daemon answers a rejected challenge solution with one of these texts as the HTTP
//! response body, so every text is byte for byte the text of the Zig daemon's
//! `explainError`.
//!
//! # Where the error kinds live
//!
//! Zig matched on the global `anyerror` set, so any library's error could be explained by
//! name. Rust has no global error set, and core must not depend on the crates whose errors
//! it explains. We therefore define the table over [`ErrorKind`], an enum that names each
//! explained error once, here in core. Other crates map into it:
//!
//! - Application crates (`sibuna-challenge`, `sibuna-net`, `sibuna-policy`) sit above core
//!   and may implement `From<TheirError> for ErrorKind`, mapping anything the table does not
//!   describe to [`ErrorKind::Unexpected`].
//! - Reusable crates (`sibuna-store`, `sibuna-http`) never depend on core. Their errors are
//!   mapped by the daemon, either with a `match` or through [`ErrorKind::from_name`] when
//!   the error exposes its Zig name.
//!
//! [`explain_name`] keeps Zig's by-name behaviour for callers that only have a name.

/// Every error with a dedicated explanation, named as in the Zig daemon, plus
/// [`ErrorKind::Unexpected`] for everything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The challenge passed its validity window.
    ChallengeExpired,
    /// The challenge identifier is not in the active store.
    ChallengeNotFound,
    /// The nonce is malformed or not numeric.
    InvalidNonce,
    /// The hash does not meet the difficulty.
    DifficultyNotMet,
    /// The challenge was already spent.
    DoubleSpendAttempt,
    /// The client address or User-Agent differs from the challenge binding.
    FingerprintMismatch,
    /// The challenge identifier is not a well-formed record.
    MalformedChallenge,
    /// The challenge identifier failed authentication.
    InvalidChallengeTag,
    /// The proof of sequential work does not verify.
    InvalidProof,
    /// A nonce was sent for a PoSW challenge, or a proof for a hashcash challenge.
    WrongSolutionType,
    /// The session token signature failed verification.
    InvalidTokenSignature,
    /// The session token expired.
    TokenExpired,
    /// The token was issued to another network location.
    TokenBoundAddressMismatch,
    /// The session cookie cannot be decoded.
    MalformedToken,
    /// A request line or header field violates HTTP/1.1.
    InvalidHttpHeader,
    /// The request head is larger than the connection buffer.
    HeaderTooLarge,
    /// The request target is longer than 4096 bytes.
    UriTooLong,
    /// The HTTP version is not supported.
    UnsupportedHttpVersion,
    /// The peer or the origin closed the connection.
    ConnectionReset,
    /// The key is not in the decay map.
    KeyNotFound,
    /// The cache entry expired.
    Expired,
    /// A fixed store reached its capacity.
    StoreFull,
    /// Any error without a dedicated explanation.
    Unexpected,
}

impl ErrorKind {
    /// Every kind, in the order of the Zig table, `Unexpected` last.
    pub const ALL: [ErrorKind; 23] = [
        ErrorKind::ChallengeExpired,
        ErrorKind::ChallengeNotFound,
        ErrorKind::InvalidNonce,
        ErrorKind::DifficultyNotMet,
        ErrorKind::DoubleSpendAttempt,
        ErrorKind::FingerprintMismatch,
        ErrorKind::MalformedChallenge,
        ErrorKind::InvalidChallengeTag,
        ErrorKind::InvalidProof,
        ErrorKind::WrongSolutionType,
        ErrorKind::InvalidTokenSignature,
        ErrorKind::TokenExpired,
        ErrorKind::TokenBoundAddressMismatch,
        ErrorKind::MalformedToken,
        ErrorKind::InvalidHttpHeader,
        ErrorKind::HeaderTooLarge,
        ErrorKind::UriTooLong,
        ErrorKind::UnsupportedHttpVersion,
        ErrorKind::ConnectionReset,
        ErrorKind::KeyNotFound,
        ErrorKind::Expired,
        ErrorKind::StoreFull,
        ErrorKind::Unexpected,
    ];

    /// Returns the Zig error name of this kind (`"ChallengeExpired"`); `Unexpected` has the
    /// name `"Unexpected"`, which no Zig error used.
    pub fn name(self) -> &'static str {
        match self {
            ErrorKind::ChallengeExpired => "ChallengeExpired",
            ErrorKind::ChallengeNotFound => "ChallengeNotFound",
            ErrorKind::InvalidNonce => "InvalidNonce",
            ErrorKind::DifficultyNotMet => "DifficultyNotMet",
            ErrorKind::DoubleSpendAttempt => "DoubleSpendAttempt",
            ErrorKind::FingerprintMismatch => "FingerprintMismatch",
            ErrorKind::MalformedChallenge => "MalformedChallenge",
            ErrorKind::InvalidChallengeTag => "InvalidChallengeTag",
            ErrorKind::InvalidProof => "InvalidProof",
            ErrorKind::WrongSolutionType => "WrongSolutionType",
            ErrorKind::InvalidTokenSignature => "InvalidTokenSignature",
            ErrorKind::TokenExpired => "TokenExpired",
            ErrorKind::TokenBoundAddressMismatch => "TokenBoundAddressMismatch",
            ErrorKind::MalformedToken => "MalformedToken",
            ErrorKind::InvalidHttpHeader => "InvalidHttpHeader",
            ErrorKind::HeaderTooLarge => "HeaderTooLarge",
            ErrorKind::UriTooLong => "UriTooLong",
            ErrorKind::UnsupportedHttpVersion => "UnsupportedHttpVersion",
            ErrorKind::ConnectionReset => "ConnectionReset",
            ErrorKind::KeyNotFound => "KeyNotFound",
            ErrorKind::Expired => "Expired",
            ErrorKind::StoreFull => "StoreFull",
            ErrorKind::Unexpected => "Unexpected",
        }
    }

    /// Returns the kind whose Zig error name is `name` (exact, case-sensitive), or `None`
    /// for any other name, including `"Unexpected"`.
    pub fn from_name(name: &str) -> Option<ErrorKind> {
        ErrorKind::ALL
            .into_iter()
            .find(|kind| *kind != ErrorKind::Unexpected && kind.name() == name)
    }

    /// Returns the explanation of this kind: a title rule, a sentence and a hint, without
    /// a trailing newline. The text is static and identical to the Zig daemon's.
    pub fn explain(self) -> &'static str {
        match self {
            ErrorKind::ChallengeExpired => CHALLENGE_EXPIRED,
            ErrorKind::ChallengeNotFound => CHALLENGE_NOT_FOUND,
            ErrorKind::InvalidNonce => INVALID_NONCE,
            ErrorKind::DifficultyNotMet => DIFFICULTY_NOT_MET,
            ErrorKind::DoubleSpendAttempt => DOUBLE_SPEND_ATTEMPT,
            ErrorKind::FingerprintMismatch => FINGERPRINT_MISMATCH,
            ErrorKind::MalformedChallenge => MALFORMED_CHALLENGE,
            ErrorKind::InvalidChallengeTag => INVALID_CHALLENGE_TAG,
            ErrorKind::InvalidProof => INVALID_PROOF,
            ErrorKind::WrongSolutionType => WRONG_SOLUTION_TYPE,
            ErrorKind::InvalidTokenSignature => INVALID_TOKEN_SIGNATURE,
            ErrorKind::TokenExpired => TOKEN_EXPIRED,
            ErrorKind::TokenBoundAddressMismatch => TOKEN_BOUND_ADDRESS_MISMATCH,
            ErrorKind::MalformedToken => MALFORMED_TOKEN,
            ErrorKind::InvalidHttpHeader => INVALID_HTTP_HEADER,
            ErrorKind::HeaderTooLarge => HEADER_TOO_LARGE,
            ErrorKind::UriTooLong => URI_TOO_LONG,
            ErrorKind::UnsupportedHttpVersion => UNSUPPORTED_HTTP_VERSION,
            ErrorKind::ConnectionReset => CONNECTION_RESET,
            ErrorKind::KeyNotFound => KEY_NOT_FOUND,
            ErrorKind::Expired => EXPIRED,
            ErrorKind::StoreFull => STORE_FULL,
            ErrorKind::Unexpected => UNEXPECTED,
        }
    }
}

/// Returns the explanation for the error named `name`, or the "UNEXPECTED ERROR" text for a
/// name the table does not know, exactly as Zig's `explainError(err)` did for `@errorName`.
pub fn explain_name(name: &str) -> &'static str {
    ErrorKind::from_name(name).unwrap_or(ErrorKind::Unexpected).explain()
}

// The texts below are copied verbatim from the Zig daemon (`libs/core/src/errors.zig`);
// clients see them in HTTP responses, so they must not be edited. Each rule is as long as
// the Zig source made it, which is not always 80 columns.

const CHALLENGE_EXPIRED: &str = "\
-- CHALLENGE EXPIRED -----------------------------------------------------------

The issued proof-of-work challenge has passed its validity window.

Hint: Request a new challenge from /__sibuna/challenge.json and re-run the solver.";

const CHALLENGE_NOT_FOUND: &str = "\
-- CHALLENGE NOT FOUND ---------------------------------------------------------

The challenge ID specified by the client does not exist in the active store.

Hint: Verify that the challenge ID was issued by this cluster and not evicted.";

const INVALID_NONCE: &str = "\
-- INVALID NONCE ---------------------------------------------------------------

The client submitted a malformed or non-numeric nonce parameter.

Hint: Submit the nonce as an unsigned 64-bit integer formatted as a decimal string.";

const DIFFICULTY_NOT_MET: &str = "\
-- DIFFICULTY NOT MET ----------------------------------------------------------

The calculated hash did not contain the required number of leading zero hex chars.

Hint: Continue incrementing the nonce until the hash satisfies the target difficulty.";

const DOUBLE_SPEND_ATTEMPT: &str = "\
-- DOUBLE SPEND PREVENTED ------------------------------------------------------

This challenge has already been marked as spent by a previous verification pass.

Hint: Challenges are single-use; request a new challenge for new verification runs.";

const FINGERPRINT_MISMATCH: &str = "\
-- CLIENT FINGERPRINT MISMATCH --------------------------------------------------

The client IP address or User-Agent does not match the issued challenge binding.

Hint: Ensure the same browser or HTTP client submits the solver response.";

const MALFORMED_CHALLENGE: &str = "\
-- MALFORMED CHALLENGE ---------------------------------------------------------

The challenge identifier is not a well-formed Sibuna challenge record.

Hint: Fetch a fresh challenge from /__sibuna/challenge.json and submit it unchanged.";

const INVALID_CHALLENGE_TAG: &str = "\
-- INVALID CHALLENGE TAG -------------------------------------------------------

The challenge identifier failed authentication; it was not issued by this cluster.

Hint: Challenges cannot be forged or edited; request a new one from the daemon.";

const INVALID_PROOF: &str = "\
-- INVALID PROOF OF SEQUENTIAL WORK --------------------------------------------

The submitted proof does not open the committed labels for the derived challenges.

Hint: Run the prover to completion for the exact depth and opening count issued.";

const WRONG_SOLUTION_TYPE: &str = "\
-- WRONG SOLUTION TYPE ---------------------------------------------------------

A nonce was submitted for a PoSW challenge, or a proof for a hashcash challenge.

Hint: Submit \"nonce\" for hashcash challenges and \"proof\" for posw challenges.";

const INVALID_TOKEN_SIGNATURE: &str = "\
-- INVALID TOKEN SIGNATURE -----------------------------------------------------

The Ed25519 signature on the session cookie failed verification.

Hint: Re-authenticate through the challenge page to obtain a newly signed token.";

const TOKEN_EXPIRED: &str = "\
-- TOKEN EXPIRED ---------------------------------------------------------------

The session token expiry timestamp has elapsed.

Hint: Present a new proof-of-work challenge to renew the authentication session.";

const TOKEN_BOUND_ADDRESS_MISMATCH: &str = "\
-- NETWORK BINDING MISMATCH ----------------------------------------------------

The token was issued to a different client IP address or TLS session fingerprint.

Hint: Session cookies cannot be shared across different network locations.";

const MALFORMED_TOKEN: &str = "\
-- MALFORMED TOKEN -------------------------------------------------------------

The auth cookie cannot be decoded as a valid compact binary token or JWT.

Hint: Clear the cookie and navigate to the origin to trigger a fresh challenge.";

const INVALID_HTTP_HEADER: &str = "\
-- INVALID HTTP HEADER ---------------------------------------------------------

An incoming request line or header field violates the HTTP/1.1 specification.

Hint: Ensure headers conform to RFC 9112 and contain valid ASCII name/value pairs.";

const HEADER_TOO_LARGE: &str = "\
-- HEADER TOO LARGE ------------------------------------------------------------

Request headers exceeded the pre-allocated 16 KB connection buffer.

Hint: Reduce cookie size or custom headers, or increase connection buffer capacity.";

const URI_TOO_LONG: &str = "\
-- URI TOO LONG ----------------------------------------------------------------

The request target path exceeds the maximum allowed URI length of 4096 bytes.

Hint: Truncate query parameters or switch from GET query strings to POST payloads.";

const UNSUPPORTED_HTTP_VERSION: &str = "\
-- UNSUPPORTED HTTP VERSION ----------------------------------------------------

The client requested an unsupported HTTP protocol version.

Hint: Use HTTP/1.1 or HTTP/2 when establishing connection with Sibuna.";

const CONNECTION_RESET: &str = "\
-- CONNECTION RESET ------------------------------------------------------------

The peer or upstream backend closed the connection unexpectedly.

Hint: Verify backend origin health and ensure timeouts are properly configured.";

const KEY_NOT_FOUND: &str = "\
-- KEY NOT FOUND ---------------------------------------------------------------

The requested key does not exist in the decay map.

Hint: Check if the key was expired or never inserted into the cache.";

const EXPIRED: &str = "\
-- ENTRY EXPIRED ---------------------------------------------------------------

The cache entry reached its time-to-live expiration timestamp.

Hint: Refresh the key from the authoritative storage layer.";

const STORE_FULL: &str = "\
-- STORE FULL ------------------------------------------------------------------

The fixed ring buffer or decay map reached its maximum allocated capacity.

Hint: Increase store capacity at startup or configure shorter entry TTLs.";

const UNEXPECTED: &str = "\
-- UNEXPECTED ERROR -------------------------------------------------------------

An undocumented or unexpected system error occurred.

Hint: Check system logs or report this issue with the full stack trace.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_error_returns_elm_style_messages_with_hints() {
        let message = ErrorKind::ChallengeExpired.explain();
        assert!(message.contains("-- CHALLENGE EXPIRED --"));
        assert!(message.contains("Hint: Request a new challenge"));
    }

    #[test]
    fn names_round_trip_and_unknown_names_are_unexpected() {
        for kind in ErrorKind::ALL {
            if kind == ErrorKind::Unexpected {
                assert_eq!(ErrorKind::from_name(kind.name()), None);
            } else {
                assert_eq!(ErrorKind::from_name(kind.name()), Some(kind));
                assert_eq!(explain_name(kind.name()), kind.explain());
            }
        }
        assert_eq!(explain_name("OutOfMemory"), UNEXPECTED);
        assert_eq!(explain_name("challengeexpired"), UNEXPECTED);
    }

    #[test]
    fn every_explanation_has_a_rule_a_sentence_and_a_hint() {
        for kind in ErrorKind::ALL {
            let text = kind.explain();
            let lines: Vec<&str> = text.split('\n').collect();
            assert_eq!(lines.len(), 5, "{kind:?}");
            assert!(lines[0].starts_with("-- ") && lines[0].ends_with("---"), "{kind:?}");
            assert!(lines[1].is_empty() && lines[3].is_empty(), "{kind:?}");
            assert!(lines[4].starts_with("Hint: "), "{kind:?}");
            assert!(text.is_ascii());
        }
    }
}

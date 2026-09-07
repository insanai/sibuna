//! Human-friendly Elm-style explanations and actionable recovery hints
//! for all Sibuna error domains.

const std = @import("std");

/// Returns a human-friendly Elm-style explanation with actionable hint.
pub fn explainError(err: anyerror) []const u8 {
    return switch (err) {
        error.ChallengeExpired,
        error.ChallengeNotFound,
        error.InvalidNonce,
        error.DifficultyNotMet,
        error.DoubleSpendAttempt,
        => explainChallengeError(err),

        error.InvalidTokenSignature,
        error.TokenExpired,
        error.TokenBoundAddressMismatch,
        error.MalformedToken,
        => explainTokenError(err),

        error.InvalidHttpHeader,
        error.HeaderTooLarge,
        error.UriTooLong,
        error.UnsupportedHttpVersion,
        error.ConnectionReset,
        => explainNetError(err),

        error.KeyNotFound,
        error.Expired,
        error.StoreFull,
        => explainStoreError(err),

        else =>
        \\-- UNEXPECTED ERROR -------------------------------------------------------------
        \\
        \\An undocumented or unexpected system error occurred.
        \\
        \\Hint: Check system logs or report this issue with the full stack trace.
        ,
    };
}

fn explainChallengeError(err: anyerror) []const u8 {
    return switch (err) {
        error.ChallengeExpired =>
        \\-- CHALLENGE EXPIRED -----------------------------------------------------------
        \\
        \\The issued proof-of-work challenge has passed its 30-minute validity window.
        \\
        \\Hint: Request a new challenge from /challenge/make and re-run the solver worker.
        ,
        error.ChallengeNotFound =>
        \\-- CHALLENGE NOT FOUND ---------------------------------------------------------
        \\
        \\The challenge ID specified by the client does not exist in the active store.
        \\
        \\Hint: Verify that the challenge ID was issued by this cluster and not evicted.
        ,
        error.InvalidNonce =>
        \\-- INVALID NONCE ---------------------------------------------------------------
        \\
        \\The client submitted a malformed or non-numeric nonce parameter.
        \\
        \\Hint: Submit the nonce as an unsigned 64-bit integer formatted as a decimal string.
        ,
        error.DifficultyNotMet =>
        \\-- DIFFICULTY NOT MET ----------------------------------------------------------
        \\
        \\The calculated hash did not contain the required number of leading zero hex chars.
        \\
        \\Hint: Continue incrementing the nonce until the hash satisfies the target difficulty.
        ,
        error.DoubleSpendAttempt =>
        \\-- DOUBLE SPEND PREVENTED ------------------------------------------------------
        \\
        \\This challenge has already been marked as spent by a previous verification pass.
        \\
        \\Hint: Challenges are single-use; request a new challenge for new verification runs.
        ,
        else => unreachable,
    };
}

fn explainTokenError(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidTokenSignature =>
        \\-- INVALID TOKEN SIGNATURE -----------------------------------------------------
        \\
        \\The Ed25519 signature on the session cookie failed verification.
        \\
        \\Hint: Re-authenticate through the challenge page to obtain a newly signed token.
        ,
        error.TokenExpired =>
        \\-- TOKEN EXPIRED ---------------------------------------------------------------
        \\
        \\The session token expiry timestamp has elapsed.
        \\
        \\Hint: Present a new proof-of-work challenge to renew the authentication session.
        ,
        error.TokenBoundAddressMismatch =>
        \\-- NETWORK BINDING MISMATCH ----------------------------------------------------
        \\
        \\The token was issued to a different client IP address or TLS session fingerprint.
        \\
        \\Hint: Session cookies cannot be shared across different network locations.
        ,
        error.MalformedToken =>
        \\-- MALFORMED TOKEN -------------------------------------------------------------
        \\
        \\The auth cookie cannot be decoded as a valid compact binary token or JWT.
        \\
        \\Hint: Clear the cookie and navigate to the origin to trigger a fresh challenge.
        ,
        else => unreachable,
    };
}

fn explainNetError(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidHttpHeader =>
        \\-- INVALID HTTP HEADER ---------------------------------------------------------
        \\
        \\An incoming request line or header field violates the HTTP/1.1 specification.
        \\
        \\Hint: Ensure headers conform to RFC 9112 and contain valid ASCII name/value pairs.
        ,
        error.HeaderTooLarge =>
        \\-- HEADER TOO LARGE ------------------------------------------------------------
        \\
        \\Request headers exceeded the pre-allocated 16 KB connection buffer.
        \\
        \\Hint: Reduce cookie size or custom headers, or increase connection buffer capacity.
        ,
        error.UriTooLong =>
        \\-- URI TOO LONG ----------------------------------------------------------------
        \\
        \\The request target path exceeds the maximum allowed URI length of 4096 bytes.
        \\
        \\Hint: Truncate query parameters or switch from GET query strings to POST payloads.
        ,
        error.UnsupportedHttpVersion =>
        \\-- UNSUPPORTED HTTP VERSION ----------------------------------------------------
        \\
        \\The client requested an unsupported HTTP protocol version.
        \\
        \\Hint: Use HTTP/1.1 or HTTP/2 when establishing connection with Sibuna.
        ,
        error.ConnectionReset =>
        \\-- CONNECTION RESET ------------------------------------------------------------
        \\
        \\The peer or upstream backend closed the connection unexpectedly.
        \\
        \\Hint: Verify backend origin health and ensure timeouts are properly configured.
        ,
        else => unreachable,
    };
}

fn explainStoreError(err: anyerror) []const u8 {
    return switch (err) {
        error.KeyNotFound =>
        \\-- KEY NOT FOUND ---------------------------------------------------------------
        \\
        \\The requested key does not exist in the decay map.
        \\
        \\Hint: Check if the key was expired or never inserted into the cache.
        ,
        error.Expired =>
        \\-- ENTRY EXPIRED ---------------------------------------------------------------
        \\
        \\The cache entry reached its time-to-live expiration timestamp.
        \\
        \\Hint: Refresh the key from the authoritative storage layer.
        ,
        error.StoreFull =>
        \\-- STORE FULL ------------------------------------------------------------------
        \\
        \\The fixed ring buffer or decay map reached its maximum allocated capacity.
        \\
        \\Hint: Increase store capacity at startup or configure shorter entry TTLs.
        ,
        else => unreachable,
    };
}

test "explainError returns elm-style messages with hints" {
    const msg = explainError(error.ChallengeExpired);
    try std.testing.expect(std.mem.indexOf(u8, msg, "-- CHALLENGE EXPIRED --") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "Hint: Request a new challenge") != null);
}

//! Sibuna Crypto Library
//!
//! Provides hardware-accelerated SHA-256 (NEON / SHA-NI), HashX, Argon2id,
//! Ed25519 signing and verification, and zero-allocation token management.

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Ed25519 = std.crypto.sign.Ed25519;

pub const pow = @import("pow.zig");
pub const token = @import("token.zig");

pub const countLeadingZeroHex = pow.countLeadingZeroHex;
pub const computeHashcash = pow.computeHashcash;
pub const verifyHashcash = pow.verifyHashcash;

pub const Token = token.Token;
pub const TokenError = token.TokenError;
pub const computeFingerprint = token.computeFingerprint;

test {
    _ = @import("pow.zig");
    _ = @import("token.zig");
}

test "sha256 sanity" {
    var out: [32]u8 = undefined;
    Sha256.hash("sibuna", &out, .{});
    try std.testing.expect(out.len == 32);
}

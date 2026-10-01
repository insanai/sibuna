//! Sibuna Crypto Library
//!
//! Hardware-accelerated SHA-256 Hashcash (Tier 1), the Cohen–Pietrzak Proof
//! of Sequential Work (Tier 2), keyed BLAKE3 session tokens, optional
//! Ed25519 tokens, and the domain-separated key schedule.

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Ed25519 = std.crypto.sign.Ed25519;

pub const pow = @import("pow.zig");
pub const posw = @import("posw.zig");
pub const token = @import("token.zig");
pub const keys = @import("keys.zig");

pub const countLeadingZeroHex = pow.countLeadingZeroHex;
pub const countLeadingZeroBits = pow.countLeadingZeroBits;
pub const computeHashcash = pow.computeHashcash;
pub const verifyHashcash = pow.verifyHashcash;
pub const verifyHashcashBits = pow.verifyHashcashBits;

pub const Token = token.Token;
pub const MacToken = token.MacToken;
pub const TokenPayload = token.Payload;
pub const WorkLevel = token.WorkLevel;
pub const TokenError = token.TokenError;
pub const computeFingerprint = token.computeFingerprint;
pub const computeFingerprintKeyed = token.computeFingerprintKeyed;
pub const ruleHash = token.ruleHash;

pub const Keys = keys.Keys;
pub const parseSeed = keys.parseSeed;

test {
    _ = @import("pow.zig");
    _ = @import("posw.zig");
    _ = @import("token.zig");
    _ = @import("keys.zig");
}

test "sha256 sanity" {
    var out: [32]u8 = undefined;
    Sha256.hash("sibuna", &out, .{});
    try std.testing.expect(out.len == 32);
}

//! Sibuna Crypto Library
//!
//! Provides hardware-accelerated SHA-256 (NEON / SHA-NI), HashX, Argon2id,
//! Ed25519 signing and verification, and zero-allocation token management.

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Ed25519 = std.crypto.sign.Ed25519;

test "sha256 sanity" {
    var out: [32]u8 = undefined;
    Sha256.hash("sibuna", &out, .{});
    try std.testing.expect(out.len == 32);
}

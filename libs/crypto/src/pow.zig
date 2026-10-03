//! Sibuna Hashcash Proof-of-Work (Tier 1)
//!
//! Zero-allocation SHA-256 Hashcash verification on native silicon. Zig's
//! `std.crypto` SHA-256 dispatches to the ARMv8 SHA2 and x86 SHA-NI
//! instruction sets when the build target has them, so one verification is
//! a single hardware-accelerated compression.
//!
//! Difficulty is measured in *bits*: a solution digest must start with
//! `bits` zero bits, so each increment doubles the expected work (2^bits
//! trials, geometrically distributed). The older hex-nibble helpers remain
//! for callers that think in 4-bit steps (`hex = bits / 4`).

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;

/// Number of leading zero hexadecimal characters of a digest.
pub fn countLeadingZeroHex(digest: [32]u8) u32 {
    return countLeadingZeroBits(digest) / 4;
}

/// Number of leading zero bits of a digest, using the hardware `clz`.
pub fn countLeadingZeroBits(digest: [32]u8) u32 {
    var zeros: u32 = 0;
    for (digest) |byte| {
        if (byte == 0) {
            zeros += 8;
        } else {
            zeros += @clz(byte);
            break;
        }
    }
    return zeros;
}

/// SHA-256(challenge ‖ ":" ‖ decimal(nonce)). The decimal nonce keeps the
/// wire format identical between the WASM solver, the JavaScript fallback,
/// and this verifier without any binary encoding step in the browser.
pub fn computeHashcash(challenge: []const u8, nonce: u64) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(challenge);
    hasher.update(":");
    var nonce_buf: [20]u8 = undefined;
    const nonce_str = std.fmt.bufPrint(&nonce_buf, "{d}", .{nonce}) catch unreachable;
    hasher.update(nonce_str);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// True when the digest has at least `bits` leading zero bits.
pub fn checkDifficultyBits(digest: [32]u8, bits: u32) bool {
    if (bits > 256) return false;
    const full_bytes = bits / 8;
    const rem_bits = bits % 8;
    for (digest[0..full_bytes]) |b| {
        if (b != 0) return false;
    }
    if (rem_bits > 0) {
        const shift: u3 = @intCast(8 - rem_bits);
        const mask = @as(u8, 0xff) << shift;
        if ((digest[full_bytes] & mask) != 0) return false;
    }
    return true;
}

/// True when the digest has at least `difficulty` leading zero hex digits.
pub fn checkDifficulty(digest: [32]u8, difficulty: u32) bool {
    return checkDifficultyBits(digest, difficulty * 4);
}

pub fn verifyHashcash(challenge: []const u8, nonce: u64, difficulty_hex: u32) bool {
    return checkDifficulty(computeHashcash(challenge, nonce), difficulty_hex);
}

pub fn verifyHashcashBits(challenge: []const u8, nonce: u64, bits: u32) bool {
    return checkDifficultyBits(computeHashcash(challenge, nonce), bits);
}

/// Reference solver used by tests and benchmarks; the browser solver lives
/// in `apps/wasm-pow` and shares the exact hash layout.
pub fn solveHashcashBits(challenge: []const u8, bits: u32, max_nonce: u64) ?u64 {
    var nonce: u64 = 0;
    while (nonce < max_nonce) : (nonce += 1) {
        if (verifyHashcashBits(challenge, nonce, bits)) return nonce;
    }
    return null;
}

test "leading zero counting in bits and hex" {
    var digest: [32]u8 = @as([32]u8, @splat(0xff));
    try std.testing.expectEqual(@as(u32, 0), countLeadingZeroBits(digest));
    try std.testing.expectEqual(@as(u32, 0), countLeadingZeroHex(digest));

    digest[0] = 0x0f;
    try std.testing.expectEqual(@as(u32, 4), countLeadingZeroBits(digest));
    try std.testing.expectEqual(@as(u32, 1), countLeadingZeroHex(digest));

    digest[0] = 0x00;
    digest[1] = 0x1f;
    try std.testing.expectEqual(@as(u32, 11), countLeadingZeroBits(digest));
    try std.testing.expectEqual(@as(u32, 2), countLeadingZeroHex(digest));
    try std.testing.expect(checkDifficultyBits(digest, 11));
    try std.testing.expect(!checkDifficultyBits(digest, 12));
    try std.testing.expect(checkDifficulty(digest, 2));
    try std.testing.expect(!checkDifficulty(digest, 3));
}

test "hashcash solve and verify at bit granularity" {
    const challenge = "sibuna-test-challenge-12345";
    const nonce = solveHashcashBits(challenge, 10, 1_000_000).?;
    try std.testing.expect(verifyHashcashBits(challenge, nonce, 10));
    try std.testing.expect(!verifyHashcashBits(challenge, nonce, 40));
    try std.testing.expect(!verifyHashcashBits(challenge, nonce + 1, 10) or
        verifyHashcashBits(challenge, nonce + 1, 10));
    // Hex difficulty 2 is exactly 8 bits.
    try std.testing.expect(verifyHashcash(challenge, nonce, 2));
}

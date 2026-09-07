//! Sibuna Proof-of-Work Verification Engine
//!
//! Provides ultra-fast, zero-allocation SHA-256 Hashcash verification
//! running natively on bare-metal silicon (leveraging SHA-NI / NEON).

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;

/// Calculates the number of leading zero hexadecimal characters in a 32-byte digest.
pub fn countLeadingZeroHex(digest: [32]u8) u32 {
    var zeros: u32 = 0;
    for (digest) |byte| {
        if ((byte >> 4) == 0) {
            zeros += 1;
            if ((byte & 0x0f) == 0) {
                zeros += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    return zeros;
}

/// Computes SHA-256(challenge ++ ":" ++ nonce) into a 32-byte output digest.
pub fn computeHashcash(challenge: []const u8, nonce: u64) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(challenge);
    hasher.update(":");
    var nonce_buf: [32]u8 = undefined;
    const nonce_str = std.fmt.bufPrint(&nonce_buf, "{d}", .{nonce}) catch "0";
    hasher.update(nonce_str);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Fast branchless prefix check for target difficulty (hex nibbles).
pub fn checkDifficulty(digest: [32]u8, difficulty: u32) bool {
    const full_bytes = difficulty / 2;
    var i: usize = 0;
    while (i < full_bytes) : (i += 1) {
        if (digest[i] != 0) return false;
    }
    if (difficulty % 2 != 0) {
        if ((digest[full_bytes] >> 4) != 0) return false;
    }
    return true;
}

/// Calculates the number of leading zero bits using hardware CLZ instructions.
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

/// Verifies fine-grained bit-level difficulty allowing 2x scaling per bit.
pub fn checkDifficultyBits(digest: [32]u8, bits: u32) bool {
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

/// Verifies whether the proof-of-work solution satisfies the target hex difficulty.
pub fn verifyHashcash(challenge: []const u8, nonce: u64, difficulty: u32) bool {
    const digest = computeHashcash(challenge, nonce);
    return checkDifficulty(digest, difficulty);
}

/// Verifies whether the proof-of-work solution satisfies bit-level difficulty.
pub fn verifyHashcashBits(challenge: []const u8, nonce: u64, bits: u32) bool {
    const digest = computeHashcash(challenge, nonce);
    return checkDifficultyBits(digest, bits);
}

test "countLeadingZeroHex counts nibbles correctly" {
    var digest: [32]u8 = [_]u8{0xff} ** 32;
    try std.testing.expectEqual(@as(u32, 0), countLeadingZeroHex(digest));

    digest[0] = 0x0f;
    try std.testing.expectEqual(@as(u32, 1), countLeadingZeroHex(digest));

    digest[0] = 0x00;
    digest[1] = 0x0a;
    try std.testing.expectEqual(@as(u32, 3), countLeadingZeroHex(digest));
}

test "verifyHashcash finds and validates solution" {
    const challenge = "sibuna-test-challenge-12345";
    const difficulty = 2; // 2 hex zeros is fast to find in unit test
    var nonce: u64 = 0;
    while (nonce < 100_000) : (nonce += 1) {
        if (verifyHashcash(challenge, nonce, difficulty)) {
            break;
        }
    }
    try std.testing.expect(nonce < 100_000);
    try std.testing.expect(verifyHashcash(challenge, nonce, difficulty));
    try std.testing.expect(!verifyHashcash(challenge, nonce, 10));
}

test "countLeadingZeroBits and checkDifficultyBits" {
    var digest: [32]u8 = [_]u8{0xff} ** 32;
    try std.testing.expectEqual(@as(u32, 0), countLeadingZeroBits(digest));

    digest[0] = 0x7f; // 01111111 -> 1 leading zero bit
    try std.testing.expectEqual(@as(u32, 1), countLeadingZeroBits(digest));
    try std.testing.expect(checkDifficultyBits(digest, 1));
    try std.testing.expect(!checkDifficultyBits(digest, 2));

    digest[0] = 0x00;
    digest[1] = 0x1f; // 00011111 -> 8 + 3 = 11 leading zero bits
    try std.testing.expectEqual(@as(u32, 11), countLeadingZeroBits(digest));
    try std.testing.expect(checkDifficultyBits(digest, 11));
    try std.testing.expect(!checkDifficultyBits(digest, 12));
}

//! Sibuna Key Schedule
//!
//! Every secret the daemon uses is derived from one 32-byte master seed with
//! BLAKE3 in keyed mode. Domain-separated derivation means a compromise or
//! rotation of one purpose key never touches the others, and a cluster only
//! has to agree on a single seed for every node to mint and verify the same
//! tokens and challenge identifiers.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub const seed_len = 32;

pub const Keys = struct {
    /// Keyed-hash MAC key for session tokens.
    token: [32]u8,
    /// PRF key that makes challenge identifiers unpredictable.
    challenge: [32]u8,
    /// Seed for the optional Ed25519 signing key pair.
    ed25519_seed: [32]u8,
    /// Key that hashes client identities in stores and logs.
    fingerprint: [32]u8,
    /// MAC key for requirement tickets, which carry a challenged request's demand to issuance.
    /// Not node-bound: any member sharing the seed honours a ticket another member authored.
    requirement: [32]u8,

    pub fn derive(seed: *const [seed_len]u8) Keys {
        return .{
            .token = subkey(seed, "sibuna/token/v1"),
            .challenge = subkey(seed, "sibuna/challenge/v1"),
            .ed25519_seed = subkey(seed, "sibuna/ed25519/v1"),
            .fingerprint = subkey(seed, "sibuna/fingerprint/v1"),
            .requirement = subkey(seed, "sibuna/requirement/v1"),
        };
    }
};

fn subkey(seed: *const [seed_len]u8, purpose: []const u8) [32]u8 {
    var hasher = Blake3.init(.{ .key = seed.* });
    hasher.update(purpose);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Parses a seed given as 64 hexadecimal characters, or as exactly 32 raw
/// bytes, which is the format of both `--secret-file` and the environment.
pub fn parseSeed(text: []const u8) ?[seed_len]u8 {
    var seed: [seed_len]u8 = undefined;
    const trimmed = std.mem.trim(u8, text, " \r\n\t");
    if (trimmed.len == seed_len * 2) {
        _ = std.fmt.hexToBytes(&seed, trimmed) catch return null;
        return seed;
    }
    if (text.len == seed_len) {
        @memcpy(&seed, text);
        return seed;
    }
    return null;
}

test "derived keys are distinct per purpose and stable" {
    const seed = @as([32]u8, @splat(7));
    const a = Keys.derive(&seed);
    const b = Keys.derive(&seed);
    try std.testing.expectEqualSlices(u8, &a.token, &b.token);
    try std.testing.expect(!std.mem.eql(u8, &a.token, &a.challenge));
    try std.testing.expect(!std.mem.eql(u8, &a.challenge, &a.ed25519_seed));
    try std.testing.expect(!std.mem.eql(u8, &a.requirement, &a.token));
    try std.testing.expect(!std.mem.eql(u8, &a.requirement, &a.challenge));
    const other = Keys.derive(&(@as([32]u8, @splat(8))));
    try std.testing.expect(!std.mem.eql(u8, &a.token, &other.token));
}

test "parseSeed accepts hex and raw forms" {
    const hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
    const seed = parseSeed(hex).?;
    try std.testing.expectEqual(@as(u8, 0x00), seed[0]);
    try std.testing.expectEqual(@as(u8, 0xff), seed[31]);
    try std.testing.expect(parseSeed("short") == null);
    const raw = @as([32]u8, @splat(1));
    try std.testing.expectEqualSlices(u8, &raw, &parseSeed(&raw).?);
}

//! Sibuna Challenge Coordinator
//!
//! Manages issuance of Proof-of-Work challenges, verification of client solutions,
//! single-use spend protection, and minting of Ed25519 compact session tokens.

const std = @import("std");
const crypto = @import("crypto");
const store = @import("store");

pub const ChallengePayload = struct {
    id: [32]u8,
    difficulty: u32,
    algorithm: []const u8 = "sha256",
};

pub const VerifiedResult = struct {
    token: [crypto.Token.encoded_size]u8,
    ttl_seconds: u64,
};

pub const Coordinator = struct {
    key_pair: crypto.Ed25519.KeyPair,
    challenge_store: *store.ChallengeStore,
    default_difficulty: u32,
    challenge_ttl: u32,
    token_ttl: u64,
    counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(1),

    pub fn init(
        store_ptr: *store.ChallengeStore,
        seed: [32]u8,
        difficulty: u32,
        challenge_ttl: u32,
        token_ttl: u64,
    ) Coordinator {
        const key_pair = crypto.Ed25519.KeyPair.generateDeterministic(seed) catch
            unreachable;
        return .{
            .key_pair = key_pair,
            .challenge_store = store_ptr,
            .default_difficulty = difficulty,
            .challenge_ttl = challenge_ttl,
            .token_ttl = token_ttl,
        };
    }

    pub fn createChallenge(
        self: *Coordinator,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) !ChallengePayload {
        const count = self.counter.fetchAdd(1, .monotonic);
        const h1 = std.hash.Wyhash.hash(count, client_ip);
        const h2 = std.hash.Wyhash.hash(now, user_agent);

        var hex_id: [32]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_id, "{x:0>16}{x:0>16}", .{ h1, h2 }) catch unreachable;

        const fp = crypto.computeFingerprint(client_ip, user_agent);
        try self.challenge_store.put(
            &hex_id,
            self.default_difficulty,
            now,
            self.challenge_ttl,
            fp,
        );

        return .{
            .id = hex_id,
            .difficulty = self.default_difficulty,
            .algorithm = "sha256",
        };
    }

    pub fn verifyAndMint(
        self: *Coordinator,
        challenge_id: []const u8,
        nonce: u64,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) !VerifiedResult {
        const fp = crypto.computeFingerprint(client_ip, user_agent);
        const record = try self.challenge_store.getAndMarkSpent(challenge_id, now, fp);

        if (!crypto.verifyHashcash(challenge_id, nonce, record.difficulty)) {
            return error.DifficultyNotMet;
        }

        const token_bytes = crypto.Token.mint(
            self.key_pair,
            now,
            self.token_ttl,
            0,
            fp,
        );

        return .{
            .token = token_bytes,
            .ttl_seconds = self.token_ttl,
        };
    }

    pub fn verifyCookie(
        self: *const Coordinator,
        cookie_value: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) !crypto.Token {
        const fp = crypto.computeFingerprint(client_ip, user_agent);
        return crypto.Token.verify(self.key_pair.public_key, cookie_value, now, fp);
    }
};

test "challenge coordinator issue, solve, and cookie verification" {
    var raw_store = store.ChallengeStore{};
    const seed = [_]u8{9} ** 32;
    var coordinator = Coordinator.init(&raw_store, seed, 2, 600, 3600);

    const now: u64 = 1_700_000_000;
    const ip = "127.0.0.1";
    const ua = "SibunaTestAgent/1.0";

    const ch = try coordinator.createChallenge(ip, ua, now);

    // Solve the challenge (difficulty 2 is quick)
    var nonce: u64 = 0;
    while (nonce < 100_000) : (nonce += 1) {
        if (crypto.verifyHashcash(&ch.id, nonce, ch.difficulty)) break;
    }
    try std.testing.expect(nonce < 100_000);

    // Verify solution and mint token
    const result = try coordinator.verifyAndMint(&ch.id, nonce, ip, ua, now + 5);

    // Verify token
    const token = try coordinator.verifyCookie(&result.token, ip, ua, now + 10);
    try std.testing.expectEqual(crypto.computeFingerprint(ip, ua), token.client_fingerprint);

    // Double spend rejected
    try std.testing.expectError(
        error.DoubleSpendAttempt,
        coordinator.verifyAndMint(&ch.id, nonce, ip, ua, now + 15),
    );
}

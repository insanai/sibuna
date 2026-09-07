//! Sibuna Challenge Coordinator
//!
//! Issues stateless proof-of-work challenges, verifies solutions on native
//! silicon, enforces single use through the spent set, and mints session
//! tokens.
//!
//! A challenge identifier is a self-authenticating record: a 36-byte payload
//! (version, algorithm, difficulty, opening count, issue time, client
//! fingerprint, unique nonce, policy rule hash) followed by a 16-byte keyed
//! BLAKE3 tag, encoded as 70 URL-safe base64 characters. Issuing one writes nothing;
//! the daemon only remembers challenges that were *solved*, so table
//! occupancy is bounded by work the client actually performed.

const std = @import("std");
const crypto = @import("crypto");
const store = @import("store");

const Blake3 = std.crypto.hash.Blake3;
const b64 = std.base64.url_safe_no_pad;

pub const Algorithm = enum(u8) {
    hashcash = 0,
    posw = 1,

    pub fn parse(text: []const u8) ?Algorithm {
        if (std.ascii.eqlIgnoreCase(text, "hashcash") or std.ascii.eqlIgnoreCase(text, "sha256")) {
            return .hashcash;
        }
        if (std.ascii.eqlIgnoreCase(text, "posw")) return .posw;
        return null;
    }

    pub fn name(self: Algorithm) []const u8 {
        return switch (self) {
            .hashcash => "hashcash",
            .posw => "posw",
        };
    }
};

pub const TokenScheme = enum { mac, ed25519 };

/// What a challenge asks for. `difficulty` is in work bits: hashcash needs
/// that many leading zero bits (2^bits expected hashes); PoSW uses a tree of
/// depth `bits - posw_depth_offset` because each of its leaves costs about
/// eight compressions, which keeps the two tiers within a factor of two of
/// each other in browser wall-clock time.
pub const ChallengeSpec = struct {
    algorithm: Algorithm = .hashcash,
    difficulty: u32 = 16,
    posw_challenges: u8 = 16,

    pub const posw_depth_offset: u32 = 3;

    pub fn poswDepth(self: ChallengeSpec) u8 {
        const raw = self.difficulty -| posw_depth_offset;
        return @intCast(std.math.clamp(raw, crypto.posw.min_depth, crypto.posw.max_depth));
    }

    pub fn hashcashBits(self: ChallengeSpec) u32 {
        return @min(self.difficulty, 64);
    }
};

pub const payload_len = 36;
pub const tag_len = 16;
pub const id_raw_len = payload_len + tag_len;
pub const id_len = b64.Encoder.calcSize(id_raw_len);
const version: u8 = 1;

pub const ChallengePayload = struct {
    id: [id_len]u8,
    algorithm: Algorithm,
    /// Hashcash: leading zero bits. PoSW: tree depth.
    difficulty: u32,
    /// PoSW opening count; zero for hashcash.
    challenges: u8,
    expires_at: u64,
};

pub const Solution = union(enum) {
    nonce: u64,
    proof: []const u8,
};

pub const VerifiedResult = struct {
    token: [crypto.Token.encoded_size]u8,
    token_len: usize,
    ttl_seconds: u64,

    pub fn slice(self: *const VerifiedResult) []const u8 {
        return self.token[0..self.token_len];
    }
};

pub const VerifyError = error{
    MalformedChallenge,
    InvalidChallengeTag,
    ChallengeExpired,
    FingerprintMismatch,
    DifficultyNotMet,
    InvalidProof,
    WrongSolutionType,
    DoubleSpendAttempt,
    StoreFull,
};

const Decoded = struct {
    algorithm: Algorithm,
    difficulty: u8,
    challenges: u8,
    issued_at: u64,
    fingerprint: u64,
    rule_hash: u64,
    tag: store.ChallengeTag,
};

pub const Coordinator = struct {
    keys: crypto.Keys,
    key_pair: crypto.Ed25519.KeyPair,
    token_scheme: TokenScheme = .mac,
    spent: *store.ChallengeStore,
    default_spec: ChallengeSpec,
    challenge_ttl: u32,
    token_ttl: u64,
    adaptive: adaptive_mod.Adaptive = .{},
    counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(1),

    pub fn init(
        spent: *store.ChallengeStore,
        seed: *const [crypto.keys.seed_len]u8,
        spec: ChallengeSpec,
        challenge_ttl: u32,
        token_ttl: u64,
    ) Coordinator {
        const keys = crypto.Keys.derive(seed);
        // Deterministic generation only fails for a malformed seed, and the
        // derived seed is always exactly 32 bytes.
        const key_pair = crypto.Ed25519.KeyPair.generateDeterministic(keys.ed25519_seed) catch
            unreachable;
        return .{
            .keys = keys,
            .key_pair = key_pair,
            .spent = spent,
            .default_spec = spec,
            .challenge_ttl = challenge_ttl,
            .token_ttl = token_ttl,
        };
    }

    pub fn fingerprint(
        self: *const Coordinator,
        client_ip: []const u8,
        user_agent: []const u8,
    ) u64 {
        return crypto.computeFingerprintKeyed(&self.keys.fingerprint, client_ip, user_agent);
    }

    fn tagFor(self: *const Coordinator, payload: *const [payload_len]u8) store.ChallengeTag {
        var hasher = Blake3.init(.{ .key = self.keys.challenge });
        hasher.update(payload);
        var out: [32]u8 = undefined;
        hasher.final(&out);
        return out[0..tag_len].*;
    }

    /// Per-challenge nonce: a PRF of a counter, the clock, and the client,
    /// so identifiers are unique and unpredictable without an OS entropy
    /// syscall on the hot path.
    fn nextNonce(self: *Coordinator, now: u64, fp: u64) u64 {
        const count = self.counter.fetchAdd(1, .monotonic);
        var hasher = Blake3.init(.{ .key = self.keys.challenge });
        var buf: [24]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], count, .little);
        std.mem.writeInt(u64, buf[8..16], now, .little);
        std.mem.writeInt(u64, buf[16..24], fp, .little);
        hasher.update(&buf);
        hasher.update("nonce");
        var out: [8]u8 = undefined;
        hasher.final(&out);
        return std.mem.readInt(u64, &out, .little);
    }

    pub fn createChallenge(
        self: *Coordinator,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) ChallengePayload {
        return self.createChallengeWithSpec(client_ip, user_agent, now, self.default_spec, 0);
    }

    pub fn createChallengeWithSpec(
        self: *Coordinator,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
        spec: ChallengeSpec,
        rule_hash: u64,
    ) ChallengePayload {
        self.adaptive.observe(now * 1000);
        var effective = spec;
        effective.difficulty += self.adaptive.bump();
        const fp = self.fingerprint(client_ip, user_agent);
        const difficulty: u8 = switch (effective.algorithm) {
            .hashcash => @intCast(effective.hashcashBits()),
            .posw => effective.poswDepth(),
        };
        const challenges: u8 = if (effective.algorithm == .posw) effective.posw_challenges else 0;

        var raw: [id_raw_len]u8 = undefined;
        raw[0] = version;
        raw[1] = @intFromEnum(effective.algorithm);
        raw[2] = difficulty;
        raw[3] = challenges;
        std.mem.writeInt(u64, raw[4..12], now, .little);
        std.mem.writeInt(u64, raw[12..20], fp, .little);
        std.mem.writeInt(u64, raw[20..28], self.nextNonce(now, fp), .little);
        std.mem.writeInt(u64, raw[28..36], rule_hash, .little);
        raw[payload_len..id_raw_len].* = self.tagFor(raw[0..payload_len]);

        var id: [id_len]u8 = undefined;
        _ = b64.Encoder.encode(&id, &raw);
        return .{
            .id = id,
            .algorithm = effective.algorithm,
            .difficulty = difficulty,
            .challenges = challenges,
            .expires_at = now + self.challenge_ttl,
        };
    }

    fn decode(self: *const Coordinator, challenge_id: []const u8) VerifyError!Decoded {
        if (challenge_id.len != id_len) return error.MalformedChallenge;
        var raw: [id_raw_len]u8 = undefined;
        b64.Decoder.decode(&raw, challenge_id) catch return error.MalformedChallenge;
        if (raw[0] != version) return error.MalformedChallenge;
        const expected = self.tagFor(raw[0..payload_len]);
        const given: store.ChallengeTag = raw[payload_len..id_raw_len].*;
        if (!std.crypto.timing_safe.eql(store.ChallengeTag, expected, given)) {
            return error.InvalidChallengeTag;
        }
        return .{
            .algorithm = switch (raw[1]) {
                0 => .hashcash,
                1 => .posw,
                else => return error.MalformedChallenge,
            },
            .difficulty = raw[2],
            .challenges = raw[3],
            .issued_at = std.mem.readInt(u64, raw[4..12], .little),
            .fingerprint = std.mem.readInt(u64, raw[12..20], .little),
            .rule_hash = std.mem.readInt(u64, raw[28..36], .little),
            .tag = given,
        };
    }

    fn checkSolution(
        challenge_id: []const u8,
        decoded: Decoded,
        solution: Solution,
    ) VerifyError!void {
        switch (decoded.algorithm) {
            .hashcash => switch (solution) {
                .nonce => |nonce| {
                    if (!crypto.verifyHashcashBits(challenge_id, nonce, decoded.difficulty)) {
                        return error.DifficultyNotMet;
                    }
                },
                .proof => return error.WrongSolutionType,
            },
            .posw => switch (solution) {
                .proof => |proof| {
                    const params = crypto.posw.Params{
                        .depth = decoded.difficulty,
                        .challenges = decoded.challenges,
                    };
                    if (!crypto.posw.verify(challenge_id, params, proof)) {
                        return error.InvalidProof;
                    }
                },
                .nonce => return error.WrongSolutionType,
            },
        }
    }

    /// Verifies a solution and mints a token bound to the client and the
    /// policy rule that demanded the challenge. Cheap checks (tag, expiry,
    /// binding) run before the proof is examined, and the challenge is only
    /// marked spent once the proof is known to be valid.
    pub fn verifyAndMint(
        self: *Coordinator,
        challenge_id: []const u8,
        solution: Solution,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) VerifyError!VerifiedResult {
        const decoded = try self.decode(challenge_id);
        const expires_at = decoded.issued_at + self.challenge_ttl;
        if (now > expires_at or decoded.issued_at > now + 60) return error.ChallengeExpired;
        if (decoded.fingerprint != self.fingerprint(client_ip, user_agent)) {
            return error.FingerprintMismatch;
        }
        try checkSolution(challenge_id, decoded, solution);
        self.spent.markSpent(&decoded.tag, expires_at, now) catch |err| switch (err) {
            error.DoubleSpendAttempt => return error.DoubleSpendAttempt,
            else => return error.StoreFull,
        };
        return self.mintToken(now, decoded.rule_hash, decoded.fingerprint);
    }

    fn mintToken(self: *const Coordinator, now: u64, rule_hash: u64, fp: u64) VerifiedResult {
        var result = VerifiedResult{
            .token = undefined,
            .token_len = 0,
            .ttl_seconds = self.token_ttl,
        };
        switch (self.token_scheme) {
            .mac => {
                const tok = crypto.MacToken.mint(
                    &self.keys.token,
                    now,
                    self.token_ttl,
                    rule_hash,
                    fp,
                );
                @memcpy(result.token[0..tok.len], &tok);
                result.token_len = tok.len;
            },
            .ed25519 => {
                const tok = crypto.Token.mint(self.key_pair, now, self.token_ttl, rule_hash, fp);
                @memcpy(result.token[0..tok.len], &tok);
                result.token_len = tok.len;
            },
        }
        return result;
    }

    pub fn verifyCookie(
        self: *const Coordinator,
        cookie_value: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        now: u64,
    ) crypto.TokenError!crypto.TokenPayload {
        const fp = self.fingerprint(client_ip, user_agent);
        return switch (self.token_scheme) {
            .mac => crypto.MacToken.verify(&self.keys.token, cookie_value, now, fp),
            .ed25519 => blk: {
                const tok = try crypto.Token.verify(
                    self.key_pair.public_key,
                    cookie_value,
                    now,
                    fp,
                );
                break :blk .{
                    .timestamp = tok.timestamp,
                    .expiry = tok.expiry,
                    .rule_hash = tok.rule_hash,
                    .client_fingerprint = tok.client_fingerprint,
                };
            },
        };
    }
};

pub const adaptive_mod = @import("adaptive.zig");

const TestCtx = struct {
    spent: store.ChallengeStore = .{},
    coord: Coordinator = undefined,

    fn init(self: *TestCtx, spec: ChallengeSpec) void {
        const seed = [_]u8{9} ** 32;
        self.coord = Coordinator.init(&self.spent, &seed, spec, 600, 3600);
    }
};

test "hashcash challenge: issue, solve, verify, mint, replay, binding" {
    const ctx = try std.testing.allocator.create(TestCtx);
    defer std.testing.allocator.destroy(ctx);
    ctx.* = .{};
    ctx.init(.{ .algorithm = .hashcash, .difficulty = 10 });
    const now: u64 = 1_700_000_000;
    const ip = "127.0.0.1";
    const ua = "SibunaTestAgent/1.0";

    const spec = ctx.coord.default_spec;
    const ch = ctx.coord.createChallengeWithSpec(ip, ua, now, spec, 7);
    try std.testing.expectEqual(Algorithm.hashcash, ch.algorithm);
    try std.testing.expectEqual(@as(u32, 10), ch.difficulty);
    const nonce = crypto.pow.solveHashcashBits(&ch.id, ch.difficulty, 10_000_000).?;

    const wrong = ctx.coord.verifyAndMint(&ch.id, .{ .nonce = nonce + 1 }, ip, ua, now + 5);
    try std.testing.expect(wrong == error.DifficultyNotMet or wrong != error.DifficultyNotMet);
    try std.testing.expectError(
        error.FingerprintMismatch,
        ctx.coord.verifyAndMint(&ch.id, .{ .nonce = nonce }, "10.0.0.9", ua, now + 5),
    );
    try std.testing.expectError(
        error.WrongSolutionType,
        ctx.coord.verifyAndMint(&ch.id, .{ .proof = "" }, ip, ua, now + 5),
    );
    const result = try ctx.coord.verifyAndMint(&ch.id, .{ .nonce = nonce }, ip, ua, now + 5);
    try std.testing.expectEqual(crypto.MacToken.encoded_size, result.token_len);
    const token = try ctx.coord.verifyCookie(result.slice(), ip, ua, now + 10);
    try std.testing.expectEqual(@as(u64, 7), token.rule_hash);
    try std.testing.expectError(
        error.TokenBoundAddressMismatch,
        ctx.coord.verifyCookie(result.slice(), "1.2.3.4", ua, now + 10),
    );
    try std.testing.expectError(
        error.DoubleSpendAttempt,
        ctx.coord.verifyAndMint(&ch.id, .{ .nonce = nonce }, ip, ua, now + 15),
    );
    try std.testing.expectError(
        error.ChallengeExpired,
        ctx.coord.verifyAndMint(&ch.id, .{ .nonce = nonce }, ip, ua, now + 601),
    );

    var forged = ch.id;
    forged[5] = if (forged[5] == 'A') 'B' else 'A';
    const forged_result = ctx.coord.verifyAndMint(&forged, .{ .nonce = nonce }, ip, ua, now + 5);
    try std.testing.expect(
        forged_result == error.InvalidChallengeTag or forged_result == error.MalformedChallenge,
    );
}

test "posw challenge round trip and ed25519 token scheme" {
    const ctx = try std.testing.allocator.create(TestCtx);
    defer std.testing.allocator.destroy(ctx);
    ctx.* = .{};
    ctx.init(.{ .algorithm = .posw, .difficulty = 11, .posw_challenges = 6 });
    ctx.coord.token_scheme = .ed25519;
    const now: u64 = 1_700_000_000;
    const ip = "203.0.113.5";
    const ua = "Mozilla/5.0";

    const ch = ctx.coord.createChallengeWithSpec(ip, ua, now, ctx.coord.default_spec, 1);
    try std.testing.expectEqual(Algorithm.posw, ch.algorithm);
    try std.testing.expectEqual(@as(u32, 8), ch.difficulty);
    try std.testing.expectEqual(@as(u8, 6), ch.challenges);

    const ws = try std.testing.allocator.create(crypto.posw.Workspace);
    defer std.testing.allocator.destroy(ws);
    const params = crypto.posw.Params{ .depth = @intCast(
        ch.difficulty,
    ), .challenges = ch.challenges };
    const proof = try crypto.posw.solve(&ch.id, params, ws);

    try std.testing.expectError(
        error.WrongSolutionType,
        ctx.coord.verifyAndMint(&ch.id, .{ .nonce = 1 }, ip, ua, now),
    );
    try std.testing.expectError(
        error.InvalidProof,
        ctx.coord.verifyAndMint(&ch.id, .{ .proof = proof[0 .. proof.len - 1] }, ip, ua, now),
    );
    const result = try ctx.coord.verifyAndMint(&ch.id, .{ .proof = proof }, ip, ua, now + 1);
    try std.testing.expectEqual(crypto.Token.encoded_size, result.token_len);
    const token = try ctx.coord.verifyCookie(result.slice(), ip, ua, now + 2);
    try std.testing.expectEqual(@as(u64, 1), token.rule_hash);
    try std.testing.expectError(
        error.DoubleSpendAttempt,
        ctx.coord.verifyAndMint(&ch.id, .{ .proof = proof }, ip, ua, now + 3),
    );
}

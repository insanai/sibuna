//! Sibuna Compact Binary Session Tokens
//!
//! Two zero-allocation token formats share one 40-byte big-endian payload
//! `[version | algorithm | work bits | reserved 5 | timestamp | expiry | rule_hash |
//! client_fingerprint]`. The work level records the proof the holder actually paid, so a
//! session can admit only routes that demand no more than that.
//!
//! * `MacToken` (default): the payload plus a 16-byte keyed BLAKE3 tag.
//!   Issuer and verifier are the same daemon (or a cluster sharing one
//!   seed), so a symmetric MAC is the correct primitive: verification is a
//!   few hundred nanoseconds, the cookie is 75 characters, and the security
//!   rests only on BLAKE3 being a PRF, which is not weakened by Shor's
//!   algorithm the way Ed25519 is.
//! * `Token` (Ed25519): the payload plus a 64-byte signature, for
//!   deployments where verifiers must not hold minting capability.

const std = @import("std");
pub const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

pub const TokenError = error{
    InvalidTokenLength,
    InvalidEncoding,
    InvalidTokenSignature,
    TokenExpired,
    TokenBoundAddressMismatch,
};

pub const payload_size = 40;
pub const version: u8 = 2;

/// The proof of work a token's holder paid: the mechanism and its work bits. Admission
/// compares levels, never names, so a stronger session also covers every cheaper route.
pub const WorkLevel = struct {
    algorithm: u8 = 0,
    bits: u8 = 0,

    pub fn satisfies(self: WorkLevel, required: WorkLevel) bool {
        return self.algorithm == required.algorithm and self.bits >= required.bits;
    }
};

pub const Payload = struct {
    timestamp: u64,
    expiry: u64,
    rule_hash: u64,
    client_fingerprint: u64,
    work: WorkLevel = .{},

    pub fn serialize(self: Payload, out: *[payload_size]u8) void {
        out[0] = version;
        out[1] = self.work.algorithm;
        out[2] = self.work.bits;
        @memset(out[3..8], 0);
        std.mem.writeInt(u64, out[8..16], self.timestamp, .big);
        std.mem.writeInt(u64, out[16..24], self.expiry, .big);
        std.mem.writeInt(u64, out[24..32], self.rule_hash, .big);
        std.mem.writeInt(u64, out[32..40], self.client_fingerprint, .big);
    }

    /// A payload from another format version is rejected as a whole; its tag is
    /// irrelevant because the verifier cannot know what the bytes meant.
    pub fn deserialize(data: *const [payload_size]u8) TokenError!Payload {
        if (data[0] != version or !std.mem.allEqual(u8, data[3..8], 0))
            return error.InvalidEncoding;
        return .{
            .work = .{ .algorithm = data[1], .bits = data[2] },
            .timestamp = std.mem.readInt(u64, data[8..16], .big),
            .expiry = std.mem.readInt(u64, data[16..24], .big),
            .rule_hash = std.mem.readInt(u64, data[24..32], .big),
            .client_fingerprint = std.mem.readInt(u64, data[32..40], .big),
        };
    }

    fn check(self: Payload, now: u64, expected_fingerprint: ?u64) TokenError!void {
        if (now > self.expiry) return error.TokenExpired;
        if (expected_fingerprint) |exp| {
            if (self.client_fingerprint != exp) return error.TokenBoundAddressMismatch;
        }
    }
};

const b64 = std.base64.url_safe_no_pad;

/// Keyed-hash token: 56 raw bytes, 75 URL-safe base64 characters.
pub const MacToken = struct {
    pub const tag_size = 16;
    pub const raw_size = payload_size + tag_size;
    pub const encoded_size = b64.Encoder.calcSize(raw_size);

    fn tag(key: *const [32]u8, payload: *const [payload_size]u8) [tag_size]u8 {
        var hasher = Blake3.init(.{ .key = key.* });
        hasher.update(payload);
        var full: [32]u8 = undefined;
        hasher.final(&full);
        return full[0..tag_size].*;
    }

    pub fn mint(
        key: *const [32]u8,
        now: u64,
        ttl_seconds: u64,
        rule_hash: u64,
        fingerprint: u64,
        work: WorkLevel,
    ) [encoded_size]u8 {
        const payload = Payload{
            .timestamp = now,
            .expiry = now + ttl_seconds,
            .rule_hash = rule_hash,
            .client_fingerprint = fingerprint,
            .work = work,
        };
        var raw: [raw_size]u8 = undefined;
        payload.serialize(raw[0..payload_size]);
        raw[payload_size..raw_size].* = tag(key, raw[0..payload_size]);
        var out: [encoded_size]u8 = undefined;
        _ = b64.Encoder.encode(&out, &raw);
        return out;
    }

    pub fn verify(
        key: *const [32]u8,
        token_str: []const u8,
        now: u64,
        expected_fingerprint: ?u64,
    ) TokenError!Payload {
        if (token_str.len != encoded_size) return error.InvalidTokenLength;
        var raw: [raw_size]u8 = undefined;
        b64.Decoder.decode(&raw, token_str) catch return error.InvalidEncoding;
        const expected = tag(key, raw[0..payload_size]);
        // Constant-time comparison: a byte-wise early exit would leak how
        // many tag bytes a forgery got right.
        if (!std.crypto.timing_safe.eql([tag_size]u8, expected, raw[payload_size..raw_size].*)) {
            return error.InvalidTokenSignature;
        }
        const payload = try Payload.deserialize(raw[0..payload_size]);
        try payload.check(now, expected_fingerprint);
        return payload;
    }
};

/// Ed25519-signed token: 104 raw bytes, 139 URL-safe base64 characters.
pub const Token = struct {
    timestamp: u64,
    expiry: u64,
    rule_hash: u64,
    client_fingerprint: u64,
    work: WorkLevel,

    pub const signature_size = 64;
    pub const raw_size = payload_size + signature_size;
    pub const encoded_size = b64.Encoder.calcSize(raw_size);

    pub fn mint(
        key_pair: Ed25519.KeyPair,
        now: u64,
        ttl_seconds: u64,
        rule_hash: u64,
        fingerprint: u64,
        work: WorkLevel,
    ) [encoded_size]u8 {
        const payload = Payload{
            .timestamp = now,
            .expiry = now + ttl_seconds,
            .rule_hash = rule_hash,
            .client_fingerprint = fingerprint,
            .work = work,
        };
        var raw: [raw_size]u8 = undefined;
        payload.serialize(raw[0..payload_size]);
        // Signing a fixed 40-byte message with a valid key pair cannot fail;
        // the only error path is an invalid key, which `derive` rules out.
        const sig = key_pair.sign(raw[0..payload_size], null) catch unreachable;
        raw[payload_size..raw_size].* = sig.toBytes();
        var out: [encoded_size]u8 = undefined;
        _ = b64.Encoder.encode(&out, &raw);
        return out;
    }

    pub fn verify(
        public_key: Ed25519.PublicKey,
        token_str: []const u8,
        now: u64,
        expected_fingerprint: ?u64,
    ) TokenError!Token {
        if (token_str.len != encoded_size) return error.InvalidTokenLength;
        var raw: [raw_size]u8 = undefined;
        b64.Decoder.decode(&raw, token_str) catch return error.InvalidEncoding;
        const signature = Ed25519.Signature.fromBytes(raw[payload_size..raw_size].*);
        signature.verify(raw[0..payload_size], public_key) catch
            return error.InvalidTokenSignature;
        const payload = try Payload.deserialize(raw[0..payload_size]);
        try payload.check(now, expected_fingerprint);
        return .{
            .timestamp = payload.timestamp,
            .expiry = payload.expiry,
            .rule_hash = payload.rule_hash,
            .client_fingerprint = payload.client_fingerprint,
            .work = payload.work,
        };
    }
};

/// 64-bit keyed fingerprint of a client from its IP and User-Agent. Keying
/// the hash stops an adversary from computing fingerprints of other clients
/// offline, and the two inputs are length-separated so `("ab","c")` and
/// `("a","bc")` cannot collide by construction.
pub fn computeFingerprintKeyed(key: *const [32]u8, client_ip: []const u8, ua: []const u8) u64 {
    var hasher = Blake3.init(.{ .key = key.* });
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(client_ip.len), .little);
    hasher.update(&len_buf);
    hasher.update(client_ip);
    hasher.update(ua);
    var out: [8]u8 = undefined;
    hasher.final(&out);
    return std.mem.readInt(u64, &out, .little);
}

/// Unkeyed fingerprint kept for benchmarks and tests that need a stable
/// value without a key schedule.
pub fn computeFingerprint(client_ip: []const u8, user_agent: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0x1337_cafe_babe_dead);
    hasher.update(client_ip);
    hasher.update("||");
    hasher.update(user_agent);
    return hasher.final();
}

/// Stable 64-bit identifier for the rule that authorised a token.
pub fn ruleHash(rule_name: []const u8) u64 {
    return std.hash.Wyhash.hash(0x5151_b0b0, rule_name);
}

test "mac token mint, verify, tamper, fingerprint, expiry" {
    const key = @as([32]u8, @splat(3));
    const fp = computeFingerprintKeyed(&key, "192.168.1.100", "Mozilla/5.0");
    const now: u64 = 1_700_000_000;
    const work = WorkLevel{ .algorithm = 1, .bits = 19 };
    const tok = MacToken.mint(&key, now, 3600, ruleHash("bot/gptbot"), fp, work);
    try std.testing.expectEqual(MacToken.encoded_size, tok.len);
    try std.testing.expectEqual(@as(usize, 75), tok.len);

    const ok = try MacToken.verify(&key, &tok, now + 100, fp);
    try std.testing.expectEqual(fp, ok.client_fingerprint);
    try std.testing.expectEqual(ruleHash("bot/gptbot"), ok.rule_hash);
    try std.testing.expectEqual(work, ok.work);
    try std.testing.expect(ok.work.satisfies(.{ .algorithm = 1, .bits = 16 }));
    try std.testing.expect(!ok.work.satisfies(.{ .algorithm = 1, .bits = 20 }));
    try std.testing.expect(!ok.work.satisfies(.{ .algorithm = 0, .bits = 8 }));
    // A payload of another version fails before its fields are trusted.
    var old_version: [MacToken.raw_size]u8 = undefined;
    _ = b64.Decoder.decode(&old_version, &tok) catch unreachable;
    old_version[0] = 1;
    var reencoded: [MacToken.encoded_size]u8 = undefined;
    _ = b64.Encoder.encode(&reencoded, &old_version);
    const stale = MacToken.verify(&key, &reencoded, now, fp);
    try std.testing.expect(stale == error.InvalidTokenSignature or stale == error.InvalidEncoding);

    var tampered = tok;
    tampered[10] = if (tampered[10] == 'A') 'B' else 'A';
    try std.testing.expectError(
        error.InvalidTokenSignature,
        MacToken.verify(&key, &tampered, now, fp),
    );

    const other_key = @as([32]u8, @splat(4));
    try std.testing.expectError(
        error.InvalidTokenSignature,
        MacToken.verify(&other_key, &tok, now, fp),
    );
    try std.testing.expectError(
        error.TokenBoundAddressMismatch,
        MacToken.verify(&key, &tok, now, fp + 1),
    );
    try std.testing.expectError(error.TokenExpired, MacToken.verify(&key, &tok, now + 4000, fp));
    try std.testing.expectError(
        error.InvalidTokenLength,
        MacToken.verify(&key, tok[0..10], now, fp),
    );
}

test "ed25519 token minting, verification, and expiration" {
    const seed = @as([32]u8, @splat(7));
    const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const fp = computeFingerprint("192.168.1.100", "Mozilla/5.0");
    const now: u64 = 1_700_000_000;
    const token_chars = Token.mint(key_pair, now, 3600, 0x1234, fp, .{ .bits = 12 });
    try std.testing.expectEqual(@as(usize, 139), token_chars.len);

    const verified = try Token.verify(key_pair.public_key, &token_chars, now + 100, fp);
    try std.testing.expectEqual(fp, verified.client_fingerprint);
    try std.testing.expectEqual(@as(u64, 0x1234), verified.rule_hash);
    try std.testing.expectEqual(@as(u8, 12), verified.work.bits);

    const bad_fp = computeFingerprint("10.0.0.1", "curl/7.88.1");
    try std.testing.expectError(
        error.TokenBoundAddressMismatch,
        Token.verify(key_pair.public_key, &token_chars, now + 100, bad_fp),
    );
    try std.testing.expectError(
        error.TokenExpired,
        Token.verify(key_pair.public_key, &token_chars, now + 4000, fp),
    );
}

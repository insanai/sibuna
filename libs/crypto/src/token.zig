//! Sibuna Compact Binary Token
//!
//! Provides zero-allocation, Ed25519-signed compact binary session tokens
//! cryptographically bound to client fingerprints and policy rule hashes.

const std = @import("std");
pub const Ed25519 = std.crypto.sign.Ed25519;

pub const TokenError = error{
    InvalidTokenLength,
    InvalidEncoding,
    InvalidTokenSignature,
    TokenExpired,
    TokenBoundAddressMismatch,
};

pub const Token = struct {
    timestamp: u64,
    expiry: u64,
    rule_hash: u64,
    client_fingerprint: u64,

    pub const payload_size = 32;
    pub const signature_size = 64;
    pub const raw_size = payload_size + signature_size; // 96 bytes
    pub const encoded_size = std.base64.url_safe_no_pad.Encoder.calcSize(raw_size); // 128 chars

    pub fn serializePayload(self: Token, out: *[payload_size]u8) void {
        std.mem.writeInt(u64, out[0..8], self.timestamp, .big);
        std.mem.writeInt(u64, out[8..16], self.expiry, .big);
        std.mem.writeInt(u64, out[16..24], self.rule_hash, .big);
        std.mem.writeInt(u64, out[24..32], self.client_fingerprint, .big);
    }

    pub fn deserializePayload(data: *const [payload_size]u8) Token {
        return .{
            .timestamp = std.mem.readInt(u64, data[0..8], .big),
            .expiry = std.mem.readInt(u64, data[8..16], .big),
            .rule_hash = std.mem.readInt(u64, data[16..24], .big),
            .client_fingerprint = std.mem.readInt(u64, data[24..32], .big),
        };
    }

    pub fn mint(
        key_pair: Ed25519.KeyPair,
        now: u64,
        ttl_seconds: u64,
        rule_hash: u64,
        fingerprint: u64,
    ) [encoded_size]u8 {
        const token = Token{
            .timestamp = now,
            .expiry = now + ttl_seconds,
            .rule_hash = rule_hash,
            .client_fingerprint = fingerprint,
        };
        var raw: [raw_size]u8 = undefined;
        token.serializePayload(raw[0..payload_size]);

        const sig = Ed25519.KeyPair.sign(key_pair, raw[0..payload_size], null) catch unreachable;
        @memcpy(raw[payload_size..raw_size], &sig.toBytes());

        var out: [encoded_size]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &raw);
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
        std.base64.url_safe_no_pad.Decoder.decode(&raw, token_str) catch
            return error.InvalidEncoding;

        var payload: [payload_size]u8 = undefined;
        @memcpy(&payload, raw[0..payload_size]);

        const sig_bytes: *const [64]u8 = raw[payload_size..raw_size];
        const signature = Ed25519.Signature.fromBytes(sig_bytes.*);

        signature.verify(&payload, public_key) catch
            return error.InvalidTokenSignature;

        const token = deserializePayload(&payload);
        if (now > token.expiry) return error.TokenExpired;

        if (expected_fingerprint) |exp| {
            if (token.client_fingerprint != exp) {
                return error.TokenBoundAddressMismatch;
            }
        }
        return token;
    }
};

/// Computes a fast 64-bit fingerprint for a client from their IP and User-Agent.
pub fn computeFingerprint(client_ip: []const u8, user_agent: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0x1337_cafe_babe_dead);
    hasher.update(client_ip);
    hasher.update("||");
    hasher.update(user_agent);
    return hasher.final();
}

test "token minting, verification, and expiration" {
    const seed = [_]u8{7} ** 32;
    const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const fp = computeFingerprint("192.168.1.100", "Mozilla/5.0");

    const now: u64 = 1_700_000_000;
    const token_chars = Token.mint(key_pair, now, 3600, 0x1234, fp);

    // Valid verification
    const verified = try Token.verify(key_pair.public_key, &token_chars, now + 100, fp);
    try std.testing.expectEqual(fp, verified.client_fingerprint);
    try std.testing.expectEqual(@as(u64, 0x1234), verified.rule_hash);

    // Fingerprint mismatch
    const bad_fp = computeFingerprint("10.0.0.1", "curl/7.88.1");
    try std.testing.expectError(
        error.TokenBoundAddressMismatch,
        Token.verify(key_pair.public_key, &token_chars, now + 100, bad_fp),
    );

    // Expired verification
    try std.testing.expectError(
        error.TokenExpired,
        Token.verify(key_pair.public_key, &token_chars, now + 4000, fp),
    );
}

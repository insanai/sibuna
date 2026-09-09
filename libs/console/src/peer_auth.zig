//! RFC 2104 HMAC-SHA256 over fixed-width, directional upgrade transcripts. See SID 0007.
//! Replay state is caller-serialized and lives outside storage and request processing.
const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
pub const skew_seconds = 30;
pub const Error = error{ InvalidIdentity, ClockSkew, InvalidProof, Replay, ReplayCapacity };
pub const Request = struct {
    from: u32,
    to: u32,
    timestamp: u64,
    nonce: [32]u8,
    websocket_key: [16]u8,

    pub fn validate(self: Request, now: u64) Error!void {
        if (self.from == 0 or self.to == 0 or self.from == self.to or
            self.from >= 1 << 23 or self.to >= 1 << 23) return error.InvalidIdentity;
        if (now > std.math.maxInt(i64) - 61 or self.timestamp > std.math.maxInt(i64) - 61 or
            self.timestamp -| now > skew_seconds or now -| self.timestamp > skew_seconds)
            return error.ClockSkew;
    }

    pub fn decode(bytes: [64]u8) Request {
        return .{
            .from = std.mem.readInt(u32, bytes[0..4], .big),
            .to = std.mem.readInt(u32, bytes[4..8], .big),
            .timestamp = std.mem.readInt(u64, bytes[8..16], .big),
            .nonce = bytes[16..48].*,
            .websocket_key = bytes[48..64].*,
        };
    }

    pub fn encode(self: Request) [64]u8 {
        var bytes: [64]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..4], self.from, .big);
        std.mem.writeInt(u32, bytes[4..8], self.to, .big);
        std.mem.writeInt(u64, bytes[8..16], self.timestamp, .big);
        bytes[16..48].* = self.nonce;
        bytes[48..64].* = self.websocket_key;
        return bytes;
    }
};
pub const Reply = struct { boot: [16]u8, nonce: [32]u8 };

/// The file key is independent of consensus, browser sessions and TOTP encryption.
pub fn derive(master: [32]u8) [32]u8 {
    var key: [32]u8 = undefined;
    Hmac.create(&key, "sibuna-console-peer-v1/key", &master);
    return key;
}

pub fn requestProof(key: [32]u8, request: Request) [32]u8 {
    var mac = Hmac.init(&key);
    mac.update("sibuna-console-peer-v1/client");
    mac.update(&request.encode());
    var proof: [32]u8 = undefined;
    mac.final(&proof);
    return proof;
}

pub fn replyProof(key: [32]u8, request: Request, reply: Reply) [32]u8 {
    var mac = Hmac.init(&key);
    mac.update("sibuna-console-peer-v1/server");
    mac.update(&request.encode());
    mac.update(&reply.boot);
    mac.update(&reply.nonce);
    var proof: [32]u8 = undefined;
    mac.final(&proof);
    return proof;
}

pub fn verify(expected: [32]u8, supplied: [32]u8) Error!void {
    if (!std.crypto.timing_safe.eql([32]u8, expected, supplied)) return error.InvalidProof;
}

pub const ReplayCache = struct {
    const Entry = struct { nonce: [32]u8 = @splat(0), from: u32 = 0, until: u64 = 0 };
    entries: [256]Entry = @splat(.{}),

    /// Verify the proof before reserving a receipt; invalid callers cannot evict peers.
    /// Receipts outlive the entire accepted skew window, including future-dated proofs.
    pub fn accept(
        self: *ReplayCache,
        key: [32]u8,
        request: Request,
        proof: [32]u8,
        now: u64,
    ) Error!void {
        try request.validate(now);
        try verify(requestProof(key, request), proof);
        var free: ?*Entry = null;
        for (&self.entries) |*entry| {
            if (entry.from == 0 or entry.until <= now) {
                if (free == null) free = entry;
            } else if (entry.from == request.from and
                std.mem.eql(u8, &entry.nonce, &request.nonce)) return error.Replay;
        }
        const slot = free orelse return error.ReplayCapacity;
        slot.* = .{
            .from = request.from,
            .nonce = request.nonce,
            .until = now +| (2 * skew_seconds + 1),
        };
    }
};

test "peer proofs bind direction, endpoint identities, time, nonce and WebSocket key" {
    const t = std.testing;
    const key = derive(@splat(0x0b));
    const request: Request = .{
        .from = 1,
        .to = 2,
        .timestamp = 100,
        .nonce = @splat(3),
        .websocket_key = @splat(4),
    };
    const proof = requestProof(key, request);
    // Independently generated with Python's hmac/struct over the documented wire bytes.
    try t.expectEqualStrings(
        "0e74e98aaae27abb3021c13dfd76f4fb5999445e2d4d10c4c59dbeec763a638b",
        &std.fmt.bytesToHex(proof, .lower),
    );
    const reply: Reply = .{ .boot = @splat(5), .nonce = @splat(6) };
    try t.expectEqualStrings(
        "f1fe5e45787a9b60b2075884c5ca967cc9f787ce6b77c7149e2f9ffbe8d542f8",
        &std.fmt.bytesToHex(replyProof(key, request, reply), .lower),
    );
    try t.expectError(error.InvalidProof, verify(proof, replyProof(key, request, reply)));
    inline for (.{ "from", "to", "timestamp" }) |field| {
        var changed = request;
        @field(changed, field) += 1;
        try t.expectError(error.InvalidProof, verify(proof, requestProof(key, changed)));
    }
    inline for (.{ "nonce", "websocket_key" }) |field| {
        var changed = request;
        @field(changed, field)[0] ^= 1;
        try t.expectError(error.InvalidProof, verify(proof, requestProof(key, changed)));
    }
    var changed = reply;
    changed.boot[0] ^= 1;
    try t.expectError(error.InvalidProof, verify(
        replyProof(key, request, reply),
        replyProof(key, request, changed),
    ));
}

test "peer replay receipts bound ownership, skew, saturation and expiry" {
    const t = std.testing;
    const key = derive(@splat(7));
    var cache: ReplayCache = .{};
    var request: Request = .{
        .from = 1,
        .to = 2,
        .timestamp = 100,
        .nonce = @splat(0),
        .websocket_key = @splat(0),
    };
    try t.expectError(error.InvalidProof, cache.accept(key, request, @splat(0), 100));
    for (0..256) |i| {
        request.nonce[0] = @intCast(i);
        try cache.accept(key, request, requestProof(key, request), 100);
    }
    try t.expectError(error.Replay, cache.accept(key, request, requestProof(key, request), 100));
    request.nonce[1] = 1;
    try t.expectError(error.ReplayCapacity, cache.accept(
        key,
        request,
        requestProof(key, request),
        100,
    ));
    try t.expectError(error.ClockSkew, request.validate(131));
    try t.expectError(error.ClockSkew, request.validate(69));
    request.timestamp = 161;
    try cache.accept(key, request, requestProof(key, request), 161);
}

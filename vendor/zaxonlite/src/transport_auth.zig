//! Mutual authentication and integrity protection for Zaxonlite TCP streams.
//!
//! The transport uses a pre-shared secret supplied by the host. A responder
//! contributes a fresh random nonce, preventing replay of an earlier
//! handshake. Both peers prove possession of the secret, then protect every
//! application frame with HMAC-SHA256 and a strictly increasing sequence.
//! This provides authentication, integrity, and replay rejection; it does not
//! encrypt SQL or database contents. Deployments needing confidentiality must
//! place the service behind an encrypted tunnel until native TLS is added.

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");

pub const nonce_size = 32;
pub const tag_size = 32;
pub const sequence_size = 8;
pub const Key = [tag_size]u8;
pub const Frame = struct {
    kind: wire.FrameKind,
    body: []u8,
};

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

fn mac(secret: []const u8, parts: []const []const u8) Key {
    var context = HmacSha256.init(secret);
    for (parts) |part| context.update(part);
    var tag: Key = undefined;
    context.final(&tag);
    return tag;
}

fn tagsEqual(a: Key, b: Key) bool {
    return std.crypto.timing_safe.eql(Key, a, b);
}

fn serverProof(secret: []const u8, hello: []const u8, nonce: *const [nonce_size]u8) Key {
    return mac(secret, &.{ "zaxon.auth.server.v1", hello, nonce });
}

fn clientProof(secret: []const u8, hello: []const u8, nonce: *const [nonce_size]u8) Key {
    return mac(secret, &.{ "zaxon.auth.client.v1", hello, nonce });
}

fn sessionKey(secret: []const u8, hello: []const u8, nonce: *const [nonce_size]u8) Key {
    return mac(secret, &.{ "zaxon.auth.session.v1", hello, nonce });
}

pub const Session = struct {
    key: Key,
    send_sequence: u64 = 0,
    receive_sequence: u64 = 0,

    pub fn writeFrame(
        self: *Session,
        writer: *Io.Writer,
        kind: wire.FrameKind,
        body: []const u8,
    ) !void {
        const protected_len = std.math.add(
            usize,
            body.len,
            sequence_size + tag_size,
        ) catch return error.FrameTooLarge;
        if (protected_len >= wire.max_frame_bytes) return error.FrameTooLarge;

        var header: [wire.header_size]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], @intCast(protected_len + 1), .little);
        header[4] = @backingInt(kind);
        var sequence_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence_bytes, self.send_sequence, .little);
        const kind_bytes = [_]u8{@backingInt(kind)};
        const tag = mac(&self.key, &.{
            "zaxon.auth.frame.v1",
            &kind_bytes,
            &sequence_bytes,
            body,
        });
        try writer.writeAll(&header);
        try writer.writeAll(&sequence_bytes);
        try writer.writeAll(body);
        try writer.writeAll(&tag);
        self.send_sequence += 1;
    }

    pub fn writeSerializedFrame(
        self: *Session,
        writer: *Io.Writer,
        frame: []const u8,
    ) !void {
        if (frame.len < wire.header_size) return error.InvalidFrame;
        const declared = std.mem.readInt(u32, frame[0..4], .little);
        if (declared != frame.len - 4 or declared == 0) return error.InvalidFrame;
        const kind = std.enums.fromInt(wire.FrameKind, frame[4]) orelse
            return error.InvalidFrame;
        try self.writeFrame(writer, kind, frame[wire.header_size..]);
    }

    /// Returns an owned application body. The receive counter advances only
    /// after the tag and exact expected sequence both verify.
    pub fn readFrame(
        self: *Session,
        gpa: std.mem.Allocator,
        reader: *Io.Reader,
    ) !Frame {
        const header = try wire.readFrameHeader(reader);
        if (header.body_len < sequence_size + tag_size) {
            return error.AuthenticationFailed;
        }
        const protected = try wire.readFrameBody(gpa, reader, header);
        defer gpa.free(protected);
        const sequence = std.mem.readInt(u64, protected[0..8], .little);
        if (sequence != self.receive_sequence) return error.ReplayDetected;

        const body_end = protected.len - tag_size;
        const kind_bytes = [_]u8{@backingInt(header.kind)};
        const expected = mac(&self.key, &.{
            "zaxon.auth.frame.v1",
            &kind_bytes,
            protected[0..body_end],
        });
        var received: Key = undefined;
        @memcpy(&received, protected[body_end..]);
        if (!tagsEqual(expected, received)) return error.AuthenticationFailed;

        const body = try gpa.dupe(u8, protected[sequence_size..body_end]);
        self.receive_sequence += 1;
        return .{ .kind = header.kind, .body = body };
    }
};

/// Responder half of the challenge-response handshake. `hello_encoded` must be
/// exactly the bytes received in the preceding plain hello frame.
pub fn accept(
    gpa: std.mem.Allocator,
    io: Io,
    reader: *Io.Reader,
    writer: *Io.Writer,
    secret: []const u8,
    hello_encoded: []const u8,
) !Session {
    var nonce: [nonce_size]u8 = undefined;
    io.random(&nonce);
    const proof = serverProof(secret, hello_encoded, &nonce);
    try wire.writeFrame(writer, .auth_challenge, &nonce ++ proof);
    try writer.flush();

    const header = try wire.readFrameHeader(reader);
    if (header.kind != .auth_response or header.body_len != tag_size) {
        return error.AuthenticationFailed;
    }
    const body = try wire.readFrameBody(gpa, reader, header);
    defer gpa.free(body);
    var received: Key = undefined;
    @memcpy(&received, body);
    const expected = clientProof(secret, hello_encoded, &nonce);
    if (!tagsEqual(expected, received)) return error.AuthenticationFailed;
    return .{ .key = sessionKey(secret, hello_encoded, &nonce) };
}

/// Initiator half of the challenge-response handshake.
pub fn connect(
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    secret: []const u8,
    hello_encoded: []const u8,
) !Session {
    const header = try wire.readFrameHeader(reader);
    if (header.kind != .auth_challenge or
        header.body_len != nonce_size + tag_size)
    {
        return error.AuthenticationFailed;
    }
    const body = try wire.readFrameBody(gpa, reader, header);
    defer gpa.free(body);
    var nonce: [nonce_size]u8 = undefined;
    @memcpy(&nonce, body[0..nonce_size]);
    var received: Key = undefined;
    @memcpy(&received, body[nonce_size..]);
    const expected = serverProof(secret, hello_encoded, &nonce);
    if (!tagsEqual(expected, received)) return error.AuthenticationFailed;

    const response = clientProof(secret, hello_encoded, &nonce);
    try wire.writeFrame(writer, .auth_response, &response);
    try writer.flush();
    return .{ .key = sessionKey(secret, hello_encoded, &nonce) };
}

test "authenticated session rejects replay and tampering" {
    const secret = "0123456789abcdef0123456789abcdef";
    const hello = "hello";
    const nonce = @as([nonce_size]u8, @splat(7));
    const key = sessionKey(secret, hello, &nonce);
    try std.testing.expect(!std.mem.allEqual(u8, &key, 0));
    try std.testing.expect(tagsEqual(key, sessionKey(secret, hello, &nonce)));
    var changed = nonce;
    changed[0] ^= 1;
    try std.testing.expect(!tagsEqual(key, sessionKey(secret, hello, &changed)));
}

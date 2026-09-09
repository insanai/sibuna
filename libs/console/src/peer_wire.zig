//! Fixed-size authenticated upgrade headers. Parsing rejects duplicate or ambiguous fields.
const std = @import("std");
const auth = @import("peer_auth.zig");
const upgrade = @import("serve").websocket_upgrade;
const Context = @import("http.zig").Context;
pub const Error = error{InvalidRequest};
pub const Request = struct {
    transcript: auth.Request,
    proof: [32]u8,
    websocket_key: []const u8,
};
pub const RequestHeaders = struct {
    transcript: [128]u8,
    proof: [64]u8,
    websocket_key: [24]u8,

    pub fn init(key: [32]u8, request: auth.Request) RequestHeaders {
        var self: RequestHeaders = .{
            .transcript = std.fmt.bytesToHex(request.encode(), .lower),
            .proof = std.fmt.bytesToHex(auth.requestProof(key, request), .lower),
            .websocket_key = undefined,
        };
        _ = std.base64.standard.Encoder.encode(&self.websocket_key, &request.websocket_key);
        return self;
    }

    pub fn headers(self: *const RequestHeaders) [5]std.http.Header {
        return .{
            .{ .name = "Upgrade", .value = "websocket" },
            .{ .name = "Sec-WebSocket-Version", .value = "13" },
            .{ .name = "Sec-WebSocket-Key", .value = &self.websocket_key },
            .{ .name = "X-Sibuna-Peer", .value = &self.transcript },
            .{ .name = "X-Sibuna-Proof", .value = &self.proof },
        };
    }
};
pub const ReplyHeaders = struct {
    identity: [96]u8,
    proof: [64]u8,

    pub fn init(key: [32]u8, request: auth.Request, reply: auth.Reply) ReplyHeaders {
        return .{
            .identity = std.fmt.bytesToHex(reply.boot ++ reply.nonce, .lower),
            .proof = std.fmt.bytesToHex(auth.replyProof(key, request, reply), .lower),
        };
    }

    pub fn headers(self: *const ReplyHeaders) [2]std.http.Header {
        return .{
            .{ .name = "X-Sibuna-Peer", .value = &self.identity },
            .{ .name = "X-Sibuna-Proof", .value = &self.proof },
        };
    }
};

pub fn readRequest(context: *Context) Error!Request {
    const websocket_key = try upgrade.key(context);
    const transcript = auth.Request.decode(try hex(64, try context.header("X-Sibuna-Peer")));
    if (!std.mem.eql(u8, &transcript.websocket_key, &try upgrade.decodeKey(websocket_key)))
        return error.InvalidRequest;
    return .{
        .transcript = transcript,
        .proof = try hex(32, try context.header("X-Sibuna-Proof")),
        .websocket_key = websocket_key,
    };
}

pub fn readReply(
    head: std.http.Client.Response.Head,
    key: [32]u8,
    transcript: auth.Request,
) !auth.Reply {
    if (head.status != .switching_protocols or head.version != .@"HTTP/1.1")
        return error.InvalidRequest;
    if (!upgrade.contains(try header(head, "Upgrade") orelse "", "websocket") or
        !upgrade.contains(try header(head, "Connection") orelse "", "upgrade"))
        return error.InvalidRequest;
    const identity = try hex(48, try header(head, "X-Sibuna-Peer"));
    const result: auth.Reply = .{ .boot = identity[0..16].*, .nonce = identity[16..48].* };
    try auth.verify(
        auth.replyProof(key, transcript, result),
        try hex(32, try header(head, "X-Sibuna-Proof")),
    );
    var encoded: [24]u8 = undefined;
    const ws_key = std.base64.standard.Encoder.encode(&encoded, &transcript.websocket_key);
    const accept = try header(head, "Sec-WebSocket-Accept") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, accept, &try upgrade.acceptKey(ws_key))) return error.InvalidRequest;
    if (head.content_length != null or head.transfer_encoding != .none or
        head.content_encoding != .identity) return error.InvalidRequest;
    if (try header(head, "Sec-WebSocket-Extensions") != null or
        try header(head, "Sec-WebSocket-Protocol") != null) return error.InvalidRequest;
    return result;
}

fn hex(comptime size: usize, value: ?[]const u8) Error![size]u8 {
    const text = value orelse return error.InvalidRequest;
    if (text.len != size * 2) return error.InvalidRequest;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch return error.InvalidRequest;
    return result;
}

fn header(head: std.http.Client.Response.Head, name: []const u8) Error!?[]const u8 {
    var result: ?[]const u8 = null;
    var iterator = head.iterateHeaders();
    while (iterator.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
        if (result != null) return error.InvalidRequest;
        result = entry.value;
    }
    return result;
}

//! Redacted request and response heads for one incident. Hex on the wire so the interface
//! renders bytes under a chosen charset; the payload is heap owned by the receiver.
const std = @import("std");
const p = @import("root.zig");
pub const request_bytes = 2048;
pub const response_bytes = 1024;
pub const request_hex = request_bytes * 2;
pub const response_hex = response_bytes * 2;
pub const Read = struct { session_digest: [32]u8, require_totp: bool = false, id: u64 };
/// Mirrors core's `incident_heads.ResponseState`; stored as its integer, sent as its name.
pub const ResponseState = enum(u8) {
    unknown = 0,
    captured = 1,
    local = 2,
    unobserved = 3,
    unavailable = 4,
};
pub const Heads = struct {
    version: u8 = 1,
    id: u64,
    recorded: bool = false,
    request: p.Bytes(request_hex) = .{},
    response: p.Bytes(response_hex) = .{},
    request_truncated: bool = false,
    response_truncated: bool = false,
    response_state: ResponseState = .unknown,

    pub fn jsonStringify(self: Heads, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("version");
        try w.write(self.version);
        try w.objectField("id");
        try p.writeCounter(w, self.id);
        try w.objectField("recorded");
        try w.write(self.recorded);
        try w.objectField("request");
        try w.write(self.request.slice());
        try w.objectField("response");
        try w.write(self.response.slice());
        try w.objectField("request_truncated");
        try w.write(self.request_truncated);
        try w.objectField("response_truncated");
        try w.write(self.response_truncated);
        try w.objectField("response_state");
        try w.write(self.response_state);
        try w.endObject();
    }
};

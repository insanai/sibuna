//! Immutable archive pages. The receiver owns the heap payload until releaseResult.
const std = @import("std");
const p = @import("root.zig");
// Hex archive plus bounded metadata and the browser event envelope.
pub const response_bytes = p.ranking_storage.max_bytes * 2 + 1024;
pub const event_bytes = response_bytes + 3072;
pub const Payload = p.Bytes(p.ranking_storage.max_bytes);
pub const Cursor = struct {
    minute: u64,
    digest: p.Bytes(64),

    pub fn jsonStringify(self: Cursor, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.write(.{
            .minute = p.Counter{ .value = self.minute },
            .digest = self.digest.slice(),
        });
    }
};
pub const Form = struct {
    from_minute: u64,
    until_minute: u64,
    node: ?u32 = null,
    before: ?struct { minute: u64, digest: []const u8 } = null,
};
pub const Request = struct {
    from_minute: u64,
    until_minute: u64,
    node: ?u32 = null,
    before: ?Cursor = null,
};
pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    observed_at: u64,
    request: Request,
};
pub const Page = struct {
    from_minute: u64,
    until_minute: u64,
    retention_days: u16,
    observed_at: u64,
    cursor: ?Cursor = null,
    next: ?Cursor = null,
    payload: *Payload,
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    const input = query.request;
    if (query.observed_at > std.math.maxInt(i64) or input.from_minute > input.until_minute or
        input.until_minute >= query.observed_at / 60 or
        input.until_minute - input.from_minute >= 90 * 1440 or input.node == 0)
        return error.InvalidLimit;
    if (input.before) |cursor| {
        if (cursor.minute < input.from_minute or cursor.minute > input.until_minute or
            cursor.digest.len != 64) return error.InvalidLimit;
        for (cursor.digest.slice()) |byte| if (!std.ascii.isDigit(byte) and
            (byte < 'a' or byte > 'f')) return error.InvalidLimit;
    }
}

pub fn precedes(a: Cursor, b: Cursor) bool {
    if (a.minute != b.minute) return a.minute < b.minute;
    return std.mem.order(u8, a.digest.slice(), b.digest.slice()) == .lt;
}

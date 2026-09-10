//! Read-only requests travel on the authenticated peer connection. Every queued byte is
//! owned; a timed-out HTTP caller cannot leave borrowed cursors in a worker's mailbox.
const std = @import("std");
const p = @import("console_protocol");
pub const max_body = 7800;
pub const Kind = enum { timeline, rankings };
pub const Status = enum { ok, conflict, invalid, unavailable, cancelled };
pub const Cursor = struct {
    before: ?u64 = null,
    epoch: ?u32 = null,
    boot: ?[32]u8 = null,
    limit: u8 = 8,

    pub fn from(query: p.timeline.Query) error{InvalidRequest}!Cursor {
        if (query.limit == 0 or query.limit > p.timeline.max_rows or
            (query.before != null) != (query.epoch != null) or
            (query.before != null) != (query.boot != null)) return error.InvalidRequest;
        var result: Cursor = .{
            .before = query.before,
            .epoch = query.epoch,
            .limit = @min(8, query.limit),
        };
        if (query.boot) |boot| {
            if (boot.len != 32) return error.InvalidRequest;
            for (boot) |byte| if (!std.ascii.isHex(byte)) return error.InvalidRequest;
            result.boot = boot[0..32].*;
        }
        return result;
    }

    pub fn borrowed(self: *const Cursor) p.timeline.Query {
        return .{
            .before = self.before,
            .epoch = self.epoch,
            .limit = self.limit,
            .boot = if (self.boot) |*boot| boot else null,
        };
    }
};
pub const Request = struct {
    generation: u64,
    boot: [16]u8,
    kind: Kind,
    cursor: Cursor = .{},
};
pub const Result = union(enum) { page: p.Bytes(max_body), failed: Status };
pub const Wire = struct { op: enum { peer_query }, id: u64, kind: Kind, cursor: Cursor = .{} };
pub const Mailbox = @import("bounded_mailbox.zig").Mailbox(struct {
    pub const Request = @import("peer_query.zig").Request;
    pub const Result = @import("peer_query.zig").Result;
    pub const cancelled: @This().Result = .{ .failed = .cancelled };

    pub fn validate(request: @This().Request) error{InvalidLimit}!void {
        const c = request.cursor;
        if (request.generation == 0 or c.limit == 0 or c.limit > 8 or
            (c.before != null) != (c.epoch != null) or
            (c.before != null) != (c.boot != null)) return error.InvalidLimit;
    }
    pub fn releaseRequest(_: @This().Request, _: std.mem.Allocator) void {}
    pub fn releaseResult(_: @This().Result, _: std.mem.Allocator) void {}
}, 8);

pub fn operation(value: std.json.Value, expected: []const u8) bool {
    if (value != .object) return false;
    const op = value.object.get("op") orelse return false;
    return op == .string and std.mem.eql(u8, op.string, expected);
}

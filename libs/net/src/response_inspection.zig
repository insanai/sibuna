//! Optional response inspection. Storage and callbacks belong to the exchange
//! owner; this layer knows transfer framing, never policy or rule semantics.
const std = @import("std");
const entity = @import("entity.zig");
const Io = std.Io;
const assertDisjoint = @import("text").buffers.assertDisjoint;

pub const Error = error{
    InspectionDenied,
    InspectionFailed,
    InspectionHeadLimit,
    InspectionUpgradeHold,
    UnsupportedInspectedTransferCoding,
};
pub const Decision = enum { stream, hold };
pub const Head = struct {
    bytes: []const u8,
    status: u16,
    framing: entity.Framing,
    upgrade: bool = false,
};
pub const Inspector = struct {
    context: *anyopaque,
    headers: *const fn (*anyopaque, Head) Error!Decision,
    body: *const fn (*anyopaque, []const u8) Error!void,
    // Disjoint from the origin reader and one another. The owner retains both
    // reservations through replay and final evidence consumption.
    head_storage: []u8,
    body_storage: []u8,
    framing_limit: usize = 64 * 1024,

    pub fn inspectHeaders(self: Inspector, head: Head) Error!Decision {
        const decision = try self.headers(self.context, head);
        if (head.upgrade and decision == .hold) return error.InspectionUpgradeHold;
        return decision;
    }

    pub fn acquire(
        self: Inspector,
        reader: *Io.Reader,
        head: Head,
        progress: ?entity.Progress,
    ) (Error || entity.Error)!Held {
        if (head.upgrade) return error.InspectionUpgradeHold;
        if (head.bytes.len > self.head_storage.len) return error.InspectionHeadLimit;
        if (head.framing != .none and !supportedTransferCoding(head.bytes))
            return error.UnsupportedInspectedTransferCoding;
        assertDisjoint(self.head_storage, reader.buffer);
        assertDisjoint(self.head_storage, self.body_storage);
        @memcpy(self.head_storage[0..head.bytes.len], head.bytes);
        reader.toss(head.bytes.len);
        const bytes = try entity.read(.{
            .reader = reader,
            .output = self.body_storage,
            .framing_limit = self.framing_limit,
            .progress = progress,
        }, head.framing);
        try self.body(self.context, bytes);
        return .{ .head = self.head_storage[0..head.bytes.len], .body = bytes };
    }
};

pub const Held = struct { head: []const u8, body: []const u8 };

// Removing chunk framing does not decode another transfer coding. A connector
// must implement that coding before it can claim inspection of its representation.
fn supportedTransferCoding(head: []const u8) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!std.ascii.eqlIgnoreCase(value, "chunked")) return false;
    }
    return true;
}

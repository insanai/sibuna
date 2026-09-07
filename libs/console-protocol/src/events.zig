//! Keyset cursors use time and id; ids cross the browser boundary as decimal strings.
const std = @import("std");
const Bytes = @import("root.zig").Bytes;
pub const Cursor = struct { time: u64, id: u64 };
pub const Query = struct {
    session_digest: [32]u8,
    now: u64,
    grouped: bool = false,
    export_page: bool = false,
    before: ?Cursor = null,
    limit: u16 = 10,
    from: u64 = 0,
    until: u64 = std.math.maxInt(i64),
    node: u32 = 0,
    campaign: u64 = 0,
    incident: u64 = 0,
    category: Bytes(32) = .{},
    ip: Bytes(48) = .{},
    path_prefix: Bytes(256) = .{},
};
pub const Capture = struct {
    version: u8 = 1,
    selected_status: u16,
    query_bytes: u32,
    body_bytes: u32,
    declared_body_bytes: u32,
    truncated: u16,
};
pub const Row = struct {
    capture: ?Capture = null,
    id: u64 = 0,
    grouped: bool = false,
    count: u64 = 1,
    first_seen: u64 = 0,
    node: u32 = 0,
    time: u64 = 0,
    ip: Bytes(48) = .{},
    method: Bytes(8) = .{},
    path: Bytes(256) = .{},
    category: Bytes(32) = .{},
    user_agent: Bytes(128) = .{},
    campaign: ?u64 = null,
    display_truncated: bool = false,
    query_redacted: bool = false,

    pub fn write(self: *const Row, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var id: [20]u8 = undefined;
        var campaign: [20]u8 = undefined;
        const id_text = std.fmt.bufPrint(&id, "{d}", .{self.id}) catch unreachable;
        const campaign_text: ?[]const u8 = if (self.campaign) |value|
            std.fmt.bufPrint(&campaign, "{d}", .{value}) catch unreachable
        else
            null;
        try std.json.Stringify.value(.{
            .id = id_text,
            .grouped = self.grouped,
            .count = self.count,
            .first_seen = self.first_seen,
            .node = self.node,
            .time = self.time,
            .ip = self.ip.slice(),
            .method = self.method.slice(),
            .path = self.path.slice(),
            .category = self.category.slice(),
            .user_agent = self.user_agent.slice(),
            .campaign = campaign_text,
            .display_truncated = self.display_truncated,
            .query_redacted = self.query_redacted,
            .evidence_version = if (self.capture) |c| @as(?u16, c.version) else null,
            .capture = self.capture,
            .country = @as(?[]const u8, null),
            .response_status = @as(?u16, null),
            .matched_rule = @as(?[]const u8, null),
        }, .{}, w);
    }
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > 10 or query.from > query.until or
        query.until > std.math.maxInt(i64) or query.campaign > std.math.maxInt(i64) or
        query.incident > std.math.maxInt(i64))
        return error.InvalidLimit;
    if (query.before) |cursor| {
        if (cursor.time > std.math.maxInt(i64) or cursor.id > std.math.maxInt(i64))
            return error.InvalidLimit;
    }
}

const std = @import("std");
const p = @import("console_protocol");
pub const Model = struct {
    rows: [10]p.events.Row = @splat(.{}),
    count: usize = 0,
    loaded: bool = false,
    busy: bool = false,
    focus_results: bool = false,
    grouped: bool = false,
    exporting: bool = false,
    export_ready: bool = false,
    node: u32 = 0,
    campaign: u64 = 0,
    incident: u64 = 0,
    next: ?p.events.Cursor = null,
    cursors: [64]?p.events.Cursor = @splat(null),
    page: usize = 0,
    category: p.Bytes(32) = .{},
    ip: p.Bytes(48) = .{},
    path: p.Bytes(256) = .{},
    hours: u32 = 0,
    until: u64 = 0,

    pub fn decode(self: *Model, value: WirePage) !void {
        if (value.rows.len > self.rows.len) return error.InvalidResponse;
        var parsed: [10]p.events.Row = @splat(.{});
        for (value.rows, 0..) |row, i| {
            if (row.capture) |capture| {
                if (capture.version != 1) return error.InvalidResponse;
            }
            parsed[i] = .{
                .id = try std.fmt.parseInt(u64, row.id, 10),
                .grouped = row.grouped,
                .count = row.count,
                .first_seen = row.first_seen,
                .node = row.node,
                .time = row.time,
                .ip = try p.Bytes(48).init(row.ip),
                .method = try p.Bytes(8).init(row.method),
                .path = try p.Bytes(256).init(row.path),
                .category = try p.Bytes(32).init(row.category),
                .user_agent = try p.Bytes(128).init(row.user_agent),
                .query_redacted = row.query_redacted,
                .display_truncated = row.display_truncated,
                .capture = row.capture,
            };
            if (row.campaign) |id| parsed[i].campaign = try std.fmt.parseInt(u64, id, 10);
        }
        var next: ?p.events.Cursor = null;
        if (value.next) |cursor| next = .{
            .time = cursor.time,
            .id = try std.fmt.parseInt(u64, cursor.id, 10),
        };
        self.rows = parsed;
        self.count = value.rows.len;
        self.next = next;
        self.loaded = true;
    }
};

pub fn field(value: std.json.Value, key: []const u8) ?std.json.Value {
    return if (value == .object) value.object.get(key) else null;
}
pub fn string(value: std.json.Value, key: []const u8) []const u8 {
    const item = field(value, key) orelse return "";
    return if (item == .string) item.string else "";
}

pub const WirePage = struct {
    rows: []const WireRow = &.{},
    next: ?struct { time: u64, id: []const u8 } = null,
};
pub const WireRow = struct {
    id: []const u8,
    grouped: bool = false,
    count: u64 = 1,
    first_seen: u64 = 0,
    node: u32 = 0,
    time: u64 = 0,
    ip: []const u8 = "",
    method: []const u8 = "",
    path: []const u8 = "",
    category: []const u8 = "",
    user_agent: []const u8 = "",
    query_redacted: bool = false,
    display_truncated: bool = false,
    campaign: ?[]const u8 = null,
    capture: ?p.events.Capture = null,
};

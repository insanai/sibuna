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
    next: ?p.events.Cursor = null,
    cursors: [64]?p.events.Cursor = @splat(null),
    page: usize = 0,
    category: p.Bytes(32) = .{},
    ip: p.Bytes(48) = .{},
    path: p.Bytes(256) = .{},
    hours: u32 = 0,
    until: u64 = 0,

    pub fn decode(self: *Model, value: std.json.Value) !void {
        const rows = field(value, "rows") orelse return error.InvalidResponse;
        if (rows != .array or rows.array.items.len > self.rows.len) return error.InvalidResponse;
        var parsed: [10]p.events.Row = @splat(.{});
        for (rows.array.items, 0..) |row, i| {
            parsed[i] = .{
                .id = try std.fmt.parseInt(u64, string(row, "id"), 10),
                .grouped = boolean(row, "grouped"),
                .count = number(row, "count"),
                .first_seen = number(row, "first_seen"),
                .node = std.math.cast(u32, number(row, "node")) orelse
                    return error.InvalidResponse,
                .time = number(row, "time"),
                .ip = try p.Bytes(48).init(string(row, "ip")),
                .method = try p.Bytes(8).init(string(row, "method")),
                .path = try p.Bytes(256).init(string(row, "path")),
                .category = try p.Bytes(32).init(string(row, "category")),
                .user_agent = try p.Bytes(128).init(string(row, "user_agent")),
                .query_redacted = boolean(row, "query_redacted"),
                .display_truncated = boolean(row, "display_truncated"),
            };
            if (string(row, "campaign").len != 0)
                parsed[i].campaign = try std.fmt.parseInt(u64, string(row, "campaign"), 10);
        }
        var next: ?p.events.Cursor = null;
        const cursor = field(value, "next") orelse return error.InvalidResponse;
        if (cursor != .null) next = .{
            .time = number(cursor, "time"),
            .id = try std.fmt.parseInt(u64, string(cursor, "id"), 10),
        };
        self.rows = parsed;
        self.count = rows.array.items.len;
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
fn number(value: std.json.Value, key: []const u8) u64 {
    const item = field(value, key) orelse return 0;
    return if (item == .integer and item.integer >= 0) @intCast(item.integer) else 0;
}
fn boolean(value: std.json.Value, key: []const u8) bool {
    const item = field(value, key) orelse return false;
    return item == .bool and item.bool;
}

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
    country: p.events.country.Filter = .{},
    ip: p.Bytes(48) = .{},
    path: p.Bytes(256) = .{},
    hours: u32 = 0,
    from: ?u64 = null,
    module: ?p.security.Module = null,
    until: u64 = 0,

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.next = null;
        self.from = null;
        self.module = null;
        for (&self.cursors) |*cursor| cursor.* = null;
        for (&self.rows) |*row| clearRow(row);
    }

    pub fn decode(self: *Model, value: WirePage) !void {
        if (value.rows.len > self.rows.len) return error.InvalidResponse;
        var parsed: [10]p.events.Row = undefined;
        for (&parsed) |*row| clearRow(row);
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
                .crs = if (row.crs) |crs| try crs.decode() else null,
                .geography = try p.events.country.Mapping.decode(row.geography),
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

/// Keep per-row initialization out of the caller so the optimizer cannot replace the
/// loop with a duplicate multi-kilobyte default row array in the Wasm data segment.
noinline fn clearRow(row: *p.events.Row) void {
    @memset(std.mem.asBytes(row), 0);
    row.capture = null;
    row.crs = null;
    row.campaign = null;
    row.count = 1;
}

test "event reset restores every default and erases retained evidence display buffers" {
    const t = std.testing;
    var model: Model = .{ .loaded = true, .count = 1, .next = .{ .time = 10, .id = 8 } };
    model.rows[0].path = try p.Bytes(256).init("private incident path");
    model.rows[0].capture = .{
        .selected_status = 403,
        .query_bytes = 1,
        .body_bytes = 2,
        .declared_body_bytes = 2,
        .truncated = 0,
    };
    model.rows[0].crs = .{
        .rule_id = 942100,
        .phase = 2,
        .severity = 2,
        .revision = 1,
        .source_digest = @splat(0xab),
        .enforcing = false,
        .denied = false,
        .would_deny = true,
        .coverage = .incomplete,
        .selected_status = 403,
        .blocking_paranoia = 1,
        .detection_paranoia = 1,
    };
    model.clear();
    try t.expectEqualDeep(Model{}, model);
    try t.expect(std.mem.allEqual(u8, &model.rows[0].path.data, 0));
}

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
    geography: p.events.country.Wire = .{},
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
    crs: ?p.events.security_evidence.Wire = null,
};

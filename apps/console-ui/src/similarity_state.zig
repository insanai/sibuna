const std = @import("std");
const p = @import("console_protocol");
pub const Model = struct {
    source: u64 = 0,
    generation: u32 = 0,
    from: u64 = 0,
    until: u64 = 0,
    next: ?p.events.Cursor = null,
    best: p.similarity.Best = .{},
    scanned: u64 = 0,
    invalid: u64 = 0,
    running: bool = false,
    busy: bool = false,
    complete: bool = false,
    unavailable: bool = false,
    received_at: u64 = 0,

    pub fn accept(self: *Model, part: WirePart) !void {
        if (part.rows.len > 10 or part.scanned > 64 or part.invalid > part.scanned or
            part.rows.len > part.scanned or (part.next != null and part.scanned != 64))
            return error.InvalidResponse;
        if (part.next) |cursor| {
            const id = try std.fmt.parseInt(u64, cursor.id, 10);
            const before = self.next orelse p.events.Cursor{
                .time = self.until,
                .id = std.math.maxInt(i64),
            };
            if (cursor.time > before.time or
                (cursor.time == before.time and id >= before.id)) return error.InvalidResponse;
        }
        var best = self.best;
        for (part.rows) |row| {
            if (!std.math.isFinite(row.distance) or row.distance < 0 or row.distance > 2)
                return error.InvalidResponse;
            const id = try std.fmt.parseInt(u64, row.id, 10);
            if (id == 0 or id > std.math.maxInt(i64) or id == self.source)
                return error.InvalidResponse;
            best.add(.{ .id = id, .time = row.time, .node = row.node, .distance = row.distance });
        }
        self.next = if (part.next) |cursor| .{
            .time = cursor.time,
            .id = try std.fmt.parseInt(u64, cursor.id, 10),
        } else null;
        self.best = best;
        self.scanned += part.scanned;
        self.invalid += part.invalid;
        self.unavailable = !part.source_available;
        self.complete = self.next == null;
        self.running = !self.complete;
    }
};
pub const WirePart = struct {
    generation: u32 = 0,
    source_available: bool = false,
    scanned: u16 = 0,
    invalid: u16 = 0,
    rows: []const struct { id: []const u8, node: u32, time: u64, distance: f64 } = &.{},
    next: ?struct { time: u64, id: []const u8 } = null,
};

test "invalid similarity parts cannot alter accumulated matches or move the cursor forward" {
    var model: Model = .{ .source = 1, .until = 200, .next = .{ .time = 190, .id = 10 } };
    const previous = model;
    try std.testing.expectError(error.InvalidResponse, model.accept(.{
        .scanned = 64,
        .next = .{ .time = 191, .id = "10" },
    }));
    try std.testing.expectEqualDeep(previous, model);
    try std.testing.expectError(error.InvalidResponse, model.accept(.{
        .scanned = 2,
        .rows = &.{
            .{ .id = "2", .node = 1, .time = 180, .distance = 0.1 },
            .{ .id = "3", .node = 1, .time = 180, .distance = std.math.nan(f64) },
        },
    }));
    try std.testing.expectEqualDeep(previous, model);
}

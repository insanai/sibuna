//! Incremental cosine search contracts. Cursors bound one scan to 64 historical rows;
//! each part's best ten suffice to merge the global best ten without retaining all inputs.
const std = @import("std");
const events = @import("events.zig");
pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    source: u64,
    from: u64 = 0,
    until: u64,
    before: ?events.Cursor = null,
};
pub const Match = struct {
    id: u64 = 0,
    node: u32 = 0,
    time: u64 = 0,
    distance: f64 = 0,
};
pub const Best = struct {
    rows: [10]Match = @splat(.{}),
    count: u8 = 0,

    pub fn add(self: *Best, candidate: Match) void {
        std.debug.assert(std.math.isFinite(candidate.distance));
        std.debug.assert(candidate.distance >= 0 and candidate.distance <= 2);
        for (self.rows[0..self.count]) |row| if (row.id == candidate.id) return;
        var position: usize = 0;
        while (position < self.count) : (position += 1) {
            const row = self.rows[position];
            if (candidate.distance < row.distance or
                (candidate.distance == row.distance and candidate.id < row.id)) break;
        }
        if (position == self.rows.len) return;
        const last = @min(self.count, self.rows.len - 1);
        var index: usize = last;
        while (index > position) : (index -= 1) self.rows[index] = self.rows[index - 1];
        self.rows[position] = candidate;
        self.count = @intCast(@min(self.count + 1, self.rows.len));
    }
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.source == 0 or query.source > std.math.maxInt(i64) or
        query.from > query.until or query.until > std.math.maxInt(i64)) return error.InvalidLimit;
    if (query.before) |cursor| {
        if (cursor.time > query.until or cursor.id > std.math.maxInt(i64))
            return error.InvalidLimit;
    }
}

test "merging partition top tens matches whole-scan ordering with deterministic ties" {
    var all: Best = .{};
    var merged: Best = .{};
    for (0..8) |part| {
        var subset: Best = .{};
        for (0..64) |index| {
            const id = part * 64 + index + 1;
            const distance = @as(f64, @floatFromInt(id % 23)) / 23;
            const candidate: Match = .{ .id = id, .distance = distance };
            all.add(candidate);
            subset.add(candidate);
        }
        for (subset.rows[0..subset.count]) |row| merged.add(row);
    }
    try std.testing.expectEqualDeep(all, merged);
    const previous = merged;
    merged.add(merged.rows[0]);
    try std.testing.expectEqualDeep(previous, merged);
}

pub const Part = struct {
    source_available: bool = false,
    scanned: u16 = 0,
    invalid: u16 = 0,
    next: ?events.Cursor = null,
    best: Best = .{},
};

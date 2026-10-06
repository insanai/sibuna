//! Owned private-test evidence pages stay separate from small scalar status polls.
const std = @import("std");
const api = @import("security-evidence").detail;
pub const capacity = 64;
pub const page_capacity = 2;
pub const Page = struct {
    total: u8 = 0,
    offset: u8 = 0,
    count: u8 = 0,
    next: ?u8 = null,
    rows: [page_capacity]?api.Detail = @splat(null),

    pub fn validate(self: *const Page) error{InvalidEvidence}!void {
        if (self.total > capacity or self.offset > self.total or
            self.offset % page_capacity != 0 or
            self.count != @min(page_capacity, self.total - self.offset))
            return error.InvalidEvidence;
        const end = self.offset + self.count;
        const next: ?u8 = if (end < self.total) end else null;
        if (self.next != next) return error.InvalidEvidence;
        for (self.rows[0..self.count]) |row| {
            const detail = row orelse return error.InvalidEvidence;
            try detail.validate();
        }
        for (self.rows[self.count..]) |row| if (row != null) return error.InvalidEvidence;
    }
};

pub fn page(rows: []const api.Detail, offset: u8, output: *Page) !void {
    if (rows.len > capacity or offset > rows.len or offset % page_capacity != 0)
        return error.InvalidEvidence;
    output.* = .{ .total = @intCast(rows.len), .offset = offset };
    output.count = @intCast(@min(page_capacity, rows.len - offset));
    const end = offset + output.count;
    for (rows[offset..end], output.rows[0..output.count]) |row, *destination|
        destination.* = row;
    if (end < rows.len) output.next = end;
    try output.validate();
}

test "maximum private detail pages stay within HTTP bounds and reject hidden rows" {
    const t = std.testing;
    var rows: [3]api.Detail = @splat(.{ .rule_id = std.math.maxInt(u32), .phase = 5 });
    for (&rows) |*row| {
        row.message = api.Preview(96).copy(&@as([65536]u8, @splat(255)));
        row.tags = @splat(api.Preview(64).copy(&@as([65536]u8, @splat(254))));
        row.tag_count = 4;
        row.omitted_tags = 65532;
        row.score = .{};
        for (&row.score.?.buckets) |*bucket| bucket.* = .{
            .writes = std.math.maxInt(u32),
            .delta = std.math.minInt(i64),
        };
    }
    var output: Page = undefined;
    try page(&rows, 0, &output);
    try t.expectEqual(@as(?u8, 2), output.next);
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, output, .{});
    defer t.allocator.free(bytes);
    try t.expect(bytes.len < 12 * 1024);
    try page(&rows, 2, &output);
    try t.expect(output.next == null and output.count == 1);
    output.rows[1] = rows[0];
    try t.expectError(error.InvalidEvidence, output.validate());
    try t.expectError(error.InvalidEvidence, page(&rows, 1, &output));
}

pub const Wire = struct {
    total: u8,
    offset: u8,
    count: u8,
    next: ?u8,
    rows: [page_capacity]?api.Wire,

    pub fn into(self: Wire, output: *Page) !void {
        output.* = .{
            .total = self.total,
            .offset = self.offset,
            .count = self.count,
            .next = self.next,
        };
        for (self.rows, &output.rows) |row, *destination| if (row) |value| {
            var detail: api.Detail = undefined;
            try value.into(&detail);
            destination.* = detail;
        };
        try output.validate();
    }
};

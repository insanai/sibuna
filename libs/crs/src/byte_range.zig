//! Immutable byte-membership tables. Compilation is off-path; inspection never allocates.
const std = @import("std");
const work = @import("work.zig");

pub const Error = error{ InvalidRange, SourceLimit } || work.Error;
pub const Findings = struct { count: usize = 0, first: ?usize = null, last: ?usize = null };

pub const Range = struct {
    table: [4]u64 = @splat(0),

    pub fn inspect(self: Range, input: []const u8, budget: *work.Budget) Error!Findings {
        const cost = std.math.mul(u64, @intCast(input.len), 4) catch return error.WorkLimit;
        try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
        var result: Findings = .{};
        for (input, 0..) |byte, index| {
            if (self.table[byte >> 6] & (@as(u64, 1) << @as(u6, @truncate(byte))) != 0) continue;
            if (result.first == null) result.first = index;
            result.last = index;
            result.count += 1;
        }
        return result;
    }
};

pub fn compile(input: []const u8) Error!Range {
    if (input.len > 64 * 1024) return error.SourceLimit;
    var result: Range = .{};
    var items = std.mem.splitScalar(u8, input, ',');
    while (items.next()) |item| {
        const separator = std.mem.indexOfScalar(u8, item, '-');
        const start = try number(if (separator) |index| item[0..index] else item);
        const end = if (separator) |index| try number(item[index + 1 ..]) else start;
        if (start > end) return error.InvalidRange;
        for (@as(usize, start)..@as(usize, end) + 1) |value| {
            result.table[value >> 6] |= @as(u64, 1) << @as(u6, @truncate(value));
        }
    }
    return result;
}

fn number(input: []const u8) Error!u8 {
    var position: usize = 0;
    while (position < input.len and std.ascii.isWhitespace(input[position])) position += 1;
    if (position < input.len and input[position] == '+') position += 1;
    const start = position;
    var value: u16 = 0;
    while (position < input.len and std.ascii.isDigit(input[position])) : (position += 1) {
        value = value * 10 + input[position] - '0';
        if (value > 255) return error.InvalidRange;
    }
    if (position == start) return error.InvalidRange;
    return @intCast(value);
}

test "byte range unions count each invalid byte once and retain binary offsets" {
    const range = try compile("0-31, 32-126,9,65-90,+255suffix");
    const same = try compile("0-126,255");
    try std.testing.expectEqualSlices(u64, &same.table, &range.table);
    var budget: work.Budget = .{ .remaining = 2048 };
    const result = try range.inspect("A\x00\x80B\xc2\xff", &budget);
    try std.testing.expectEqual(@as(usize, 2), result.count);
    try std.testing.expectEqual(@as(usize, 2), result.first.?);
    try std.testing.expectEqual(@as(usize, 4), result.last.?);
    const full = try compile("0-255");
    var bytes: [256]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
    try std.testing.expectEqual(@as(usize, 0), (try full.inspect(&bytes, &budget)).count);
}

test "range compilation rejects malformed boundaries and work exhaustion is separate" {
    for ([_][]const u8{ "", "-1", "1-", "256", "10-9", "0,,1", "1,", "x" }) |text| {
        try std.testing.expectError(error.InvalidRange, compile(text));
    }
    const range = try compile("+1suffix-2suffix,2-3-ignored");
    var budget: work.Budget = .{ .remaining = 4 };
    try std.testing.expectError(error.WorkLimit, range.inspect("A", &budget));
    try std.testing.expectEqual(@as(u64, 4), budget.remaining);
}

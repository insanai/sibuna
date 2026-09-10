//! Display counters keep exact u64 precision. Identifiers, input values and wire numbers
//! retain their ungrouped representation; only human-readable counts use separators.
const std = @import("std");
pub const capacity = 26;

pub fn text(value: u64, buffer: *[capacity]u8) []const u8 {
    var remaining = value;
    var start: usize = buffer.len;
    var digits: u8 = 0;
    while (true) {
        start -= 1;
        buffer[start] = '0' + @as(u8, @intCast(remaining % 10));
        remaining /= 10;
        digits += 1;
        if (remaining == 0) return buffer[start..];
        if (digits == 3) {
            start -= 1;
            buffer[start] = ',';
            digits = 0;
        }
    }
}

pub fn write(w: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
    var buffer: [capacity]u8 = undefined;
    try w.writeAll(text(value, &buffer));
}

test "display grouping preserves zero, boundaries and full unsigned counter precision" {
    var buffer: [capacity]u8 = undefined;
    const cases = .{
        .{ @as(u64, 0), "0" },
        .{ @as(u64, 999), "999" },
        .{ @as(u64, 1000), "1,000" },
        .{ @as(u64, 1000000), "1,000,000" },
        .{ std.math.maxInt(u64), "18,446,744,073,709,551,615" },
    };
    inline for (cases) |case| try std.testing.expectEqualStrings(case[1], text(case[0], &buffer));
}

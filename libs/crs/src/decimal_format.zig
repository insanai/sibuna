//! Fixed-capacity integer rendering for transaction values, without general formatting.
const std = @import("std");
const work = @import("work.zig");

/// The largest absolute value determines digits; a signed type reserves its minus sign.
pub fn capacity(comptime T: type) comptime_int {
    const info = @typeInfo(T);
    if (info != .int or info.int.bits == 0 or info.int.bits > 64) {
        @compileError("decimal transaction formatting requires a 1..64-bit integer");
    }
    const signed = info.int.signedness == .signed;
    var maximum: u128 = if (signed)
        @as(u128, 1) << (info.int.bits - 1)
    else
        std.math.maxInt(T);
    var digits = 1;
    while (maximum >= 10) : (maximum /= 10) digits += 1;
    if (signed) digits += 1;
    return digits;
}

/// Copy work is reserved before any write. The result borrows the dedicated array.
/// Widening before negation handles every minimum signed integer without overflow.
pub fn write(
    comptime T: type,
    value: T,
    output: *[capacity(T)]u8,
    budget: *work.Budget,
) work.Error![]const u8 {
    try budget.debit(capacity(T) * 4);
    const wide: i128 = value;
    const negative = wide < 0;
    var remaining: u64 = @intCast(if (negative) -wide else wide);
    var position: usize = output.len;
    while (true) {
        position -= 1;
        output[position] = @intCast('0' + remaining % 10);
        remaining /= 10;
        if (remaining == 0) break;
    }
    if (negative) {
        position -= 1;
        output[position] = '-';
    }
    return output[position..];
}

fn check(comptime T: type, value: T) !void {
    var output: [capacity(T)]u8 = @splat('x');
    var expected: [21]u8 = undefined;
    var budget: work.Budget = .{ .remaining = capacity(T) * 4 };
    try std.testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected, "{d}", .{value}),
        try write(T, value, &output, &budget),
    );
    try std.testing.expectEqual(@as(u64, 0), budget.remaining);
    @memset(&output, 'x');
    try std.testing.expectError(error.WorkLimit, write(T, value, &output, &budget));
    try std.testing.expectEqualSlices(u8, &(@as([capacity(T)]u8, @splat('x'))), &output);
}

test "fixed decimal rendering covers zero extrema and atomic work failure" {
    inline for (.{ i8, u8, i32, u32, i64, u64, usize }) |T| {
        try check(T, 0);
        try check(T, std.math.minInt(T));
        try check(T, std.math.maxInt(T));
    }
    var random: std.Random.DefaultPrng = .init(0xdeca1);
    for (0..1000) |_| {
        try check(i64, random.random().int(i64));
        try check(u64, random.random().int(u64));
    }
}

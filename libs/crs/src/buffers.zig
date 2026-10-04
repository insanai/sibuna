//! Buffer ownership invariants shared by transforms and runtime strings.
const std = @import("std");

pub fn assertDisjoint(left: []const u8, right: []const u8) void {
    if (left.len == 0 or right.len == 0) return;
    const first = @intFromPtr(left.ptr);
    const second = @intFromPtr(right.ptr);
    // Subtraction avoids overflowing an address while computing an exclusive end.
    std.debug.assert(if (first <= second)
        second - first >= left.len
    else
        first - second >= right.len);
}

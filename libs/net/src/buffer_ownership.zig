//! Buffer ownership invariants shared by reserved transport operations.
const std = @import("std");

pub fn assertDisjoint(a: []const u8, b: []const u8) void {
    if (a.len == 0 or b.len == 0) return;
    const first = @intFromPtr(a.ptr);
    const second = @intFromPtr(b.ptr);
    std.debug.assert(first + a.len <= second or second + b.len <= first);
}

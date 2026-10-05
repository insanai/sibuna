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

pub fn assertExclusive(regions: []const []const u8) void {
    for (regions, 0..) |left, index| {
        for (regions[index + 1 ..]) |right| assertDisjoint(left, right);
    }
}

/// Owned bounded text; unused bytes never belong to the wire representation.
pub fn Bytes(comptime capacity: usize) type {
    return struct {
        pub const byte_capacity = capacity;
        data: [capacity]u8 = @splat(0),
        len: usize = 0,

        pub fn init(value: []const u8) error{TooLarge}!@This() {
            var result: @This() = undefined;
            try result.set(value);
            return result;
        }

        /// Caller-owned outputs avoid large error-union copies. Oversize input leaves
        /// the previous value intact; overlapping slices are moved before tail erasure.
        pub fn set(self: *@This(), value: []const u8) error{TooLarge}!void {
            if (value.len > capacity) return error.TooLarge;
            const output = self.data[0..value.len];
            if (@intFromPtr(output.ptr) <= @intFromPtr(value.ptr)) {
                std.mem.copyForwards(u8, output, value);
            } else std.mem.copyBackwards(u8, output, value);
            @memset(self.data[value.len..], 0);
            self.len = value.len;
        }

        pub fn slice(self: *const @This()) []const u8 {
            std.debug.assert(self.len <= capacity);
            return self.data[0..self.len];
        }
    };
}

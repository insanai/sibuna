//! A shared transaction work budget. Exhaustion is never a negative match.
const std = @import("std");

pub const Error = error{WorkLimit};

pub const Budget = struct {
    remaining: u64,

    /// Reserve a bounded scan before traversing input. Checked arithmetic keeps a
    /// hostile length from wrapping into a cheap scan on native or Wasm targets.
    pub fn debitLinear(self: *Budget, bytes: u64, visits: u64, overhead: u64) Error!void {
        const cost = std.math.mul(u64, bytes, visits) catch return error.WorkLimit;
        try self.debit(std.math.add(u64, cost, overhead) catch return error.WorkLimit);
    }

    pub fn debit(self: *Budget, units: u64) Error!void {
        if (units > self.remaining) return error.WorkLimit;
        self.remaining -= units;
    }
};

test "budget preserves its balance on refused work" {
    var budget: Budget = .{ .remaining = 3 };
    try budget.debit(2);
    try std.testing.expectError(error.WorkLimit, budget.debit(2));
    try std.testing.expectEqual(@as(u64, 1), budget.remaining);
    try std.testing.expectError(error.WorkLimit, budget.debitLinear(std.math.maxInt(u64), 2, 0));
    try std.testing.expectEqual(@as(u64, 1), budget.remaining);
    try budget.debit(1);
    try std.testing.expectError(error.WorkLimit, budget.debit(1));
}

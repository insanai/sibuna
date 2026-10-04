//! A shared transaction work budget. Exhaustion is never a negative match.
const std = @import("std");

pub const Error = error{WorkLimit};

pub const Budget = struct {
    remaining: u64,

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
    try budget.debit(1);
    try std.testing.expectError(error.WorkLimit, budget.debit(1));
}

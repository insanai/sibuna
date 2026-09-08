//! Fixed-window management budgets are separate from password verification limits.
//! Live slots cannot be evicted to reset an allowance; all counters advance under one lock.
const std = @import("std");
pub const Kind = enum { query, export_page, mutation };
pub const Budget = struct {
    const Slot = struct {
        digest: [32]u8 = @splat(0),
        until: u64 = 0,
        queries: u16 = 0,
        exports: u16 = 0,
        mutations: u16 = 0,
    };
    slots: [4096]Slot = @splat(.{}),
    mutex: std.Io.Mutex = .init,
    until: u64 = 0,
    queries: u16 = 0,
    exports: u16 = 0,

    pub fn allow(self: *Budget, io: std.Io, digest: [32]u8, now: u64, kind: Kind) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.until <= now) {
            self.until = now + 60;
            self.queries = 0;
            self.exports = 0;
        }
        const exporting = kind == .export_page;
        if (self.queries >= 1200 or (exporting and self.exports >= 30)) return false;
        var found: ?*Slot = null;
        var free: ?*Slot = null;
        for (&self.slots) |*slot| {
            if (slot.until <= now) {
                if (free == null) free = slot;
            } else if (std.mem.eql(u8, &slot.digest, &digest)) {
                found = slot;
                break;
            }
        }
        const slot = found orelse free orelse return false;
        if (found == null) slot.* = .{ .digest = digest, .until = now + 60 };
        if (slot.queries >= 120 or (exporting and slot.exports >= 6)) return false;
        if (kind == .mutation and slot.mutations >= 60) return false;
        slot.queries += 1;
        self.queries += 1;
        if (kind == .mutation) slot.mutations += 1;
        if (exporting) {
            slot.exports += 1;
            self.exports += 1;
        }
        return true;
    }
};

test "investigation budgets isolate sessions and exports and bound global work" {
    const budget = try std.testing.allocator.create(Budget);
    defer std.testing.allocator.destroy(budget);
    budget.* = .{};
    const io = std.testing.io;
    for (0..6) |_| try std.testing.expect(budget.allow(io, @splat(1), 10, .export_page));
    try std.testing.expect(!budget.allow(io, @splat(1), 10, .export_page));
    for (0..114) |_| try std.testing.expect(budget.allow(io, @splat(1), 10, .query));
    try std.testing.expect(!budget.allow(io, @splat(1), 69, .query));
    try std.testing.expect(budget.allow(io, @splat(2), 69, .query));
    try std.testing.expect(budget.allow(io, @splat(1), 70, .export_page));
    budget.queries = 1200;
    try std.testing.expect(!budget.allow(io, @splat(3), 70, .query));
}

test "management mutations have an independent sixty-per-minute session allowance" {
    const t = std.testing;
    const budget = try t.allocator.create(Budget);
    defer t.allocator.destroy(budget);
    budget.* = .{};
    for (0..60) |_| try t.expect(budget.allow(t.io, @splat(1), 10, .mutation));
    try t.expect(!budget.allow(t.io, @splat(1), 69, .mutation));
    try t.expect(budget.allow(t.io, @splat(1), 69, .query));
    try t.expect(budget.allow(t.io, @splat(2), 69, .mutation));
    try t.expect(budget.allow(t.io, @splat(1), 70, .mutation));
}

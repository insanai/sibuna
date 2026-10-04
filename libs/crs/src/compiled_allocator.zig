//! A single-owner payload ceiling for off-path compilation. Initialize in place:
//! allocator interfaces borrow this object through program destruction. Backing
//! allocator metadata and RSS are measured separately, not called payload bytes.
const std = @import("std");
const Allocator = std.mem.Allocator;
pub const Budget = struct {
    parent: Allocator,
    limit: usize,
    used: usize = 0,
    peak: usize = 0,
    exhausted: bool = false,
    last_failure: enum { none, ceiling, backing } = .none,

    pub fn allocator(self: *Budget) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn replace(self: *Budget, previous: usize, next: usize) bool {
        std.debug.assert(previous <= self.used and self.used <= self.limit);
        if (next <= self.limit - (self.used - previous)) return true;
        self.exhausted = true;
        self.last_failure = .ceiling;
        return false;
    }

    fn account(self: *Budget, previous: usize, next: usize) void {
        std.debug.assert(previous <= self.used);
        self.used = self.used - previous + next;
        self.peak = @max(self.peak, self.used);
        std.debug.assert(self.used <= self.limit);
    }

    fn alloc(ctx: *anyopaque, length: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.replace(0, length)) return null;
        const pointer = self.parent.rawAlloc(length, alignment, ra) orelse {
            self.last_failure = .backing;
            return null;
        };
        self.last_failure = .none;
        self.account(0, length);
        return pointer;
    }

    fn resize(
        ctx: *anyopaque,
        bytes: []u8,
        alignment: std.mem.Alignment,
        length: usize,
        ra: usize,
    ) bool {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.replace(bytes.len, length)) return false;
        if (!self.parent.rawResize(bytes, alignment, length, ra)) {
            self.last_failure = .backing;
            return false;
        }
        self.last_failure = .none;
        self.account(bytes.len, length);
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        bytes: []u8,
        alignment: std.mem.Alignment,
        length: usize,
        ra: usize,
    ) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.replace(bytes.len, length)) return null;
        const pointer = self.parent.rawRemap(bytes, alignment, length, ra) orelse {
            self.last_failure = .backing;
            return null;
        };
        self.last_failure = .none;
        self.account(bytes.len, length);
        return pointer;
    }

    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(bytes, alignment, ra);
        self.account(bytes.len, 0);
    }
};

test "live compilation payload is reclaimed and capacity refusal leaves accounting intact" {
    var budget: Budget = .{ .parent = std.testing.allocator, .limit = 64 };
    const allocator = budget.allocator();
    const first = try allocator.alloc(u8, 32);
    const second = try allocator.alloc(u8, 32);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expectEqual(@as(usize, 64), budget.used);
    allocator.free(first);
    const replacement = try allocator.alloc(u8, 32);
    allocator.free(second);
    allocator.free(replacement);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    try std.testing.expectEqual(@as(usize, 64), budget.peak);
    try std.testing.expect(budget.exhausted);
}

test "resize and realloc account successful growth, shrink and backing allocation failures" {
    var backing: [128]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var budget: Budget = .{ .parent = fixed.allocator(), .limit = 256 };
    const allocator = budget.allocator();
    var bytes = try allocator.alloc(u8, 32);
    try std.testing.expect(allocator.resize(bytes, 64));
    bytes = bytes.ptr[0..64];
    try std.testing.expectEqual(@as(usize, 64), budget.used);
    bytes = try allocator.realloc(bytes, 96);
    try std.testing.expectEqual(@as(usize, 96), budget.used);
    try std.testing.expect(allocator.resize(bytes, 16));
    bytes = bytes.ptr[0..16];
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 200));
    try std.testing.expect(!budget.exhausted);
    try std.testing.expectEqual(.backing, budget.last_failure);
    allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    try std.testing.expectEqual(@as(usize, 96), budget.peak);
}

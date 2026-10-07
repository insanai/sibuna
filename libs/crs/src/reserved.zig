//! Untouched scratch reservations. In safe builds `Allocator.alloc` fills new memory with
//! 0xAA, which makes every reserved page resident when a generation is selected; released
//! binaries are safe builds, so a default pool held its whole reservation in RSS. Slot
//! scratch is written before it is read, so it is reserved without that fill and pages
//! become resident only when transactions use them. Capacity accounting is unchanged.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// `Allocator.alloc` without the safe-build fill. Contents are undefined; release with
/// `Allocator.free` or with the owning arena.
pub fn alloc(allocator: Allocator, comptime T: type, n: usize) Allocator.Error![]T {
    const bytes = std.math.mul(usize, @sizeOf(T), n) catch return error.OutOfMemory;
    if (bytes == 0) return &.{};
    const raw = allocator.rawAlloc(bytes, .of(T), @returnAddress()) orelse
        return error.OutOfMemory;
    const typed: [*]T = @ptrCast(@alignCast(raw));
    return typed[0..n];
}

test "untouched reservations keep the interface's ownership and overflow rules" {
    const t = std.testing;
    const words = try alloc(t.allocator, u64, 3);
    defer t.allocator.free(words);
    try t.expectEqual(3, words.len);
    try t.expect(std.mem.isAligned(@intFromPtr(words.ptr), @alignOf(u64)));
    try t.expectEqual(0, (try alloc(t.allocator, u64, 0)).len);
    try t.expectError(error.OutOfMemory, alloc(t.allocator, u64, std.math.maxInt(usize)));
}

test "page-sized reservations are not written" {
    // Fresh anonymous pages read as zero; the safe-build fill would leave 0xAA.
    const page = std.heap.pageSize();
    const bytes = try alloc(std.heap.page_allocator, u8, 4 * page);
    defer std.heap.page_allocator.free(bytes);
    try std.testing.expect(std.mem.allEqual(u8, bytes, 0));
}

//! Off-path sample memory is erased before returning it to the backing allocator.
//! Initialize in place and keep this wrapper alive until every borrowed allocator
//! interface has finished. Refusing resize/remap makes every release observable.
const std = @import("std");
const Allocator = std.mem.Allocator;
pub const Erasing = struct {
    parent: Allocator,

    pub fn allocator(self: *Erasing) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = Allocator.noResize,
            .remap = Allocator.noRemap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, length: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Erasing = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(length, alignment, ra);
    }

    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Erasing = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, bytes);
        self.parent.rawFree(bytes, alignment, ra);
    }
};

test "private sample releases erase arena blocks and allocations replaced by realloc" {
    const t = std.testing;
    var backing: [4096]u8 = @splat(0x99);
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var erasing: Erasing = .{ .parent = fixed.allocator() };
    const allocator = erasing.allocator();
    var bytes = try allocator.alloc(u8, 64);
    @memset(bytes, 0x55);
    const previous = bytes;
    bytes = try allocator.realloc(bytes, 128);
    try t.expectEqualSlices(u8, &@as([64]u8, @splat(0)), previous);
    try t.expectEqualSlices(u8, &@as([64]u8, @splat(0x55)), bytes[0..64]);
    allocator.free(bytes);
    var arena: std.heap.ArenaAllocator = .init(allocator);
    const sample = try arena.allocator().alloc(u8, 512);
    @memset(sample, 0x77);
    arena.deinit();
    for (sample) |byte| try t.expectEqual(@as(u8, 0), byte);
}

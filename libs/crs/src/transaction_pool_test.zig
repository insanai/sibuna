const std = @import("std");
const pools = @import("transaction_pool.zig");
const rules = @import("rule_program.zig");
const prepare = @import("rule_program_test.zig").prepare;
const limits = @import("transaction_slot_test.zig").limits;

test "pool exhaustion, reuse and closing retain already admitted work" {
    var program = try prepare(
        \\SecAction "id:1,setvar:tx.score=1"
    , &.{});
    defer program.deinit();
    var pool: pools.Pool = undefined;
    try pool.init(std.testing.allocator, &program, limits, 2, 2 * 1024 * 1024);
    defer pool.deinit();
    var first = try pool.lease();
    var second = try pool.lease();
    try std.testing.expect(first.slot() != second.slot());
    try std.testing.expectError(error.PoolBusy, pool.lease());
    first.release();
    var reused = try pool.lease();
    defer reused.release();
    pool.close();
    try std.testing.expectError(error.PoolClosed, pool.lease());
    try std.testing.expect(!pool.drained());
    var evaluation = try second.slot().begin(.{
        .entries = &.{},
        .coverage = @splat(.complete),
    }, true);
    _ = try evaluation.run(.request_body);
    try std.testing.expectEqualStrings(
        "1",
        (try second.slot().store.get("score", &second.slot().budget)).?,
    );
    second.release();
    try std.testing.expect(!pool.drained());
}

fn allocationFailure(allocator: std.mem.Allocator, program: *const rules.Program) !void {
    var pool: pools.Pool = undefined;
    var fixed = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    try pool.init(fixed.allocator(), program, limits, 3, 3 * 1024 * 1024);
    pool.close();
    defer pool.deinit();
}

test "pool initialization unwinds completed slots when reservation or allocation fails" {
    var program = try prepare(
        \\SecRule ARGS "@rx (x+)" "id:1,capture"
    , &.{});
    defer program.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailure,
        .{&program},
    );
    var pool: pools.Pool = undefined;
    try std.testing.expectError(
        error.ReservationLimit,
        pool.init(std.testing.allocator, &program, limits, 2, 1),
    );
}

const Concurrent = struct {
    pool: *pools.Pool,
    visits: [2]std.atomic.Value(u32) = .{ .init(0), .init(0) },
    collisions: std.atomic.Value(u32) = .init(0),
    completed: std.atomic.Value(u32) = .init(0),

    fn run(self: *Concurrent) void {
        for (0..1000) |_| {
            var lease = self.pool.lease() catch |err| switch (err) {
                error.PoolBusy => continue,
                else => unreachable,
            };
            if (self.visits[lease.index].fetchAdd(1, .acq_rel) != 0)
                _ = self.collisions.fetchAdd(1, .monotonic);
            lease.slot().request[0] = @intCast(lease.index);
            _ = self.visits[lease.index].fetchSub(1, .acq_rel);
            _ = self.completed.fetchAdd(1, .monotonic);
            lease.release();
        }
    }
};

test "concurrent leasing never shares mutable workspace storage" {
    var program = try prepare(
        \\SecAction "id:1"
    , &.{});
    defer program.deinit();
    var pool: pools.Pool = undefined;
    try pool.init(std.testing.allocator, &program, limits, 2, 2 * 1024 * 1024);
    defer pool.deinit();
    var concurrent: Concurrent = .{ .pool = &pool };
    var threads: [4]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Concurrent.run, .{&concurrent});
        spawned += 1;
    }
    for (threads) |thread| thread.join();
    pool.close();
    try std.testing.expect(pool.drained());
    try std.testing.expect(concurrent.completed.load(.acquire) > 0);
    try std.testing.expectEqual(@as(u32, 0), concurrent.collisions.load(.acquire));
}

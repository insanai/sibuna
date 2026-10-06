const std = @import("std");
const pools = @import("transaction_pool.zig");
const rules = @import("rule_program.zig");
const prepare = @import("rule_program_test.zig").prepare;
const limits = @import("transaction_slot_test.zig").limits;
const io = std.testing.io;
const any: pools.Demand = .{ .request_bytes = 0 };

test "pool exhaustion, reuse and closing retain already admitted work" {
    var program = try prepare(
        \\SecAction "id:1,setvar:tx.score=1"
    , &.{});
    defer program.deinit();
    var pool: pools.Pool = undefined;
    try pool.init(std.testing.allocator, &program, limits, 2, 2 * 1024 * 1024);
    defer pool.deinit();
    var first = try pool.lease(any);
    var second = try pool.lease(any);
    try std.testing.expect(first.slot() != second.slot());
    try std.testing.expectError(error.PoolBusy, pool.lease(any));
    first.release(io);
    var reused = try pool.lease(any);
    defer reused.release(io);
    pool.close();
    try std.testing.expectError(error.PoolClosed, pool.lease(any));
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
    second.release(io);
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
            var lease = self.pool.lease(any) catch |err| switch (err) {
                error.PoolBusy => continue,
                else => unreachable,
            };
            if (self.visits[lease.index].fetchAdd(1, .acq_rel) != 0)
                _ = self.collisions.fetchAdd(1, .monotonic);
            lease.slot().request[0] = @intCast(lease.index);
            _ = self.visits[lease.index].fetchSub(1, .acq_rel);
            _ = self.completed.fetchAdd(1, .monotonic);
            lease.release(io);
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

const tiered = blk: {
    var selected = limits;
    selected.request = 2 * pools.small_request_bytes;
    break :blk selected;
};

test "small requests prefer small slots, spill upward and never displace large ones" {
    var program = try prepare(
        \\SecAction "id:1"
    , &.{});
    defer program.deinit();
    var pool: pools.Pool = undefined;
    try pool.init(std.testing.allocator, &program, tiered, 1, 8 * 1024 * 1024);
    defer pool.deinit();
    try std.testing.expect(pool.slotCount(.large) == 1 and pool.slotCount(.small) >= 2);
    try std.testing.expect(pool.reserved_bytes <= 8 * 1024 * 1024);
    var held: [pools.max_slots]pools.Lease = undefined;
    var used: usize = 0;
    defer for (held[0..used]) |*lease| lease.release(io);
    for (0..pool.slotCount(.small)) |_| {
        held[used] = try pool.lease(any);
        try std.testing.expect(held[used].tier == .small);
        try std.testing.expect(held[used].slot().request.len == pools.small_request_bytes);
        used += 1;
    }
    held[used] = try pool.lease(any);
    try std.testing.expect(held[used].tier == .large);
    used += 1;
    try std.testing.expectError(error.PoolBusy, pool.lease(any));
    used -= 1;
    held[used].release(io);
    // Unknown and oversized bodies need the configured bound even while small slots idle.
    held[0].release(io);
    var chunked = try pool.lease(.{ .request_bytes = null });
    try std.testing.expect(chunked.tier == .large);
    try std.testing.expectError(error.PoolBusy, pool.lease(.{ .request_bytes = 100_000 }));
    chunked.release(io);
    held[0] = try pool.lease(.{ .request_bytes = pools.small_request_bytes });
    try std.testing.expect(held[0].tier == .small);
    pool.close();
}

const Releaser = struct {
    lease: pools.Lease,

    fn run(self: *Releaser) void {
        std.Io.sleep(io, .fromMilliseconds(20), .awake) catch {};
        self.lease.release(io);
    }
};

test "a busy pool parks a request until a release or its bounded deadline" {
    var program = try prepare(
        \\SecAction "id:1"
    , &.{});
    defer program.deinit();
    var pool: pools.Pool = undefined;
    try pool.init(std.testing.allocator, &program, limits, 1, 1024 * 1024);
    defer pool.deinit();
    const wait: std.Io.Clock.Duration = .{ .raw = .fromSeconds(5), .clock = .awake };
    var releaser: Releaser = .{ .lease = try pool.lease(any) };
    const thread = try std.Thread.spawn(.{}, Releaser.run, .{&releaser});
    var woken = try pool.leaseWithin(io, any, wait);
    thread.join();
    const short: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(30), .clock = .awake };
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.PoolBusy, pool.leaseWithin(io, any, short));
    const elapsed = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake));
    try std.testing.expect(elapsed.raw.nanoseconds >= 30 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), pool.waiters.load(.acquire));
    woken.release(io);
    pool.close();
    try std.testing.expectError(error.PoolClosed, pool.leaseWithin(io, any, short));
}

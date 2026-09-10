//! Counter sets belong to immutable rule generations. Callers pin that generation while
//! recording or reading; only a quiescent owner may reset it for reuse. No request allocation.
const std = @import("std");

pub fn Counters(comptime capacity: usize) type {
    std.debug.assert(capacity > 0 and capacity <= 128);
    return struct {
        const Self = @This();
        pub const Matches = std.StaticBitSet(capacity);
        pub const Snapshot = struct {
            generation: u64,
            values: [capacity]u64,
            overflow: bool,

            /// Deltas are exact per counter, not simultaneous across different rules.
            /// Partial output on failure must never be published by the caller.
            pub fn delta(
                self: *const Snapshot,
                before: *const Snapshot,
                output: *[capacity]u64,
            ) error{ GenerationChanged, CounterOverflow, InvalidSequence }!void {
                if (self.generation == 0 or self.generation != before.generation)
                    return error.GenerationChanged;
                if (self.overflow or before.overflow) return error.CounterOverflow;
                for (self.values, before.values, output) |after, previous, *difference| {
                    if (after < previous) return error.InvalidSequence;
                    difference.* = after - previous;
                }
            }
        };
        generation: u64 = 0,
        values: [capacity]std.atomic.Value(u64) = @splat(.init(0)),
        overflow: std.atomic.Value(bool) = .init(false),

        pub fn record(self: *Self, matches: *const Matches) void {
            std.debug.assert(self.generation != 0);
            var indices = matches.iterator(.{});
            while (indices.next()) |index| {
                std.debug.assert(index < capacity);
                self.increment(index);
            }
        }

        fn increment(self: *Self, index: usize) void {
            const counter = &self.values[index];
            var previous = counter.load(.monotonic);
            while (true) {
                if (previous == std.math.maxInt(u64)) {
                    self.overflow.store(true, .monotonic);
                    return;
                }
                previous = counter.cmpxchgWeak(
                    previous,
                    previous + 1,
                    .monotonic,
                    .monotonic,
                ) orelse return;
            }
        }

        pub fn read(self: *const Self, output: *Snapshot) void {
            output.generation = self.generation;
            for (&self.values, &output.values) |*counter, *value|
                value.* = counter.load(.monotonic);
            // Saturating increments never expose a wrapped zero while overflow is being set.
            output.overflow = self.overflow.load(.monotonic);
        }

        pub fn reset(self: *Self, generation: u64) void {
            std.debug.assert(generation != 0);
            self.generation = generation;
            for (&self.values) |*value| value.store(0, .monotonic);
            self.overflow.store(false, .monotonic);
        }
    };
}

test "concurrent rule matches accumulate and generation changes fence old baselines" {
    const t = std.testing;
    const C = Counters(4);
    var counters: C = .{ .generation = 1 };
    var before: C.Snapshot = undefined;
    counters.read(&before);
    const Worker = struct {
        fn run(shared: *C) void {
            var matches = C.Matches.initEmpty();
            matches.set(0);
            matches.set(3);
            for (0..10000) |_| shared.record(&matches);
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{&counters});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    var after: C.Snapshot = undefined;
    var delta: [4]u64 = undefined;
    counters.read(&after);
    try after.delta(&before, &delta);
    try t.expectEqualSlices(u64, &.{ 40000, 0, 0, 40000 }, &delta);
    counters.reset(2);
    counters.read(&after);
    try t.expectEqualSlices(u64, &.{ 0, 0, 0, 0 }, &after.values);
    try t.expectError(error.GenerationChanged, after.delta(&before, &delta));
}

test "counter wrap cannot produce an apparently complete interval" {
    const t = std.testing;
    const C = Counters(1);
    var counters: C = .{ .generation = 1 };
    var before: C.Snapshot = undefined;
    counters.read(&before);
    counters.values[0].store(std.math.maxInt(u64), .monotonic);
    const matches = C.Matches.initFull();
    counters.record(&matches);
    var after: C.Snapshot = undefined;
    counters.read(&after);
    var delta: [1]u64 = undefined;
    try t.expectEqual(std.math.maxInt(u64), after.values[0]);
    try t.expectError(error.CounterOverflow, after.delta(&before, &delta));
}

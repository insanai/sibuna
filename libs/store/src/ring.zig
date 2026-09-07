//! Bounded Multi-Producer Single-Consumer Queue
//!
//! Vyukov's sequence-stamped ring: every slot carries a sequence number
//! that tells producers whether it is free and the consumer whether it is
//! full, so neither side takes a lock. Worker threads push incident records
//! from the response path; the storage thread drains them. A full ring
//! drops the newest record rather than blocking a request, which is the
//! correct trade for forensics data under a flood.

const std = @import("std");

pub fn BoundedQueue(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity >= 2 and std.math.isPowerOfTwo(capacity));
    return struct {
        const Self = @This();
        const mask = capacity - 1;

        const Slot = struct {
            sequence: std.atomic.Value(usize),
            value: T,
        };

        slots: [capacity]Slot,
        head: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
        tail: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),

        pub fn init() Self {
            var self: Self = .{ .slots = undefined };
            for (&self.slots, 0..) |*slot, i| {
                slot.sequence = std.atomic.Value(usize).init(i);
            }
            return self;
        }

        /// Returns false when the queue is full; the value is not stored.
        pub fn push(self: *Self, value: T) bool {
            var pos = self.tail.load(.monotonic);
            while (true) {
                const slot = &self.slots[pos & mask];
                const seq = slot.sequence.load(.acquire);
                const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos));
                if (diff == 0) {
                    if (self.tail.cmpxchgWeak(pos, pos + 1, .monotonic, .monotonic) == null) {
                        slot.value = value;
                        slot.sequence.store(pos + 1, .release);
                        return true;
                    }
                } else if (diff < 0) {
                    return false;
                } else {
                    pos = self.tail.load(.monotonic);
                }
            }
        }

        /// Single consumer only.
        pub fn pop(self: *Self) ?T {
            const pos = self.head.load(.monotonic);
            const slot = &self.slots[pos & mask];
            const seq = slot.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos + 1));
            if (diff < 0) return null;
            const value = slot.value;
            self.head.store(pos + 1, .monotonic);
            slot.sequence.store(pos + capacity, .release);
            return value;
        }
    };
}

test "bounded queue preserves order, reports full, and wraps" {
    const Q = BoundedQueue(u32, 8);
    var q = Q.init();
    try std.testing.expect(q.pop() == null);
    var i: u32 = 0;
    while (i < 8) : (i += 1) try std.testing.expect(q.push(i));
    try std.testing.expect(!q.push(99));
    i = 0;
    while (i < 8) : (i += 1) try std.testing.expectEqual(i, q.pop().?);
    try std.testing.expect(q.pop() == null);
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expect(q.push(round));
        try std.testing.expect(q.push(round + 1000));
        try std.testing.expectEqual(round, q.pop().?);
        try std.testing.expectEqual(round + 1000, q.pop().?);
    }
}

test "bounded queue accepts concurrent producers" {
    const Q = BoundedQueue(u64, 1024);
    const q = try std.testing.allocator.create(Q);
    defer std.testing.allocator.destroy(q);
    q.* = Q.init();
    const Producer = struct {
        fn run(queue: *Q, base: u64) void {
            var n: u64 = 0;
            while (n < 200) : (n += 1) {
                while (!queue.push(base + n)) std.atomic.spinLoopHint();
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, idx| {
        t.* = try std.Thread.spawn(.{}, Producer.run, .{ q, @as(u64, idx) * 1000 });
    }
    var seen: u64 = 0;
    var sum: u64 = 0;
    while (seen < 800) {
        if (q.pop()) |v| {
            seen += 1;
            sum += v;
        } else std.atomic.spinLoopHint();
    }
    for (threads) |t| t.join();
    var expected: u64 = 0;
    for (0..4) |idx| {
        for (0..200) |n| expected += @as(u64, idx) * 1000 + n;
    }
    try std.testing.expectEqual(expected, sum);
}

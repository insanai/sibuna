//! Caller-serialized bounded outbox. Overflow invalidates the affected topic until reset;
//! gap notices have reserved storage and always precede surviving queued data.
const std = @import("std");
const p = @import("console_protocol");
const s = p.subscriptions;
pub const Frame = struct {
    topic: p.Topic,
    epoch: u64,
    bytes: p.Bytes(s.record_bytes),
};
pub const Gap = struct { topic: p.Topic, epoch: u64, dropped: u64 };
pub const Item = union(enum) { frame: Frame, gap: Gap };

pub fn Queue(comptime capacity: usize) type {
    std.debug.assert(capacity > 0);
    return struct {
        const Self = @This();
        frames: [capacity]Frame = undefined,
        head: usize = 0,
        count: usize = 0,
        blocked: [s.topic_count]bool = @splat(false),
        gaps: [s.topic_count]?Gap = @splat(null),

        /// Returns the invalidated topic so its publisher can pause. Caller must never
        /// queue further data for that topic until a fresh subscription resets its epoch.
        pub fn offer(self: *Self, frame: Frame) ?p.Topic {
            if (self.blocked[@intFromEnum(frame.topic)]) return frame.topic;
            var invalidated: ?p.Topic = null;
            if (self.count == capacity) {
                const victim = &self.frames[self.head];
                const topic = victim.topic;
                const epoch = victim.epoch;
                invalidated = topic;
                self.invalidate(topic, epoch, 0);
            }
            if (self.blocked[@intFromEnum(frame.topic)]) {
                self.gaps[@intFromEnum(frame.topic)].?.dropped += 1;
                return invalidated;
            }
            self.frames[(self.head + self.count) % capacity] = frame;
            self.count += 1;
            return invalidated;
        }

        /// A ring gap and a queue overflow use the same resynchronization barrier.
        pub fn invalidate(self: *Self, topic: p.Topic, epoch: u64, dropped: u64) void {
            const index = @intFromEnum(topic);
            const removed = self.remove(topic);
            self.blocked[index] = true;
            self.gaps[index] = .{ .topic = topic, .epoch = epoch, .dropped = dropped + removed };
        }

        pub fn reset(self: *Self, topic: p.Topic) void {
            _ = self.remove(topic);
            self.blocked[@intFromEnum(topic)] = false;
            self.gaps[@intFromEnum(topic)] = null;
        }

        pub fn pop(self: *Self) ?Item {
            for (&self.gaps) |*entry| {
                if (entry.*) |gap| {
                    entry.* = null;
                    return .{ .gap = gap };
                }
            }
            if (self.count == 0) return null;
            const frame = self.frames[self.head];
            self.head = (self.head + 1) % capacity;
            self.count -= 1;
            return .{ .frame = frame };
        }

        // Compact in logical FIFO order, which also works when the physical ring wraps.
        fn remove(self: *Self, topic: p.Topic) usize {
            var kept: usize = 0;
            const previous = self.count;
            for (0..previous) |offset| {
                const index = (self.head + offset) % capacity;
                if (self.frames[index].topic == topic) continue;
                const destination = (self.head + kept) % capacity;
                if (destination != index) self.frames[destination] = self.frames[index];
                kept += 1;
            }
            self.count = kept;
            return previous - kept;
        }
    };
}

test "overflow emits a gap before other topics and never completes a broken snapshot" {
    const t = std.testing;
    var queue: Queue(3) = .{};
    const stats: Frame = .{ .topic = .stats, .epoch = 1, .bytes = try p.Bytes(2048).init("s") };
    const events: Frame = .{ .topic = .events, .epoch = 2, .bytes = try p.Bytes(2048).init("e") };
    try t.expectEqual(null, queue.offer(stats));
    try t.expectEqual(null, queue.offer(events));
    try t.expectEqual(null, queue.offer(stats));
    try t.expectEqual(p.Topic.stats, queue.offer(stats).?);
    try t.expectEqual(@as(u64, 3), queue.pop().?.gap.dropped);
    try t.expectEqual(p.Topic.events, queue.pop().?.frame.topic);
    try t.expectEqual(null, queue.pop());
    try t.expectEqual(p.Topic.stats, queue.offer(stats).?);
    queue.reset(.stats);
    try t.expectEqual(null, queue.offer(stats));
    try t.expectEqual(p.Topic.stats, queue.pop().?.frame.topic);
    for (0..9) |_| {
        try t.expectEqual(null, queue.offer(events));
        try t.expectEqual(null, queue.offer(stats));
        queue.reset(.events);
        try t.expectEqual(p.Topic.stats, queue.pop().?.frame.topic);
        try t.expectEqual(null, queue.pop());
    }
}

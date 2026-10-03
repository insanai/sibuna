//! Single-publisher topic journals. Publishing never waits for readers or allocates.
//! A contended publication still advances the sequence: consumers observe the missing
//! record as a gap and must obtain a new snapshot instead of applying later deltas.
const repeat = @import("text").repeat;
const std = @import("std");

pub fn Ring(comptime capacity: u32, comptime payload_bytes: u16, comptime Metadata: type) type {
    std.debug.assert(capacity > 0 and payload_bytes > 0);
    return struct {
        const Self = @This();
        pub const Record = Entry(payload_bytes, Metadata);
        pub const Read = union(enum) {
            record,
            empty,
            busy,
            gap: struct { dropped: u64, next: u64 },
        };
        mutex: std.Io.Mutex = .init,
        head: std.atomic.Value(u64) = .init(0),
        lost: std.atomic.Value(u64) = .init(0),
        // A separate initialized sequence array avoids touching every payload at startup.
        sequences: [capacity]u64 = @splat(0),
        records: [capacity]Record = undefined,

        pub fn watermark(self: *const Self) u64 {
            return self.head.load(.acquire);
        }

        /// The composing hub owns the sole publisher. Sequence exhaustion ends that epoch.
        pub fn publish(
            self: *Self,
            io: std.Io,
            metadata: Metadata,
            payload: []const u8,
        ) error{ TooLarge, SequenceExhausted }!bool {
            if (payload.len > payload_bytes) return error.TooLarge;
            const previous = self.head.load(.monotonic);
            if (previous == std.math.maxInt(u64)) return error.SequenceExhausted;
            const sequence = previous + 1;
            if (!self.mutex.tryLock()) {
                _ = self.lost.fetchAdd(1, .monotonic);
                self.head.store(sequence, .release);
                return false;
            }
            defer self.mutex.unlock(io);
            const index: usize = @intCast(sequence % capacity);
            self.records[index].metadata = metadata;
            self.records[index].len = @intCast(payload.len);
            @memcpy(self.records[index].bytes[0..payload.len], payload);
            self.sequences[index] = sequence;
            self.head.store(sequence, .release);
            return true;
        }

        /// Copies into caller-owned memory; no borrowed ring storage escapes the lock.
        pub fn read(self: *Self, io: std.Io, sequence: u64, output: *Record) Read {
            std.debug.assert(sequence > 0);
            if (!self.mutex.tryLock()) return .busy;
            defer self.mutex.unlock(io);
            const head = self.head.load(.acquire);
            if (sequence > head) return .empty;
            const oldest = head -| capacity + 1;
            if (sequence < oldest) return .{ .gap = .{
                .dropped = oldest - sequence,
                .next = oldest,
            } };
            const index: usize = @intCast(sequence % capacity);
            if (self.sequences[index] != sequence) return .{ .gap = .{
                .dropped = 1,
                .next = sequence + 1,
            } };
            output.* = self.records[index];
            return .record;
        }
    };
}

test "topic overwrite and contention report exact gaps without borrowing payload storage" {
    const T = Ring(4, 16, u8);
    var ring: T = .{};
    var record: T.Record = undefined;
    const t = std.testing;
    try t.expect(ring.read(t.io, 1, &record) == .empty);
    for (0..6) |_| try t.expect(try ring.publish(t.io, 7, "old"));
    const gap = ring.read(t.io, 1, &record).gap;
    try t.expectEqual(@as(u64, 2), gap.dropped);
    try t.expectEqual(@as(u64, 3), gap.next);
    try t.expect(ring.read(t.io, 3, &record) == .record);
    try t.expectEqualStrings("old", record.payload());
    try t.expect(try ring.publish(t.io, 8, "new"));
    try t.expectEqualStrings("old", record.payload());
    try t.expect(ring.mutex.tryLock());
    try t.expect(!try ring.publish(t.io, 9, "lost"));
    try t.expect(ring.read(t.io, 8, &record) == .busy);
    ring.mutex.unlock(t.io);
    try t.expectEqual(@as(u64, 1), ring.read(t.io, 8, &record).gap.dropped);
    try t.expectEqual(@as(u64, 1), ring.lost.load(.monotonic));
    try t.expectError(error.TooLarge, ring.publish(t.io, 0, &repeat("a", 17)));
    try t.expectEqual(@as(u64, 8), ring.watermark());
}

fn Entry(comptime size: u16, comptime Metadata: type) type {
    return struct {
        metadata: Metadata,
        len: u16,
        bytes: [size]u8,

        pub fn payload(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

//! Bounded connection leases. Reaping interrupts I/O on the client socket and on the origin
//! socket of the exchange in flight; only the owning worker releases a slot.
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const core = @import("core");

/// Registry of open connections for the idle reaper. Each slot pairs a
/// socket with its last-activity time under a small lock; the reaper
/// shuts a stale socket down while holding that lock, and a connection
/// unregisters under the same lock before it closes, so a reused
/// descriptor can never be shut down by mistake.
pub const IdleTable = struct {
    pub const capacity = 8192;

    const Slot = struct {
        lock: core.Lock = .{},
        active: bool = false,
        stream: Io.net.Stream = undefined,
        activity: net.duplex.Activity = .{},
    };

    slots: [capacity]Slot = @as([capacity]Slot, @splat(.{})),
    cursor: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn register(self: *IdleTable, io: Io, stream: Io.net.Stream, now_ms: u64) ?u32 {
        const start = self.cursor.fetchAdd(1, .monotonic) % capacity;
        var probe: u32 = 0;
        while (probe < capacity) : (probe += 1) {
            const idx = (start + probe) % capacity;
            const slot = &self.slots[idx];
            slot.lock.lock(io);
            defer slot.lock.unlock(io);
            if (!slot.active) {
                slot.active = true;
                slot.stream = stream;
                slot.activity.at_ms.store(now_ms, .monotonic);
                slot.activity.timeout_ms.store(0, .monotonic);
                slot.activity.deadline_ms.store(0, .monotonic);
                slot.activity.detachPeer(io);
                return idx;
            }
        }
        return null;
    }

    pub fn touch(self: *IdleTable, io: Io, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        slot.lock.lock(io);
        defer slot.lock.unlock(io);
        slot.activity.at_ms.store(now_ms, .monotonic);
    }

    pub fn unregister(self: *IdleTable, io: Io, idx: u32) void {
        const slot = &self.slots[idx];
        slot.lock.lock(io);
        defer slot.lock.unlock(io);
        slot.active = false;
    }

    /// Valid only between register and unregister; the caller owns that connection lease.
    pub fn activity(self: *IdleTable, idx: u32) *net.duplex.Activity {
        std.debug.assert(idx < capacity);
        return &self.slots[idx].activity;
    }

    pub fn shutdown(self: *IdleTable, io: Io) void {
        for (&self.slots) |*slot| {
            slot.lock.lock(io);
            defer slot.lock.unlock(io);
            if (slot.active) net.interrupt(io, slot.stream);
        }
    }

    /// Shuts down every connection idle longer than `timeout_ms`, together with the origin
    /// socket its exchange holds; the blocked worker then sees end-of-stream on whichever
    /// side it waits for and releases the thread and the connection slot.
    pub fn reap(self: *IdleTable, io: Io, now_ms: u64, timeout_ms: u64) u32 {
        var reaped: u32 = 0;
        for (&self.slots) |*slot| {
            slot.lock.lock(io);
            defer slot.lock.unlock(io);
            if (slot.active and slot.activity.expired(now_ms, timeout_ms)) {
                net.interrupt(io, slot.stream);
                slot.activity.shutdownPeer(io);
                // Keep ownership until unregister; an old worker must not clear a reused slot.
                reaped += 1;
            }
        }
        return reaped;
    }
};

test "reaped idle slots remain owned until the original connection unregisters" {
    const io = std.testing.io;
    const table = try std.testing.allocator.create(IdleTable);
    defer std.testing.allocator.destroy(table);
    table.* = .{};
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const stream = try listener.accept(io);
    defer stream.close(io);
    const old = table.register(io, stream, 0).?;
    try std.testing.expectEqual(@as(u32, 0), table.reap(io, 200, 0));
    table.slots[old].activity.timeout_ms.store(100, .monotonic);
    try std.testing.expectEqual(@as(u32, 1), table.reap(io, 200, 0));
    table.cursor.store(old, .monotonic);
    // The same socket is sufficient to check registry ownership; neither registration closes it.
    const fresh = table.register(io, stream, 200).?;
    try std.testing.expect(old != fresh);
    table.unregister(io, old);
    try std.testing.expect(table.slots[fresh].active);
    table.unregister(io, fresh);
}

test "an absolute inspection deadline expires despite progress and resets on reuse" {
    const io = std.testing.io;
    const t = std.testing;
    const table = try t.allocator.create(IdleTable);
    defer t.allocator.destroy(table);
    table.* = .{};
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const stream = try listener.accept(io);
    defer stream.close(io);
    const index = table.register(io, stream, 0).?;
    const activity = table.activity(index);
    activity.deadline_ms.store(100, .monotonic);
    table.touch(io, index, 99);
    try t.expectEqual(@as(u32, 0), table.reap(io, 99, 0));
    try t.expectEqual(@as(u32, 1), table.reap(io, 100, 0));
    activity.deadline_ms.store(0, .monotonic);
    try t.expectEqual(@as(u32, 0), table.reap(io, 101, 0));
    // A new connection must not inherit the previous borrower's deadline.
    activity.deadline_ms.store(100, .monotonic);
    table.unregister(io, index);
    table.cursor.store(index, .monotonic);
    try t.expectEqual(index, table.register(io, stream, 200).?);
    try t.expectEqual(@as(u64, 0), table.activity(index).deadline_ms.load(.monotonic));
    table.unregister(io, index);
}

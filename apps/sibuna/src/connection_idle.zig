//! Bounded connection leases. Reaping interrupts I/O on the client socket and on the origin
//! socket of the exchange in flight; only the owning worker releases a slot.
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const store = @import("store");

/// Registry of open connections for the idle reaper. Each slot pairs a
/// socket with its last-activity time under a tiny spinlock; the reaper
/// shuts a stale socket down while holding that lock, and a connection
/// unregisters under the same lock before it closes, so a reused
/// descriptor can never be shut down by mistake.
pub const IdleTable = struct {
    pub const capacity = 8192;

    const Slot = struct {
        lock: store.rate_limiter.SpinLock = .{},
        active: bool = false,
        stream: Io.net.Stream = undefined,
        activity: net.duplex.Activity = .{},
    };

    slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
    cursor: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn register(self: *IdleTable, stream: Io.net.Stream, now_ms: u64) ?u32 {
        const start = self.cursor.fetchAdd(1, .monotonic) % capacity;
        var probe: u32 = 0;
        while (probe < capacity) : (probe += 1) {
            const idx = (start + probe) % capacity;
            const slot = &self.slots[idx];
            slot.lock.lock();
            defer slot.lock.unlock();
            if (!slot.active) {
                slot.active = true;
                slot.stream = stream;
                slot.activity.at_ms.store(now_ms, .monotonic);
                slot.activity.timeout_ms.store(0, .monotonic);
                slot.activity.detachPeer();
                return idx;
            }
        }
        return null;
    }

    pub fn touch(self: *IdleTable, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        slot.lock.lock();
        defer slot.lock.unlock();
        slot.activity.at_ms.store(now_ms, .monotonic);
    }

    pub fn unregister(self: *IdleTable, idx: u32) void {
        const slot = &self.slots[idx];
        slot.lock.lock();
        defer slot.lock.unlock();
        slot.active = false;
    }

    /// Valid only between register and unregister; the caller owns that connection lease.
    pub fn activity(self: *IdleTable, idx: u32) *net.duplex.Activity {
        std.debug.assert(idx < capacity);
        return &self.slots[idx].activity;
    }

    pub fn shutdown(self: *IdleTable, io: Io) void {
        for (&self.slots) |*slot| {
            slot.lock.lock();
            defer slot.lock.unlock();
            if (slot.active) slot.stream.shutdown(io, .both) catch {};
        }
    }

    /// Shuts down every connection idle longer than `timeout_ms`, together with the origin
    /// socket its exchange holds; the blocked worker then sees end-of-stream on whichever
    /// side it waits for and releases the thread and the connection slot.
    pub fn reap(self: *IdleTable, io: Io, now_ms: u64, timeout_ms: u64) u32 {
        var reaped: u32 = 0;
        for (&self.slots) |*slot| {
            slot.lock.lock();
            defer slot.lock.unlock();
            const override = slot.activity.timeout_ms.load(.monotonic);
            const timeout = if (override == 0) timeout_ms else override;
            if (slot.active and timeout != 0 and
                now_ms -| slot.activity.at_ms.load(.monotonic) > timeout)
            {
                slot.stream.shutdown(io, .both) catch {};
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
    const old = table.register(stream, 0).?;
    try std.testing.expectEqual(@as(u32, 0), table.reap(io, 200, 0));
    table.slots[old].activity.timeout_ms.store(100, .monotonic);
    try std.testing.expectEqual(@as(u32, 1), table.reap(io, 200, 0));
    table.cursor.store(old, .monotonic);
    // The same socket is sufficient to check registry ownership; neither registration closes it.
    const fresh = table.register(stream, 200).?;
    try std.testing.expect(old != fresh);
    table.unregister(old);
    try std.testing.expect(table.slots[fresh].active);
    table.unregister(fresh);
}

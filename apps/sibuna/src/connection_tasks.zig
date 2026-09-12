//! Fixed joinable task slots. A completed slot is joined before reuse; shutdown joins
//! every remaining thread after admission stops. No task retains borrowed state afterwards.
const std = @import("std");
const Io = std.Io;
pub const Pool = struct {
    pub const capacity = 8192;
    const Handler = *const fn (Io.net.Stream, Io, *anyopaque) void;
    const Slot = struct {
        thread: ?std.Thread = null,
        done: std.atomic.Value(bool) = .init(true),
        stream: Io.net.Stream = undefined,
        io: Io = undefined,
        context: *anyopaque = undefined,
        handler: Handler = undefined,
    };
    slots: [capacity]Slot = @splat(.{}),
    mutex: Io.Mutex = .init,

    /// The slot a new task takes: the lowest whose previous thread has finished. Kept
    /// separate from `launch` so the reuse policy can be tested without sockets or threads.
    ///
    /// Taking the lowest slot rather than advancing a cursor is what bounds memory. A
    /// finished thread still owns its stack until it is joined, and a cursor reaches a
    /// finished slot again only after a full lap of the table, so thousands of finished
    /// threads would sit unjoined and resident memory would grow with the number of
    /// connections served instead of the number open at once.
    fn freeSlot(self: *Pool) ?usize {
        for (&self.slots, 0..) |*slot, index| {
            if (slot.done.load(.acquire)) return index;
        }
        return null;
    }

    pub fn launch(
        self: *Pool,
        io: Io,
        stream: Io.net.Stream,
        context: *anyopaque,
        handler: Handler,
    ) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = &self.slots[self.freeSlot() orelse return error.Capacity];
        // The slot is free, so its thread has already run to completion; joining reclaims
        // that thread's stack before this connection allocates a new one.
        if (slot.thread) |thread| thread.join();
        slot.thread = null;
        slot.stream = stream;
        slot.io = io;
        slot.context = context;
        slot.handler = handler;
        slot.done.store(false, .release);
        errdefer slot.done.store(true, .release);
        slot.thread = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, run, .{slot});
    }

    fn run(slot: *Slot) void {
        slot.handler(slot.stream, slot.io, slot.context);
        slot.done.store(true, .release);
    }

    /// Caller has joined accept workers, so no launch can race with this traversal.
    pub fn join(self: *Pool) void {
        for (&self.slots) |*slot| {
            if (slot.thread) |thread| thread.join();
            slot.thread = null;
        }
    }
};

test "a task takes the lowest finished slot instead of walking the table" {
    // The reuse policy is what bounds memory: a finished thread keeps its stack until it is
    // joined, and a slot is joined only when it is taken again. Walking forward would defer
    // every join by a full lap, leaving thousands of finished threads resident at once.
    const pool = try std.testing.allocator.create(Pool);
    defer std.testing.allocator.destroy(pool);
    pool.* = .{};
    try std.testing.expectEqual(@as(?usize, 0), pool.freeSlot());
    pool.slots[0].done.store(false, .release);
    try std.testing.expectEqual(@as(?usize, 1), pool.freeSlot());
    // Once the first task finishes it is chosen again, so its thread is joined promptly
    // rather than after the table wraps.
    pool.slots[1].done.store(false, .release);
    pool.slots[0].done.store(true, .release);
    try std.testing.expectEqual(@as(?usize, 0), pool.freeSlot());
    // A full table reports exhaustion so the caller answers 503 instead of overcommitting.
    for (&pool.slots) |*slot| slot.done.store(false, .release);
    try std.testing.expectEqual(@as(?usize, null), pool.freeSlot());
}

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
    cursor: usize = 0,

    pub fn launch(
        self: *Pool,
        io: Io,
        stream: Io.net.Stream,
        context: *anyopaque,
        handler: Handler,
    ) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        for (0..capacity) |offset| {
            const index = (self.cursor + offset) % capacity;
            const slot = &self.slots[index];
            if (!slot.done.load(.acquire)) continue;
            if (slot.thread) |thread| thread.join();
            slot.thread = null;
            slot.stream = stream;
            slot.io = io;
            slot.context = context;
            slot.handler = handler;
            slot.done.store(false, .release);
            errdefer slot.done.store(true, .release);
            slot.thread = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, run, .{slot});
            self.cursor = (index + 1) % capacity;
            return;
        }
        return error.Capacity;
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

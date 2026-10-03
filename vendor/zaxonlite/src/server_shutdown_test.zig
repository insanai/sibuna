//! Deterministic host waits: no ticker exists in this fixture.
const std = @import("std");
const Io = std.Io;
const Node = @import("node.zig").Node;
const deadlines = @import("net_deadline.zig");
const waits = @import("server_waiters.zig");

pub fn check(comptime Server: type, comptime api: anytype) !void {
    try checkShutdownGrace(Server, api.shutdown);
    try checkConnectionInterruption(Server, api.close);
    const Harness = struct {
        server: *Server,
        mode: enum { writer, frontier, applied, pending, fence },
        result: ?anyerror = null,
        done: Io.Event = .unset,

        fn never(_: *Node, _: void) !@import("node.zig").ExecResult {
            return error.ExecutedAfterCancellation;
        }

        fn unsettled(_: *const Node) bool {
            return false;
        }

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            self.perform() catch |err| {
                self.result = err;
            };
        }

        fn perform(self: *@This()) !void {
            const server = self.server;
            switch (self.mode) {
                .writer => _ = try api.write(server, never, {}),
                .frontier => {
                    server.mutex.lockUncancelable(server.io);
                    defer server.mutex.unlock(server.io);
                    try api.frontier(server, unsettled, 0);
                },
                .pending => try awaitPending(server),
                .fence => try awaitFence(server),
                .applied => {
                    var out: Io.Writer.Allocating = .init(std.testing.allocator);
                    defer out.deinit();
                    try api.wait(server, .{ .op = "wait", .applied = 999 }, &out.writer);
                    const unavailable = std.mem.indexOf(u8, out.written(), "unavailable");
                    try std.testing.expect(unavailable != null);
                },
            }
        }

        fn parked(self: *@This()) bool {
            const s = self.server;
            return switch (self.mode) {
                .writer => s.writer_queue_head != null,
                .frontier => s.frontier_waiters != 0,
                .applied => s.waiters.items.len != 0,
                .pending => s.write_waiter != null,
                .fence => s.fences.items.len != 0,
            };
        }
    };
    for ([_]bool{ false, true }) |failure| {
        for (std.enums.values(@FieldType(Harness, "mode"))) |mode| {
            try checkOne(Server, api, Harness, mode, failure);
        }
    }
}

fn checkConnectionInterruption(comptime Server: type, comptime close: anytype) !void {
    const io = std.testing.io;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);

    var server = Server{
        .gpa = std.testing.allocator,
        .io = io,
        .node = undefined,
        .options = .{ .directory = "", .node_id = 1 },
        .membership = undefined,
        .transport_configuration_id = 1,
        .held = undefined,
    };
    defer server.active_connections.deinit(std.testing.allocator);
    try server.active_connections.append(std.testing.allocator, .{
        .stream = accepted,
        .handshake_deadline_ms = 0,
    });
    server.connection_interrupting = true;

    const Closing = struct {
        server: *Server,
        stream: Io.net.Stream,
        started: Io.Event = .unset,
        done: Io.Event = .unset,

        fn run(self: *@This()) void {
            self.started.set(self.server.io);
            close(self.server, self.stream);
            self.done.set(self.server.io);
        }
    };
    var closing = Closing{ .server = &server, .stream = accepted };
    const thread = try std.Thread.spawn(.{}, Closing.run, .{&closing});
    const deadline = deadlines.after(io, 2000);
    while (!closing.started.isSet()) {
        if (deadlines.expired(io, deadline)) std.c._exit(1);
        closing.started.waitTimeout(io, .{ .deadline = deadline }) catch {};
    }
    io.sleep(.fromMilliseconds(100), .awake) catch {};
    try std.testing.expect(!closing.done.isSet());
    server.mutex.lockUncancelable(io);
    try std.testing.expectEqual(@as(usize, 1), server.active_connections.items.len);
    server.connection_interrupting = false;
    server.handler_cond.broadcast(io);
    server.mutex.unlock(io);
    while (!closing.done.isSet()) {
        if (deadlines.expired(io, deadline)) std.c._exit(1);
        closing.done.waitTimeout(io, .{ .deadline = deadline }) catch {};
    }
    thread.join();
    try std.testing.expectEqual(@as(usize, 0), server.active_connections.items.len);
}

fn checkOne(
    comptime Server: type,
    comptime api: anytype,
    comptime Harness: type,
    mode: @FieldType(Harness, "mode"),
    failure: bool,
) !void {
    const io = std.testing.io;
    var node: Node = undefined;
    var log: @typeInfo(@TypeOf(node.log)).pointer.child = undefined;
    node.log = &log;
    log.core.role = .leader;
    node.applied_slot = 0;
    node.fatal_storage_error = false;
    var server = Server{
        .gpa = std.testing.allocator,
        .io = io,
        .node = &node,
        .options = .{ .directory = "", .node_id = 1 },
        .membership = undefined,
        .transport_configuration_id = 1,
        .held = undefined,
        .writer_gate_busy = true,
    };
    defer server.waiters.deinit(std.testing.allocator);
    defer server.fences.deinit(std.testing.allocator);
    var worker = Harness{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Harness.run, .{&worker});
    // Checking registration with the owning mutex proves the waiter has
    // released that mutex in its condition wait; no scheduling guess is needed.
    const end = deadlines.after(io, 2000);
    while (true) {
        server.mutex.lockUncancelable(io);
        if (worker.parked()) break;
        server.mutex.unlock(io);
        if (deadlines.expired(io, end)) std.c._exit(1);
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    if (failure) {
        server.failed = true;
        api.fail(&server);
    } else {
        server.shutdown_flag.store(true, .release);
        api.wake(&server);
        // Exercise a granted ticket waking concurrently with shutdown.
        if (mode == .writer) api.release(&server);
    }
    server.mutex.unlock(io);
    while (!worker.done.isSet()) {
        if (deadlines.expired(io, end)) std.c._exit(1);
        worker.done.waitTimeout(io, .{ .deadline = end }) catch {};
    }
    thread.join();
    if (mode == .applied) {
        try std.testing.expectEqual(@as(?anyerror, null), worker.result);
    } else {
        const expected = if (mode == .pending) error.Ambiguous else error.Unavailable;
        try std.testing.expectEqual(@as(?anyerror, expected), worker.result);
    }
    try expectDrained(&server);
    try std.testing.expectEqual(@as(u64, 0), server.tick_count);
    if (failure) {
        try std.testing.expectEqual(error.TestHostFailure, server.first_failure.?);
        try std.testing.expect(node.storageFailed());
        try std.testing.expect(server.fatal_shutdown_requested);
    }
}

fn expectDrained(server: anytype) !void {
    try std.testing.expect(server.write_waiter == null);
    try std.testing.expectEqual(@as(usize, 0), server.fences.items.len);
    try std.testing.expect(server.writer_queue_head == null);
    try std.testing.expect(server.writer_queue_tail == null);
    try std.testing.expectEqual(@as(u32, 0), server.frontier_waiters);
    try std.testing.expectEqual(@as(usize, 0), server.waiters.items.len);
}

fn awaitPending(server: anytype) !void {
    server.mutex.lockUncancelable(server.io);
    defer server.mutex.unlock(server.io);
    var waiter = waits.WriteWaiter{ .slot = 1, .batch_id = 1 };
    server.write_waiter = &waiter;
    defer server.write_waiter = null;
    try waiter.awaitOutcome(server, 0, 10_000);
}

fn awaitFence(server: anytype) !void {
    server.mutex.lockUncancelable(server.io);
    defer server.mutex.unlock(server.io);
    var fence = waits.FenceWaiter{
        .id = 1,
        .ballot = .{ .round = 1, .priority = 1, .node = 1 },
        .fence_slot = 1,
        .needed = 2,
    };
    try server.fences.append(server.gpa, &fence);
    defer server.fences.clearRetainingCapacity();
    try fence.awaitQuorum(server, 0, 10_000);
}

/// A slow scheduler and a spurious wakeup must not extend the RPC grace period.
/// Virtual time keeps this regression independent of the host's scheduling load.
const GraceClock = struct {
    elapsed: i96 = 0,
    sleeps: usize = 0,
    waits: usize = 0,

    fn now(context: ?*anyopaque, _: Io.Clock) Io.Timestamp {
        const self: *GraceClock = @ptrCast(@alignCast(context.?));
        return .{ .nanoseconds = self.elapsed };
    }

    fn sleep(context: ?*anyopaque, _: Io.Timeout) Io.Cancelable!void {
        const self: *GraceClock = @ptrCast(@alignCast(context.?));
        self.sleeps += 1;
        self.elapsed += 10 * std.time.ns_per_ms;
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, timeout: Io.Timeout) Io.Cancelable!void {
        const self: *GraceClock = @ptrCast(@alignCast(context.?));
        // Every retry must retain the same absolute deadline, including after
        // the first, deliberately spurious wakeup.
        std.debug.assert(timeout == .deadline);
        std.debug.assert(timeout.deadline.clock == .awake);
        std.debug.assert(timeout.deadline.raw.nanoseconds == 250 * std.time.ns_per_ms);
        self.waits += 1;
        if (self.waits > 1) self.elapsed = 300 * std.time.ns_per_ms;
    }
};

fn checkShutdownGrace(comptime Server: type, comptime shutdown: anytype) !void {
    var vtable = std.testing.io.vtable.*;
    vtable.now = GraceClock.now;
    vtable.sleep = GraceClock.sleep;
    vtable.futexWait = GraceClock.wait;
    for (0..4) |mode| {
        var clock = GraceClock{};
        var server = Server{
            .gpa = std.testing.allocator,
            .io = .{ .vtable = &vtable, .userdata = &clock },
            .node = undefined,
            .options = .{ .directory = "", .node_id = 1 },
            .membership = undefined,
            .transport_configuration_id = 1,
            .held = undefined,
            .shutdown_flag = .init(true),
            .failed = mode == 3,
            .stop_response_requested = mode != 0,
            .stop_response_sent = if (mode == 2) .is_set else .unset,
        };
        shutdown(&server);
        try std.testing.expectEqual(@as(usize, 0), clock.sleeps);
        try std.testing.expectEqual(@as(usize, if (mode == 1) 2 else 0), clock.waits);
        try std.testing.expect(clock.elapsed <= 300 * std.time.ns_per_ms);
    }
}

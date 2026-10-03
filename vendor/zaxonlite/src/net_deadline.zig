//! Monotonic connection deadlines and scoped cancellation of blocking TLS I/O.
const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const macos = @import("net_connect_macos.zig");

pub fn after(io: Io, milliseconds: u64) Io.Clock.Timestamp {
    return .{
        .clock = .awake,
        .raw = .{ .nanoseconds = Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds +
            @as(i96, milliseconds) * std.time.ns_per_ms },
    };
}

pub fn expired(io: Io, deadline: Io.Clock.Timestamp) bool {
    std.debug.assert(deadline.clock == .awake);
    return Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >= deadline.raw.nanoseconds;
}

pub fn budget(io: Io, milliseconds: ?u64, outer: ?Io.Clock.Timestamp) ?Io.Clock.Timestamp {
    const local = after(io, milliseconds orelse return outer);
    const end = outer orelse return local;
    std.debug.assert(end.clock == .awake);
    return if (local.raw.nanoseconds < end.raw.nanoseconds) local else end;
}

pub fn connectIp(io: Io, address: Io.net.IpAddress, deadline: ?Io.Clock.Timestamp) !Io.net.Stream {
    return connectUntil(io, dialIp, .{ io, address }, deadline);
}

fn dialIp(io: Io, address: Io.net.IpAddress) anyerror!Io.net.Stream {
    if (builtin.os.tag == .macos) return macos.connectIp(io, address);
    return address.connect(io, .{ .mode = .stream });
}

pub fn connectUnix(io: Io, path: []const u8, deadline: ?Io.Clock.Timestamp) !Io.net.Stream {
    const address = try Io.net.UnixAddress.init(path);
    return connectUntil(io, dialUnix, .{ io, &address }, deadline);
}

fn dialUnix(io: Io, address: *const Io.net.UnixAddress) anyerror!Io.net.Stream {
    if (builtin.os.tag == .macos) return macos.connectUnix(io, address);
    return address.connect(io);
}

/// Zig 0.16 Threaded panics on TCP ConnectOptions.timeout; Unix connect has
/// no timeout option. Race the cancelable operation with a monotonic deadline.
/// Drain both results: connect may succeed concurrently with expiry.
fn connectUntil(
    io: Io,
    comptime dial: anytype,
    args: anytype,
    deadline: ?Io.Clock.Timestamp,
) !Io.net.Stream {
    const end = deadline orelse return @call(.auto, dial, args);
    if (expired(io, end)) return error.Timeout;
    const Result = union(enum) {
        connected: @typeInfo(@TypeOf(dial)).@"fn".return_type.?,
        elapsed: Io.Cancelable!void,
    };
    var buffer: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &buffer);
    defer while (select.cancel()) |result| {
        switch (result) {
            .connected => |connection| if (connection) |stream| stream.close(io) else |_| {},
            .elapsed => {},
        }
    };
    try select.concurrent(.connected, dial, args);
    try select.concurrent(.elapsed, Io.Clock.Timestamp.wait, .{ end, io });
    switch (try select.await()) {
        .connected => |connection| {
            const stream = try connection;
            if (expired(io, end)) {
                stream.close(io);
                return error.Timeout;
            }
            return stream;
        },
        .elapsed => |result| {
            try result;
            return error.Timeout;
        },
    }
}

/// Must stay at a stable address from start through finish. Only shuts down a
/// borrowed socket; its owner joins the watchdog before closing or reusing it.
pub const SocketWatch = struct {
    io: Io,
    stream: Io.net.Stream,
    deadline: ?Io.Clock.Timestamp,
    mutex: Io.Mutex = .init,
    done: Io.Event = .unset,
    completed: bool = false,
    timed_out: bool = false,
    thread: ?std.Thread = null,

    pub fn start(self: *SocketWatch) !void {
        if (self.deadline) |end| {
            if (expired(self.io, end)) return error.Timeout;
            self.thread = try std.Thread.spawn(.{}, run, .{self});
        }
    }

    /// Idempotent; true means this operation lost the race with its deadline.
    pub fn finish(self: *SocketWatch) bool {
        self.mutex.lockUncancelable(self.io);
        if (!self.completed) {
            if (self.deadline) |end| {
                if (expired(self.io, end)) self.expireLocked();
            }
            self.completed = true;
        }
        self.mutex.unlock(self.io);
        self.done.set(self.io);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        return self.timed_out;
    }

    fn expireLocked(self: *SocketWatch) void {
        self.timed_out = true;
        self.stream.shutdown(self.io, .both) catch {};
    }

    fn run(self: *SocketWatch) void {
        const end = self.deadline.?;
        while (true) {
            // Event.waitTimeout may wake spuriously. Only the clock establishes expiry.
            self.done.waitTimeout(self.io, .{ .deadline = end }) catch {};
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.completed) return;
            if (expired(self.io, end)) {
                self.expireLocked();
                return;
            }
        }
    }
};

test "connection deadline cancels and joins an operation blocked before socket registration" {
    const Dial = struct {
        fn run(io: Io, finished: *Io.Event) Io.Cancelable!Io.net.Stream {
            defer finished.set(io);
            var event: Io.Event = .unset;
            try event.wait(io);
            unreachable;
        }
    };
    const io = std.testing.io;
    var finished: Io.Event = .unset;
    try std.testing.expectError(error.Timeout, connectUntil(
        io,
        Dial.run,
        .{ io, &finished },
        after(io, 25),
    ));
    try std.testing.expect(finished.isSet());
}

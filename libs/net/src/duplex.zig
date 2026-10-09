//! Bounded byte relay after an HTTP upgrade. One existing connection worker services both
//! directions; no extra threads, allocations or unbounded output queues are introduced.
const std = @import("std");
const Io = std.Io;
const windows = @import("builtin").os.tag == .windows;
const posix = if (windows) @import("socket").windows else std.posix;
const core = @import("core");
const system = @import("socket_system.zig").system;
pub const Error = error{ ConnectionFailed, IdleTimeout };
pub const Endpoint = struct { stream: Io.net.Stream, reader: *Io.Reader };
/// Liveness of one client connection as the idle reaper sees it. The stamp advances whenever
/// bytes move in either direction of the exchange in flight, so the deadline measures
/// silence rather than response length, and the origin socket of that exchange is attached
/// so a stall is cut on both sides and the connection slot comes back.
pub const Activity = struct {
    at_ms: std.atomic.Value(u64) = .init(0),
    /// Sticky until the connection owner unregisters; socket EOF is not a cancellation signal.
    cancelled: std.atomic.Value(bool) = .init(false),
    /// Zero uses the HTTP owner's default; an upgrade sets its own idle bound.
    timeout_ms: std.atomic.Value(u64) = .init(0),
    /// Absolute inspection deadline; progress never extends a scarce workspace lease.
    deadline_ms: std.atomic.Value(u64) = .init(0),
    /// Orders attach, detach and the reaper's shutdown: the owner detaches before it closes
    /// or pools the socket, so the reaper never shuts down a reused descriptor.
    peer_lock: core.Lock = .{},
    peer: ?Io.net.Stream = null,

    pub fn expired(self: *const Activity, now_ms: u64, default_timeout_ms: u64) bool {
        const deadline = self.deadline_ms.load(.monotonic);
        if (deadline != 0 and now_ms >= deadline) return true;
        const override = self.timeout_ms.load(.monotonic);
        const timeout = if (override == 0) default_timeout_ms else override;
        return timeout != 0 and now_ms -| self.at_ms.load(.monotonic) > timeout;
    }

    pub fn cancel(self: *Activity) void {
        self.cancelled.store(true, .release);
    }

    pub fn touch(self: *Activity, io: Io) void {
        self.at_ms.store(nowMs(io), .monotonic);
    }

    pub fn attachPeer(self: *Activity, io: Io, stream: Io.net.Stream) void {
        self.peer_lock.lock(io);
        defer self.peer_lock.unlock(io);
        self.peer = stream;
    }

    pub fn detachPeer(self: *Activity, io: Io) void {
        self.peer_lock.lock(io);
        defer self.peer_lock.unlock(io);
        self.peer = null;
    }

    /// Interrupts the attached origin socket; the owner still closes it.
    pub fn shutdownPeer(self: *Activity, io: Io) void {
        self.peer_lock.lock(io);
        defer self.peer_lock.unlock(io);
        if (self.peer) |stream| @import("socket").interrupt(io, stream);
    }
};
pub const Options = struct {
    idle_timeout_seconds: u32 = 300,
    /// The owner keeps this atomic alive until the relay returns, alongside both sockets.
    activity: ?*Activity = null,
};
const capacity = 16 * 1024;

const Direction = struct {
    prefix: []const u8,
    bytes: [capacity]u8 = undefined,
    begin: usize = 0,
    end: usize = 0,
    eof: bool = false,
    closed: bool = false,

    fn pending(self: *const Direction) []const u8 {
        return self.bytes[self.begin..self.end];
    }

    fn prefill(self: *Direction) void {
        if (self.begin != self.end or self.prefix.len == 0) return;
        const count = @min(capacity, self.prefix.len);
        @memcpy(self.bytes[0..count], self.prefix[0..count]);
        self.prefix = self.prefix[count..];
        self.begin = 0;
        self.end = count;
    }

    fn receive(self: *Direction, fd: posix.socket_t) Error!bool {
        std.debug.assert(self.begin == self.end and self.prefix.len == 0 and !self.eof);
        const result = system.recv(fd, &self.bytes, capacity, posix.MSG.DONTWAIT);
        switch (posix.errno(result)) {
            .SUCCESS => {
                self.begin = 0;
                self.end = @intCast(result);
                self.eof = result == 0;
                return result > 0;
            },
            .AGAIN, .INTR => return false,
            else => return error.ConnectionFailed,
        }
    }

    fn send(self: *Direction, fd: posix.socket_t) Error!bool {
        const bytes = self.pending();
        std.debug.assert(bytes.len != 0);
        const result = system.send(
            fd,
            bytes.ptr,
            bytes.len,
            posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT,
        );
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.ConnectionFailed;
                self.begin += @intCast(result);
                return true;
            },
            .AGAIN, .INTR => return false,
            else => return error.ConnectionFailed,
        }
    }
};

/// Readers may already contain bytes after the upgrade head. Consume those exact prefixes
/// before reading the descriptors directly. Neither reader is used again by the caller.
pub fn relay(io: Io, endpoints: [2]Endpoint, options: Options) Error!void {
    var directions = [_]Direction{
        .{ .prefix = endpoints[0].reader.buffered() },
        .{ .prefix = endpoints[1].reader.buffered() },
    };
    defer {
        for (endpoints) |endpoint|
            @import("socket").shutdown(io, endpoint.stream, .both) catch {};
    }
    var last_activity = nowMs(io);
    if (options.activity) |activity| {
        activity.at_ms.store(last_activity, .monotonic);
        activity.timeout_ms.store(if (options.idle_timeout_seconds == 0)
            std.math.maxInt(u64)
        else
            @as(u64, options.idle_timeout_seconds) * 1000, .monotonic);
    }
    while (true) {
        if (options.activity) |activity| {
            if (activity.cancelled.load(.acquire)) return error.ConnectionFailed;
        }
        var descriptors: [2]posix.pollfd = undefined;
        for (&directions, 0..) |*direction, index| {
            direction.prefill();
            if (direction.eof and direction.pending().len == 0 and !direction.closed) {
                @import("socket").shutdown(io, endpoints[1 - index].stream, .send) catch {};
                direction.closed = true;
            }
        }
        if (directions[0].closed and directions[1].closed) return;
        for (&descriptors, 0..) |*descriptor, index| {
            const events = interests(&directions[index], &directions[1 - index]);
            // A half-closed descriptor with no pending work reports HUP continuously.
            // Disable it until it has bytes to write, avoiding an idle busy loop.
            descriptor.* = .{
                .fd = if (events == 0)
                    (if (windows) posix.invalid_socket else -1)
                else
                    endpoints[index].stream.socket.handle,
                .events = events,
                .revents = 0,
            };
        }
        const result = system.poll(&descriptors, descriptors.len, 100);
        switch (posix.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ConnectionFailed,
        }
        const progressed = try transfer(&directions, &descriptors);
        const now = nowMs(io);
        if (progressed) {
            last_activity = now;
            if (options.activity) |activity| activity.at_ms.store(now, .monotonic);
        }
        if (options.idle_timeout_seconds != 0 and
            now -| last_activity >= @as(u64, options.idle_timeout_seconds) * 1000)
            return error.IdleTimeout;
    }
}

fn interests(incoming: *const Direction, outgoing: *const Direction) i16 {
    var events: i16 = 0;
    if (!incoming.eof and incoming.pending().len == 0) events |= posix.POLL.IN;
    if (outgoing.pending().len != 0) events |= posix.POLL.OUT;
    return events;
}

fn transfer(directions: *[2]Direction, descriptors: *const [2]posix.pollfd) Error!bool {
    var progressed = false;
    for (descriptors, 0..) |descriptor, index| {
        if (descriptor.revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0)
            return error.ConnectionFailed;
        const incoming = &directions[index];
        const outgoing = &directions[1 - index];
        if (descriptor.revents & posix.POLL.OUT != 0 and outgoing.pending().len != 0)
            progressed = (try outgoing.send(descriptor.fd)) or progressed;
        if (descriptor.revents & (posix.POLL.IN | posix.POLL.HUP) != 0 and
            !incoming.eof and incoming.pending().len == 0)
            progressed = (try incoming.receive(descriptor.fd)) or progressed;
    }
    return progressed;
}

pub fn nowMs(io: Io) u64 {
    return @intCast(@max(0, @divTrunc(Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms)));
}

test "prefetched upgrade bytes larger than one relay buffer remain ordered under backpressure" {
    var input: [capacity + 17]u8 = @splat(1);
    @memset(input[capacity..], 2);
    var direction: Direction = .{ .prefix = &input };
    direction.prefill();
    try std.testing.expectEqual(capacity, direction.pending().len);
    direction.begin = capacity - 3;
    direction.prefill();
    try std.testing.expectEqual(@as(usize, 3), direction.pending().len);
    try std.testing.expectEqual(@as(usize, 17), direction.prefix.len);
    direction.begin = direction.end;
    direction.prefill();
    try std.testing.expectEqual(@as(usize, 17), direction.pending().len);
    try std.testing.expect(std.mem.allEqual(u8, direction.pending(), 2));
}

const CancellationFixture = struct {
    streams: [2]Io.net.Stream,
    activity: Activity = .{},
    started: std.atomic.Value(bool) = .init(false),
    finished: std.atomic.Value(bool) = .init(false),
    result: ?Error = null,

    fn run(self: *@This()) void {
        var buffers: [2][16]u8 = undefined;
        var first = self.streams[0].reader(std.testing.io, &buffers[0]);
        var second = self.streams[1].reader(std.testing.io, &buffers[1]);
        self.started.store(true, .release);
        relay(std.testing.io, .{
            .{ .stream = self.streams[0], .reader = &first.interface },
            .{ .stream = self.streams[1], .reader = &second.interface },
        }, .{ .idle_timeout_seconds = 0, .activity = &self.activity }) catch |err| {
            self.result = err;
        };
        self.finished.store(true, .release);
    }
};

test "cancelled upgrade exits with idle timeout disabled while both peers stay open" {
    const t = std.testing;
    const io = t.io;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const first = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer first.close(io);
    const first_stream = try listener.accept(io);
    defer first_stream.close(io);
    const second = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer second.close(io);
    const second_stream = try listener.accept(io);
    defer second_stream.close(io);
    var fixture: CancellationFixture = .{ .streams = .{ first_stream, second_stream } };
    const worker = try std.Thread.spawn(.{}, CancellationFixture.run, .{&fixture});
    defer {
        fixture.activity.cancel();
        // Cleanup also interrupts sockets so a failing assertion can still join the worker.
        for (fixture.streams) |stream| @import("socket").interrupt(io, stream);
        worker.join();
    }
    while (!fixture.started.load(.acquire)) std.atomic.spinLoopHint();
    try Io.sleep(io, .fromMilliseconds(50), .awake);
    // Cancellation alone must end the relay; no socket is interrupted before this assertion.
    fixture.activity.cancel();
    const deadline = nowMs(io) + 3000;
    while (!fixture.finished.load(.acquire) and nowMs(io) < deadline)
        try Io.sleep(io, .fromMilliseconds(5), .awake);
    try t.expect(fixture.finished.load(.acquire));
    try t.expectEqual(error.ConnectionFailed, fixture.result.?);
}

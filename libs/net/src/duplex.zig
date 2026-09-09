//! Bounded byte relay after an HTTP upgrade. One existing connection worker services both
//! directions; no extra threads, allocations or unbounded output queues are introduced.
const std = @import("std");
const Io = std.Io;
const posix = std.posix;
pub const Error = error{ ConnectionFailed, IdleTimeout };
pub const Endpoint = struct { stream: Io.net.Stream, reader: *Io.Reader };
pub const Activity = struct {
    at_ms: std.atomic.Value(u64) = .init(0),
    /// Zero uses the HTTP owner's default; an upgrade sets its own idle bound.
    timeout_ms: std.atomic.Value(u64) = .init(0),
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
        const result = posix.system.recv(fd, &self.bytes, capacity, posix.MSG.DONTWAIT);
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
        const result = posix.system.send(
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
    defer for (endpoints) |endpoint| endpoint.stream.shutdown(io, .both) catch {};
    var last_activity = nowMs(io);
    if (options.activity) |activity| {
        activity.at_ms.store(last_activity, .monotonic);
        activity.timeout_ms.store(if (options.idle_timeout_seconds == 0)
            std.math.maxInt(u64)
        else
            @as(u64, options.idle_timeout_seconds) * 1000, .monotonic);
    }
    while (true) {
        var descriptors: [2]posix.pollfd = undefined;
        for (&directions, 0..) |*direction, index| {
            direction.prefill();
            if (direction.eof and direction.pending().len == 0 and !direction.closed) {
                endpoints[1 - index].stream.shutdown(io, .send) catch {};
                direction.closed = true;
            }
        }
        if (directions[0].closed and directions[1].closed) return;
        for (&descriptors, 0..) |*descriptor, index| {
            const events = interests(&directions[index], &directions[1 - index]);
            // A half-closed descriptor with no pending work reports HUP continuously.
            // Disable it until it has bytes to write, avoiding an idle busy loop.
            descriptor.* = .{
                .fd = if (events == 0) -1 else endpoints[index].stream.socket.handle,
                .events = events,
                .revents = 0,
            };
        }
        const result = posix.system.poll(&descriptors, descriptors.len, 100);
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

fn nowMs(io: Io) u64 {
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

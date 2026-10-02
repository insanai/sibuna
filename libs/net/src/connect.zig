//! Zig 0.16 Threaded panics for connect timeouts. Use a nonblocking POSIX connect
//! and a monotonic deadline, restoring blocking mode before handing the stream to Io.
//! The deadline variants also bound reads and writes with poll so a silent peer cannot
//! hold a probe thread past its budget.
const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const windows = @import("builtin").os.tag == .windows;
const windows_socket = @import("windows_socket.zig");
const Error = error{UpstreamUnreachable};

/// Windows Io owns AFD handles, so an overload drain must not call Winsock recv.
pub fn drainPending(stream: Io.net.Stream) void {
    var buffer: [4096]u8 = undefined;
    for (0..8) |_| {
        const count = windows_socket.receive(stream.socket.handle, &buffer, 1_000_000) catch
            return;
        if (count == 0) return;
    }
}

pub fn bounded(io: Io, address: Io.net.IpAddress) Error!Io.net.Stream {
    const deadline = Io.Clock.awake.now(io).nanoseconds + 5 * std.time.ns_per_s;
    return boundedDeadline(io, address, deadline);
}

fn wait(io: Io, fd: posix.socket_t) Error!void {
    const deadline = Io.Clock.awake.now(io).nanoseconds + 5 * std.time.ns_per_s;
    return waitUntil(io, fd, deadline);
}

fn waitUntil(io: Io, fd: posix.socket_t, deadline: i96) Error!void {
    var descriptor = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    while (Io.Clock.awake.now(io).nanoseconds < deadline) {
        const result = posix.system.poll(&descriptor, 1, 100);
        switch (posix.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.UpstreamUnreachable,
        }
        if (result == 0) continue;
        var failure: c_int = 0;
        var size: posix.socklen_t = @sizeOf(c_int);
        const status = posix.system.getsockopt(
            fd,
            posix.SOL.SOCKET,
            posix.SO.ERROR,
            @ptrCast(&failure),
            &size,
        );
        if (posix.errno(status) != .SUCCESS or failure != 0) return error.UpstreamUnreachable;
        return;
    }
    return error.UpstreamUnreachable;
}

/// Disables Nagle's algorithm on a connected stream. Sibuna already coalesces each message in
/// its writer and flushes only before it would wait (`proxy.step`), so a kernel hold-back
/// saves no packets and delays the next small write until the peer acknowledges the last,
/// up to its delayed-ACK timer (40 ms on Linux). Failure only leaves the default behaviour.
pub fn noDelay(stream: Io.net.Stream) void {
    if (windows) return windows_socket.noDelay(stream);
    const one: c_int = 1;
    const bytes = std.mem.asBytes(&one);
    const fd = stream.socket.handle;
    _ = posix.system.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, bytes, bytes.len);
}

/// `bounded` with an explicit absolute awake-clock deadline in nanoseconds.
pub fn boundedDeadline(io: Io, address: Io.net.IpAddress, deadline_ns: i96) Error!Io.net.Stream {
    if (windows) return windows_socket.connect(io, address, deadline_ns) catch
        return error.UpstreamUnreachable;
    const local: Io.net.IpAddress = switch (address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = local.bind(io, .{ .mode = .stream }) catch return error.UpstreamUnreachable;
    errdefer socket.close(io);
    const fd = socket.handle;
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    if (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, @as(usize, nonblock))) != .SUCCESS)
        return error.UpstreamUnreachable;
    var native: Io.Threaded.PosixAddress = undefined;
    const length = Io.Threaded.addressToPosix(&address, &native);
    switch (posix.errno(posix.system.connect(fd, &native.any, length))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitUntil(io, fd, deadline_ns),
        else => return error.UpstreamUnreachable,
    }
    if (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, @as(usize, 0))) != .SUCCESS)
        return error.UpstreamUnreachable;
    return .{ .socket = socket };
}

/// Writes all bytes, polling for writability so a stalled peer cannot block past the deadline.
pub fn writeBounded(io: Io, stream: Io.net.Stream, bytes: []const u8, deadline_ns: i96) !void {
    if (windows) return windows_socket.writeBounded(io, stream, bytes, deadline_ns);
    const fd = stream.socket.handle;
    var offset: usize = 0;
    while (offset < bytes.len) {
        try ready(io, fd, posix.POLL.OUT, deadline_ns);
        const written = posix.system.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(written)) {
            .SUCCESS => offset += @intCast(written),
            .INTR, .AGAIN => continue,
            else => return error.UpstreamUnreachable,
        }
    }
}

/// Reads until the peer closes, `out` is full, or the deadline passes; returns the count.
pub fn readBounded(io: Io, stream: Io.net.Stream, out: []u8, deadline_ns: i96) !usize {
    if (windows) return windows_socket.readBounded(io, stream, out, deadline_ns);
    const fd = stream.socket.handle;
    var length: usize = 0;
    while (length < out.len) {
        try ready(io, fd, posix.POLL.IN, deadline_ns);
        const count = posix.system.read(fd, out[length..].ptr, out.len - length);
        switch (posix.errno(count)) {
            .SUCCESS => {
                if (count == 0) return length;
                length += @intCast(count);
            },
            .INTR, .AGAIN => continue,
            else => return error.UpstreamUnreachable,
        }
    }
    return length;
}

fn ready(io: Io, fd: posix.socket_t, events: i16, deadline_ns: i96) Error!void {
    var descriptor = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    while (Io.Clock.awake.now(io).nanoseconds < deadline_ns) {
        const result = posix.system.poll(&descriptor, 1, 100);
        switch (posix.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.UpstreamUnreachable,
        }
        if (result != 0) return;
    }
    return error.UpstreamUnreachable;
}

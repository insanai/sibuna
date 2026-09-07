//! Zig 0.16 Threaded panics for connect timeouts. Use a nonblocking POSIX connect
//! and a monotonic deadline, restoring blocking mode before handing the stream to Io.
const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const Error = error{UpstreamUnreachable};

pub fn bounded(io: Io, address: Io.net.IpAddress) Error!Io.net.Stream {
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
        .INPROGRESS, .INTR => try wait(io, fd),
        else => return error.UpstreamUnreachable,
    }
    if (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, @as(usize, 0))) != .SUCCESS)
        return error.UpstreamUnreachable;
    return .{ .socket = socket };
}

fn wait(io: Io, fd: posix.socket_t) Error!void {
    const deadline = Io.Clock.awake.now(io).nanoseconds + 5 * std.time.ns_per_s;
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

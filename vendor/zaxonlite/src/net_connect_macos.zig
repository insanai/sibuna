//! Zig 0.16's blocking connect retries EINTR and panics on a subsequent EISCONN.
//! Issue one nonblocking connect, then observe completion through poll/SO_ERROR.
const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const c = std.c;

pub fn connectIp(io: Io, address: Io.net.IpAddress) !Io.net.Stream {
    var storage: Io.Threaded.PosixAddress = undefined;
    const length = Io.Threaded.addressToPosix(&address, &storage);
    var stream = try connect(io, &storage.any, length);
    errdefer stream.close(io);
    var local_length: posix.socklen_t = @sizeOf(@TypeOf(storage));
    while (true) switch (posix.errno(c.getsockname(
        stream.socket.handle,
        &storage.any,
        &local_length,
    ))) {
        .SUCCESS => break,
        .INTR => try io.checkCancel(),
        else => |err| return posix.unexpectedErrno(err),
    };
    stream.socket.address = Io.Threaded.addressFromPosix(&storage);
    return stream;
}

pub fn connectUnix(io: Io, address: *const Io.net.UnixAddress) !Io.net.Stream {
    var storage: posix.sockaddr.un = .{ .path = @splat(0) };
    std.debug.assert(address.path.len < storage.path.len);
    @memcpy(storage.path[0..address.path.len], address.path);
    const length: posix.socklen_t = @intCast(
        @offsetOf(posix.sockaddr.un, "path") + address.path.len + 1,
    );
    storage.len = @intCast(length);
    return connect(io, @ptrCast(&storage), length);
}

fn connect(io: Io, address: *const posix.sockaddr, length: posix.socklen_t) !Io.net.Stream {
    const fd = try openSocket(io, address.family);
    const stream: Io.net.Stream = .{ .socket = .{
        .handle = fd,
        .address = .{ .ip4 = .loopback(0) },
    } };
    errdefer stream.close(io);
    _ = try fcntl(io, fd, posix.F.SETFD, posix.FD_CLOEXEC);
    const original = try fcntl(io, fd, posix.F.GETFL, 0);
    const nonblocking = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    _ = try fcntl(io, fd, posix.F.SETFL, original | nonblocking);
    var socket = Socket{ .fd = fd, .address = address, .length = length };
    try complete(io, &socket);
    // The stream readers and TLS transport expect a blocking descriptor.
    _ = try fcntl(io, fd, posix.F.SETFL, original);
    return stream;
}

fn openSocket(io: Io, family: posix.sa_family_t) !posix.socket_t {
    while (true) {
        try io.checkCancel();
        const fd = c.socket(family, posix.SOCK.STREAM, 0);
        switch (posix.errno(fd)) {
            .SUCCESS => return fd,
            .INTR => continue,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .INVAL => return error.ProtocolUnsupportedBySystem,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            .PROTOTYPE => return error.SocketModeUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn fcntl(io: Io, fd: posix.fd_t, operation: c_int, value: usize) !usize {
    while (true) {
        try io.checkCancel();
        const result = c.fcntl(fd, operation, value);
        switch (posix.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

const Socket = struct {
    fd: posix.fd_t,
    address: *const posix.sockaddr,
    length: posix.socklen_t,

    fn start(self: *Socket) posix.E {
        return posix.errno(c.connect(self.fd, self.address, self.length));
    }

    fn ready(self: *Socket) !bool {
        var descriptor = posix.pollfd{ .fd = self.fd, .events = posix.POLL.OUT, .revents = 0 };
        const result = c.poll(@ptrCast(&descriptor), 1, 0);
        switch (posix.errno(result)) {
            .SUCCESS => return result != 0,
            .INTR => return false,
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn status(self: *Socket) !posix.E {
        var result: c_int = 0;
        var length: posix.socklen_t = @sizeOf(c_int);
        const rc = c.getsockopt(self.fd, posix.SOL.SOCKET, posix.SO.ERROR, &result, &length);
        switch (posix.errno(rc)) {
            .SUCCESS => return @fromBackingInt(@intCast(result)),
            .INTR => return .INPROGRESS,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
};

/// A socket interrupted during connect can finish in the kernel. Never reissue
/// connect: poll readiness and inspect SO_ERROR, keeping every wait cancelable.
fn complete(io: Io, socket: anytype) !void {
    try io.checkCancel();
    if (try connected(socket.start())) return;
    while (true) {
        try io.checkCancel();
        if (try socket.ready()) {
            if (try connected(try socket.status())) return;
        }
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

fn connected(result: posix.E) !bool {
    return switch (result) {
        .SUCCESS, .ISCONN => true,
        .INTR, .INPROGRESS, .ALREADY => false,
        .AGAIN => return error.WouldBlock,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .CONNABORTED => error.ConnectionAborted,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .TIMEDOUT => error.Timeout,
        .ACCES => error.AccessDenied,
        .PERM => error.PermissionDenied,
        .NETDOWN => error.NetworkDown,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .NOBUFS, .NOMEM => error.SystemResources,
        .LOOP => error.SymLinkLoop,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .ROFS => error.ReadOnlyFileSystem,
        else => posix.unexpectedErrno(result),
    };
}

test "interrupted connect waits for completion without dialing the socket twice" {
    const Fake = struct {
        calls: usize = 0,
        polls: usize = 0,
        completion: posix.E,

        fn start(self: *@This()) posix.E {
            self.calls += 1;
            return if (self.calls == 1) .INTR else .ISCONN;
        }
        fn ready(self: *@This()) !bool {
            self.polls += 1;
            return self.polls > 1; // One interrupted poll before the socket becomes writable.
        }
        fn status(self: *@This()) !posix.E {
            return self.completion;
        }
    };
    var success = Fake{ .completion = .SUCCESS };
    try complete(std.testing.io, &success);
    try std.testing.expectEqual(@as(usize, 1), success.calls);
    try std.testing.expectEqual(@as(usize, 2), success.polls);
    var refused = Fake{ .completion = .CONNREFUSED };
    try std.testing.expectError(error.ConnectionRefused, complete(std.testing.io, &refused));
    try std.testing.expectEqual(@as(usize, 1), refused.calls);
    try std.testing.expect(try connected(.ISCONN));
}

test "a pending nonblocking connect remains cancelable" {
    const Fake = struct {
        waiting: Io.Event = .unset,
        fn start(_: *@This()) posix.E {
            return .INPROGRESS;
        }
        fn ready(self: *@This()) !bool {
            self.waiting.set(std.testing.io);
            return false;
        }
        fn status(_: *@This()) !posix.E {
            unreachable;
        }
        fn run(self: *@This()) !void {
            try complete(std.testing.io, self);
        }
    };
    var socket = Fake{};
    var future = try std.testing.io.concurrent(Fake.run, .{&socket});
    socket.waiting.waitUncancelable(std.testing.io);
    try std.testing.expectError(error.Canceled, future.cancel(std.testing.io));
}

test "macOS IPv4 and IPv6 connections restore blocking close-on-exec streams" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const io = std.testing.io;
    for ([_][]const u8{ "127.0.0.1", "::1" }) |host| {
        const address = try Io.net.IpAddress.parse(host, 0);
        var server = try address.listen(io, .{});
        defer server.deinit(io);
        const stream = try connectIp(io, server.socket.address);
        defer stream.close(io);
        const peer = try server.accept(io);
        defer peer.close(io);
        const flags = try fcntl(io, stream.socket.handle, posix.F.GETFL, 0);
        const nonblocking = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        try std.testing.expectEqual(@as(usize, 0), flags & nonblocking);
        const descriptor_flags = try fcntl(io, stream.socket.handle, posix.F.GETFD, 0);
        try std.testing.expect(descriptor_flags & posix.FD_CLOEXEC != 0);
        try std.testing.expect(stream.socket.address.getPort() != 0);
    }
}

//! Native socket lifetime operations shared by the HTTP service and streaming relay.
//! No application, policy or database dependencies belong in this module.
const std = @import("std");
pub const windows = @import("windows.zig");
pub const stack = @import("stack.zig");

test {
    _ = stack;
}

/// OpenBSD TCP can return EINVAL after its protocol control block is gone,
/// even for a valid shutdown direction. Zig 0.17 treats EINVAL as a programmer
/// bug in Debug. Keep this native compatibility mapping here, preserving the
/// descriptor's ownership and cancellation; other platforms use the Io backend.
pub fn shutdown(io: std.Io, stream: std.Io.net.Stream, how: std.Io.net.ShutdownHow) std.Io.net.ShutdownError!void {
    if (@import("builtin").os.tag != .openbsd) return stream.shutdown(io, how);
    const direction: c_int = switch (how) {
        .recv => std.posix.SHUT.RD,
        .send => std.posix.SHUT.WR,
        .both => std.posix.SHUT.RDWR,
    };
    try io.checkCancel();
    while (true) {
        switch (std.posix.errno(std.c.shutdown(stream.socket.handle, direction))) {
            .SUCCESS => return,
            .INTR => try io.checkCancel(),
            .INVAL, .NOTCONN => return error.SocketUnconnected,
            .NOBUFS => return error.SystemResources,
            .CONNRESET => return error.ConnectionResetByPeer,
            .CONNABORTED => return error.ConnectionAborted,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

/// Interrupt I/O without closing or reusing a handle. The owning worker still closes
/// it; callers join that worker before releasing shared state. A normal Windows
/// shutdown leaves already pending reads blocked;
/// abortive disconnect completes them even when the remote peer never closes.
pub fn interrupt(io: std.Io, stream: std.Io.net.Stream) void {
    if (@import("builtin").os.tag == .windows) {
        windows.interrupt(stream) catch |err| {
            std.log.warn("SOCKET001: interrupt failed: {t}", .{err});
        };
        return;
    }
    shutdown(io, stream, .both) catch |err| switch (err) {
        error.SocketUnconnected => {},
        else => std.log.warn("SOCKET001: interrupt failed: {t}", .{err}),
    };
}

test "shutdown after bidirectional EOF remains a normal connection teardown" {
    const t = std.testing;
    const io = t.io;
    var listener = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const stream = try listener.accept(io);
    defer stream.close(io);
    try shutdown(io, client, .send);
    try shutdown(io, stream, .send);
    var bytes: [1]u8 = undefined;
    var reader = stream.reader(io, &.{});
    try t.expectEqual(@as(usize, 0), try reader.interface.readSliceShort(&bytes));
    var peer_reader = client.reader(io, &.{});
    try t.expectEqual(@as(usize, 0), try peer_reader.interface.readSliceShort(&bytes));
    for (0..2) |_| {
        shutdown(io, stream, .both) catch |err| switch (err) {
            error.SocketUnconnected => {},
            else => return err,
        };
    }
}

test "interrupt releases a pending stream read while its peer stays open" {
    const t = std.testing;
    const io = t.io;
    var listener = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const stream = try listener.accept(io);
    defer stream.close(io);
    const Pending = struct {
        stream: std.Io.net.Stream,
        entered: std.atomic.Value(bool) = .init(false),
        fn read(self: *@This()) void {
            var bytes: [1]u8 = undefined;
            var reader = self.stream.reader(std.testing.io, &.{});
            self.entered.store(true, .release);
            _ = reader.interface.readSliceShort(&bytes) catch return;
        }
    };
    var pending: Pending = .{ .stream = stream };
    const thread = try std.Thread.spawn(.{}, Pending.read, .{&pending});
    defer {
        interrupt(io, stream);
        thread.join();
    }
    while (!pending.entered.load(.acquire)) std.atomic.spinLoopHint();
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
}

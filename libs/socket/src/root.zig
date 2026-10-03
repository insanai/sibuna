//! Native socket lifetime operations shared by the HTTP service and streaming relay.
//! No application, policy or database dependencies belong in this module.
const std = @import("std");
pub const windows = @import("windows.zig");

/// Interrupt I/O without closing or reusing a handle. The owning worker still closes
/// it; callers join that worker before releasing shared state. A normal Windows shutdown leaves already pending reads blocked;
/// abortive disconnect completes them even when the remote peer never closes.
pub fn interrupt(io: std.Io, stream: std.Io.net.Stream) void {
    if (@import("builtin").os.tag == .windows) {
        windows.interrupt(stream) catch |err| {
            std.log.warn("SOCKET001: interrupt failed: {t}", .{err});
        };
        return;
    }
    stream.shutdown(io, .both) catch |err| switch (err) {
        error.SocketUnconnected => {},
        else => std.log.warn("SOCKET001: interrupt failed: {t}", .{err}),
    };
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

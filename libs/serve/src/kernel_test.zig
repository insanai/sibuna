const std = @import("std");
const Kernel = @import("kernel.zig").Kernel;
const Context = @import("context.zig").Context;
const t = std.testing;

fn handler(_: *anyopaque, context: *Context) Context.Error!void {
    try context.respond(.ok, "text/plain", "bounded service", &.{});
}

test "listener serves HTTP and joins an idle connection on shutdown" {
    var application: u8 = 0;
    const kernel = try Kernel.start(
        t.allocator,
        t.io,
        try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        &application,
        handler,
    );
    var owned = true;
    defer if (owned) kernel.stop();
    const address = kernel.listener.socket.address;
    const stream = try address.connect(t.io, .{ .mode = .stream });
    defer stream.close(t.io);
    var send: [1024]u8 = undefined;
    var writer = stream.writer(t.io, &send);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try writer.interface.flush();
    var receive: [1024]u8 = undefined;
    var reader = stream.reader(t.io, &receive);
    var response: [2048]u8 = undefined;
    const n = try reader.interface.readSliceShort(&response);
    try t.expect(std.mem.startsWith(u8, response[0..n], "HTTP/1.1 200"));
    try t.expect(std.mem.indexOf(u8, response[0..n], "bounded service") != null);
    try t.expect(std.mem.indexOf(u8, response[0..n], "Content-Security-Policy") != null);
    const idle = try address.connect(t.io, .{ .mode = .stream });
    defer idle.close(t.io);
    kernel.stop();
    owned = false;
}

fn refuse(_: *anyopaque, context: *Context) Context.Error!void {
    try context.respond(.forbidden, "text/plain", "change password", &.{});
}

test "early refusal flushes before input drain and releases a stalled peer within its budget" {
    var application: u8 = 0;
    const kernel = try Kernel.start(
        t.allocator,
        t.io,
        try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        &application,
        refuse,
    );
    defer kernel.stop();
    const stream = try kernel.listener.socket.address.connect(t.io, .{ .mode = .stream });
    defer stream.close(t.io);
    var send: [256]u8 = undefined;
    var writer = stream.writer(t.io, &send);
    try writer.interface.writeAll("POST / HTTP/1.1\r\nHost: localhost\r\n" ++
        "Content-Length: 2\r\n\r\n");
    try writer.interface.flush();
    var receive: [1024]u8 = undefined;
    var reader = stream.reader(t.io, &receive);
    var prefix: [12]u8 = undefined;
    try reader.interface.readSliceAll(&prefix);
    try t.expectEqualStrings("HTTP/1.1 403", &prefix);
    // The client withholds its body and EOF. The reply still arrives, and closing
    // the connection is bounded without waiting for the advertised body length.
    const started = std.Io.Clock.awake.now(t.io).nanoseconds;
    var response: [2048]u8 = undefined;
    const count = try reader.interface.readSliceShort(&response);
    try t.expect(std.mem.indexOf(u8, response[0..count], "change password") != null);
    try t.expect(std.Io.Clock.awake.now(t.io).nanoseconds - started < 3 * std.time.ns_per_s);
}

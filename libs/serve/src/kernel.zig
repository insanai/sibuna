//! A bounded listener with joinable workers and a watchdog. No detached work survives stop.
const std = @import("std");
const Io = std.Io;
const Context = @import("context.zig").Context;

pub const Kernel = struct {
    pub const Handler = *const fn (*anyopaque, *Context) Context.Error!void;
    const Slot = struct {
        stream: ?Io.net.Stream = null,
        thread: ?std.Thread = null,
        deadline: std.atomic.Value(i64) = .init(0),
    };
    gpa: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    handler: Handler,
    application: *anyopaque,
    mutex: Io.Mutex = .init,
    slots: [96]Slot = @splat(.{}),
    stopping: std.atomic.Value(bool) = .init(false),
    subscribers: std.atomic.Value(u16) = .init(0),
    acceptor: ?std.Thread = null,
    watchdog: ?std.Thread = null,

    pub fn start(
        gpa: std.mem.Allocator,
        io: Io,
        address: Io.net.IpAddress,
        application: *anyopaque,
        handler: Handler,
    ) !*Kernel {
        const self = try gpa.create(Kernel);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .listener = try address.listen(io, .{ .reuse_address = true }),
            .application = application,
            .handler = handler,
        };
        errdefer self.listener.deinit(io);
        self.watchdog = try std.Thread.spawn(
            .{ .stack_size = @import("stack.zig").bytes(256 * 1024) },
            watch,
            .{self},
        );
        errdefer {
            self.stopping.store(true, .release);
            self.watchdog.?.join();
        }
        self.acceptor = try std.Thread.spawn(
            .{ .stack_size = @import("stack.zig").bytes(256 * 1024) },
            accept,
            .{self},
        );
        return self;
    }

    pub fn stop(self: *Kernel) void {
        self.stopping.store(true, .release);
        // A self-connection wakes accept without closing/reusing its descriptor underneath it.
        var wake_address = self.listener.socket.address;
        switch (wake_address) {
            .ip4 => |*ip| {
                if (std.mem.allEqual(u8, &ip.bytes, 0)) ip.bytes = .{ 127, 0, 0, 1 };
            },
            .ip6 => |*ip| {
                if (std.mem.allEqual(u8, &ip.bytes, 0)) ip.bytes = @as([15]u8, @splat(0)) ++ .{1};
            },
        }
        if (wake_address.connect(self.io, .{ .mode = .stream })) |stream| {
            stream.close(self.io);
        } else |err| {
            std.log.err("listener wake failed: {t}", .{err});
            self.listener.deinit(self.io);
            self.join();
            self.gpa.destroy(self);
            return;
        }
        self.join();
        self.listener.deinit(self.io);
        self.gpa.destroy(self);
    }

    fn join(self: *Kernel) void {
        if (self.acceptor) |thread| thread.join();
        if (self.watchdog) |thread| thread.join();
        self.mutex.lockUncancelable(self.io);
        for (&self.slots) |*slot| if (slot.stream) |stream| shutdown(stream, self.io);
        self.mutex.unlock(self.io);
        for (&self.slots) |*slot| if (slot.thread) |thread| thread.join();
    }

    fn accept(self: *Kernel) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |err| {
                if (!self.stopping.load(.acquire)) std.log.warn("console accept: {t}", .{err});
                continue;
            };
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);
                return;
            }
            if (!self.admit(stream)) reject(stream, self.io);
        }
    }

    fn admit(self: *Kernel, stream: Io.net.Stream) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (&self.slots, 0..) |*slot, index| {
            if (slot.stream != null) continue;
            if (slot.thread) |thread| thread.join();
            slot.thread = null;
            slot.stream = stream;
            const now = @divTrunc(Io.Clock.awake.now(self.io).nanoseconds, std.time.ns_per_s);
            slot.deadline.store(@intCast(now + 10), .release);
            slot.thread = std.Thread.spawn(
                .{ .stack_size = @import("stack.zig").bytes(256 * 1024) },
                run,
                .{ self, index },
            ) catch |err| {
                std.log.warn("console thread capacity: {t}", .{err});
                slot.stream = null;
                return false;
            };
            return true;
        }
        return false;
    }

    fn run(self: *Kernel, index: usize) void {
        const slot = &self.slots[index];
        const stream = slot.stream.?;
        var unread_body = false;
        defer {
            if (unread_body) finish(stream, self.io, &slot.deadline);
            self.mutex.lockUncancelable(self.io);
            stream.close(self.io);
            slot.stream = null;
            self.mutex.unlock(self.io);
        }
        var receive: [16 * 1024]u8 = undefined;
        var send: [16 * 1024]u8 = undefined;
        var reader = stream.reader(self.io, &receive);
        var writer = stream.writer(self.io, &send);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = server.receiveHead() catch |err| {
            if (err == error.HttpHeadersOversize) {
                writer.interface.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\n" ++
                    "Connection: close\r\nContent-Length: 0\r\n\r\n") catch return;
                writer.interface.flush() catch return;
            }
            return;
        };
        unread_body = (request.head.content_length orelse 0) != 0 or
            request.head.transfer_encoding == .chunked;
        var context: Context = .{
            .request = &request,
            .io = self.io,
            .peer = stream.socket.address,
            .stream = stream,
            .subscribers = &self.subscribers,
            .deadline = &slot.deadline,
        };
        self.handler(self.application, &context) catch |err| switch (err) {
            error.WriteFailed, error.ReadFailed, error.EndOfStream => {},
            else => std.log.warn("console request rejected: {t}", .{err}),
        };
        unread_body = unread_body and !context.body_received;
    }

    fn watch(self: *Kernel) void {
        while (!self.stopping.load(.acquire)) {
            Io.sleep(self.io, Io.Duration.fromMilliseconds(100), .awake) catch return;
            const now = @divTrunc(Io.Clock.awake.now(self.io).nanoseconds, std.time.ns_per_s);
            self.mutex.lockUncancelable(self.io);
            for (&self.slots) |*slot| {
                if (slot.stream) |stream| {
                    if (now >= slot.deadline.load(.acquire)) shutdown(stream, self.io);
                }
            }
            self.mutex.unlock(self.io);
        }
    }
};

// Closing over unread request bytes can reset TCP and discard an already flushed
// authorization error. Half-close output first, then drain at most 64 KiB until peer
// EOF. The watchdog bounds this grace period to one second, including a stalled client.
// Run only for an unread body: ordinary replies must retain graceful background delivery.
// Do not hold the slot mutex here: the watchdog must be able to interrupt this read.
fn finish(stream: Io.net.Stream, io: Io, deadline: *std.atomic.Value(i64)) void {
    stream.shutdown(io, .send) catch return;
    const now = @divTrunc(Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_s);
    deadline.store(@intCast(now + 1), .release);
    var buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &.{});
    for (0..16) |_| {
        const count = reader.interface.readSliceShort(&buffer) catch return;
        if (count != buffer.len) return;
    }
}

fn shutdown(stream: Io.net.Stream, io: Io) void {
    @import("socket").interrupt(io, stream);
}

fn reject(stream: Io.net.Stream, io: Io) void {
    defer stream.close(io);
    var bytes: [256]u8 = undefined;
    var writer = stream.writer(io, &bytes);
    writer.interface.writeAll("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n" ++
        "Retry-After: 1\r\nContent-Length: 0\r\n\r\n") catch return;
    writer.interface.flush() catch return;
}

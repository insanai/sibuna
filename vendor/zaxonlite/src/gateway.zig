//! Stateless TCP gateway for Zaxonlite client connections.
//!
//! The gateway deliberately operates below the Zaxon wire protocol. Mutual
//! authentication and frame integrity remain end-to-end between the client
//! and selected storage node, and backup streams need no special proxy path.

const std = @import("std");
const Io = std.Io;
const client = @import("client.zig");
const diagnostic = @import("diagnostic.zig");
const deadlines = @import("net_deadline.zig");

pub const Options = struct {
    listen_host: []const u8 = "127.0.0.1",
    listen_port: u16,
    backends: []const client.Endpoint,
    /// Hard cap for raw passthrough connections. Backend servers enforce
    /// their own stricter global/per-peer admission after the TLS handshake.
    max_connections: usize = 128,
    /// Optional embedding-owned graceful shutdown signal. Setting it and
    /// connecting once to the listener wakes the accept loop.
    shutdown_flag: ?*std.atomic.Value(bool) = null,
    /// Optional embedding-owned first-failure publication.
    failure_name_buffer: ?*[128]u8 = null,
    failure_name_len: ?*std.atomic.Value(u8) = null,
};

pub fn serve(
    gpa: std.mem.Allocator,
    io: Io,
    options: Options,
    err_out: *Io.Writer,
) !u8 {
    if (options.backends.len == 0) {
        return report(err_out, "at least one storage backend is required");
    }
    if (options.max_connections == 0) {
        return report(err_out, "gateway connection limit must be non-zero");
    }
    const address = std.Io.net.IpAddress.parse(
        options.listen_host,
        options.listen_port,
    ) catch return report(err_out, "invalid gateway listen address");
    var listener = address.listen(io, .{ .reuse_address = true }) catch |err| {
        publishFailure(options, err);
        try diagnostic.write(
            err_out,
            "gateway listen failed",
            @errorName(err),
            "Check address ownership, port availability, and permissions.",
        );
        try err_out.flush();
        return 4;
    };
    var listener_open = true;
    defer if (listener_open) listener.deinit(io);
    var runtime = Runtime{ .gpa = gpa, .io = io };
    defer runtime.deinit();

    var next: usize = 0;
    var exit_code: u8 = 0;
    while (true) {
        if (options.shutdown_flag) |flag| {
            if (flag.load(.acquire)) break;
        }
        const inbound = listener.accept(io) catch |err| switch (err) {
            error.ConnectionAborted => continue,
            else => {
                publishFailure(options, err);
                exit_code = 4;
                break;
            },
        };
        if (options.shutdown_flag) |flag| {
            if (flag.load(.acquire)) {
                inbound.close(io);
                break;
            }
        }
        next = handleInboundConnection(gpa, io, &runtime, inbound, options, next);
    }
    listener.deinit(io);
    listener_open = false;
    runtime.shutdown();
    runtime.wait();
    return exit_code;
}

fn publishFailure(options: Options, err: anyerror) void {
    const buffer = options.failure_name_buffer orelse return;
    const published = options.failure_name_len orelse return;
    if (published.load(.acquire) != 0) return;
    const name = @errorName(err);
    const len: u8 = @intCast(@min(name.len, buffer.len));
    @memcpy(buffer[0..len], name[0..len]);
    published.store(len, .release);
}

fn handleInboundConnection(
    gpa: std.mem.Allocator,
    io: Io,
    runtime: *Runtime,
    inbound: std.Io.net.Stream,
    options: Options,
    next: usize,
) usize {
    const context = gpa.create(Proxy) catch {
        inbound.close(io);
        return next;
    };
    if (!runtime.tryStarted(inbound, options.max_connections, true)) {
        gpa.destroy(context);
        inbound.close(io);
        return next;
    }
    context.* = .{
        .gpa = gpa,
        .io = io,
        .owner = runtime,
        .inbound = inbound,
        .backends = options.backends,
        .first = next,
    };
    const new_next = (next + 1) % options.backends.len;
    const thread = std.Thread.spawn(.{}, Proxy.run, .{context}) catch {
        runtime.finished(inbound);
        inbound.close(io);
        gpa.destroy(context);
        return new_next;
    };
    thread.detach();
    return new_next;
}

fn report(err_out: *Io.Writer, message: []const u8) !u8 {
    try diagnostic.write(
        err_out,
        "invalid gateway configuration",
        message,
        "Configure at least one authenticated storage endpoint.",
    );
    try err_out.flush();
    return 2;
}

const Proxy = struct {
    gpa: std.mem.Allocator,
    io: Io,
    owner: *Runtime,
    inbound: std.Io.net.Stream,
    backends: []const client.Endpoint,
    first: usize,

    fn run(self: *Proxy) void {
        defer self.gpa.destroy(self);
        defer self.inbound.close(self.io);
        defer self.owner.finished(self.inbound);
        var outbound = self.connect() orelse return;
        defer outbound.close(self.io);
        if (!self.owner.tryStarted(outbound, 0, false)) return;
        defer self.owner.finished(outbound);

        var upload = Copy{
            .io = self.io,
            .source = self.inbound,
            .destination = outbound,
        };
        const thread = std.Thread.spawn(.{}, Copy.run, .{&upload}) catch return;
        var download = Copy{
            .io = self.io,
            .source = outbound,
            .destination = self.inbound,
        };
        download.run();
        thread.join();
    }

    fn connect(self: *Proxy) ?std.Io.net.Stream {
        var offset: usize = 0;
        while (offset < self.backends.len) : (offset += 1) {
            if (self.owner.isStopping()) return null;
            const backend = self.backends[(self.first + offset) % self.backends.len];
            const address = std.Io.net.IpAddress.parse(
                backend.host,
                backend.port,
            ) catch continue;
            return deadlines.connectIp(
                self.io,
                address,
                deadlines.after(self.io, 1000),
            ) catch continue;
        }
        return null;
    }
};

const Runtime = struct {
    const Tracked = struct { stream: Io.net.Stream, inbound: bool };

    gpa: std.mem.Allocator,
    io: Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    active: std.ArrayList(Tracked) = .empty,
    inbound_count: usize = 0,
    stopping: bool = false,

    fn deinit(self: *Runtime) void {
        self.active.deinit(self.gpa);
    }

    fn tryStarted(
        self: *Runtime,
        stream: std.Io.net.Stream,
        limit: usize,
        inbound: bool,
    ) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping or (inbound and self.inbound_count >= limit)) return false;
        self.active.append(self.gpa, .{ .stream = stream, .inbound = inbound }) catch return false;
        if (inbound) self.inbound_count += 1;
        return true;
    }

    fn finished(self: *Runtime, stream: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(self.io);
        for (self.active.items, 0..) |candidate, index| {
            if (candidate.stream.socket.handle == stream.socket.handle) {
                if (candidate.inbound) self.inbound_count -= 1;
                _ = self.active.swapRemove(index);
                break;
            }
        }
        self.cond.signal(self.io);
        self.mutex.unlock(self.io);
    }

    fn isStopping(self: *Runtime) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.stopping;
    }

    fn shutdown(self: *Runtime) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.stopping = true;
        for (self.active.items) |tracked| {
            tracked.stream.shutdown(self.io, .both) catch {};
        }
    }

    fn wait(self: *Runtime) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.active.items.len > 0) {
            self.cond.waitUncancelable(self.io, &self.mutex);
        }
    }
};

const Copy = struct {
    io: Io,
    source: std.Io.net.Stream,
    destination: std.Io.net.Stream,

    fn run(self: *Copy) void {
        self.copy();
        self.source.shutdown(self.io, .both) catch {};
        self.destination.shutdown(self.io, .both) catch {};
    }

    fn copy(self: *Copy) void {
        var source_buffer: [16 * 1024]u8 = undefined;
        var reader = self.source.reader(self.io, &source_buffer);
        var destination_buffer: [16 * 1024]u8 = undefined;
        var writer = self.destination.writer(self.io, &destination_buffer);
        while (true) {
            _ = reader.interface.stream(
                &writer.interface,
                .limited(16 * 1024),
            ) catch return;
            writer.interface.flush() catch return;
        }
    }
};

test "gateway defaults to bounded admission" {
    try std.testing.expectEqual(@as(usize, 128), (Options{
        .listen_port = 1,
        .backends = &.{},
    }).max_connections);
}

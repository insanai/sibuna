const std = @import("std");
const ws = @import("serve").websocket;
const Context = @import("http.zig").Context;
const http = @import("http.zig");
const App = @import("app.zig").App;
const p = @import("console_protocol");

pub fn handle(app: *App, context: *Context, principal: p.Principal) !void {
    const origin = try context.header("Origin") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, origin, app.config.origin.slice())) return error.InvalidRequest;
    const key = try @import("serve").websocket_upgrade.key(context);
    const digest = try http.session(context);
    if (context.subscribers.fetchAdd(1, .acq_rel) >= 64) {
        _ = context.subscribers.fetchSub(1, .release);
        return http.fail(context, .service_unavailable, "CONSOLE503");
    }
    defer _ = context.subscribers.fetchSub(1, .release);
    const channel = if (std.mem.eql(u8, context.request.head.target, "/console/ws"))
        try app.hub.attach()
    else
        null;
    defer if (channel) |handle_id| app.hub.detach(handle_id);
    _ = try context.request.respondWebSocket(.{ .key = key });
    try context.request.server.out.flush();
    var stream: Stream = .{
        .app = app,
        .context = context,
        .digest = digest,
        .principal = principal,
        .channel = channel,
        .kiosk = principal.kiosk,
        .last_read = .init(app.now()),
    };
    stream.run();
}

/// Management streams use an independent admission quota and never acquire browser roles.
pub fn peer(app: *App, context: *Context) !void {
    const wire = @import("peer_wire.zig");
    if (!app.config.behind_proxy or app.config.peers.count == 0)
        return http.fail(context, .not_found, "CONSOLE404");
    const input = try wire.readRequest(context);
    const index = app.peers.admit(input.transcript, input.proof, app.now()) catch
        return http.fail(context, .forbidden, "CONSOLEPEER");
    defer app.peers.release(index);
    const channel = try app.hub.attachPeer();
    defer app.hub.detach(channel);
    var nonce: [32]u8 = undefined;
    app.io.random(&nonce);
    const reply = wire.ReplyHeaders.init(app.peers.key.?, input.transcript, .{
        .boot = app.history.boot,
        .nonce = nonce,
    });
    _ = try context.request.respondWebSocket(.{
        .key = input.websocket_key,
        .extra_headers = &reply.headers(),
    });
    try context.request.server.out.flush();
    var stream: Stream = .{
        .app = app,
        .context = context,
        .channel = channel,
        .kiosk = true,
        .peer_node = input.transcript.from,
        .peer_expires = app.now() + 3600,
        .last_read = .init(app.now()),
    };
    stream.run();
}

const Stream = struct {
    const Control = struct { opcode: ws.Opcode, len: u8, bytes: [125]u8 = undefined };
    app: *App,
    context: *Context,
    digest: [32]u8 = @splat(0),
    principal: p.Principal = undefined,
    peer_node: ?u32 = null,
    peer_expires: u64 = 0,
    channel: ?@import("subscription_hub.zig").Handle = null,
    kiosk: bool,
    command_second: u64 = 0,
    command_count: u8 = 0,
    subscribed: std.atomic.Value(bool) = .init(false),
    stopped: std.atomic.Value(bool) = .init(false),
    close_code: std.atomic.Value(u16) = .init(0),
    last_read: std.atomic.Value(u64),
    mutex: std.Io.Mutex = .init,
    controls: [8]Control = undefined,
    control_len: usize = 0,
    queries: @import("peer_query_queue.zig").Queue = .{},

    // Both tasks borrow this handler; shutdown wakes the reader before its owner returns.
    fn run(self: *Stream) void {
        const reader = std.Thread.spawn(
            .{ .stack_size = @import("serve").stack.bytes(256 * 1024) },
            Stream.read,
            .{self},
        ) catch return;
        self.write();
        self.context.stream.shutdown(self.app.io, .both) catch |err| switch (err) {
            error.SocketUnconnected => {},
            else => std.log.warn("console stream shutdown: {t}", .{err}),
        };
        reader.join();
    }

    fn write(self: *Stream) void {
        var epoch: [16]u8 = undefined;
        self.app.io.random(&epoch);
        const epoch_hex = std.fmt.bytesToHex(epoch, .lower);
        var sequence: u64 = 0;
        var last_data: u64 = 0;
        var last_auth = self.app.now();
        var last_ping = last_auth;
        while (!self.stopped.load(.acquire)) {
            if (!self.flushControls()) break;
            const now = self.app.now();
            const expires = if (self.peer_node != null)
                self.peer_expires
            else
                self.principal.expires;
            if (now >= expires or now -| self.last_read.load(.acquire) >= 60) {
                self.close(1008);
                break;
            }
            if (now -| last_auth >= 5) {
                if (!self.authorize()) break;
                last_auth = now;
            }
            if (self.peer_node != null and !self.reply()) break;
            if (self.channel) |handle_id| {
                if (!self.deliver(handle_id)) break;
            } else if (self.subscribed.load(.acquire) and now != last_data) {
                if (!self.statistics(&epoch_hex, sequence, now)) break;
                sequence += 1;
                last_data = now;
            }
            if (now -| last_ping >= 20) {
                if (!self.send(.ping, "")) break;
                last_ping = now;
            }
            // Progressing idle writers stay alive between 20-second pings. A blocked
            // write or authorization still expires under the independent kernel watchdog.
            self.context.extend(10);
            std.Io.sleep(self.app.io, std.Io.Duration.fromMilliseconds(100), .awake) catch break;
        }
        const code = self.close_code.load(.acquire);
        if (code != 0) self.close(code);
        self.stopped.store(true, .release);
    }

    fn reply(self: *Stream) bool {
        const request = self.queries.take(self.app.io) orelse return true;
        // A full peer page plus its envelope must fit, or every large reply closes the stream.
        var buffer: [@import("peer_query.zig").max_body + 512]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        @import("peer_query_server.zig").respond(self.app, request, &writer) catch return false;
        return self.send(.text, writer.buffered());
    }

    fn statistics(self: *Stream, epoch: []const u8, sequence: u64, now: u64) bool {
        var buffer: [8192]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        std.json.Stringify.value(.{
            .op = if (sequence == 0) "snapshot" else "delta",
            .epoch = epoch,
            .seq = sequence,
            .topic = "stats",
            .data = self.app.stats.snapshot(
                self.app.io,
                self.app.telemetry,
                self.app.metrics,
                now,
            ),
        }, .{}, &writer) catch return false;
        return self.send(.text, writer.buffered());
    }

    fn deliver(self: *Stream, handle_id: @import("subscription_hub.zig").Handle) bool {
        for (0..p.subscriptions.messages_per_second) |_| {
            const item = self.app.hub.take(handle_id) orelse return true;
            if (item == .frame) {
                if (!self.send(.text, item.frame.bytes.slice())) return false;
                continue;
            }
            var buffer: [512]u8 = undefined;
            var epoch: [64]u8 = undefined;
            const text = std.fmt.bufPrint(&epoch, "{s}:{d}", .{
                self.app.hub.boot, item.gap.epoch,
            }) catch return false;
            var writer: std.Io.Writer = .fixed(&buffer);
            std.json.Stringify.value(.{
                .op = "gap",
                .topic = item.gap.topic,
                .epoch = text,
                .dropped = p.Counter{ .value = item.gap.dropped },
            }, .{}, &writer) catch return false;
            if (!self.send(.text, writer.buffered())) return false;
        }
        return true;
    }

    fn authorize(self: *Stream) bool {
        if (self.peer_node) |node| {
            if (!self.app.stopping.load(.acquire) and self.app.config.peers.contains(node))
                return true;
            self.close(1008);
            return false;
        }
        const result = self.app.request(.{ .authorize = .{
            .session_digest = self.digest,
        } }) catch {
            self.close(1013);
            return false;
        };
        if (result != .authorized or self.app.restricted(result.authorized)) {
            if (self.channel != null) _ = self.send(.text, "{\"error\":\"unauthorized\"}");
            self.close(1008);
            return false;
        }
        self.principal = result.authorized;
        return true;
    }

    fn send(self: *Stream, opcode: ws.Opcode, payload: []const u8) bool {
        var buffer: [8206]u8 = undefined;
        const frame = ws.encode(&buffer, opcode, true, payload, .server, null) catch return false;
        self.context.extend(10);
        self.context.request.server.out.writeAll(frame) catch return false;
        self.context.request.server.out.flush() catch return false;
        return true;
    }

    fn close(self: *Stream, code: u16) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, code, .big);
        _ = self.send(.close, &bytes);
    }

    fn flushControls(self: *Stream) bool {
        var copy: [8]Control = undefined;
        self.mutex.lockUncancelable(self.app.io);
        const count = self.control_len;
        @memcpy(copy[0..count], self.controls[0..count]);
        self.control_len = 0;
        self.mutex.unlock(self.app.io);
        for (copy[0..count]) |control| {
            if (!self.send(control.opcode, control.bytes[0..control.len])) return false;
            if (control.opcode == .close) return false;
        }
        return true;
    }

    fn enqueue(self: *Stream, opcode: ws.Opcode, payload: []const u8) bool {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        if (self.control_len == self.controls.len) return false;
        const control = &self.controls[self.control_len];
        control.* = .{ .opcode = opcode, .len = @intCast(payload.len) };
        @memcpy(control.bytes[0..payload.len], payload);
        self.control_len += 1;
        return true;
    }

    fn read(self: *Stream) void {
        var receiver: ws.Receiver = .{};
        while (!self.stopped.load(.acquire)) {
            const event = self.receive(&receiver) catch |err| {
                self.close_code.store(switch (err) {
                    error.TooLarge => 1009,
                    error.InvalidUtf8 => 1007,
                    error.ReadFailed, error.EndOfStream => 0,
                    else => 1002,
                }, .release);
                self.stopped.store(true, .release);
                return;
            };
            self.last_read.store(self.app.now(), .release);
            const accepted = switch (event) {
                .fragment, .pong => true,
                .ping => |payload| self.enqueue(.pong, payload),
                .close => |payload| self.enqueue(.close, payload),
                .text => |payload| self.subscribe(payload),
                .binary => false,
            };
            if (!accepted) {
                self.close_code.store(1008, .release);
                self.stopped.store(true, .release);
                return;
            }
            if (event == .close) return;
        }
    }

    fn receive(self: *Stream, receiver: *ws.Receiver) !ws.Event {
        return @import("serve").websocket_io.receive(
            self.context.request.server.reader.in,
            receiver,
            .server,
        );
    }

    fn command(
        self: *Stream,
        handle_id: @import("subscription_hub.zig").Handle,
        payload: []const u8,
    ) bool {
        const now = self.app.now();
        if (now != self.command_second) {
            self.command_second = now;
            self.command_count = 0;
        }
        if (self.command_count == 64) return false;
        self.command_count += 1;
        if (self.peer_node != null) {
            if (self.queries.accept(self.app.io, payload) catch return false) return true;
        }
        const input = p.subscriptions.parse(payload) catch return false;
        if (input.op == .ping) return self.enqueue(.text, "{\"op\":\"pong\"}");
        if (self.kiosk and input.topic != .stats) return false;
        self.app.hub.command(handle_id, input) catch return false;
        return true;
    }

    fn subscribe(self: *Stream, payload: []const u8) bool {
        if (self.channel) |handle_id| return self.command(handle_id, payload);
        var buffer: [8192]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buffer);
        const parsed = std.json.parseFromSlice(struct {
            op: []const u8,
            topics: []const []const u8 = &.{},
        }, fixed.allocator(), payload, .{}) catch return false;
        defer parsed.deinit();
        if (std.mem.eql(u8, parsed.value.op, "unsubscribe")) {
            self.subscribed.store(false, .release);
            return true;
        }
        if (!std.mem.eql(u8, parsed.value.op, "subscribe") or parsed.value.topics.len != 1 or
            !std.mem.eql(u8, parsed.value.topics[0], "stats")) return false;
        self.subscribed.store(true, .release);
        return true;
    }
};

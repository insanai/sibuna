//! One authenticated TLS connection, exclusively owned by a cancellable peer worker.
const std = @import("std");
const p = @import("console_protocol");
const net = @import("net").outbound;
const ws = @import("serve").websocket;
const auth = @import("peer_auth.zig");
const wire = @import("peer_wire.zig");
const Store = @import("peer_store.zig").Store;
pub const Input = struct {
    store: *Store,
    index: u8,
    gpa: std.mem.Allocator,
    progress: *std.atomic.Value(i64),
};
pub const allocation_bytes = 6 * 1024 * 1024;

pub fn run(input: Input) anyerror!void {
    const io = input.store.io;
    // All TLS, certificate and parser allocations have a per-connection ceiling.
    const memory = try input.gpa.alloc(u8, allocation_bytes);
    defer input.gpa.free(memory);
    var fixed = std.heap.FixedBufferAllocator.init(memory);
    const gpa = fixed.allocator();
    const receiver = try gpa.create(p.subscription_client.Client);
    receiver.* = .{};
    const arena = try gpa.alloc(u8, 512 * 1024);
    var client: std.http.Client = .{ .allocator = gpa, .io = io, .read_buffer_size = 16384 };
    defer client.deinit();
    try trust(&client, input.store.config.ca_file.slice());
    const target = input.store.config.targets[input.index];
    const origin = try @import("peer_config.zig").parseOrigin(target.origin.slice());
    const addresses = try net.resolve(io, origin.host, origin.port, .configured_management);
    const connection = try connect(&client, addresses, origin.host);
    // Upgrade sockets must never enter the HTTP pool or try to drain a response body.
    connection.closing = true;
    var url: [280]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url, "{s}/console/peer", .{
        target.origin.slice(),
    }));
    var transcript: auth.Request = .{
        .from = input.store.self_node,
        .to = target.node,
        .timestamp = seconds(io),
        .nonce = undefined,
        .websocket_key = undefined,
    };
    io.random(&transcript.nonce);
    io.random(&transcript.websocket_key);
    const key = input.store.key orelse return error.InvalidProof;
    const headers = wire.RequestHeaders.init(key, transcript);
    var request = client.request(.GET, uri, .{
        .connection = connection,
        .redirect_behavior = .unhandled,
        .headers = .{ .connection = .{ .override = "Upgrade" } },
        .extra_headers = &headers.headers(),
    }) catch |err| {
        client.connection_pool.release(connection, io);
        return err;
    };
    defer {
        connection.closing = true;
        request.deinit();
    }
    try request.sendBodiless();
    const response = try request.receiveHead(&.{});
    const identity = try wire.readReply(response.head, key, transcript);
    const handle = try input.store.activate(input.index, identity.boot);
    try send(connection, .text, "{\"op\":\"sub\",\"topic\":\"stats\",\"args\":{}}");
    try receive(input, connection, handle, receiver, arena);
}

fn connect(
    client: *std.http.Client,
    addresses: net.Addresses,
    host: []const u8,
) !*std.http.Client.Connection {
    for (addresses.items[0..addresses.count]) |address| {
        return net.connect(client, .{
            .address = address,
            .host = try net.Host.init(host),
            .secure = true,
            .policy = .configured_management,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => continue,
        };
    }
    return error.PeerUnavailable;
}

fn trust(client: *std.http.Client, path: []const u8) !void {
    if (path.len == 0) return;
    const file = try std.Io.Dir.cwd().openFile(client.io, path, .{});
    defer file.close(client.io);
    const stat = try file.stat(client.io);
    if (stat.kind != .file or stat.size == 0 or stat.size > 128 * 1024)
        return error.InvalidPeerTrust;
    var reader = file.reader(client.io, &.{});
    const now = std.Io.Clock.real.now(client.io);
    try client.ca_bundle.addCertsFromFile(client.allocator, &reader, now.toSeconds());
    if (client.ca_bundle.map.count() == 0) return error.InvalidPeerTrust;
    client.now = now;
}

fn receive(
    input: Input,
    connection: *std.http.Client.Connection,
    handle: @import("peer_store.zig").Handle,
    client: *p.subscription_client.Client,
    arena: []u8,
) !void {
    var frames: ws.Receiver = .{};
    var second = seconds(input.store.io);
    var count: u16 = 0;
    while (true) {
        const event = try @import("serve").websocket_io.receive(
            connection.reader(),
            &frames,
            .client,
        );
        const now = seconds(input.store.io);
        if (second != now) {
            second = now;
            count = 0;
        }
        if (count == 128) return error.PeerRateLimit;
        count += 1;
        switch (event) {
            .fragment, .pong => {},
            .ping => |payload| try send(connection, .pong, payload),
            .close => |payload| {
                try send(connection, .close, payload);
                return;
            },
            .binary => return error.InvalidMessage,
            .text => |payload| try update(input, handle, client, arena, payload),
        }
    }
}

fn update(
    input: Input,
    handle: @import("peer_store.zig").Handle,
    client: *p.subscription_client.Client,
    memory: []u8,
    payload: []const u8,
) !void {
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const gpa = arena.allocator();
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, payload, .{});
    const event = try client.receive(parsed.value, gpa);
    switch (event) {
        .none => return,
        .unauthorized, .gap => return error.PeerResync,
        .changed => |topic| if (topic != .stats) return error.InvalidMessage,
    }
    // Unavailable initial hub views have no counters and are never published as zero.
    const position = client.position(.stats) orelse return error.InvalidMessage;
    var view_arena = std.heap.FixedBufferAllocator.init(memory);
    const value = try std.json.parseFromSlice(
        p.StatsSnapshot,
        view_arena.allocator(),
        client.view(.stats),
        .{},
    );
    const accepted = try input.store.publish(handle, .{
        .value = &value.value,
        .watermark = position.watermark,
        .sequence = position.sequence,
        .received_at = seconds(input.store.io),
    });
    if (accepted) input.progress.store(monotonic(input.store.io), .release);
}

fn send(connection: *std.http.Client.Connection, opcode: ws.Opcode, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    connection.client.io.random(&mask);
    var buffer: [2062]u8 = undefined;
    try connection.writer().writeAll(try ws.encode(&buffer, opcode, true, payload, .client, mask));
    try connection.flush();
}

pub fn monotonic(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_s));
}

fn seconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Clock.real.now(io).toSeconds()));
}

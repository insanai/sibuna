//! Management-only outbound connections. DNS answers are bounded, validated together and
//! copied before connection; HTTPS uses the original hostname for SNI and certificate checks.
//! Callers provide a cancellable deadline scope. Never used on a data-plane request path.
const std = @import("std");
const Io = std.Io;
pub const Policy = enum { public_only, loopback_allowed, configured_management };
pub const max_addresses = 16;
pub const Error = error{
    InvalidHost,
    TargetRejected,
    HostUnresolved,
    TooManyAddresses,
    HttpUnavailable,
    TlsUnavailable,
    Canceled,
};
pub const Host = struct {
    data: [Io.net.HostName.max_len]u8 = undefined,
    len: u8 = 0,

    pub fn init(text: []const u8) Error!Host {
        if (text.len == 0 or text.len > Io.net.HostName.max_len) return error.InvalidHost;
        var result: Host = .{ .len = @intCast(text.len) };
        @memcpy(result.data[0..text.len], text);
        return result;
    }

    pub fn slice(self: *const Host) []const u8 {
        return self.data[0..self.len];
    }
};
pub const Addresses = struct {
    items: [max_addresses]Io.net.IpAddress = undefined,
    count: u8 = 0,

    pub fn add(self: *Addresses, address: Io.net.IpAddress, policy: Policy) Error!void {
        if (!allowed(address, policy)) return error.TargetRejected;
        for (self.items[0..self.count]) |previous| if (previous.eql(&address)) return;
        if (self.count == max_addresses) return error.TooManyAddresses;
        self.items[self.count] = address;
        self.count += 1;
    }
};
pub const Pinned = struct {
    address: Io.net.IpAddress,
    host: Host,
    secure: bool,
    policy: Policy,
};

pub fn resolve(io: Io, host: []const u8, port: u16, policy: Policy) Error!Addresses {
    var addresses: Addresses = .{};
    if (Io.net.IpAddress.parse(host, port)) |literal| {
        try addresses.add(literal, policy);
        return addresses;
    } else |_| {}
    const name = Io.net.HostName.init(host) catch return error.InvalidHost;
    var buffer: [max_addresses]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&buffer);
    // Drain concurrently: a publisher with >16 answers must not block before validation.
    var producer = io.async(Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port } });
    defer producer.cancel(io) catch {};
    while (queue.getOne(io)) |item| {
        if (item == .address) try addresses.add(item.address, policy);
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    }
    producer.await(io) catch |err| return mapError(err, error.HostUnresolved);
    if (addresses.count == 0) return error.HostUnresolved;
    return addresses;
}

/// `client` is exclusively owned by this operation. A numeric connection host fixes the
/// socket destination; proxied_host retains the original hostname for TLS authentication.
/// No proxy is configured and no HTTP redirect is followed.
pub fn connect(client: *std.http.Client, pinned: Pinned) Error!*std.http.Client.Connection {
    if (!allowed(pinned.address, pinned.policy)) return error.TargetRejected;
    if (pinned.secure and client.now == null) {
        const now = Io.Clock.real.now(client.io);
        client.ca_bundle.rescan(client.allocator, client.io, now) catch |err|
            return mapError(err, error.TlsUnavailable);
        client.now = now;
    }
    var storage: [80]u8 = undefined;
    const printed = std.fmt.bufPrint(&storage, "{f}", .{pinned.address}) catch unreachable;
    const colon = std.mem.lastIndexOfScalar(u8, printed, ':').?;
    const literal = if (printed[0] == '[') printed[1 .. colon - 1] else printed[0..colon];
    return client.connectTcpOptions(.{
        .host = .{ .bytes = literal },
        .port = pinned.address.getPort(),
        .proxied_host = .{ .bytes = pinned.host.slice() },
        .proxied_port = pinned.address.getPort(),
        .protocol = if (pinned.secure) .tls else .plain,
    }) catch |err| return mapError(err, error.HttpUnavailable);
}

pub const Post = struct {
    pinned: Pinned,
    url: []const u8,
    payload: []const u8,
    headers: []const std.http.Header = &.{},
};

/// Read only the bounded response head: a large or streaming error body cannot turn its
/// status into success or consume unbounded memory. The one-shot connection always closes.
pub fn post(io: Io, gpa: std.mem.Allocator, input: Post) Error!u16 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io, .read_buffer_size = 8192 };
    defer client.deinit();
    const uri = std.Uri.parse(input.url) catch return error.InvalidHost;
    const connection = try connect(&client, input.pinned);
    connection.closing = true;
    var request = client.request(.POST, uri, .{
        .connection = connection,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = input.headers,
    }) catch |err| {
        client.connection_pool.release(connection, io);
        return mapError(err, error.HttpUnavailable);
    };
    defer request.deinit();
    request.transfer_encoding = .{ .content_length = input.payload.len };
    var body = request.sendBodyUnflushed(&.{}) catch return error.HttpUnavailable;
    body.writer.writeAll(input.payload) catch return error.HttpUnavailable;
    body.end() catch return error.HttpUnavailable;
    connection.flush() catch return error.HttpUnavailable;
    const response = request.receiveHead(&.{}) catch |err|
        return mapError(err, error.HttpUnavailable);
    return @intFromEnum(response.head.status);
}

fn mapError(err: anyerror, fallback: Error) Error {
    return if (err == error.Canceled) error.Canceled else fallback;
}

pub fn allowed(address: Io.net.IpAddress, policy: Policy) bool {
    // Private networks are allowed only for administrator-configured management origins.
    // Keep unspecified, multicast, link-local and mapped IPv6 destinations excluded.
    if (policy == .configured_management) return switch (address) {
        .ip4 => |a| a.bytes[0] != 0 and a.bytes[0] < 224 and
            !(a.bytes[0] == 169 and a.bytes[1] == 254),
        .ip6 => |a| a.isLoopBack() or a.bytes[0] & 0xfe == 0xfc or
            a.bytes[0] & 0xe0 == 0x20,
    };
    return switch (address) {
        .ip4 => |a| blk: {
            const b = a.bytes;
            if (b[0] == 127) break :blk policy == .loopback_allowed;
            if (b[0] == 0 or b[0] == 10 or b[0] >= 224) break :blk false;
            if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) break :blk false;
            if (b[0] == 192 and b[1] == 168) break :blk false;
            if (b[0] == 100 and b[1] >= 64 and b[1] <= 127) break :blk false;
            break :blk !(b[0] == 169 and b[1] == 254);
        },
        .ip6 => |a| blk: {
            if (a.isLoopBack()) break :blk policy == .loopback_allowed;
            break :blk a.bytes[0] & 0xe0 == 0x20;
        },
    };
}

test "all DNS answers are checked before connecting and results have a fixed bound" {
    var answers: Addresses = .{};
    for (0..max_addresses) |index| {
        try answers.add(
            .{ .ip4 = .{ .bytes = .{ 8, 8, 8, @intCast(index) }, .port = 443 } },
            .public_only,
        );
    }
    try std.testing.expectError(error.TargetRejected, answers.add(
        try Io.net.IpAddress.parse("10.0.0.1", 443),
        .public_only,
    ));
    try std.testing.expectError(error.TooManyAddresses, answers.add(
        try Io.net.IpAddress.parse("8.8.4.4", 443),
        .public_only,
    ));
    try std.testing.expect(!allowed(
        try Io.net.IpAddress.parse("::ffff:127.0.0.1", 443),
        .public_only,
    ));
}

test "only explicit management targets may reach private networks" {
    const t = std.testing;
    for ([_][]const u8{ "10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1" }) |host| {
        const address = try Io.net.IpAddress.parse(host, 443);
        try t.expect(allowed(address, .configured_management));
        try t.expect(!allowed(address, .public_only));
        try t.expect(!allowed(address, .loopback_allowed));
    }
    for ([_][]const u8{ "0.0.0.0", "169.254.169.254", "224.0.0.1", "::", "fe80::1" }) |host|
        try t.expect(!allowed(try Io.net.IpAddress.parse(host, 443), .configured_management));
}

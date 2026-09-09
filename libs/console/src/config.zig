const std = @import("std");
const protocol = @import("console_protocol");
const Budget = @import("budget.zig").Budget;

pub const ConsoleConfig = struct {
    node_id: u32 = 0,
    enabled: bool = false,
    host: protocol.Bytes(45) = .{},
    port: u16 = 9443,
    /// Daemon version text shown on the About panel; the daemon sets it at composition.
    version: []const u8 = "",
    server_location: ?protocol.Location = null,
    behind_proxy: bool = false,
    cookie_secure: bool = false,
    key_file: protocol.Bytes(1024) = .{},
    origin: protocol.Bytes(255) = .{},
    trusted_proxies: [16]protocol.Bytes(49) = @splat(.{}),
    trusted_proxy_count: u8 = 0,
    // Peer management: an advertised console URL that peers may show as a link, and the
    // explicit data-plane listeners this console probes. Neither comes from replicated data.
    advertise: protocol.Bytes(255) = .{},
    probes: [max_probes]Probe = @splat(.{}),
    probe_count: u8 = 0,
    budget: Budget = .{},

    pub const max_probes = 8;
    pub const Probe = struct { node: u32 = 0, url: protocol.Bytes(255) = .{} };
    pub const ProbeTarget = struct { address: std.Io.net.IpAddress, host: []const u8 };
    pub const Error = error{
        StorageRequired,
        InvalidAddress,
        InvalidOrigin,
        TrustedProxyRequired,
        InvalidProxy,
        TooManyProxies,
        InvalidAdvertise,
        InvalidProbe,
        DuplicateProbe,
    } || Budget.Error || protocol.Location.Error;

    pub fn validate(self: *const ConsoleConfig, has_storage: bool) Error!void {
        try self.budget.validate();
        if (self.server_location) |location| if (!location.valid()) return error.InvalidLocation;
        if (!self.enabled) return;
        if (!has_storage) return error.StorageRequired;
        if (self.port == 0 or self.host.len > self.host.data.len) return error.InvalidAddress;
        const host = if (self.host.len == 0) "127.0.0.1" else self.host.slice();
        const address = std.Io.net.IpAddress.parse(host, self.port) catch
            return error.InvalidAddress;
        const loopback = switch (address) {
            .ip4 => |a| a.bytes[0] == 127,
            .ip6 => |a| std.mem.eql(u8, &a.bytes, &(.{0} ** 15 ++ .{1})),
        };
        try self.validateAdvertise();
        try self.validateProbes();
        if (!loopback and !self.behind_proxy) return error.TrustedProxyRequired;
        if (!self.behind_proxy) return;
        try self.validateProxy();
    }

    /// An advertised URL is an origin (scheme and authority only); HTTP is accepted only
    /// for loopback literals, as for the console's own listener.
    fn validateAdvertise(self: *const ConsoleConfig) Error!void {
        if (self.advertise.len == 0) return;
        if (self.advertise.len > self.advertise.data.len) return error.InvalidAdvertise;
        const url = self.advertise.slice();
        const https = std.mem.startsWith(u8, url, "https://");
        if (!https and !std.mem.startsWith(u8, url, "http://")) return error.InvalidAdvertise;
        const authority = url[if (https) "https://".len else "http://".len..];
        if (authority.len == 0 or std.mem.indexOfAny(u8, authority, "/?#@%\\ ") != null)
            return error.InvalidAdvertise;
        const uri = std.Uri.parse(url) catch return error.InvalidAdvertise;
        const host = uri.host orelse return error.InvalidAdvertise;
        if (host.isEmpty() or uri.user != null or uri.password != null or uri.port == 0)
            return error.InvalidAdvertise;
        if (https) return;
        var buffer: [std.Io.net.HostName.max_len]u8 = undefined;
        const name = uri.getHost(&buffer) catch return error.InvalidAdvertise;
        const address = std.Io.net.IpAddress.parse(name.bytes, 1) catch
            return error.InvalidAdvertise;
        const loopback = switch (address) {
            .ip4 => |a| a.bytes[0] == 127,
            .ip6 => |a| std.mem.eql(u8, &a.bytes, &(.{0} ** 15 ++ .{1})),
        };
        if (!loopback) return error.InvalidAdvertise;
    }

    fn validateProbes(self: *const ConsoleConfig) Error!void {
        if (self.probe_count > max_probes) return error.InvalidProbe;
        for (self.probes[0..self.probe_count], 0..) |probe, index| {
            if (probe.node == 0 or probe.node == self.node_id) return error.InvalidProbe;
            _ = try parseProbe(probe.url.slice());
            for (self.probes[0..index]) |earlier| {
                if (earlier.node == probe.node) return error.DuplicateProbe;
            }
        }
    }

    /// `http://<numeric host>[:port]` only: probes carry no TLS client and never resolve names.
    pub fn parseProbe(url: []const u8) Error!ProbeTarget {
        if (!std.mem.startsWith(u8, url, "http://")) return error.InvalidProbe;
        const authority = url["http://".len..];
        if (authority.len == 0 or std.mem.indexOfAny(u8, authority, "/?#@ \\") != null)
            return error.InvalidProbe;
        var host = authority;
        var port: u16 = 80;
        const bracketed = authority[0] == '[';
        const end = if (bracketed) std.mem.indexOfScalar(u8, authority, ']') orelse
            return error.InvalidProbe else 0;
        const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
        if (colon) |at| {
            if (bracketed and at > end or !bracketed and
                std.mem.indexOfScalar(u8, authority[0..at], ':') == null)
            {
                host = authority[0..at];
                port = std.fmt.parseInt(u16, authority[at + 1 ..], 10) catch
                    return error.InvalidProbe;
            }
        }
        const bare = if (bracketed) host[1 .. host.len - 1] else host;
        if (port == 0) return error.InvalidProbe;
        const address = std.Io.net.IpAddress.parse(bare, port) catch return error.InvalidProbe;
        return .{ .address = address, .host = host };
    }

    fn validateProxy(self: *const ConsoleConfig) Error!void {
        if (self.trusted_proxy_count == 0) return error.TrustedProxyRequired;
        if (self.trusted_proxy_count > self.trusted_proxies.len) return error.TooManyProxies;
        if (self.origin.len > self.origin.data.len) return error.InvalidOrigin;
        const origin = self.origin.slice();
        if (!std.mem.startsWith(u8, origin, "https://")) return error.InvalidOrigin;
        const authority = origin[8..];
        if (authority.len == 0) return error.InvalidOrigin;
        for (authority) |c| {
            if (c <= 32 or c >= 127 or std.mem.indexOfScalar(u8, "/?#@%\\", c) != null)
                return error.InvalidOrigin;
        }
        const uri = std.Uri.parse(origin) catch return error.InvalidOrigin;
        if (uri.host == null or uri.host.?.isEmpty() or
            uri.user != null or uri.password != null or uri.port == 0)
            return error.InvalidOrigin;
        for (self.trusted_proxies[0..self.trusted_proxy_count]) |proxy| {
            if (proxy.len > proxy.data.len) return error.InvalidProxy;
            const text = proxy.slice();
            const slash = std.mem.lastIndexOfScalar(u8, text, '/') orelse
                return error.InvalidProxy;
            const ip = std.Io.net.IpAddress.parse(text[0..slash], 0) catch
                return error.InvalidProxy;
            const bits = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch
                return error.InvalidProxy;
            if (bits > @as(u8, if (ip == .ip4) 32 else 128)) return error.InvalidProxy;
        }
    }
};

test "off-loopback requires explicit HTTPS ingress and bounded CIDR list" {
    const t = std.testing;
    var cfg = ConsoleConfig{ .enabled = true };
    try cfg.validate(true);
    try t.expectError(error.StorageRequired, cfg.validate(false));
    cfg.host = try protocol.Bytes(45).init("0.0.0.0");
    try t.expectError(error.TrustedProxyRequired, cfg.validate(true));
    cfg.behind_proxy = true;
    cfg.origin = try protocol.Bytes(255).init("https://console.example");
    cfg.trusted_proxy_count = 1;
    cfg.trusted_proxies[0] = try protocol.Bytes(49).init("127.0.0.1/32");
    try cfg.validate(true);
    cfg.origin = try protocol.Bytes(255).init("https://console.example/path");
    try t.expectError(error.InvalidOrigin, cfg.validate(true));
}

test "advertised URLs and probe targets are explicit, numeric and unique" {
    const t = std.testing;
    var cfg = ConsoleConfig{ .enabled = true, .node_id = 1 };
    cfg.advertise = try protocol.Bytes(255).init("http://127.0.0.1:9443");
    try cfg.validate(true);
    cfg.advertise = try protocol.Bytes(255).init("https://console.example:8443");
    try cfg.validate(true);
    for ([_][]const u8{ "http://console.example", "https://a@b", "ftp://x", "https://x/y" }) |u| {
        cfg.advertise = try protocol.Bytes(255).init(u);
        try t.expectError(error.InvalidAdvertise, cfg.validate(true));
    }
    cfg.advertise = .{};
    cfg.probes[0] = .{ .node = 2, .url = try protocol.Bytes(255).init("http://127.0.0.1:8082") };
    cfg.probe_count = 1;
    try cfg.validate(true);
    const target = try ConsoleConfig.parseProbe("http://[::1]:8082");
    try t.expectEqualStrings("[::1]", target.host);
    try t.expectEqual(@as(u16, 8082), target.address.ip6.port);
    const bare = try ConsoleConfig.parseProbe("http://10.0.0.2");
    try t.expectEqual(@as(u16, 80), bare.address.ip4.port);
    for ([_][]const u8{ "https://127.0.0.1:1", "http://peer.example:1", "http://127.0.0.1:0" }) |u|
        try t.expectError(error.InvalidProbe, ConsoleConfig.parseProbe(u));
    cfg.probes[1] = .{ .node = 2, .url = try protocol.Bytes(255).init("http://127.0.0.1:8083") };
    cfg.probe_count = 2;
    try t.expectError(error.DuplicateProbe, cfg.validate(true));
    cfg.probes[1].node = 1;
    try t.expectError(error.InvalidProbe, cfg.validate(true));
}

test "proxy origin rejects unusable authorities and ambiguous encoded hosts" {
    var cfg = ConsoleConfig{ .enabled = true, .behind_proxy = true };
    cfg.trusted_proxy_count = 1;
    cfg.trusted_proxies[0] = try protocol.Bytes(49).init("::1/128");
    for ([_][]const u8{
        "https://:443",
        "https://console.example:0",
        "https://%65xample.com",
        "https://user@console.example",
    }) |origin| {
        cfg.origin = try protocol.Bytes(255).init(origin);
        try std.testing.expectError(error.InvalidOrigin, cfg.validate(true));
    }
    cfg.origin = try protocol.Bytes(255).init("https://[::1]:9443");
    try cfg.validate(true);
}

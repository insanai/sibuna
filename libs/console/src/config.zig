const std = @import("std");
const protocol = @import("console_protocol");
const Budget = @import("budget.zig").Budget;

pub const ConsoleConfig = struct {
    enabled: bool = false,
    host: protocol.Bytes(45) = .{},
    port: u16 = 9443,
    behind_proxy: bool = false,
    origin: protocol.Bytes(255) = .{},
    trusted_proxies: [16]protocol.Bytes(49) = @splat(.{}),
    trusted_proxy_count: u8 = 0,
    budget: Budget = .{},

    pub const Error = error{
        StorageRequired,
        InvalidAddress,
        InvalidOrigin,
        TrustedProxyRequired,
        InvalidProxy,
        TooManyProxies,
    } || Budget.Error;

    pub fn validate(self: *const ConsoleConfig, has_storage: bool) Error!void {
        try self.budget.validate();
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
        if (!loopback and !self.behind_proxy) return error.TrustedProxyRequired;
        if (!self.behind_proxy) return;
        try self.validateProxy();
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

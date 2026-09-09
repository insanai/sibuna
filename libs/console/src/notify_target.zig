//! Notification destinations are validated before storage and again before delivery.
//! Webhooks are HTTPS to public hosts (HTTP only to a loopback literal); syslog is
//! `host:port`. Resolved addresses are re-checked so a name cannot point at private space.
const std = @import("std");
const outbound = @import("net").outbound;
pub const Error = error{InvalidTarget};
pub const Scheme = enum { https, http };
pub const Webhook = struct { scheme: Scheme, host: outbound.Host, port: u16, path: []const u8 };
pub const Endpoint = struct { host: []const u8, port: u16 };

/// Associated data for a sealed secret: the destination target, so an envelope copied
/// onto a row with a different target cannot be opened. Known before the row has an id.
pub fn envelopeSubject(target: []const u8) u64 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("sibuna-console-notify-target-v1");
    hash.update(target);
    const digest = hash.finalResult();
    return std.mem.readInt(u64, digest[0..8], .little);
}

pub fn validateWebhook(url: []const u8) Error!Webhook {
    if (url.len > 512) return error.InvalidTarget;
    const scheme: Scheme = if (std.mem.startsWith(u8, url, "https://"))
        .https
    else if (std.mem.startsWith(u8, url, "http://"))
        .http
    else
        return error.InvalidTarget;
    const uri = std.Uri.parse(url) catch return error.InvalidTarget;
    if (uri.user != null or uri.password != null or uri.fragment != null)
        return error.InvalidTarget;
    var buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = (uri.getHost(&buffer) catch return error.InvalidTarget).bytes;
    if (host.len == 0 or std.mem.indexOfAny(u8, url, " \t\r\n\"'<>\\") != null)
        return error.InvalidTarget;
    const port = uri.port orelse @as(u16, if (scheme == .https) 443 else 80);
    if (port == 0) return error.InvalidTarget;
    const bare = if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']')
        host[1 .. host.len - 1]
    else
        host;
    const literal = std.Io.net.IpAddress.parse(bare, port) catch null;
    if (literal) |address| {
        if (!addressAllowed(address, scheme == .http)) return error.InvalidTarget;
    } else if (scheme == .http) return error.InvalidTarget;
    if (scheme == .https and port != 443 and port != 8443 and port < 1024)
        return error.InvalidTarget;
    var path_buffer: [256]u8 = undefined;
    const raw_path = uri.path.toRaw(&path_buffer) catch return error.InvalidTarget;
    // The caller re-derives the path from the stored URL; only its bounds matter here.
    return .{
        .scheme = scheme,
        .host = outbound.Host.init(bare) catch return error.InvalidTarget,
        .port = port,
        .path = if (raw_path.len == 0) "/" else url[url.len - remainder(url, raw_path) ..],
    };
}

fn remainder(url: []const u8, raw_path: []const u8) usize {
    // Path plus optional query, measured from the first '/' after the authority.
    const authority_start = std.mem.indexOf(u8, url, "//").? + 2;
    const slash = std.mem.indexOfScalarPos(u8, url, authority_start, '/') orelse return 0;
    _ = raw_path;
    return url.len - slash;
}

pub fn validateSyslog(text: []const u8) Error!Endpoint {
    if (text.len == 0 or text.len > 255) return error.InvalidTarget;
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    var host = text[0..colon];
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']')
        host = host[1 .. host.len - 1];
    if (host.len == 0 or std.mem.indexOfAny(u8, host, " \t\r\n/\\\"'") != null)
        return error.InvalidTarget;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidTarget;
    if (port == 0) return error.InvalidTarget;
    if (std.Io.net.IpAddress.parse(host, port) catch null) |address| {
        if (linkLocalOrMetadata(address)) return error.InvalidTarget;
    }
    return .{ .host = host, .port = port };
}

/// Public unicast only; loopback is admitted when the caller allows it (HTTP webhooks and
/// syslog collectors on the same host). Private, link-local and metadata ranges never are.
pub fn addressAllowed(address: std.Io.net.IpAddress, loopback_ok: bool) bool {
    return outbound.allowed(address, if (loopback_ok) .loopback_allowed else .public_only);
}

fn linkLocalOrMetadata(address: std.Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 169 and a.bytes[1] == 254,
        .ip6 => |a| a.bytes[0] == 0xfe and a.bytes[1] & 0xc0 == 0x80,
    };
}

test "webhook targets are https to public hosts or http to loopback literals" {
    const t = std.testing;
    const ok = try validateWebhook("https://hooks.example/notify?team=ops");
    try t.expectEqualStrings("hooks.example", ok.host.slice());
    try t.expectEqual(@as(u16, 443), ok.port);
    try t.expectEqualStrings("/notify?team=ops", ok.path);
    const local = try validateWebhook("http://127.0.0.1:8099/hook");
    try t.expectEqual(Scheme.http, local.scheme);
    try t.expectEqual(@as(u16, 8099), local.port);
    for ([_][]const u8{
        "http://hooks.example/x",   "https://user@hooks.example/x", "https://10.0.0.1/x",
        "https://169.254.169.254/", "ftp://hooks.example/x",        "https://hooks.example:22/x",
        "https://[fe80::1]/x",      "https://hooks.example/x#frag", "",
    }) |bad| try t.expectError(error.InvalidTarget, validateWebhook(bad));
}

test "syslog endpoints need a host and port and never link-local space" {
    const t = std.testing;
    const endpoint = try validateSyslog("logs.example:514");
    try t.expectEqualStrings("logs.example", endpoint.host);
    try t.expectEqual(@as(u16, 514), endpoint.port);
    try t.expectEqualStrings("::1", (try validateSyslog("[::1]:1514")).host);
    for ([_][]const u8{ "logs.example", ":514", "169.254.1.1:514", "a b:514", "x:0" }) |bad|
        try t.expectError(error.InvalidTarget, validateSyslog(bad));
}

test "decoded webhook hostnames are owned after parsing" {
    const encoded = try validateWebhook("https://%68ooks.example/notify");
    var copy = encoded;
    @memset(&copy.host.data, 0);
    try std.testing.expectEqualStrings("hooks.example", encoded.host.slice());
}

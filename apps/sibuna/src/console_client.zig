//! One-shot native management client. Each request joins its canceled I/O before any
//! borrowed payload or response buffer can be erased. It never opens application storage.
const std = @import("std");
const p = @import("console").protocol;
pub const max_response = 16 * 1024;
pub const Error = error{
    InvalidOrigin,
    InsecureOrigin,
    Canceled,
    OutOfMemory,
    Transport,
    Deadline,
    ResponseTooLarge,
    InvalidResponse,
    CredentialFile,
    CredentialPermissions,
    InvalidCredential,
};
pub const Endpoint = enum {
    login,
    logout,
    users_query,
    users_create,
    users_change,
    geo_status,
    geo_update,
    tokens_query,
    tokens_create,
    tokens_revoke,
    policies_query,
    policies_read,
    policies_import_chunk,
    policies_import_commit,
};
pub const Reply = struct { status: std.http.Status, length: usize };
const Outcome = union(enum) { reply: Error!Reply, deadline: Error!void };

pub const Session = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    origin: p.Bytes(255),
    cookie: p.Bytes(81) = .{},
    csrf: p.Bytes(64) = .{},
    bearer: p.Bytes(71) = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, origin: []const u8) Error!Session {
        try validateOrigin(origin);
        return .{
            .allocator = allocator,
            .io = io,
            .origin = p.Bytes(255).init(origin) catch return error.InvalidOrigin,
        };
    }

    pub fn deinit(self: *Session) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.cookie));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.csrf));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.bearer));
    }

    pub fn request(
        self: *Session,
        endpoint: Endpoint,
        body: []u8,
        output: *[max_response + 1]u8,
    ) Error!Reply {
        return self.requestWithin(endpoint, body, output, 20 * std.time.ns_per_s);
    }

    pub fn requestWithin(
        self: *Session,
        endpoint: Endpoint,
        body: []u8,
        output: *[max_response + 1]u8,
        timeout_ns: u64,
    ) Error!Reply {
        std.debug.assert(body.len <= 2048);
        std.debug.assert(timeout_ns <= 20 * std.time.ns_per_s);
        if (timeout_ns == 0) return error.Deadline;
        var results: [2]Outcome = undefined;
        var select: std.Io.Select(Outcome) = .init(self.io, &results);
        defer select.cancelDiscard();
        select.concurrent(.deadline, deadline, .{ self.io, timeout_ns }) catch {
            return error.Transport;
        };
        select.concurrent(.reply, exchange, .{ self, endpoint, body, output }) catch
            return error.Transport;
        return switch (select.await() catch return error.Canceled) {
            .reply => |reply| reply,
            .deadline => error.Deadline,
        };
    }
};

pub fn validateOrigin(origin: []const u8) Error!void {
    if (origin.len > 255) return error.InvalidOrigin;
    const secure = std.mem.startsWith(u8, origin, "https://");
    if (!secure and !std.mem.startsWith(u8, origin, "http://")) return error.InvalidOrigin;
    const authority = origin[if (secure) 8 else 7..];
    if (authority.len == 0) return error.InvalidOrigin;
    for (authority) |byte| {
        if (byte <= 32 or byte >= 127 or std.mem.indexOfScalar(u8, "/?#@%\\", byte) != null)
            return error.InvalidOrigin;
    }
    const uri = std.Uri.parse(origin) catch return error.InvalidOrigin;
    if (uri.host == null or uri.host.?.isEmpty() or uri.port == 0) return error.InvalidOrigin;
    if (secure) return;
    var host_buffer: [255]u8 = undefined;
    var host = uri.host.?.toRaw(&host_buffer) catch return error.InvalidOrigin;
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']')
        host = host[1 .. host.len - 1];
    const address = std.Io.net.IpAddress.parse(host, uri.port orelse 80) catch
        return error.InsecureOrigin;
    const loopback = switch (address) {
        .ip4 => |ip| ip.bytes[0] == 127,
        .ip6 => |ip| std.mem.eql(u8, &ip.bytes, &(.{0} ** 15 ++ .{1})),
    };
    if (!loopback) return error.InsecureOrigin;
}

fn exchange(
    session: *Session,
    endpoint: Endpoint,
    body: []u8,
    output: *[max_response + 1]u8,
) Error!Reply {
    var url_buffer: [320]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buffer, "{s}{s}", .{
        session.origin.slice(), path(endpoint),
    }) catch return error.InvalidOrigin;
    const uri = std.Uri.parse(url) catch return error.InvalidOrigin;
    var client: std.http.Client = .{
        .allocator = session.allocator,
        .io = session.io,
        .read_buffer_size = 16 * 1024,
        .write_buffer_size = 4096,
    };
    defer client.deinit();
    var headers = [_]std.http.Header{
        .{ .name = "Origin", .value = session.origin.slice() },
        .{ .name = "Cookie", .value = session.cookie.slice() },
        .{ .name = "X-Console-CSRF", .value = session.csrf.slice() },
    };
    if (session.bearer.len != 0) {
        std.debug.assert(session.cookie.len == 0 and session.csrf.len == 0);
        headers[1] = .{ .name = "Authorization", .value = session.bearer.slice() };
    }
    const authenticated_headers: usize = if (session.bearer.len != 0) 2 else 3;
    const header_count: usize = if (endpoint == .login) 1 else authenticated_headers;
    var request = client.request(if (endpoint == .geo_status) .GET else .POST, uri, .{
        .keep_alive = false,
        .redirect_behavior = .not_allowed,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = headers[0..header_count],
    }) catch |err| return transportError(err);
    defer request.deinit();
    if (endpoint == .geo_status) {
        std.debug.assert(body.len == 0);
        request.sendBodiless() catch return error.Transport;
    } else request.sendBodyComplete(body) catch return error.Transport;
    var response = request.receiveHead(&.{}) catch |err| return transportError(err);
    const status = response.head.status;
    if (response.head.content_encoding != .identity) return error.InvalidResponse;
    if (response.head.content_length) |length| {
        if (length > max_response) return error.ResponseTooLarge;
    }
    if (endpoint == .login and status == .ok) try captureCookie(session, response.head);
    var transfer: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &transfer);
    const reader = response.reader(&transfer);
    const length = reader.readSliceShort(output) catch return error.Transport;
    if (length > max_response) return error.ResponseTooLarge;
    return .{ .status = status, .length = length };
}

fn captureCookie(session: *Session, head: std.http.Client.Response.Head) Error!void {
    var headers = head.iterateHeaders();
    var found = false;
    const prefix = "__sibuna_console=";
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "set-cookie")) continue;
        if (!std.mem.startsWith(u8, header.value, prefix)) continue;
        const end = std.mem.indexOfScalar(u8, header.value, ';') orelse header.value.len;
        const cookie = header.value[0..end];
        if (found or cookie.len != prefix.len + 64) return error.InvalidResponse;
        for (cookie[prefix.len..]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
        session.cookie = p.Bytes(81).init(cookie) catch return error.InvalidResponse;
        found = true;
    }
    if (!found) return error.InvalidResponse;
}

fn path(endpoint: Endpoint) []const u8 {
    return switch (endpoint) {
        .login => "/console/api/login",
        .logout => "/console/api/logout",
        .users_query => "/console/api/users/query",
        .users_create => "/console/api/users/create",
        .users_change => "/console/api/users/change",
        .geo_status, .geo_update => "/console/api/geoip",
        .tokens_query => "/console/api/tokens/query",
        .tokens_create => "/console/api/tokens/create",
        .tokens_revoke => "/console/api/tokens/revoke",
        .policies_query => "/console/api/policies/query",
        .policies_read => "/console/api/policies/read",
        .policies_import_chunk => "/console/api/policies/import/chunk",
        .policies_import_commit => "/console/api/policies/import/commit",
    };
}

fn deadline(io: std.Io, timeout_ns: u64) Error!void {
    std.Io.sleep(io, .fromNanoseconds(timeout_ns), .awake) catch return error.Canceled;
}

fn transportError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.Transport,
    };
}

/// Caller owns and erases output, including bytes beyond the returned trimmed slice.
pub fn readSecret(io: std.Io, path_value: []const u8, output: []u8) Error![]const u8 {
    const before = std.Io.Dir.cwd().statFile(io, path_value, .{}) catch
        return error.CredentialFile;
    try checkFile(before, output.len);
    const file = std.Io.Dir.cwd().openFile(io, path_value, .{}) catch return error.CredentialFile;
    defer file.close(io);
    try checkFile(file.stat(io) catch return error.CredentialFile, output.len);
    var scratch: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var reader = file.reader(io, &scratch);
    const length = reader.interface.readSliceShort(output) catch return error.CredentialFile;
    if (length == output.len) return error.InvalidCredential;
    const value = std.mem.trimEnd(u8, output[0..length], "\r\n");
    if (value.len == 0) return error.InvalidCredential;
    return value;
}

fn checkFile(stat: std.Io.File.Stat, capacity: usize) Error!void {
    if (stat.kind != .file or stat.size >= capacity) return error.CredentialFile;
    if (@hasDecl(std.Io.File.Permissions, "toMode")) {
        if (stat.permissions.toMode() & 0o077 != 0) return error.CredentialPermissions;
    }
}

test "CLI origins forbid plaintext remote authorities, credentials, redirects and encodings" {
    const t = std.testing;
    try validateOrigin("http://127.0.0.1:9443");
    try validateOrigin("http://[::1]:9443");
    try validateOrigin("https://console.example:443");
    try t.expectError(error.InsecureOrigin, validateOrigin("http://localhost:9443"));
    try t.expectError(error.InsecureOrigin, validateOrigin("http://192.0.2.1:9443"));
    for ([_][]const u8{
        "https://console.example/path", "https://user@console.example", "https://a%2eb",
        "https://console.example?x=1",  "https://console.example#x",    "https://a:0",
    }) |value| try t.expectError(error.InvalidOrigin, validateOrigin(value));
}

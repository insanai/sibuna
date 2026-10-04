//! Bounded management downloads. This code allocates and must never be called by
//! a request worker. Publishers supply fixed URL/host policies; no client headers
//! or credentials are forwarded. Cancellation joins work before buffers expire.
const std = @import("std");
const Io = std.Io;
pub const maximum_bytes = 32 * 1024 * 1024;
pub const maximum_url = 2048;
pub const Error = std.http.Client.FetchError || std.http.Reader.BodyError ||
    Io.net.HostName.FromUriError || Io.ConcurrentError || Io.Cancelable || error{
    InvalidInput,
    HostRejected,
    RedirectRejected,
    DownloadDeadline,
    PublisherUnavailable,
    Capacity,
};
pub const Config = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stopping: *const std.atomic.Value(bool),
    initial_hosts: []const []const u8,
    redirect_hosts: []const []const u8 = &.{},
    deadline_ms: u32 = 120_000,
};
const Result = union(enum) { download: Error!usize, deadline: Io.Cancelable!void };

pub fn fetch(config: Config, url: []const u8, output: []u8) Error![]const u8 {
    if (output.len == 0 or output.len > maximum_bytes or config.deadline_ms == 0 or
        config.deadline_ms > 300_000 or config.initial_hosts.len == 0)
        return error.InvalidInput;
    try validateUrl(url, config.initial_hosts);
    if (config.stopping.load(.acquire)) return error.Canceled;
    var writer: Io.Writer = .fixed(output);
    var results: [2]Result = undefined;
    var select: Io.Select(Result) = .init(config.io, &results);
    // This cancellation joins the HTTP client and its TLS state, even on errors.
    // No queued worker can retain the caller's output or hostname slices afterward.
    defer select.cancelDiscard();
    const started = Io.Clock.awake.now(config.io).nanoseconds;
    try select.concurrent(.deadline, deadline, .{ config, started });
    try select.concurrent(.download, download, .{ config, url, &writer });
    return switch (try select.await()) {
        .download => |length| output[0..try length],
        .deadline => |result| blk: {
            try result;
            break :blk error.DownloadDeadline;
        },
    };
}

/// Both hops require HTTPS, the default port, exact hosts and no userinfo/fragment.
/// Signed asset query strings are allowed, but never printed in public diagnostics.
pub fn validateUrl(url: []const u8, allowed: []const []const u8) Error!void {
    if (url.len == 0 or url.len > maximum_url) return error.InvalidInput;
    const uri = try std.Uri.parse(url);
    if (!std.mem.eql(u8, uri.scheme, "https") or uri.user != null or
        uri.password != null or uri.fragment != null or (uri.port orelse 443) != 443)
        return error.HostRejected;
    var buffer: [Io.net.HostName.max_len]u8 = undefined;
    const host = try Io.net.HostName.fromUri(uri, &buffer);
    for (allowed) |name| if (std.ascii.eqlIgnoreCase(name, host.bytes)) return;
    return error.HostRejected;
}

fn download(config: Config, url: []const u8, writer: *Io.Writer) Error!usize {
    var client: std.http.Client = .{
        .allocator = config.allocator,
        .io = config.io,
        .read_buffer_size = 16 * 1024,
        .write_buffer_size = 4096,
    };
    defer client.deinit();
    var location: [maximum_url]u8 = undefined;
    const target = (try receive(&client, url, .unhandled, writer, &location)) orelse
        return writer.buffered().len;
    validateUrl(target, config.redirect_hosts) catch return error.RedirectRejected;
    var second: [maximum_url]u8 = undefined;
    if (try receive(&client, target, .not_allowed, writer, &second) != null)
        return error.RedirectRejected;
    return writer.buffered().len;
}

fn receive(
    client: *std.http.Client,
    url: []const u8,
    behavior: std.http.Client.Request.RedirectBehavior,
    writer: *Io.Writer,
    location: *[maximum_url]u8,
) Error!?[]const u8 {
    var request = try client.request(.GET, try std.Uri.parse(url), .{
        .redirect_behavior = behavior,
        .keep_alive = false,
        // Extra headers do not replace the standard client's default header.
        // Override it so publishers see exactly one identity-only negotiation.
        .headers = .{ .accept_encoding = .{ .override = "identity" } },
    });
    defer request.deinit();
    try request.sendBodiless();
    var response = try request.receiveHead(&.{});
    switch (response.head.status) {
        .ok => {},
        .moved_permanently, .found, .see_other, .temporary_redirect, .permanent_redirect => {
            const target = response.head.location orelse return error.RedirectRejected;
            if (target.len > location.len) return error.RedirectRejected;
            @memcpy(location[0..target.len], target);
            return location[0..target.len];
        },
        else => return error.PublisherUnavailable,
    }
    if (response.head.content_encoding != .identity) return error.PublisherUnavailable;
    if (response.head.content_length) |length| if (length > writer.buffer.len)
        return error.Capacity;
    var transfer: [4096]u8 = undefined;
    _ = response.reader(&transfer).streamRemaining(writer) catch |err| switch (err) {
        error.WriteFailed => return error.Capacity,
        error.ReadFailed => return response.bodyErr() orelse error.PublisherUnavailable,
    };
    return null;
}

fn deadline(config: Config, started: i96) Io.Cancelable!void {
    const limit: i96 = @as(i96, config.deadline_ms) * std.time.ns_per_ms;
    while (!config.stopping.load(.acquire)) {
        if (Io.Clock.awake.now(config.io).nanoseconds - started >= limit) return;
        try Io.sleep(config.io, .fromMilliseconds(100), .awake);
    }
    return error.Canceled;
}

test "management downloads accept exact TLS hosts and reject authority confusion" {
    const allowed = &[_][]const u8{"github.com"};
    try validateUrl("https://github.com/coreruleset/coreruleset/releases/latest", allowed);
    for ([_][]const u8{
        "http://github.com/path",
        "https://github.com:444/path",
        "https://github.com.evil.test/path",
        "https://evil.test/?next=https://github.com",
        "https://user@github.com/path",
        "https://github.com/path#fragment",
    }) |url| try std.testing.expectError(error.HostRejected, validateUrl(url, allowed));
}

test "shutdown refuses new download work and empty capacity cannot start a request" {
    var stopping: std.atomic.Value(bool) = .init(true);
    const config: Config = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .stopping = &stopping,
        .initial_hosts = &.{"github.com"},
    };
    var bytes: [16]u8 = undefined;
    try std.testing.expectError(error.Canceled, fetch(config, "https://github.com/", &bytes));
    try std.testing.expectError(error.InvalidInput, fetch(config, "https://github.com/", &.{}));
}

//! Only fixed publisher URLs are reachable. No browser-supplied destination, credentials or
//! proxy headers enter a download request. A redirect is followed once, over HTTPS only, to
//! the provider's allowlisted asset host; anything else fails closed.
const std = @import("std");
const App = @import("app.zig").App;
const geoip = @import("geoip");
pub const max_source_bytes = 32 * 1024 * 1024;
pub const checksum_bytes = 256;
const max_location = 1024;
const Result = union(enum) { download: anyerror!usize, deadline: anyerror!void };
const Behavior = std.http.Client.Request.RedirectBehavior;

/// Downloads one provider file into `output` and returns the received bytes.
pub fn fetch(
    app: *App,
    provider: geoip.Provider,
    file: u8,
    version: []const u8,
    output: []u8,
) ![]const u8 {
    var url_buffer: [geoip.provider.max_url]u8 = undefined;
    const url = try provider.url(file, version, &url_buffer);
    return fetchUrl(app, provider, url, output);
}

/// Fetches and parses the publisher's digest file for one provider file.
pub fn fetchChecksum(app: *App, provider: geoip.Provider, file: u8, version: []const u8) ![32]u8 {
    var url_buffer: [geoip.provider.max_url]u8 = undefined;
    const url = (try provider.checksumUrl(file, version, &url_buffer)) orelse
        return error.NoChecksum;
    var name_buffer: [64]u8 = undefined;
    const name = try provider.fileName(file, version, &name_buffer);
    var text: [checksum_bytes]u8 = undefined;
    const received = try fetchUrl(app, provider, url, &text);
    return geoip.provider.parseChecksumFile(received, name);
}

pub fn fetchUrl(app: *App, provider: geoip.Provider, url: []const u8, output: []u8) ![]const u8 {
    if (output.len == 0 or output.len > max_source_bytes) return error.InvalidInput;
    var writer: std.Io.Writer = .fixed(output);
    var results: [2]Result = undefined;
    var select: std.Io.Select(Result) = .init(app.io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.deadline, deadline, .{app});
    try select.concurrent(.download, download, .{ app, provider, url, &writer });
    return switch (try select.await()) {
        .download => |length| output[0..try length],
        .deadline => error.DownloadDeadline,
    };
}

fn download(
    app: *App,
    provider: geoip.Provider,
    url: []const u8,
    writer: *std.Io.Writer,
) anyerror!usize {
    var client: std.http.Client = .{ .allocator = app.gpa, .io = app.io };
    defer client.deinit();
    var location: [max_location]u8 = undefined;
    const target = (try receive(&client, url, .unhandled, writer, &location)) orelse
        return writer.buffered().len;
    const uri = try std.Uri.parse(target);
    if (!std.mem.eql(u8, uri.scheme, "https")) return error.RedirectRejected;
    var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = try uri.getHost(&host_buffer);
    if (!provider.redirectAllowed(host.bytes)) return error.RedirectRejected;
    var second: [max_location]u8 = undefined;
    if (try receive(&client, target, .not_allowed, writer, &second) != null)
        return error.RedirectRejected;
    return writer.buffered().len;
}

/// One request. A redirect status yields its target; a 200 body streams into the writer.
fn receive(
    client: *std.http.Client,
    url: []const u8,
    behavior: Behavior,
    writer: *std.Io.Writer,
    location: *[max_location]u8,
) !?[]const u8 {
    const uri = try std.Uri.parse(url);
    var request = try client.request(.GET, uri, .{
        .redirect_behavior = behavior,
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "Accept-Encoding", .value = "identity" }},
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
    var transfer: [4096]u8 = undefined;
    const reader = response.reader(&transfer);
    _ = reader.streamRemaining(writer) catch |err| switch (err) {
        error.WriteFailed => return error.Capacity,
        error.ReadFailed => return response.bodyErr() orelse error.PublisherUnavailable,
    };
    return null;
}

fn deadline(app: *App) anyerror!void {
    const start = std.Io.Clock.awake.now(app.io).nanoseconds;
    while (!app.stopping.load(.acquire)) {
        const elapsed = std.Io.Clock.awake.now(app.io).nanoseconds - start;
        if (elapsed >= 120 * std.time.ns_per_s) return;
        try std.Io.sleep(app.io, std.Io.Duration.fromMilliseconds(100), .awake);
    }
}

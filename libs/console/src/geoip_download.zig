//! Only the fixed DB-IP HTTPS publisher is reachable. No browser-supplied destination,
//! redirects, credentials or proxy headers enter the download request.
const std = @import("std");
const App = @import("app.zig").App;
const geoip = @import("geoip");
const max_bytes = geoip.gzip.max_compressed_bytes;
const Result = union(enum) { download: anyerror!usize, deadline: anyerror!void };

pub fn fetch(app: *App, version: []const u8, output: []u8) ![]const u8 {
    if (output.len != max_bytes or !geoip.Provider.dbip.versionValid(version))
        return error.InvalidInput;
    var writer: std.Io.Writer = .fixed(output);
    var results: [2]Result = undefined;
    var select: std.Io.Select(Result) = .init(app.io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.deadline, deadline, .{app});
    try select.concurrent(.download, download, .{ app, version, &writer });
    return switch (try select.await()) {
        .download => |length| output[0..try length],
        .deadline => error.DownloadDeadline,
    };
}

fn download(app: *App, version: []const u8, writer: *std.Io.Writer) anyerror!usize {
    var url_buffer: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buffer,
        "https://download.db-ip.com/free/dbip-country-lite-{s}.csv.gz",
        .{version},
    );
    var client: std.http.Client = .{ .allocator = app.gpa, .io = app.io };
    defer client.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .redirect_behavior = .not_allowed,
        .response_writer = writer,
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "Accept-Encoding", .value = "identity" }},
    });
    if (result.status != .ok) return error.PublisherUnavailable;
    return writer.buffered().len;
}

fn deadline(app: *App) anyerror!void {
    const start = std.Io.Clock.awake.now(app.io).nanoseconds;
    while (!app.stopping.load(.acquire)) {
        const elapsed = std.Io.Clock.awake.now(app.io).nanoseconds - start;
        if (elapsed >= 60 * std.time.ns_per_s) return;
        try std.Io.sleep(app.io, std.Io.Duration.fromMilliseconds(100), .awake);
    }
}

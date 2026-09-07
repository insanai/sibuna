const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");

pub fn handle(app: *App, context: *http.Context) !void {
    const user = try app.principal(context) orelse return;
    if (user.must_change) return http.fail(context, .forbidden, "CONSOLE403");
    const job = &app.geo_job;
    if (context.request.head.method == .GET) {
        job.mutex.lockUncancelable(app.io);
        const metadata = job.metadata;
        job.mutex.unlock(app.io);
        return http.json(context, .{
            .revision = metadata.revision,
            .digest = metadata.digest.slice(),
            .source_version = metadata.source_version.slice(),
            .ranges = metadata.ranges,
            .loaded_at = metadata.loaded_at,
            .status = @tagName(job.status.load(.acquire)),
            .processed_ranges = job.progress.load(.acquire),
            .source = "DB-IP IP to Country Lite",
            .license = "CC BY 4.0",
            .attribution = "https://db-ip.com",
        }, &.{});
    }
    if (context.request.head.method != .POST) return error.InvalidRequest;
    if (!user.role.allows(.manage_settings)) return http.fail(context, .forbidden, "CONSOLE403");
    try http.csrf(context, user.csrf_digest);
    const digest = try http.session(context);
    var body: [16384]u8 = undefined;
    var arena: [32768]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct {
        source_version: []const u8,
        expected_revision: u64,
        checksum: []const u8 = "",
        csv: []const u8 = "",
    }, context, &body, fixed.allocator());
    defer input.deinit();
    try job.start(.{
        .auth = .{ .session_digest = digest, .csrf_digest = user.csrf_digest, .now = app.now() },
        .expected_revision = input.value.expected_revision,
        .source_version = try p.Bytes(7).init(input.value.source_version),
        .checksum = try p.Bytes(64).init(input.value.checksum),
        .csv = try p.Bytes(8192).init(input.value.csv),
    });
    try http.json(context, .{ .accepted = true }, &.{});
}

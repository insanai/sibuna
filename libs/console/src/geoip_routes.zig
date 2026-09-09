const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");
const geoip = @import("geoip");

pub fn handle(app: *App, context: *http.Context, user: p.Principal) !void {
    const job = &app.geo_job;
    if (context.request.head.method == .GET) {
        job.mutex.lockUncancelable(app.io);
        const metadata = job.metadata;
        job.mutex.unlock(app.io);
        const provider = geoip.Provider.parse(metadata.provider.slice()) orelse .user_country;
        return http.json(context, .{
            .revision = metadata.revision,
            .digest = metadata.digest.slice(),
            .provider = provider.name(),
            .source_version = metadata.source_version.slice(),
            .source_digests = metadata.source_digests.slice(),
            .ranges = metadata.ranges,
            .loaded_at = metadata.loaded_at,
            .status = @tagName(job.status.load(.acquire)),
            .processed_ranges = job.progress.load(.acquire),
            .source = provider.title(),
            .license = provider.license(),
            .attribution = provider.attribution() orelse "",
        }, &.{});
    }
    if (context.request.head.method != .POST) return error.InvalidRequest;
    const digest = try http.session(context);
    var body: [16384]u8 = undefined;
    var arena: [32768]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct {
        provider: []const u8 = "user-country",
        source_version: []const u8,
        expected_revision: u64,
        checksum: []const u8 = "",
        csv: []const u8 = "",
    }, context, &body, fixed.allocator());
    defer input.deinit();
    if (input.value.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    try job.start(.{
        .auth = .{
            .session_digest = digest,
            .csrf_digest = user.csrf_digest,
            .require_totp = app.config.behind_proxy,
        },
        .expected_revision = input.value.expected_revision,
        .provider = try p.Bytes(p.geo.max_provider).init(input.value.provider),
        .source_version = try p.Bytes(p.geo.max_version).init(input.value.source_version),
        .checksum = try p.Bytes(64).init(input.value.checksum),
        .csv = try p.Bytes(8192).init(input.value.csv),
    });
    try http.json(context, .{ .accepted = true }, &.{});
}

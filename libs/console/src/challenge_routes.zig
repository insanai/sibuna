const std = @import("std");
const p = @import("console_protocol");
const cm = @import("store").challenge_metrics;
const http = @import("http.zig");
const App = @import("app.zig").App;

pub fn handle(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [128]u8 = undefined;
    var arena: [512]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(
        struct { bin: ?u8 = null },
        context,
        &body,
        fixed.allocator(),
    );
    defer request.deinit();
    const cfg = app.challenge_defaults;
    const selected = request.value.bin orelse configuredBin(cfg);
    return http.json(context, snapshot(
        &app.telemetry.challenges,
        cfg,
        selected,
        app.now(),
    ), &.{});
}

pub fn configuredBin(cfg: p.challenges.Defaults) u8 {
    const algorithm: cm.Algorithm = switch (cfg.algorithm) {
        .hashcash => .hashcash,
        .posw => .posw,
    };
    return @intCast(cm.index(algorithm, cfg.parameter, cfg.openings));
}

pub fn snapshot(
    metrics: *const cm.Metrics,
    configured: p.challenges.Defaults,
    selected: u8,
    now: u64,
) p.challenges.Snapshot {
    var result: p.challenges.Snapshot = .{
        .configured = configured,
        .selected = selected,
        .timestamp = now,
    };
    for (&metrics.bins, &result.bin_accepted) |*bin, *accepted| {
        accepted.* = bin.accepted.load(.monotonic);
        result.accepted +%= accepted.*;
        result.issued +%= bin.issued.load(.monotonic);
    }
    for (&metrics.causes, &result.causes) |*counter, *count| {
        count.* = counter.load(.monotonic);
        result.rejected +%= count.*;
    }
    // Totals are individually atomic observations, not a transaction or cohort ratio.
    result.submitted = metrics.submitted.load(.monotonic);
    const bin = &metrics.bins[selected];
    for (&bin.buckets, &result.buckets) |*counter, *count|
        count.* = counter.load(.monotonic);
    inline for (.{ "missing", "invalid", "wasm", "javascript", "unknown_solver" }) |name|
        @field(result, name) = @field(bin, name).load(.monotonic);
    const parameters = metrics.last_parameters.load(.monotonic);
    if (parameters & (1 << 24) != 0) result.last_issued = .{
        .algorithm = if (parameters & 1 == 0) .hashcash else .posw,
        .difficulty = 0,
        .parameter = @truncate(parameters >> 8),
        .openings = @truncate(parameters >> 16),
    };
    return result;
}

test "snapshot exposes actual issued parameters independently from configured difficulty" {
    var metrics: cm.Metrics = .{};
    metrics.issue(.posw, 13, 16);
    _ = metrics.submitted.fetchAdd(1, .monotonic);
    metrics.accept(.posw, 13, 16, .{ .milliseconds = 1 }, .wasm);
    const result = snapshot(&metrics, .{ .difficulty = 24 }, 133, 100);
    try std.testing.expectEqual(@as(u32, 24), result.configured.difficulty);
    try std.testing.expectEqual(@as(u8, 13), result.last_issued.?.parameter);
    try std.testing.expectEqual(@as(u64, 1), result.buckets[1]);
    var bytes: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    var worst = result;
    worst.bin_accepted = @splat(std.math.maxInt(u64));
    try std.json.Stringify.value(worst, .{}, &writer);
}

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

/// Retained window: durable minutes summed on the storage owner. The window ends at the
/// last sealed minute before now; a longer window continues from the returned cursor.
pub fn summary(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [512]u8 = undefined;
    var arena: [2048]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(struct {
        hours: u16 = 24,
        node: ?u32 = null,
        bin: ?u8 = null,
        before: ?struct { minute: u64, node: u32, boot: []const u8, epoch: u32 } = null,
    }, context, &body, fixed.allocator());
    defer request.deinit();
    const input = request.value;
    if (input.hours != 1 and input.hours != 24 and input.hours != 168) return error.InvalidRequest;
    const now = app.now();
    const until = now / 60 -| 1;
    var query: p.challenge_minutes.Query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .observed_at = now,
        .from_minute = until -| (@as(u64, input.hours) * 60 - 1),
        .until_minute = until,
        .node = input.node,
        .selected = input.bin orelse configuredBin(app.challenge_defaults),
    };
    if (input.before) |cursor| {
        var boot: [16]u8 = undefined;
        if (cursor.boot.len != 32) return error.InvalidRequest;
        _ = std.fmt.hexToBytes(&boot, cursor.boot) catch return error.InvalidRequest;
        query.before = .{
            .minute = cursor.minute,
            .node = cursor.node,
            .boot = boot,
            .epoch = cursor.epoch,
        };
    }
    const result = try app.request(.{ .challenge_summary = query });
    if (result == .challenge_summary) return http.json(context, result.challenge_summary, &.{});
    return http.fail(context, switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        .conflict => .conflict,
        else => .service_unavailable,
    }, "CONSOLECHALLENGE");
}

/// Per-address records over a bounded window, filtered by outcome, cause or address.
pub fn records(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [512]u8 = undefined;
    var arena: [2048]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(struct {
        hours: u16 = 24,
        node: ?u32 = null,
        outcome: ?p.challenge_records.Outcome = null,
        cause: ?u8 = null,
        address: []const u8 = "",
        before: ?struct { second: u64, id: u64 } = null,
    }, context, &body, fixed.allocator());
    defer request.deinit();
    const input = request.value;
    if (input.hours != 1 and input.hours != 24 and input.hours != 168) return error.InvalidRequest;
    const now = app.now();
    const result = try app.request(.{ .challenge_records_query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .observed_at = now,
        .from = now -| (@as(u64, input.hours) * 3600),
        .until = now,
        .node = input.node,
        .outcome = input.outcome,
        .cause = input.cause,
        .address = try p.Bytes(48).init(input.address),
        .before = if (input.before) |cursor|
            .{ .second = cursor.second, .id = cursor.id }
        else
            null,
    } });
    if (result == .challenge_records) return http.json(context, result.challenge_records, &.{});
    return failure(context, result.failed);
}

/// Adaptive-difficulty transitions over a bounded window.
pub fn difficulty(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [256]u8 = undefined;
    var arena: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(
        struct { hours: u16 = 24, node: ?u32 = null },
        context,
        &body,
        fixed.allocator(),
    );
    defer request.deinit();
    const input = request.value;
    if (input.hours != 1 and input.hours != 24 and input.hours != 168) return error.InvalidRequest;
    const now = app.now();
    const result = try app.request(.{ .challenge_difficulty_query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .observed_at = now,
        .from = now -| (@as(u64, input.hours) * 3600),
        .until = now,
        .node = input.node,
    } });
    if (result == .challenge_difficulty)
        return http.json(context, result.challenge_difficulty, &.{});
    return failure(context, result.failed);
}

fn failure(context: *http.Context, reason: p.Failure) !void {
    return http.fail(context, switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        .conflict => .conflict,
        else => .service_unavailable,
    }, "CONSOLECHALLENGE");
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

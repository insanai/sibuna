//! An authenticated bounded view of the current minute; no historical coverage is implied.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Summary = @import("space_saving.zig").Summary;
const p = @import("console_protocol").rankings;

pub fn handle(app: *App, context: *http.Context) !void {
    const credential = try http.credential(context);
    const now = app.now();
    if (!app.query_budget.allow(app.io, credential.digest, now, .query)) return error.Busy;
    if (context.request.head.method == .POST) {
        var body: [64]u8 = undefined;
        var arena: [512]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&arena);
        const query = try http.parse(p.Query, context, &body, fixed.allocator());
        defer query.deinit();
        if (query.value.node) |node| if (node != app.stats.node)
            return @import("peer_query_routes.zig").handle(app, context, .{
                .credential = credential,
                .node = node,
                .kind = .rankings,
            });
    }
    var buffer: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write(app, &writer, p.max_rows);
    return context.respond(.ok, "application/json", writer.buffered(), &.{});
}

pub fn write(app: *App, writer: *std.Io.Writer, limit: usize) !void {
    std.debug.assert(limit > 0 and limit <= p.max_rows);
    const now = app.now();
    // The minute is tens of kilobytes; keep it off the 256 KiB stream and request stacks.
    const minute = try app.gpa.create(@import("rankings.zig").Minute);
    defer app.gpa.destroy(minute);
    app.stats.rankingSnapshot(app.io, now, minute);
    const counters = minute.paths.counters[0..minute.paths.len];
    std.mem.sort(Summary.Counter, counters, {}, Summary.before);
    var rows: [p.max_rows]p.Row = undefined;
    var encoded: [p.max_rows][256]u8 = undefined;
    const count = leading(counters, limit, &rows, &encoded);
    const Referrers = @import("console_protocol").ranking_storage.Referrers;
    const hosts = minute.referrers.counters[0..minute.referrers.len];
    std.mem.sort(Referrers.Counter, hosts, {}, Referrers.before);
    var referrer_rows: [p.max_rows]p.Row = undefined;
    var referrer_encoded: [p.max_rows][256]u8 = undefined;
    const referrer_count = leading(hosts, limit, &referrer_rows, &referrer_encoded);
    return std.json.Stringify.value(p.Page{
        .node = app.stats.node,
        .boot = app.stats.boot,
        .archive = app.history.status(app.io),
        .kind = "path_prefix",
        .minute_start = now / 60 * 60,
        .snapshot_at = now,
        .first_sample = if (minute.paths.samples == 0) null else @as(?u64, minute.first_second),
        .last_sample = if (minute.paths.samples == 0) null else @as(?u64, minute.last_second),
        .retained_samples = minute.paths.samples,
        .sampling_probability = "1/64",
        .truncated_records = minute.truncated_records,
        .rejected_records = minute.rejected_records,
        .queue_loss_since_boot = app.telemetry.dropped.load(.monotonic),
        .counter_capacity = 256,
        .missing_key_bound = minute.paths.missingBound(),
        .rows = rows[0..count],
        .referrer_missing_key_bound = minute.referrers.missingBound(),
        .referrer_samples = minute.referrers.samples,
        .referrers = referrer_rows[0..referrer_count],
        .families = minute.families,
    }, .{}, writer);
}

/// Sorted counters become bounded display rows; invalid UTF-8 keys are hex encoded.
fn leading(
    counters: anytype,
    limit: usize,
    rows: *[p.max_rows]p.Row,
    encoded: *[p.max_rows][256]u8,
) usize {
    const count = @min(counters.len, limit);
    for (counters[0..count], 0..) |*counter, i| {
        const key = counter.key.slice();
        const utf8 = std.unicode.utf8ValidateSlice(key);
        if (!utf8) encodeHex(&encoded[i], key);
        rows[i] = .{
            .key = if (utf8) key else encoded[i][0 .. key.len * 2],
            .encoding = if (utf8) .utf8 else .hex,
            .estimate = counter.estimate,
            .error_bound = counter.error_bound,
        };
    }
    return count;
}

fn encodeHex(output: *[256]u8, input: []const u8) void {
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 15];
    }
}

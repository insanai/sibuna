//! An authenticated bounded view of the current minute; no historical coverage is implied.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Summary = @import("space_saving.zig").Summary;

pub fn handle(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    const now = app.now();
    if (!app.query_budget.allow(app.io, digest, now, .query)) return error.Busy;
    var minute = app.stats.rankingSnapshot(app.io, now);
    const counters = minute.paths.counters[0..minute.paths.len];
    std.mem.sort(Summary.Counter, counters, {}, Summary.before);
    const Row = struct {
        key: []const u8,
        encoding: []const u8,
        estimate: u64,
        error_bound: u64,
    };
    var rows: [12]Row = undefined;
    var encoded: [12][256]u8 = undefined;
    const count = @min(counters.len, rows.len);
    for (counters[0..count], 0..) |*counter, i| {
        const key = counter.key.slice();
        const utf8 = std.unicode.utf8ValidateSlice(key);
        if (!utf8) encodeHex(&encoded[i], key);
        rows[i] = .{
            .key = if (utf8) key else encoded[i][0 .. key.len * 2],
            .encoding = if (utf8) "utf8" else "hex",
            .estimate = counter.estimate,
            .error_bound = counter.error_bound,
        };
    }
    return http.json(context, .{
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
    }, &.{});
}

fn encodeHex(output: *[256]u8, input: []const u8) void {
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 15];
    }
}

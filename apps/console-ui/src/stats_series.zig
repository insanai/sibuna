//! Live intervals must share a boot and both clock domains; gaps never become one-second spikes.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
pub const Point = struct { second: u64 = 0, count: u64 = 0, duration_ms: u64 = 0 };

pub fn accept(state: *State, next: p.StatsSnapshot) void {
    const previous = state.stats orelse return;
    if (next.outcomes_version != 1 or previous.outcomes_version != 1 or
        std.mem.allEqual(u8, &next.boot, 0) or !std.mem.eql(u8, &previous.boot, &next.boot) or
        next.node != previous.node or next.requests < previous.requests or
        next.uptime_ms < previous.uptime_ms or next.timestamp < previous.timestamp)
    {
        state.points = @splat(.{});
        return;
    }
    const elapsed = next.uptime_ms - previous.uptime_ms;
    // A skipped UTC second, a stopped monotonic clock or a delayed observation leaves a gap.
    if (next.timestamp - previous.timestamp != 1 or elapsed == 0 or elapsed > 2000) return;
    state.points[@intCast(next.timestamp % 60)] = .{
        .second = next.timestamp,
        .count = next.requests - previous.requests,
        .duration_ms = elapsed,
    };
}

pub fn rate(point: Point) f64 {
    if (point.duration_ms == 0) return 0;
    return @as(f64, @floatFromInt(point.count)) * 1000 /
        @as(f64, @floatFromInt(point.duration_ms));
}

pub fn table(state: *const State, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const stats = state.stats orelse return;
    try writer.print("<button type=\"button\" class=\"btn btn-sm\" " ++
        "data-action=\"timeline-values\" aria-expanded=\"{}\" " ++
        "aria-controls=\"timeline-values\">Observed timeline values</button>", .{
        state.timeline_open,
    });
    if (!state.timeline_open) return writer.writeAll("<div id=\"timeline-values\" hidden></div>");
    try writer.writeAll("<div id=\"timeline-values\" data-preserve-scroll " ++
        "class=\"overflow-x-auto\" tabindex=\"0\" role=\"region\" " ++
        "aria-label=\"Scrollable timeline values\">" ++
        "<table class=\"table\"><caption>Last ten available intervals</caption><thead><tr>" ++
        "<th>Ending at</th><th>Requests</th><th>Milliseconds</th><th>Requests/s</th>" ++
        "</tr></thead><tbody>");
    var rows: usize = 0;
    for (0..60) |offset| {
        const second = stats.timestamp -| offset;
        const point = state.points[@intCast(second % 60)];
        if (point.second != second or point.duration_ms == 0) continue;
        try writer.writeAll("<tr><td>");
        try @import("events_page.zig").timestamp(writer, second);
        try writer.print("</td><td>{d}</td><td>{d}</td><td>{d:.2}</td></tr>", .{
            point.count, point.duration_ms, rate(point),
        });
        rows += 1;
        if (rows == 10) break;
    }
    if (rows == 0) try writer.writeAll("<tr><td colspan=\"4\">No consecutive observations " ++
        "with known boot and timing.</td></tr>");
    try writer.writeAll("</tbody></table></div>");
}

test "live deltas reject restarts, clock discontinuities, unknown boots and missing intervals" {
    const t = std.testing;
    const initial: p.StatsSnapshot = .{
        .outcomes_version = 1,
        .boot = @splat(1),
        .uptime_ms = 1000,
        .timestamp = 100,
        .requests = 10,
        .admitted = 10,
        .challenged = 0,
        .denied = 0,
        .origin_4xx = 0,
        .origin_5xx = 0,
        .incidents = 0,
        .incidents_dropped = 0,
        .sample_loss = 0,
        .unknown_samples = 0,
    };
    var state: State = .{ .stats = initial };
    var next = initial;
    next.uptime_ms = 2500;
    next.timestamp = 101;
    next.requests = 13;
    accept(&state, next);
    try t.expectEqual(@as(f64, 2), rate(state.points[101 % 60]));
    next.timestamp = 103;
    accept(&state, next);
    try t.expectEqual(@as(u64, 0), state.points[103 % 60].duration_ms);
    next.boot = @splat(2);
    accept(&state, next);
    for (state.points) |point| try t.expectEqual(@as(u64, 0), point.duration_ms);
    next = initial;
    next.timestamp += 1;
    next.requests = 5;
    next.uptime_ms += 1000;
    accept(&state, next);
    for (state.points) |point| try t.expectEqual(@as(u64, 0), point.duration_ms);
    next = initial;
    next.timestamp += 1;
    next.uptime_ms += 1000;
    next.outcomes_version = 0;
    accept(&state, next);
    for (state.points) |point| try t.expectEqual(@as(u64, 0), point.duration_ms);
    next = initial;
    next.timestamp -= 1;
    next.uptime_ms += 1000;
    accept(&state, next);
    for (state.points) |point| try t.expectEqual(@as(u64, 0), point.duration_ms);
}

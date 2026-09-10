//! The same sixty observations drive tiles and the expanded charts. Missing intervals
//! break the line; an observed zero is a baseline, not an absent observation.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const html = @import("html");
pub const Metric = std.meta.FieldEnum(p.dashboard.Rates);

pub fn tone(metric: Metric) []const u8 {
    return switch (metric) {
        .admitted => "sb-decision-admitted",
        .challenged => "sb-decision-challenged",
        .denied, .rate_limited => "sb-decision-denied",
        .banned => "sb-decision-banned",
        else => "sb-decision-info",
    };
}

pub fn name(metric: Metric) []const u8 {
    return switch (metric) {
        .requests => "Requests",
        .admitted => "Admitted",
        .challenged => "Challenged",
        .denied => "Denied",
        .banned => "Banned",
        .rate_limited => "Rate limited",
        .other => "Other",
        .origin_4xx => "Origin 4xx",
        .origin_5xx => "Origin 5xx",
    };
}

pub fn values(state: *const State, metric: Metric) [60]?f64 {
    var result: [60]?f64 = @splat(null);
    const stats = state.stats orelse return result;
    if ((metric == .origin_4xx or metric == .origin_5xx) and
        stats.proxy_mode != .reverse_proxy) return result;
    for (&result, 0..) |*value, i| {
        const second = stats.timestamp -| (59 - i);
        const point = state.points[@intCast(second % 60)];
        if (point.second != second) continue;
        const rates = point.outcome_rates orelse continue;
        const rate = switch (metric) {
            inline else => |key| @field(rates, @tagName(key)),
        };
        if (std.math.isFinite(rate) and rate >= 0) value.* = rate;
    }
    return result;
}

pub fn render(
    state: *const State,
    w: *std.Io.Writer,
    metric: Metric,
    label: []const u8,
) std.Io.Writer.Error!void {
    const series = values(state, metric);
    var maximum: f64 = 1;
    var observed: usize = 0;
    for (series) |value| if (value) |rate| {
        maximum = @max(maximum, rate);
        observed += 1;
    };
    try html.render(w, "<svg class=\"sb-sparkline\" viewBox=\"0 0 180 40\" role=\"img\" " ++
        "aria-label=\"{{ label }} per second, last 60 seconds; " ++
        "{{ observed }} observed intervals\">" ++
        "<path fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" d=\"", .{
        .label = label,
        .observed = observed,
    });
    var connected = false;
    for (series, 0..) |value, i| {
        const rate = value orelse {
            connected = false;
            continue;
        };
        try w.print("{c}{d},{d:.2} ", .{
            @as(u8, if (connected) 'L' else 'M'), i * 3, 38 - rate / maximum * 36,
        });
        connected = true;
    }
    try w.writeAll("\"/></svg>");
}

test "outcome sparklines leave gaps and never invent origin responses in forward auth" {
    const t = std.testing;
    var state: State = .{};
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.timestamp = 100;
    state.stats.?.proxy_mode = .reverse_proxy;
    state.points[100 % 60] = .{ .second = 100, .outcome_rates = .{} };
    state.points[98 % 60] = .{ .second = 98, .outcome_rates = .{ .admitted = 10 } };
    const admitted = values(&state, .admitted);
    try t.expectEqual(@as(?f64, 10), admitted[57]);
    try t.expect(admitted[58] == null);
    try t.expectEqual(@as(?f64, 0), admitted[59]);
    state.stats.?.proxy_mode = .forward_auth;
    for (values(&state, .origin_4xx)) |rate| try t.expect(rate == null);
}

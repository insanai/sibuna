//! Daily retained counters are distinct from live boot totals and sixty-second sparklines.
const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");
const sparkline = @import("outcome_sparkline.zig");
const comparison = @import("console_protocol").minute_summary;
const deviation = @import("deviation_display.zig");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<section class=\"sb-tiles\" aria-label=\"Request summary\">");
    const labels = [_][]const u8{
        "Requests", "Admitted",   "Challenged", "Policy denied", "Banned", "Rate limited",
        "Other",    "Origin 4xx", "Origin 5xx",
    };
    inline for (@typeInfo(sparkline.Metric).@"enum".field_names, labels) |field_name, label|
        try tile(state, w, @field(sparkline.Metric, field_name), label);
    try gaugeTile(state, w, .active_bans, "Active ban entries");
    try gaugeTile(state, w, .nodes_healthy, "Nodes healthy");
    try w.writeAll("</section>");
    if (state.stats) |stats| if (stats.proxy_mode == .forward_auth) try w.writeAll(
        "<p class=\"sb-note\">Forward auth: admitted counts authorization approvals. " ++
            "The ingress carries uploads, WebSockets and origin responses. " ++
            "Bodies omitted from authorization requests are not inspected.</p>",
    );
    try w.writeAll("<p class=\"sb-note\">Outcomes count parsed external requests once. " ++
        "Banned counts requests, not distinct addresses. Origin 4xx/5xx overlap admitted " ++
        "traffic. Counter loads are not simultaneous. Active ban entries are unexpired " ++
        "slots of the hashed ban table on contributing nodes, not distinct historical " ++
        "addresses; nodes healthy is this console's probe of configured peers plus " ++
        "itself, with unprobed peers counted separately.</p>");
}

/// Gauges are snapshot values with no retained daily history: the deviation marker stays
/// explicitly unavailable rather than comparing a level with a day's total (R9, R11).
fn gaugeTile(
    state: *const State,
    w: *Writer,
    gauge: sparkline.Gauge,
    label: []const u8,
) Writer.Error!void {
    try html.render(w, "<article class=\"sb-tile {{ tone }}\">" ++
        "<span class=\"sb-subtitle\">{{ label }}</span><strong>", .{
        .label = label,
        .tone = sparkline.gaugeTone(gauge),
    });
    if (state.stats) |stats| switch (gauge) {
        .active_bans => if (stats.active_bans) |count| {
            try @import("count_display.zig").write(w, count);
        } else try w.writeAll("Not recorded"),
        .nodes_healthy => if (stats.cluster_health) |health| {
            try w.print("{d} of {d}", .{ health.healthy, health.total() });
            if (health.unknown != 0) try w.print(" · {d} unprobed", .{health.unknown});
        } else try w.writeAll("Not recorded"),
        // Process gauges belong to the Nodes page, never to a traffic tile.
        .memory, .cpu => unreachable,
    } else try w.writeAll("—");
    try w.writeAll("</strong>");
    if (!state.kiosk and state.traffic_period.hours != 0) {
        try w.writeAll("<p class=\"sb-note\">Yesterday: ");
        try deviation.write(w, .unavailable);
        try w.writeAll("</p>");
    }
    try sparkline.renderGauge(state, w, gauge, label);
    try w.writeAll("</article>");
}

fn tile(
    state: *const State,
    w: *Writer,
    key: sparkline.Metric,
    label: []const u8,
) Writer.Error!void {
    const retained = !state.kiosk and state.traffic_period.hours != 0;
    const change: comparison.Deviation = if (retained)
        state.traffic_period.change(key)
    else
        .unavailable;
    try html.render(w, "<article class=\"sb-tile {{ tone }}{{ tint }}\">" ++
        "<span class=\"sb-subtitle\">{{ label }}</span><strong>", .{
        .label = label,
        .tone = sparkline.tone(key),
        .tint = if (deviation.tinted(change)) " sb-deviation" else "",
    });
    if (retained) {
        try retainedValue(state, w, key);
    } else try liveValue(state, w, key);
    try w.writeAll("</strong>");
    if (retained) {
        try w.writeAll("<p class=\"sb-note\">Yesterday: ");
        try deviation.write(w, change);
        try w.writeAll("</p>");
    }
    try sparkline.render(state, w, key, label);
    try w.writeAll("</article>");
}

fn retainedValue(state: *const State, w: *Writer, key: sparkline.Metric) Writer.Error!void {
    if (key == .origin_4xx or key == .origin_5xx) return w.writeAll("Not recorded");
    const totals = state.traffic_period.read(0) catch return w.writeAll("Unavailable");
    if (totals.rows == 0) return w.writeAll("—");
    try @import("count_display.zig").write(w, comparison.value(totals.counts, key));
}

fn liveValue(state: *const State, w: *Writer, key: sparkline.Metric) Writer.Error!void {
    const stats = state.stats orelse return w.writeAll("—");
    const origin = key == .origin_4xx or key == .origin_5xx;
    const separated = key == .denied or key == .banned or key == .rate_limited or key == .other;
    if (origin and stats.proxy_mode != .reverse_proxy) return w.writeAll("Not observed");
    if (separated and stats.outcomes_version != 1) return w.writeAll("Not recorded");
    const value = switch (key) {
        inline else => |field| @field(stats, @tagName(field)),
    };
    try @import("count_display.zig").write(w, value);
}

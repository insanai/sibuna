const std = @import("std");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const keys = .{ "rate_limited", "challenged", "banned" };
    const labels = .{ "Rate limiting", "Challenges", "Bans" };
    const now = if (state.stats) |stats| stats.timestamp else state.browser_time;
    var maximum: f64 = 1;
    for (state.points) |point| {
        if (point.second > now or now - point.second >= 60) continue;
        if (point.outcome_rates) |rates| inline for (keys) |key| {
            maximum = @max(maximum, @field(rates, key));
        };
    }
    var maximum_buffer: [48]u8 = undefined;
    const maximum_text = std.fmt.bufPrint(&maximum_buffer, "{d:.2}", .{maximum}) catch unreachable;
    try html.render(w, "<p class=\"sb-note\">Live outcome trends: requests per second, " ++
        "60-second window. All three charts share a maximum of {{ maximum }} requests/s. " ++
        "Gaps remain unobserved; each contributing node uses its own elapsed time.</p>" ++
        "<section class=\"sb-tiles\">", .{ .maximum = maximum_text });
    inline for (keys, labels) |key, label| {
        try html.render(w, "<article class=\"sb-panel {{ tone }}\"><h3>{{ label }}</h3>" ++
            "<svg class=\"sb-outcome-chart\" viewBox=\"0 0 360 90\" role=\"img\" " ++
            "aria-label=\"{{ label }} requests per second; values below\">", .{
            .label = label,
            .tone = @import("outcome_sparkline.zig").tone(
                @field(@import("outcome_sparkline.zig").Metric, key),
            ),
        });
        for (0..60) |index| {
            const second = now -| (59 - index);
            const point = state.points[@intCast(second % 60)];
            if (point.second != second) continue;
            const rates = point.outcome_rates orelse continue;
            const height = @field(rates, key) / maximum * 80;
            try w.print("<rect x=\"{d}\" y=\"{d:.2}\" width=\"4\" height=\"{d:.2}\" " ++
                "fill=\"currentColor\"/>", .{ index * 6, 85 - height, height });
        }
        try html.render(w, "</svg><details><summary>{{ label }} trend values</summary>" ++
            "<table class=\"table\"><thead><tr><th>Seconds ago</th>" ++
            "<th>Requests/s</th></tr></thead><tbody>", .{ .label = label });
        for (0..60) |age| {
            const second = now -| age;
            const point = state.points[@intCast(second % 60)];
            try html.render(w, "<tr><th>{{ age }}</th><td>", .{ .age = age });
            if (point.second == second and point.outcome_rates != null) {
                try w.print("{d:.2}", .{@field(point.outcome_rates.?, key)});
            } else try w.writeAll("Unobserved");
            try w.writeAll("</td></tr>");
        }
        try html.render(w, "</tbody></table></details></article>", .{});
    }
    try w.writeAll("</section>");
}

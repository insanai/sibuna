const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const counts = @import("count_display.zig");
const Writer = std.Io.Writer;

pub fn render(w: *Writer, key: []const u8, today: ?p.rule_hit_history.Today) Writer.Error!void {
    try w.writeAll("<div class=\"my-3\"><p class=\"font-semibold\">Recorded hits today (UTC)</p>");
    if (today) |value| {
        try w.writeAll("<p class=\"text-xl tabular-nums\">");
        if (value.partial) {
            try w.writeAll("Incomplete");
        } else if (value.hits) |hits| {
            try counts.write(w, hits);
        } else try w.writeAll("Unavailable");
        try w.writeAll("</p>");
        try w.writeAll("<p class=\"sb-note\">Snapshot: ");
        try @import("events_page.zig").timestamp(w, value.observed_at);
        try w.writeAll(". Refresh policies for newer observations.</p>");
        try @import("counter_sparkline.zig").render(
            w,
            &value.hours,
            "Recorded hourly matches today; gaps have no observations",
        );
        try html.render(w, "<p class=\"sb-note\">{{ complete }} complete intervals " ++
            "among {{ rows }} recorded intervals. The newest minute may still be pending.</p>", .{
            .complete = value.complete,
            .rows = value.rows,
        });
        if (value.partial or value.unconfirmed != 0) try w.writeAll("<p class=\"sb-note\">" ++
            "Coverage is incomplete or a storage acknowledgement is missing. " ++
            "Open history to inspect a bounded period.</p>");
        try table(w, value);
    } else try w.writeAll("<p>Unavailable until rule history is recorded.</p>");
    if (key.len != 0) try html.render(w, "<form data-submit=\"rule-hits-open\" class=\"my-2\">" ++
        "<input type=\"hidden\" name=\"key\" value=\"{{ key }}\">" ++
        "<button class=\"btn btn-sm\">Compare rule hits</button></form>", .{ .key = key });
    try w.writeAll("</div>");
}

fn table(w: *Writer, today: p.rule_hit_history.Today) Writer.Error!void {
    try w.writeAll("<details><summary>Hourly values</summary><div class=\"overflow-x-auto\">" ++
        "<table class=\"table table-xs\"><caption>Recorded UTC hourly cohorts</caption>" ++
        "<thead><tr><th scope=\"col\">Hour</th><th scope=\"col\">Matches</th>" ++
        "</tr></thead><tbody>");
    for (today.hours, 0..) |value, hour| {
        try w.print("<tr><th scope=\"row\">{d:0>2}:00</th><td class=\"tabular-nums\">", .{hour});
        if (value) |count| try counts.write(w, count) else try w.writeAll("Not recorded");
        try w.writeAll("</td></tr>");
    }
    try w.writeAll("</tbody></table></div></details>");
}

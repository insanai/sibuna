const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;
const timestamp = @import("events_page.zig").timestamp;
const modules = [_][]const u8{ "Inspection", "Honeypot", "Other recorded findings" };

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, "<main class=\"sb-main\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">SECURITY / STATISTICS</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Security overview</h1>" ++
        "<p class=\"sb-subtitle\">Understand findings and follow the recorded evidence.</p>" ++
        "</div><button class=\"btn btn-sm\" data-action=\"security-refresh\">" ++
        "Refresh findings</button></header>", .{});
    try @import("statistics_tabs.zig").render(true, w);
    try @import("render.zig").message(state, w);
    try @import("dashboard_scope.zig").render(state, w);
    try window(state, w);
    try requestTiles(state, w);
    try html.render(w, "<section class=\"sb-panels\"><div>", .{});
    try @import("security_outcome_charts.zig").render(state, w);
    try findings(state, w);
    try html.render(w, "</div><article class=\"sb-panel\"><h2>Live event feed</h2>", .{});
    try feed(state, w);
    try html.render(w, "</article></section><section class=\"sb-panels\">", .{});
    try ranks(state, w, true);
    try ranks(state, w, false);
    try html.render(w, "</section><article class=\"sb-panel\"><h2>Rule hits</h2>" ++
        "<p class=\"sb-note\">Not recorded. Historical incidents retain a category; " ++
        "they do not retain a terminal policy rule identifier or per-rule hit counter.</p>" ++
        "<button class=\"btn btn-sm\" data-action=\"policies\">Review policy</button>" ++
        "</article></main>", .{});
}

pub fn window(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.security_overview;
    try html.render(w, "<form id=\"security-window\" class=\"sb-filter-toolbar my-3\">" ++
        "<div class=\"sb-filter-field\">" ++
        "<label for=\"security-hours\">Recorded findings period</label>" ++
        "<select id=\"security-hours\" name=\"hours\" class=\"select select-bordered\">", .{});
    const labels = [_][]const u8{ "1 hour", "24 hours", "7 days", "30 days" };
    for ([_]u16{ 1, 24, 168, 720 }, labels) |hours, label| {
        try html.render(w, "<option value=\"{{ hours }}\"{{ selected }}>{{ label }}</option>", .{
            .hours = hours,
            .label = label,
            .selected = if (hours == model.hours) " selected" else "",
        });
    }
    try html.render(w, "</select></div><button class=\"btn\">Apply period</button></form>" ++
        "<p class=\"sb-note\">Retained findings from ", .{});
    try timestamp(w, model.request.from);
    try w.writeAll(" up to ");
    try timestamp(w, model.request.until);
    try html.render(w, " (exclusive). Counts include audit findings and may omit dropped, " ++
        "unconfirmed or expired incidents. They are not a count of blocked requests. " ++
        "Each panel queries this console's storage replica independently.</p>", .{});
    if (model.request.node == 0) {
        try w.writeAll("<p class=\"sb-note\">Findings scope: all recorded nodes.</p>");
    } else try html.render(w, "<p class=\"sb-note\">Findings scope: node {{ node }}.</p>", .{
        .node = model.request.node,
    });
    if (state.stats) |stats| try html.render(w, "<p class=\"sb-note\">" ++
        "{{ dropped }} incident queue drops since contributing node boots. " ++
        "This does not measure losses before those boots or replica lag.</p>", .{
        .dropped = stats.incidents_dropped,
    });
}

pub fn requestTiles(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, "<p class=\"sb-note\">{{ status }} · Last update {{ age }} seconds " ++
        "ago. " ++
        "Request totals cover contributing node boots. Recorded findings cover the selected " ++
        "period.</p><section class=\"sb-tiles sb-security-tiles\" " ++
        "aria-label=\"Security modules\">", .{
        .status = @import("dashboard_scope.zig").status(state),
        .age = if (state.received_at == 0) 0 else state.browser_time -| state.received_at,
    });
    const keys = .{
        "inspection", "reputation", "rate_limited",
        "challenged", "banned",     "honeypot",
    };
    const labels = .{
        "Inspection", "Reputation", "Rate limiting",
        "Challenges", "Bans",       "Honeypot",
    };
    inline for (keys, labels, 0..) |key, label, index| {
        try html.render(w, "<article class=\"sb-tile {{ tone }}\"><h3>{{ label }}</h3><strong>", .{
            .label = label,
            .tone = @import("outcome_sparkline.zig").tone(switch (index) {
                2 => .rate_limited,
                3 => .challenged,
                4 => .banned,
                else => .requests,
            }),
        });
        if (index == 0 or index == 5) {
            if (state.security_overview.loaded[0]) {
                const module: usize = if (index == 0) 0 else 1;
                const total = state.security_overview.modules[module].total;
                try @import("count_display.zig").write(w, total);
            } else try w.writeAll("Unavailable");
        } else if (index == 1) {
            try w.writeAll("Not recorded");
        } else if (index == 4) {
            try bansTile(state, w);
            continue;
        } else if (state.stats) |stats| {
            if (stats.outcomes_version == 1) {
                try @import("count_display.zig").write(w, @field(stats, key));
            } else try w.writeAll("Not recorded");
        } else try w.writeAll("Unavailable");
        try html.render(w, "</strong><p class=\"sb-note\">{{ population }}</p></article>", .{
            .population = switch (index) {
                0, 5 => "Retained findings / selected period",
                1 => "Separate decisions are not captured",
                else => "Requests / contributing node boots",
            },
        });
    }
    try html.render(w, "</section><p class=\"sb-note\">Reputation trends and source addresses " ++
        "are not recorded separately. Rate-limit, challenge and ban source addresses are not " ++
        "recorded; active ban entries are unexpired hashed table slots, not distinct " ++
        "historical addresses.</p>", .{});
}

fn bansTile(state: *const State, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse return w.writeAll("Unavailable</strong>" ++
        "<p class=\"sb-note\">Active entries / contributing node boots</p></article>");
    if (stats.active_bans) |count| {
        try @import("count_display.zig").write(w, count);
    } else try w.writeAll("Not recorded");
    try w.writeAll("</strong><p class=\"sb-note\">Active entries now; ");
    if (stats.outcomes_version == 1) {
        try @import("count_display.zig").write(w, stats.banned);
        try w.writeAll(" requests denied by bans</p></article>");
    } else try w.writeAll("denied requests not recorded</p></article>");
}

pub fn findings(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.security_overview;
    var maximum: u64 = 1;
    for (model.modules) |module| for (module.trend) |count| {
        maximum = @max(maximum, count);
    };
    for (modules, 0..) |label, index| {
        if (index == 2 and model.loaded[0] and model.modules[2].total == 0) continue;
        const module = &model.modules[index];
        try html.render(w, "<article class=\"sb-panel mb-4\"><h2>{{ label }}</h2>", .{
            .label = label,
        });
        if (!try available(state, w, 0)) {
            try w.writeAll("</article>");
            continue;
        }
        try w.writeAll("<p><strong>");
        try @import("count_display.zig").write(w, module.total);
        try w.writeAll("</strong> recorded findings</p>");
        if (!state.kiosk) try html.render(w, "<button class=\"btn btn-ghost h-auto w-full\" " ++
            "data-action=\"security-module-{{ module }}\" " ++
            "aria-label=\"Open {{ label }} events for this period\">", .{
            .module = index,
            .label = label,
        });
        try chart(w, &module.trend, maximum);
        if (!state.kiosk) try w.writeAll("</button>");
        try trendTable(w, model.request, &module.trend, maximum);
        if (state.kiosk) {
            try w.writeAll("</article>");
            continue;
        }
        try w.writeAll("<h3>Top source addresses</h3>");
        var found = false;
        for (module.sources, 0..) |entry, rank| if (entry) |row| {
            found = true;
            try html.render(w, "<p><button class=\"btn btn-ghost btn-sm\" " ++
                "data-action=\"security-source-{{ module }}-{{ rank }}\">{{ label }}" ++
                "</button> {{ count }} findings</p>", .{
                .module = index,
                .rank = rank,
                .label = row.label.slice(),
                .count = row.count,
            });
        };
        if (!found) try w.writeAll(
            "<p class=\"sb-note\">No retained findings in this period.</p>",
        );
        try w.writeAll("</article>");
    }
}

fn trendTable(
    w: *Writer,
    range: p.security.Request,
    counts: *const [p.security.buckets]u64,
    maximum: u64,
) Writer.Error!void {
    try w.writeAll("<p class=\"sb-note\">60 equal time buckets. " ++
        "All finding charts share a maximum of ");
    try @import("count_display.zig").write(w, maximum);
    try w.writeAll(" findings per bucket.</p><details><summary>Trend values</summary>" ++
        "<div class=\"overflow-x-auto\" tabindex=\"0\" role=\"region\" " ++
        "aria-label=\"Recorded finding values\"><table class=\"table\">" ++
        "<thead><tr><th>Interval begins</th><th>Findings</th></tr></thead><tbody>");
    for (counts, 0..) |count, bucket| {
        try w.writeAll("<tr><th>");
        try timestamp(w, range.from + (range.until - range.from) * bucket / counts.len);
        try w.writeAll("</th><td>");
        try @import("count_display.zig").write(w, count);
        try w.writeAll("</td></tr>");
    }
    try w.writeAll("</tbody></table></div></details>");
}

fn chart(w: *Writer, counts: *const [p.security.buckets]u64, maximum: u64) Writer.Error!void {
    try w.writeAll("<svg viewBox=\"0 0 360 90\" role=\"img\" " ++
        "aria-label=\"Recorded findings trend; values available below\">");
    for (counts, 0..) |count, index| {
        const height = @as(f64, @floatFromInt(count)) / @as(f64, @floatFromInt(maximum)) * 80;
        try w.print("<rect x=\"{d}\" y=\"{d:.2}\" width=\"4\" height=\"{d:.2}\" " ++
            "fill=\"currentColor\"/>", .{ index * 6, 85 - height, height });
    }
    try w.writeAll("</svg>");
}

fn available(state: *const State, w: *Writer, index: usize) Writer.Error!bool {
    const model = &state.security_overview;
    if (!model.loaded[index]) {
        try html.render(w, "<p role=\"status\">{{ message }}</p>", .{
            .message = if (model.failed[index])
                "Unavailable. Narrow the period or check your connection, then refresh findings."
            else
                "Loading recorded findings…",
        });
        return false;
    }
    try html.render(w, "<p class=\"sb-note\">Storage snapshot {{ age }} seconds ago.</p>", .{
        .age = state.browser_time -| model.observed_at[index],
    });
    return true;
}

fn ranks(state: *const State, w: *Writer, categories: bool) Writer.Error!void {
    try html.render(w, "<article class=\"sb-panel\"><h2>{{ heading }}</h2>", .{
        .heading = if (categories) "Attack categories" else "Attacked paths",
    });
    if (try available(state, w, if (categories) 1 else 2)) {
        const model = &state.security_overview;
        const rows = if (categories) &model.categories else &model.paths;
        if (categories) try @import("security_category_chart.zig").render(
            w,
            rows,
            model.category_total,
        );
        try html.render(w, "<table class=\"table\"><thead><tr><th>{{ heading }}</th>" ++
            "<th>Findings</th></tr></thead><tbody>", .{
            .heading = if (categories) "Category" else "Path",
        });
        for (rows, 0..) |entry, index| if (entry) |row| {
            try html.render(w, "<tr><td class=\"break-all\"><button " ++
                "class=\"btn btn-ghost btn-sm h-auto break-all\" " ++
                "data-action=\"security-{{ kind }}-{{ index }}\">{{ label }}" ++
                "</button>{{ truncated }}</td><td>{{ count }}</td></tr>", .{
                .kind = if (categories) "category" else "path",
                .index = index,
                .label = row.label.slice(),
                .truncated = if (row.truncated) " (display shortened; opens prefix)" else "",
                .count = row.count,
            });
        };
        if (rows[0] == null) try w.writeAll(
            "<tr><td colspan=\"2\">No retained findings.</td></tr>",
        );
        try html.render(w, "</tbody></table><p class=\"sb-note\">Top five from retained " ++
            "findings in this period. Audit findings are included. Path actions open a " ++
            "prefix filter; queries and fragments are redacted.</p>", .{});
    }
    try w.writeAll("</article>");
}

fn feed(state: *const State, w: *Writer) Writer.Error!void {
    const live = state.live.topics[@intFromEnum(p.Topic.events)];
    try html.render(w, "<p class=\"sb-note\">{{ status }} · Last receipt {{ age }} seconds " ++
        "ago. Eight newest available summaries from a bounded 64-record feed; " ++
        "{{ missing }} unavailable source IDs, including expired history. " ++
        "This feed is live and independent of the findings period.</p>", .{
        .status = @import("live_status.zig").status(live),
        .age = if (live.received_at == 0) 0 else state.browser_time -| live.received_at,
        .missing = live.missing_ids,
    });
    for (state.security_overview.feed) |entry| if (entry) |row| {
        try html.render(w, "<article class=\"border-b py-3\"><p><span " ++
            "class=\"badge badge-outline\">{{ category }}</span> · Node {{ node }}</p>" ++
            "<p class=\"break-all\">{{ ip }} · {{ path }}</p><p class=\"sb-note\">", .{
            .category = row.category.slice(),
            .node = row.node,
            .ip = row.ip.slice(),
            .path = row.path.slice(),
        });
        try timestamp(w, row.time);
        try html.render(w, "</p><button class=\"btn btn-sm\" " ++
            "data-action=\"events-incident-{{ id }}\">Open incident {{ id }}</button>" ++
            "</article>", .{ .id = row.id });
    };
    if (state.security_overview.feed[0] == null)
        try w.writeAll("<p class=\"sb-note\">No recent summaries available.</p>");
}

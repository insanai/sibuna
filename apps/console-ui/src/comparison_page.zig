//! Side-by-side evidence stays separate from boot totals. Layout and labels remain stable
//! while bounded pages arrive; only fully comparable windows receive a deviation marker.
const std = @import("std");
const html = @import("html");
const State = @import("state.zig").State;
const comparison = @import("minute_comparison.zig");
const Writer = std.Io.Writer;
const format = @import("count_display.zig");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    if (state.kiosk) return;
    const model = &state.comparison;
    try html.render(w, "<section class=\"sb-panel my-4\" aria-label=\"Traffic comparison\">" ++
        "<button class=\"btn btn-sm\" data-action=\"compare-toggle\" " ++
        "aria-expanded=\"{{ open }}\" aria-controls=\"traffic-comparison\">" ++
        "Compare retained traffic</button>", .{ .open = model.open });
    if (!model.open) return w.writeAll("</section>");
    try w.writeAll("<div id=\"traffic-comparison\"><h2>Compare periods and nodes</h2>");
    try controls(state, w);
    if (model.error_message.len != 0) try html.render(
        w,
        "<p role=\"status\">{{ message }}</p>",
        .{ .message = model.error_message.slice() },
    );
    if (model.started) try results(state, w);
    try w.writeAll("</div></section>");
}

fn controls(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.comparison;
    try html.render(w, "<form class=\"sb-filters\" id=\"compare-start\">" ++
        "<fieldset class=\"sb-filter-grid sb-filter-three\"" ++
        "{{ disabled }}><label class=\"sb-filter-field\"><span>Compare with</span>" ++
        "<select class=\"select\" name=\"mode\">", .{
        .disabled = if (state.paused or model.busy[0] or model.busy[1]) " disabled" else "",
    });
    const modes = @import("comparison_controller.zig").Mode;
    inline for (.{ modes.yesterday, modes.previous, modes.node }, .{
        "Same window yesterday", "Previous period", "Another node",
    }) |mode, label| try html.render(
        w,
        "<option value=\"{{ value }}\"{{ chosen }}>{{ label }}</option>",
        .{
            .value = @tagName(mode),
            .chosen = if (model.mode == mode) " selected" else "",
            .label = label,
        },
    );
    try html.render(w, "</select></label><label class=\"sb-filter-field\">" ++
        "<span>Duration (minutes)</span><input class=\"input\" type=\"number\" " ++
        "name=\"minutes\" min=\"1\" max=\"129600\" required value=\"{{ minutes }}\">" ++
        "</label><label class=\"sb-filter-field\"><span>End (minutes ago)</span>" ++
        "<input class=\"input\" type=\"number\" name=\"offset\" min=\"0\" max=\"129599\" " ++
        "required value=\"{{ offset }}\"></label>", .{
        .minutes = model.minutes,
        .offset = model.offset,
    });
    try nodes(state, w, "node", "First node", model.windows[0].node);
    try nodes(state, w, "other_node", "Second node (node comparison)", model.windows[1].node);
    try w.writeAll("<div class=\"sb-filter-actions sb-comparison-actions\">" ++
        "<button class=\"btn btn-primary\">" ++
        "Compare</button></div></fieldset></form><p class=\"sb-note\">" ++
        "Uses closed minute intervals. End 0 means the last closed minute. " ++
        "Each comparison freezes its UTC boundaries; boot totals above stay live.</p>");
}

fn nodes(
    state: *const State,
    w: *Writer,
    name: []const u8,
    label: []const u8,
    selected: u32,
) Writer.Error!void {
    try html.render(w, "<label class=\"sb-filter-field\"><span>{{ label }}</span>" ++
        "<select class=\"select\" name=\"{{ name }}\">", .{ .label = label, .name = name });
    if (state.dashboard_scope) |scope| {
        for (scope.sources) |entry| if (entry) |source| try node(w, source.node, selected);
    } else if (state.stats) |stats| try node(w, stats.node, selected);
    try w.writeAll("</select></label>");
}

fn node(w: *Writer, id: u32, selected: u32) Writer.Error!void {
    if (id == 0) return;
    try html.render(w, "<option value=\"{{ node }}\"{{ chosen }}>Node {{ node }}</option>", .{
        .node = id,
        .chosen = if (id == selected) " selected" else "",
    });
}

fn results(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.comparison;
    try w.writeAll("<div class=\"sb-panels\">");
    for (model.windows, 0..) |window, i| {
        try html.render(w, "<article><h3>{{ label }} · Node {{ node }}</h3><p>", .{
            .label = if (i == 0) "Current window" else "Reference window",
            .node = window.node,
        });
        try @import("events_page.zig").timestamp(w, window.from * 60);
        try w.writeAll(" – ");
        try @import("events_page.zig").timestamp(w, window.until * 60);
        try html.render(w, "</p><p>{{ status }} · {{ rows }} records; " ++
            "{{ complete }} complete intervals; {{ ms }} observed ms.</p></article>", .{
            .status = status(state, i),
            .rows = window.rows,
            .complete = window.complete_rows,
            .ms = window.observed_ms,
        });
    }
    try w.writeAll("</div><div class=\"overflow-x-auto\" tabindex=\"0\" role=\"region\" " ++
        "aria-label=\"Scrollable comparison\"><table class=\"table sb-comparison\">" ++
        "<thead><tr><th>Outcome</th><th>Current</th><th>Reference</th><th>Rate change</th>" ++
        "</tr></thead><tbody>");
    inline for (@typeInfo(comparison.Metric).@"enum".fields) |field|
        try metric(state, w, @enumFromInt(field.value));
    try w.writeAll("</tbody></table></div><p class=\"sb-note\">Counts include loaded records " ++
        "only. A percentage requires complete, non-overlapping, equal-duration coverage on " ++
        "both sides, using rates normalized by observed milliseconds. " ++
        "Missing history is not zero. " ++
        "Changes of at least 25% are tinted. Rule-hit history is not recorded in these totals." ++
        "</p>");
    try html.render(w, "<button class=\"btn\" data-action=\"compare-more\"{{ disabled }}>" ++
        "Continue comparison</button>", .{ .disabled = if (state.paused or model.busy[0] or
        model.busy[1] or (model.windows[0].finished and model.windows[1].finished))
        " disabled"
    else
        "" });
}

fn metric(state: *const State, w: *Writer, key: comparison.Metric) Writer.Error!void {
    const a = state.comparison.windows[0];
    const b = state.comparison.windows[1];
    // Minute format v1 has no persisted proxy mode. Origin counts cannot distinguish
    // forward-auth non-observation from a reverse proxy observing zero errors.
    const origin = key == .origin_4xx or key == .origin_5xx;
    const change: comparison.Deviation = if (origin or state.comparison.failed[0] or
        state.comparison.failed[1]) .unavailable else comparison.deviation(a, b, key);
    const tinted = switch (change) {
        .percent => |percent| @abs(percent) >= 25,
        .new => true,
        .unavailable => false,
    };
    try html.render(w, "<tr class=\"{{ tone }}{{ tint }}\"><th>{{ label }}</th><td>", .{
        .tone = @import("outcome_sparkline.zig").tone(key),
        .tint = if (tinted) " sb-deviation" else "",
        .label = switch (key) {
            .requests => "Requests",
            .admitted => "Admitted",
            .challenged => "Challenged",
            .denied => "Policy denied",
            .banned => "Banned",
            .rate_limited => "Rate limited",
            .other => "Other",
            .origin_4xx => "Origin 4xx",
            .origin_5xx => "Origin 5xx",
        },
    });
    if (origin or a.rows == 0) {
        try w.writeAll("Not available");
    } else try format.write(w, comparison.value(a.counts, key));
    try w.writeAll("</td><td>");
    if (origin or b.rows == 0) {
        try w.writeAll("Not available");
    } else try format.write(w, comparison.value(b.counts, key));
    try w.writeAll("</td><td>");
    switch (change) {
        .unavailable => try w.writeAll("Not available"),
        .new => try w.writeAll("↑ New"),
        .percent => |percent| try w.print("{s} {d:.1}%", .{
            if (percent > 0) "↑" else if (percent < 0) "↓" else "→",
            @abs(percent),
        }),
    }
    try w.writeAll("</td></tr>");
}

fn status(state: *const State, side: usize) []const u8 {
    const model = &state.comparison;
    if (model.busy[side]) return "Loading";
    if (model.failed[side]) return "Read failed";
    if (!model.windows[side].finished) return "More pages available";
    return if (model.windows[side].covered()) "Complete coverage" else "Incomplete coverage";
}

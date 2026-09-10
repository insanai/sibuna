//! Exact recorded counts and visible coverage, with the same responsive form grid as other pages.
const std = @import("std");
const html = @import("html");
const wire = @import("console_protocol").rule_hit_history;
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const counts = @import("count_display.zig");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.rule_history;
    const input = &model.inputs;
    try html.render(w, @embedFile("snippets/rule-hit-header.html"), .{
        .key = input.key.slice(),
    });
    try html.render(w, @embedFile("snippets/rule-hit-form.html"), .{
        .disabled = if (model.busy or state.paused) " disabled" else "",
        .previous = if (input.mode == .previous) " selected" else "",
        .edit = if (input.mode == .edit) " selected" else "",
        .edit_disabled = if (input.edit_at == 0) " disabled" else "",
        .minutes = input.minutes,
        .offset = input.offset,
        .node = input.node,
        .before_revision = input.before_revision.slice(),
        .after_revision = input.after_revision.slice(),
    });
    if (input.edit_at != 0) {
        try w.writeAll("<p>Selected edit: ");
        try @import("events_page.zig").timestamp(w, input.edit_at);
        try w.writeAll("</p>");
    }
    try w.writeAll("<p class=\"sb-note\">Matches include WEIGH rules and the first matching " ++
        "terminal rule. Early inspection and reputation decisions do not evaluate those rules. " ++
        "Private tests do not count. Around an edit, the edit minute is excluded and both " ++
        "periods use the available closed minutes, up to the selected duration. Empty revision " ++
        "fields include all applied revisions. End 0 selects the last closed minute.</p>");
    if (model.message.len != 0) try html.render(
        w,
        "<p role=\"status\">{{ message }}</p>",
        .{ .message = model.message.slice() },
    );
    if (model.started) {
        try w.writeAll("<div class=\"sb-panels\">");
        for (&model.windows, 0..) |*window, side| try period(w, window, side);
        try w.writeAll("</div>");
        try deviation(w, &model.windows);
        try html.render(w, "<button class=\"btn\" data-action=\"rule-hits-more\"" ++
            "{{ disabled }}>Continue history scan</button><p class=\"sb-note\">" ++
            "Each action reads at most sixteen bounded pages. Continuing preserves the " ++
            "original rule, node, revisions and UTC periods.</p>", .{
            .disabled = if (model.busy or (model.windows[0].finished and
                model.windows[1].finished)) " disabled" else "",
        });
    }
    try w.writeAll("</section></main>");
}

fn period(w: *Writer, window: *const wire.Window, side: usize) Writer.Error!void {
    try html.render(w, "<article><h3>{{ side }} · Node {{ node }}</h3><p>", .{
        .side = if (side == 0) "Before" else "After",
        .node = window.request.node,
    });
    try @import("events_page.zig").timestamp(w, window.request.from_minute * 60);
    try w.writeAll(" – ");
    try @import("events_page.zig").timestamp(w, (window.request.until_minute + 1) * 60);
    try w.writeAll("</p><p class=\"text-2xl tabular-nums\">");
    if (window.rows == 0) {
        try w.writeAll("Not recorded");
    } else if (window.hits) |hits| {
        try counts.write(w, hits);
        try w.writeAll(" recorded matches");
    } else try w.writeAll("Count unavailable");
    try w.writeAll("</p>");
    var values: [wire.bin_count]?u64 = undefined;
    var count: usize = 0;
    for (window.bins, 0..) |bin, index| {
        if (wire.binRange(window.request, index) == null) continue;
        values[count] = if (bin.rows == 0) null else bin.hits;
        count += 1;
    }
    try @import("counter_sparkline.zig").render(
        w,
        values[0..count],
        "Recorded matches over this period; gaps have no observations",
    );
    try html.render(w, "<p class=\"sb-note\">{{ status }} · {{ complete }} complete intervals " ++
        "among {{ rows }} recorded. Retention: {{ days }} days.</p>", .{
        .status = if (window.covered()) "Complete coverage" else "Incomplete coverage",
        .complete = window.complete,
        .rows = window.rows,
        .days = window.retention_days orelse 0,
    });
    if (window.min_revision) |revision| try html.render(
        w,
        "<p>Applied revisions: {{ first }}–{{ last }}</p>",
        .{ .first = revision, .last = window.max_revision.? },
    );
    if (!window.finished) try w.writeAll("<p>More history remains to be read.</p>");
    if (window.ambiguous) try w.writeAll("<p>Overlapping generations or boots are present.</p>");
    if (window.clipped) try w.writeAll("<p>Retention removed part of this period.</p>");
    if (window.unconfirmed != 0) try w.writeAll("<p>A storage acknowledgement was missing " ++
        "during this boot. Missing intervals cannot be assumed to contain zero matches.</p>");
    try bins(w, window);
    try w.writeAll("</article>");
}

fn bins(w: *Writer, window: *const wire.Window) Writer.Error!void {
    try w.writeAll("<details><summary>Recorded values</summary><div class=\"overflow-x-auto\">" ++
        "<table class=\"table table-sm\"><caption>UTC interval cohorts, oldest first</caption>" ++
        "<thead><tr><th scope=\"col\">Period start</th><th scope=\"col\">Matches</th>" ++
        "<th scope=\"col\">Complete / recorded</th></tr></thead><tbody>");
    for (window.bins, 0..) |bin, index| {
        const range = wire.binRange(window.request, index) orelse continue;
        try w.writeAll("<tr><th scope=\"row\">");
        try @import("events_page.zig").timestamp(w, range.from_minute * 60);
        try w.writeAll("</th><td class=\"tabular-nums\">");
        if (bin.rows == 0) {
            try w.writeAll("Not recorded");
        } else if (bin.hits) |value| {
            try counts.write(w, value);
        } else try w.writeAll("Unavailable");
        try w.print("</td><td>{d} / {d}</td></tr>", .{ bin.complete, bin.rows });
    }
    try w.writeAll("</tbody></table></div></details>");
}

fn deviation(w: *Writer, windows: *const [2]wire.Window) Writer.Error!void {
    if (!windows[0].covered() or !windows[1].covered())
        return w.writeAll("<p>Deviation needs complete coverage in both periods.</p>");
    const before = windows[0].hits.?;
    const after = windows[1].hits.?;
    if (before == 0) return w.writeAll("<p>Percentage change has no nonzero reference.</p>");
    const difference = if (after >= before) after - before else before - after;
    const percent = @as(f64, @floatFromInt(difference)) * 100 / @as(f64, @floatFromInt(before));
    const sign = if (after >= before) "+" else "−";
    try w.print("<p>Recorded matches: {s}{d:.2}% from the before period.</p>", .{ sign, percent });
}

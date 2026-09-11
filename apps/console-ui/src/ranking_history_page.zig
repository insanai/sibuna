//! Side-by-side sample bounds; absent keys are bounded, never silently reported as zero.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Window = @import("ranking_history_state.zig").Window;
const Writer = std.Io.Writer;
const counts = @import("count_display.zig");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    if (state.kiosk) return;
    const model = &state.ranking_history;
    try html.render(w, "<section class=\"sb-panel my-4\" " ++
        "aria-label=\"Historical path rankings\">" ++
        "<button class=\"btn btn-sm\" data-action=\"rank-history-toggle\" " ++
        "aria-expanded=\"{{ open }}\" aria-controls=\"ranking-history\">" ++
        "Compare retained path rankings</button>", .{ .open = model.open });
    if (!model.open) return w.writeAll("</section>");
    try w.writeAll("<div id=\"ranking-history\"><h2>Retained path rankings</h2>");
    try html.render(w, @embedFile("snippets/ranking-history-form.html"), .{
        .disabled = if (model.busy or state.paused) " disabled" else "",
        .previous = if (model.inputs.mode == .previous) " selected" else "",
        .yesterday = if (model.inputs.mode == .yesterday) " selected" else "",
        .node_mode = if (model.inputs.mode == .node) " selected" else "",
        .minutes = model.inputs.minutes,
        .offset = model.inputs.offset,
        .node = model.inputs.node,
        .other_node = model.inputs.other_node,
    });
    try w.writeAll("<p class=\"sb-note\">Compares complete retained sketches, including " ++
        "retired nodes when node 0 is selected. Sample probability 1/64; path prefixes " ++
        "are limited to 128 bytes. Empty history is unavailable, not zero traffic. " ++
        "Archives seal after the 60-second late-sample window; the newest closed minute " ++
        "may still be pending. Each action reads at most sixteen archives; " ++
        "continue to complete longer scans.</p>");
    if (model.message.len != 0) try html.render(
        w,
        "<p role=\"status\">{{ message }}</p>",
        .{ .message = model.message.slice() },
    );
    if (model.started) {
        try w.writeAll("<div class=\"sb-panels\">");
        for (&model.windows, 0..) |*window, i| try coverage(w, window, i);
        try w.writeAll("</div>");
        try table(w, &model.windows);
        try referrerTable(w, &model.windows);
        try familyTables(w, &model.windows);
        try html.render(w, "<button class=\"btn\" data-action=\"rank-history-more\"" ++
            "{{ disabled }}>Continue ranking scan</button>", .{
            .disabled = if (model.busy or state.paused or
                (model.windows[0].finished and model.windows[1].finished)) " disabled" else "",
        });
    }
    try w.writeAll("</div></section>");
}

fn coverage(w: *Writer, window: *const Window, side: usize) Writer.Error!void {
    try html.render(w, "<article><h3>{{ side }}</h3><p>Node: {{ node }} " ++
        "(0 means all retained nodes)</p><p>", .{
        .side = if (side == 0) "Current rankings" else "Reference rankings",
        .node = window.query.node orelse 0,
    });
    try @import("events_page.zig").timestamp(w, window.query.from_minute * 60);
    try w.writeAll(" – ");
    try @import("events_page.zig").timestamp(w, window.query.until_minute * 60);
    try html.render(w, "</p><p>{{ status }} · {{ archives }} archives · ", .{
        .status = if (window.finished) "Scan finished" else "Partial scan",
        .archives = window.archives,
    });
    try counts.write(w, window.summary.samples);
    try w.writeAll(" retained samples.</p><p>Truncated samples: ");
    try counts.write(w, window.truncated);
    try w.writeAll("; rejected samples: ");
    try counts.write(w, window.rejected);
    try html.render(w, ". {{ loss }}</p><p class=\"sb-note\">{{ retention }} " ++
        "Archives describe retained samples only; continuity across missing archives, " ++
        "node boots and clock changes is not established.</p></article>", .{
        .loss = lossNote(window.reported_loss),
        .retention = retentionNote(window.retention_clipped),
    });
}

fn table(w: *Writer, windows: *const [2]Window) Writer.Error!void {
    try w.writeAll("<div class=\"overflow-x-auto\"><table class=\"table\">" ++
        "<caption>Sample bounds for leading retained paths</caption>" ++
        "<thead><tr><th>Path prefix</th><th>Current lower–upper</th>" ++
        "<th>Reference lower–upper</th></tr></thead><tbody>");
    for (windows, 0..) |*window, side| {
        for (window.summary.counters[0..@min(window.summary.len, 12)]) |*counter| {
            const key = counter.key.slice();
            if (side == 1) if (windows[0].summary.find(key)) |i| if (i < 12) continue;
            try w.writeAll("<tr><th><code>");
            if (std.unicode.utf8ValidateSlice(key)) {
                try html.render(w, "{{ key }}", .{ .key = key });
            } else {
                const hex = std.fmt.bytesToHex(counter.key.data, .lower);
                try html.render(w, "hex:{{ key }}", .{ .key = hex[0 .. key.len * 2] });
            }
            try w.writeAll("</code></th>");
            for (windows) |*population| try bounds(w, population, key);
            try w.writeAll("</tr>");
        }
    }
    if (windows[0].summary.len == 0 and windows[1].summary.len == 0)
        try w.writeAll("<tr><td colspan=\"3\">No retained path samples loaded.</td></tr>");
    try w.writeAll("</tbody></table></div><p class=\"sb-note\">Bounds refer to samples in " ++
        "loaded archives, not exact request counts. Untracked keys range from zero to " ++
        "the sketch's missing-key bound. No percentage is inferred from incomplete coverage.</p>");
}

fn bounds(w: *Writer, population: *const Window, key: []const u8) Writer.Error!void {
    try w.writeAll("<td>");
    if (population.archives == 0) return w.writeAll("Not available</td>");
    const summary = &population.summary;
    const Counter = p.space_saving.Summary.Counter;
    const counter = if (summary.find(key)) |i| summary.counters[i] else Counter{
        .estimate = summary.missingBound(),
        .error_bound = summary.missingBound(),
    };
    try counts.write(w, counter.estimate - counter.error_bound);
    try w.writeAll("–");
    try counts.write(w, counter.estimate);
    try w.writeAll("</td>");
}

fn lossNote(reported: bool) []const u8 {
    if (reported) return "Queue loss reported in contributing boots; " ++
        "exact loss within this period is unavailable.";
    return "No queue loss reported by loaded archives; missing archives remain unknown.";
}

fn retentionNote(clipped: bool) []const u8 {
    if (clipped) return "Retention shortened the requested window.";
    return "The configured retention and byte quota can remove older archives.";
}

fn referrerTable(w: *Writer, windows: *const [2]Window) Writer.Error!void {
    try w.writeAll("<div class=\"overflow-x-auto\"><table class=\"table mt-6\">" ++
        "<caption>Sample bounds for leading retained referring hosts</caption>" ++
        "<thead><tr><th>Referring host</th><th>Current lower–upper</th>" ++
        "<th>Reference lower–upper</th></tr></thead><tbody>");
    for (windows, 0..) |*window, side| {
        for (window.referrers.counters[0..@min(window.referrers.len, 12)]) |*counter| {
            const key = counter.key.slice();
            if (side == 1) if (windows[0].referrers.find(key)) |i| if (i < 12) continue;
            try html.render(w, "<tr><th><code>{{ key }}</code></th>", .{ .key = key });
            for (windows) |*population| try referrerBounds(w, population, key);
            try w.writeAll("</tr>");
        }
    }
    if (windows[0].referrers.len == 0 and windows[1].referrers.len == 0)
        try w.writeAll("<tr><td colspan=\"3\">No retained referring host samples loaded; " ++
            "archives written before referrers were retained carry none.</td></tr>");
    try w.writeAll("</tbody></table></div>");
}

fn referrerBounds(w: *Writer, population: *const Window, key: []const u8) Writer.Error!void {
    try w.writeAll("<td>");
    if (population.extended == 0) return w.writeAll("Not available</td>");
    const summary = &population.referrers;
    const Counter = p.ranking_storage.Referrers.Counter;
    const counter = if (summary.find(key)) |i| summary.counters[i] else Counter{
        .estimate = summary.missingBound(),
        .error_bound = summary.missingBound(),
    };
    try counts.write(w, counter.estimate - counter.error_bound);
    try w.writeAll("–");
    try counts.write(w, counter.estimate);
    try w.writeAll("</td>");
}

fn familyTables(w: *Writer, windows: *const [2]Window) Writer.Error!void {
    const family = p.client_family;
    try html.render(w, "<p class=\"sb-note\">Client families and response status are exact " ++
        "counts over retained samples in {{ current }} current and {{ reference }} reference " ++
        "archives that carry them.</p><div class=\"sb-panels\">", .{
        .current = windows[0].extended,
        .reference = windows[1].extended,
    });
    inline for (.{ "os", "browser", "status" }, .{
        "Operating system", "Browser", "Response status",
    }) |name, title| {
        try html.render(w, "<div class=\"overflow-x-auto\"><table class=\"table\">" ++
            "<caption>{{ title }}</caption><thead><tr><th>Label</th><th>Current</th>" ++
            "<th>Reference</th></tr></thead><tbody>", .{ .title = title });
        var shown: usize = 0;
        const current = &@field(windows[0].families, name);
        const reference = &@field(windows[1].families, name);
        for (current, reference, 0..) |a, b, slot| {
            if (a == 0 and b == 0) continue;
            shown += 1;
            var buffer: [8]u8 = undefined;
            const label = if (comptime std.mem.eql(u8, name, "os"))
                family.osLabel(@enumFromInt(slot))
            else if (comptime std.mem.eql(u8, name, "browser"))
                family.browserLabel(@enumFromInt(slot))
            else
                family.statusLabel(slot, &buffer);
            try html.render(w, "<tr><th scope=\"row\">{{ label }}</th>", .{ .label = label });
            for ([_]u64{ a, b }, windows) |count, *population| {
                try w.writeAll("<td>");
                if (population.extended == 0) {
                    try w.writeAll("Not available");
                } else try counts.write(w, count);
                try w.writeAll("</td>");
            }
            try w.writeAll("</tr>");
        }
        if (shown == 0) try w.writeAll("<tr><td colspan=\"3\">No samples loaded.</td></tr>");
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</div>");
}

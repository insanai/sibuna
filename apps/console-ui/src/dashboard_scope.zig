//! Live scope is independent of retained HTTP history, whose source is labelled explicitly.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;

pub fn status(state: *const State) []const u8 {
    if (state.paused) return "Paused";
    if (state.stale) {
        if (state.dashboard_scope) |scope| if (scope.stale) return "Stale";
        return "Disconnected";
    }
    if (state.stats != null) return "Live";
    if (state.dashboard_scope) |scope| if (!scope.available) return "Unavailable";
    return "Connecting";
}

pub fn viewName(state: *const State, buffer: *[32]u8) []const u8 {
    if (state.dashboard_node) |node|
        return std.fmt.bufPrint(buffer, "Node {d}", .{node}) catch unreachable;
    if (state.dashboard_scope) |scope| if (scope.count > 1) return "All configured nodes";
    if (state.stats) |stats|
        return std.fmt.bufPrint(buffer, "Node {d}", .{stats.node}) catch unreachable;
    return "Waiting for observations";
}

pub fn select(state: *State, text: []const u8) !void {
    const node = try std.fmt.parseInt(u32, text, 10);
    const scope = state.dashboard_scope orelse return error.Unavailable;
    if (node != 0) {
        var found = false;
        for (scope.sources) |item| if (item) |source| {
            found = found or source.node == node;
        };
        if (!found) return error.UnknownNode;
    }
    state.dashboard_node = if (node == 0) null else node;
    state.stats = null;
    state.points = @splat(.{});
    state.stale = false;
}

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const scope = state.dashboard_scope orelse return;
    if (scope.count <= 1) return;
    try html.render(w, @embedFile("snippets/dashboard-scope.html"), .{});
    try option(w, 0, state.dashboard_node == null, "All configured nodes");
    for (scope.sources) |entry| if (entry) |source| {
        var buffer: [32]u8 = undefined;
        const label = std.fmt.bufPrint(&buffer, "Node {d}", .{source.node}) catch unreachable;
        try option(w, source.node, state.dashboard_node == source.node, label);
    };
    try html.render(w, "</select><button class=\"btn btn-sm\">Apply view</button></form>" ++
        "<p class=\"sb-note\">{{ contributing }} / {{ count }} nodes contribute. " ++
        "Stale, unavailable or clock-skewed nodes remain outside totals. " ++
        "Totals cover each contributing node's current boot. " ++
        "Country windows cover 60 seconds ending at each source's observed time.</p>", .{
        .contributing = scope.contributing,
        .count = scope.count,
    });
    if (!scope.available) try html.render(
        w,
        "<p role=\"status\">{{ reason }}</p>",
        .{ .reason = if (scope.overflow)
            "Totals exceed the supported counter range."
        else
            "No observation is available for this view." },
    );
    if (scope.selected == 0) try html.render(
        w,
        "<p class=\"sb-note\">Country counts are lower bounds; omitted source rankings " ++
            "add at most {{ traffic }} samples or {{ incidents }} findings to any country. " ++
            "Incident geography: {{ recorded }} contributing nodes.</p>",
        .{
            .traffic = scope.traffic_uncertainty,
            .incidents = scope.incident_uncertainty,
            .recorded = scope.incident_contributing,
        },
    );
    try html.render(w, "<details><summary>Node coverage and locations</summary>" ++
        "<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>" ++
        "<th>Node</th><th>Status</th><th>Receipt age</th><th>Clock skew</th>" ++
        "<th>GeoIP / findings</th><th>Window ending (UTC)</th>" ++
        "<th>Location</th></tr></thead><tbody>", .{});
    for (scope.sources) |entry| if (entry) |source| try row(state, source, w);
    try html.render(w, "</tbody></table></div></details>", .{});
}

fn row(state: *const State, source: p.dashboard.Source, w: *Writer) Writer.Error!void {
    try html.render(w, "<tr><td>{{ node }}</td><td>{{ status }}</td><td>", .{
        .node = source.node,
        .status = if (source.clock_skew_seconds != null and source.clock_skew_seconds.? > 2)
            "clock skew"
        else
            @tagName(source.status),
    });
    if (source.age_seconds) |age| try w.print("{d} s", .{
        age +| (state.browser_time -| state.received_at),
    }) else try w.writeAll(
        "unobserved",
    );
    try w.writeAll(
        "</td><td>",
    );
    if (source.clock_skew_seconds) |skew| {
        try w.print("{d} s", .{skew});
    } else try w.writeAll(
        "unobserved",
    );
    try html.render(w, "</td><td>{{ geo }} / {{ findings }}</td><td>", .{
        .geo = if (source.geoip_available) "available" else "unavailable",
        .findings = if (source.incident_geo_available) "recorded" else "unavailable",
    });
    if (source.window_end) |end| {
        try @import("events_page.zig").timestamp(w, end);
    } else try w.writeAll("unobserved");
    try w.writeAll("</td><td>");
    if (source.location) |location| {
        try w.print("{d:.4}, {d:.4}", .{ location.lat, location.lon });
    } else try w.writeAll(
        "not configured",
    );
    try w.writeAll(
        "</td></tr>",
    );
}

fn option(w: *Writer, node: u32, selected: bool, label: []const u8) Writer.Error!void {
    try html.render(w, "<option value=\"{{ node }}\"{{ chosen }}>{{ label }}</option>", .{
        .node = node,
        .chosen = if (selected) " selected" else "",
        .label = label,
    });
}

pub fn historyAvailable(state: *const State) bool {
    if (state.dashboard_scope) |scope| return scope.history_available;
    return if (state.stats) |stats| stats.minute_history.available else false;
}

test "node selection refuses unknown nodes and clears counters without discarding geometry" {
    const t = std.testing;
    var state: State = .{ .dashboard_scope = .{ .count = 2 }, .geometry = "retained" };
    state.dashboard_scope.?.sources[0] = .{ .node = 1 };
    state.dashboard_scope.?.sources[1] = .{ .node = 2 };
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.points[0] = .{ .count = 20, .duration_ms = 1000 };
    try t.expectError(error.UnknownNode, select(&state, "3"));
    try t.expect(state.stats != null);
    try select(&state, "2");
    try t.expectEqual(@as(?u32, 2), state.dashboard_node);
    try t.expect(state.stats == null and state.points[0].duration_ms == 0);
    try t.expectEqualStrings("retained", state.geometry.?);
    try select(&state, "0");
    try t.expect(state.dashboard_node == null);
}

test "dashboard labels distinguish missing observations from connecting and name aggregate views" {
    const t = std.testing;
    var state: State = .{};
    var buffer: [32]u8 = undefined;
    try t.expectEqualStrings("Connecting", status(&state));
    try t.expectEqualStrings("Waiting for observations", viewName(&state, &buffer));
    state.dashboard_scope = .{ .count = 3, .available = false };
    try t.expectEqualStrings("Unavailable", status(&state));
    try t.expectEqualStrings("All configured nodes", viewName(&state, &buffer));
    state.dashboard_node = 2;
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stale = true;
    try t.expectEqualStrings("Disconnected", status(&state));
    state.dashboard_scope.?.stale = true;
    try t.expectEqualStrings("Stale", status(&state));
    try t.expectEqualStrings("Node 2", viewName(&state, &buffer));
}

//! Period controls and coverage are independent of the live globe's sixty-second window.
const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");

pub fn controls(state: *const State, w: *Writer) Writer.Error!void {
    if (state.kiosk) return;
    const model = &state.traffic_period;
    try html.render(w, "<form class=\"sb-filters\" id=\"traffic-period\">" ++
        "<fieldset class=\"sb-filter-toolbar\"{{ disabled }}>" ++
        "<label class=\"sb-filter-field\"><span>Traffic period</span>" ++
        "<select class=\"select\" name=\"hours\">", .{
        .disabled = if (state.paused) " disabled" else "",
    });
    for ([_]u16{ 24, 1, 168, 2160, 0 }, [_][]const u8{
        "Last 24 hours",
        "Last hour",
        "Last 7 days",
        "Last 90 days",
        "Live boot totals",
    }) |hours, label| try html.render(
        w,
        "<option value=\"{{ hours }}\"{{ selected }}>{{ label }}</option>",
        .{
            .hours = hours,
            .selected = if (model.hours == hours) " selected" else "",
            .label = label,
        },
    );
    try html.render(w, "</select></label>" ++
        "<button class=\"btn btn-primary\"{{ busy }}>Apply period</button>" ++
        "<button class=\"btn\" type=\"button\" " ++
        "data-action=\"traffic-period-refresh\"{{ busy }}>" ++
        "Refresh period</button></fieldset></form>", .{
        .busy = if (model.busy) " disabled" else "",
    });
    if (model.hours == 0) return w.writeAll(
        "<p class=\"sb-note\">Live totals since the contributing node boots.</p>",
    );
    try w.writeAll("<p class=\"sb-note\">Tiles use retained closed-minute intervals. " ++
        "Globe and sparklines remain live, covering the last 60 seconds.</p>");
    if (!@import("dashboard_scope.zig").historyAvailable(state)) try w.writeAll(
        "<p role=\"status\">Minute history is unavailable.</p>",
    );
    if (model.count == 0) return w.writeAll(
        "<p role=\"status\">Waiting for retained traffic.</p>",
    );
    try coverage(state, w);
}

fn coverage(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.traffic_period;
    const current = model.read(0) catch return w.writeAll(
        "<p role=\"status\">Traffic counters exceed the supported range.</p>",
    );
    const previous = model.read(1) catch return w.writeAll(
        "<p role=\"status\">Reference counters exceed the supported range.</p>",
    );
    try html.render(w, "<p class=\"sb-note\">{{ status }} · {{ nodes }} selected nodes · " ++
        "{{ rows }} / {{ expected }} expected minute records. Yesterday: {{ previous }}. " ++
        "Ending-minute labels: ", .{
        .status = status(current.finished, current.complete),
        .nodes = model.count,
        .rows = current.rows,
        .expected = @as(u64, model.hours) * 60 * model.count,
        .previous = status(previous.finished, previous.complete),
    });
    const until = if (model.published) |snapshot| snapshot.until else model.until;
    try @import("events_page.zig").timestamp(w, (until - @as(u64, model.hours) * 60 + 1) * 60);
    try w.writeAll(" through ");
    try @import("events_page.zig").timestamp(w, until * 60);
    try w.writeAll(" (inclusive).</p>");
    if (model.published) |snapshot| try html.render(
        w,
        "<p class=\"sb-note\">Retained scan completed {{ age }} seconds ago. " ++
            "Refreshes one minute after completion; missing history is not zero.</p>",
        .{ .age = state.browser_time -| snapshot.completed_at },
    );
    if (model.published != null and model.completed_at == null) try w.writeAll(
        "<p class=\"sb-note\">Refreshing; showing the previous completed scan.</p>",
    );
    if (model.message.len != 0) try html.render(
        w,
        "<p role=\"status\">{{ message }}</p>",
        .{ .message = model.message.slice() },
    );
}

fn status(finished: bool, complete: bool) []const u8 {
    if (!finished) return "Loading";
    return if (complete) "Complete coverage" else "Incomplete coverage";
}

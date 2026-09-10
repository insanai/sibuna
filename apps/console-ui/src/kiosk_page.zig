//! Wall display reuses traffic and aggregate Security panels. Incident evidence and
//! management controls remain outside its statistics-only authorization scope.
const std = @import("std");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;
pub const cycle_seconds = 30;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const scope = @import("dashboard_scope.zig");
    var label_buffer: [32]u8 = undefined;
    try html.render(w, "<main class=\"sb-main min-h-screen\" data-kiosk=\"true\">" ++
        "<header class=\"sb-header\"><div><p class=\"sb-subtitle\">SIBUNA · WALL DISPLAY</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">{{ view }} · {{ mode }}</h1></div>" ++
        "<div class=\"sb-status\"><span class=\"badge badge-outline\" role=\"status\">" ++
        "{{ status }}</span><span class=\"badge badge-outline\">Expires in {{ left }} min" ++
        "</span><button class=\"btn btn-sm\" data-action=\"pause\">{{ pause }}</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"theme\">Theme</button>" ++
        "<button class=\"btn btn-sm btn-outline\" data-action=\"logout\">Exit kiosk</button>" ++
        "</div></header>", .{
        .view = scope.viewName(state, &label_buffer),
        .mode = if (state.phase == .security_overview)
            "Security"
        else if (state.globe_attacks) "Attacks" else "Traffic",
        .status = scope.status(state),
        .left = (state.kiosk_expires -| state.browser_time) / 60,
        .pause = if (state.paused) "Resume" else "Pause",
    });
    try @import("render.zig").messagePublic(state, w);
    if (state.stats != null and (state.stale or state.paused)) try html.render(
        w,
        "<p class=\"sb-note\" role=\"status\">Last update {{ age }} seconds ago.</p>",
        .{ .age = state.browser_time -| state.received_at },
    );
    try @import("dashboard_scope.zig").render(state, w);
    try @import("statistics_tabs.zig").render(state.phase == .security_overview, w);
    try html.render(w, "<button class=\"btn btn-sm my-3\" data-action=\"kiosk-cycle\" " ++
        "aria-pressed=\"{{ enabled }}\">Auto-cycle: {{ label }}</button>", .{
        .enabled = if (state.kiosk_cycle) "true" else "false",
        .label = if (state.kiosk_cycle) "On" else "Off",
    });
    if (state.phase == .security_overview) return security(state, w);
    try @import("render.zig").tilesPublic(state, w);
    try html.render(w, "<section class=\"sb-panels\"><article class=\"sb-panel\">", .{});
    try @import("globe.zig").render(state, w);
    try html.render(w, "</article><article class=\"sb-panel\"><h2>Request timeline</h2>", .{});
    try @import("timeline_panel.zig").table(state, w);
    try html.render(w, "<p class=\"sb-note\">Read-only display. " ++
        "Optional cycling changes panels every " ++
        "{{ cycle }} seconds unless motion is reduced or the display is paused.</p>" ++
        "</article></section></main>", .{ .cycle = cycle_seconds });
}

/// Cycles Traffic, Attacks and Security on the display's clock; a paused or stale display
/// and a reduced-motion preference hold the current mode.
pub fn cycle(state: *State) void {
    if (!state.kiosk or !state.kiosk_cycle or state.paused or state.stale or
        state.motion.reduced) return;
    if (state.browser_time -| state.kiosk_cycled_at < cycle_seconds) return;
    state.kiosk_cycled_at = state.browser_time;
    if (state.phase == .security_overview) {
        state.phase = .dashboard;
        state.globe_attacks = false;
    } else if (state.globe_attacks) {
        state.phase = .security_overview;
    } else state.globe_attacks = true;
}

test "kiosk cycling holds while paused, stale or with reduced motion" {
    var state: State = .{
        .phase = .dashboard,
        .kiosk = true,
        .kiosk_cycle = true,
        .browser_time = 100,
    };
    cycle(&state);
    try std.testing.expect(state.globe_attacks and state.kiosk_cycled_at == 100);
    state.browser_time = 120;
    cycle(&state);
    try std.testing.expect(state.globe_attacks);
    state.browser_time = 131;
    state.paused = true;
    cycle(&state);
    try std.testing.expect(state.globe_attacks);
    state.paused = false;
    cycle(&state);
    try std.testing.expect(state.phase == .security_overview);
    state.browser_time = 162;
    cycle(&state);
    try std.testing.expect(state.phase == .dashboard and !state.globe_attacks);
}

fn security(state: *const State, w: *Writer) Writer.Error!void {
    const page = @import("security_overview_page.zig");
    try page.window(state, w);
    try page.requestTiles(state, w);
    try html.render(w, "<section class=\"sb-panels\"><div>", .{});
    try @import("security_outcome_charts.zig").render(state, w);
    try w.writeAll("</div><div>");
    try page.findings(state, w);
    try w.writeAll("</div></section></main>");
}

pub fn action(state: *State, name: []const u8) bool {
    if (!state.kiosk or !state.fullAccess() or !std.mem.eql(u8, name, "kiosk-cycle")) return false;
    state.kiosk_cycle = !state.kiosk_cycle;
    state.kiosk_cycled_at = state.browser_time;
    return true;
}

test "kiosk Security never renders retained account evidence or investigation controls" {
    var state: State = .{ .phase = .security_overview, .kiosk = true };
    state.security_overview.loaded[0] = true;
    state.security_overview.modules[0].sources[0] = .{
        .label = try @import("console_protocol").Bytes(96).init("private-address"),
    };
    var buffer: [65536]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    const private_labels = [_][]const u8{
        "private-address", "Top source addresses", "security-module-",
        "Live event feed", "Review policy",
    };
    for (private_labels) |private|
        try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), private) == null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Security modules") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Auto-cycle: Off") != null);
}

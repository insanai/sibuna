//! Wall display: the globe, the outcome tiles and the request timeline in a full-screen
//! read-only layout. No navigation shell and no mutation controls render here; the session
//! itself cannot reach any other route.
const std = @import("std");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;
pub const cycle_seconds = 30;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const status = if (state.paused) "Paused" else if (state.stale)
        "Stale"
    else if (state.stats == null) "Connecting" else "Live";
    const node: u64 = if (state.stats) |stats| stats.node else 0;
    try html.render(w, "<main class=\"sb-main min-h-screen\" data-kiosk=\"true\">" ++
        "<header class=\"sb-header\"><div><p class=\"sb-subtitle\">SIBUNA · WALL DISPLAY</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Node {{ node }} · {{ mode }}</h1></div>" ++
        "<div class=\"sb-status\"><span class=\"badge badge-outline\" role=\"status\">" ++
        "{{ status }}</span><span class=\"badge badge-outline\">Expires in {{ left }} min" ++
        "</span><button class=\"btn btn-sm\" data-action=\"pause\">{{ pause }}</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"theme\">Theme</button>" ++
        "<button class=\"btn btn-sm btn-outline\" data-action=\"logout\">Exit kiosk</button>" ++
        "</div></header>", .{
        .node = node,
        .mode = if (state.globe_attacks) "Attacks" else "Traffic",
        .status = status,
        .left = (state.kiosk_expires -| state.browser_time) / 60,
        .pause = if (state.paused) "Resume" else "Pause",
    });
    try @import("render.zig").messagePublic(state, w);
    if (state.stats != null and (state.stale or state.paused)) try html.render(
        w,
        "<p class=\"sb-note\" role=\"status\">Last update {{ age }} seconds ago.</p>",
        .{ .age = state.browser_time -| state.received_at },
    );
    try @import("render.zig").tilesPublic(state, w);
    try html.render(w, "<section class=\"sb-panels\"><article class=\"sb-panel\">", .{});
    try @import("globe.zig").render(state, w);
    try html.render(w, "</article><article class=\"sb-panel\"><h2>Request timeline</h2>", .{});
    try @import("timeline_panel.zig").table(state, w);
    try html.render(w, "<p class=\"sb-note\">Read-only display. Modes cycle every " ++
        "{{ cycle }} seconds unless motion is reduced or the display is paused.</p>" ++
        "</article></section></main>", .{ .cycle = cycle_seconds });
}

/// Alternates Traffic and Attacks on the display's own clock; a paused or stale display
/// and a reduced-motion preference hold the current mode.
pub fn cycle(state: *State) void {
    if (!state.kiosk or state.paused or state.stale or state.motion.reduced) return;
    if (state.browser_time -| state.kiosk_cycled_at < cycle_seconds) return;
    state.kiosk_cycled_at = state.browser_time;
    state.globe_attacks = !state.globe_attacks;
}

test "kiosk cycling holds while paused, stale or with reduced motion" {
    var state: State = .{ .phase = .dashboard, .kiosk = true, .browser_time = 100 };
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
    try std.testing.expect(!state.globe_attacks);
}

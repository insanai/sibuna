const std = @import("std");
const State = @import("state.zig").State;
const Phase = @import("state.zig").Phase;
const html = @import("html");
const Writer = std.Io.Writer;

pub fn begin(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, @embedFile("snippets/shell-header.html"), .{
        .open = state.navigation_open,
    });
    const active = section(state.phase);
    const actions = .{ "dashboard", "events", "challenges", "policies", "geoip", "account" };
    const labels = .{ "Statistics", "Events", "Challenges", "Policies", "GeoIP", "Account" };
    inline for (actions, labels) |action, label| {
        try html.render(w, @embedFile("snippets/shell-item.html"), .{
            .action = action,
            .label = label,
            .current = if (std.mem.eql(u8, action, active)) "page" else "false",
            .class = if (std.mem.eql(u8, action, active)) "menu-active" else "",
        });
    }
    try html.render(w, @embedFile("snippets/shell-content.html"), .{
        .role = state.role.slice(),
    });
}

pub fn end(w: *Writer) Writer.Error!void {
    try w.writeAll("</div></div>");
}

fn section(phase: Phase) []const u8 {
    return switch (phase) {
        .events, .similarity => "events",
        .challenges => "challenges",
        .policies => "policies",
        .geoip => "geoip",
        .password, .security => "account",
        else => "dashboard",
    };
}

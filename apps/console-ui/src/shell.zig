const std = @import("std");
const State = @import("state.zig").State;
const Phase = @import("state.zig").Phase;
const html = @import("html");
const Writer = std.Io.Writer;
const actions = [_][]const u8{
    "dashboard", "events", "challenges", "policies", "geoip", "users", "account",
};
const labels = [_][]const u8{
    "Statistics", "Events", "Challenges", "Policies", "GeoIP", "Users", "Account",
};

pub fn destination(name: []const u8) bool {
    for (actions) |action| if (std.mem.eql(u8, name, action)) return true;
    return false;
}

pub fn begin(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, @embedFile("snippets/shell-header.html"), .{
        .open = state.navigation_open,
    });
    const active = section(state.phase);
    for (actions, labels) |action, label| {
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
    try html.render(w, "</div></div>", .{});
}

fn section(phase: Phase) []const u8 {
    return switch (phase) {
        .events, .similarity => "events",
        .challenges => "challenges",
        .policies => "policies",
        .geoip => "geoip",
        .users => "users",
        .password, .security => "account",
        else => "dashboard",
    };
}

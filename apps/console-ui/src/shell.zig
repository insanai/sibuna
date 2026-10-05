const std = @import("std");
const State = @import("state.zig").State;
const Phase = @import("state.zig").Phase;
const html = @import("html");
const Writer = std.Io.Writer;
pub const actions = [_][]const u8{
    "dashboard", "events", "challenges", "policies", "crs",     "geoip",             "users",
    "tokens",    "audit",  "nodes",      "settings", "account", "security-overview",
};
const labels = [_][]const u8{
    "Statistics", "Events", "Challenges", "Policies", "Core Rule Set", "GeoIP",    "Users",
    "Tokens",     "Audit",  "Nodes",      "Settings", "Account",       "Security",
};

pub fn destination(name: []const u8) bool {
    for (actions) |action| if (std.mem.eql(u8, name, action)) return true;
    return false;
}

pub fn begin(state: *const State, w: *Writer) Writer.Error!void {
    var context_buffer: [32]u8 = undefined;
    try html.render(w, @embedFile("snippets/shell-header.html"), .{
        .open = state.navigation_open,
        .console_label = context(state, &context_buffer),
    });
    const active = section(state.phase);
    for (actions, labels) |action, label| {
        if (std.mem.eql(u8, action, "security-overview")) continue;
        if (std.mem.eql(u8, action, "tokens") and !state.allows(.manage_users)) continue;
        if ((std.mem.eql(u8, action, "settings") or std.mem.eql(u8, action, "crs")) and
            !state.allows(.manage_settings)) continue;
        try html.render(w, @embedFile("snippets/shell-item.html"), .{
            .action = action,
            .label = label,
            .current = if (std.mem.eql(u8, action, active)) "page" else "false",
            .class = if (std.mem.eql(u8, action, active)) "menu-active" else "",
        });
    }
    try html.render(w, @embedFile("snippets/shell-content.html"), .{
        .role = state.role.slice(),
        .theme = @tagName(state.appearance.theme),
        .density = @tagName(state.appearance.density),
    });
}

pub fn end(w: *Writer) Writer.Error!void {
    try html.render(w, "</div></div>", .{});
}

pub fn section(phase: Phase) []const u8 {
    return switch (phase) {
        .events, .similarity => "events",
        .challenges => "challenges",
        .policies => "policies",
        .geoip => "geoip",
        .crs => "crs",
        .users => "users",
        .tokens => "tokens",
        .audit => "audit",
        .nodes => "nodes",
        .settings => "settings",
        .password, .security => "account",
        else => "dashboard",
    };
}

fn context(state: *const State, buffer: *[32]u8) []const u8 {
    const node = state.console_node orelse return "Node not reported";
    return std.fmt.bufPrint(buffer, "Console node {d}", .{node}) catch unreachable;
}

test "management identity does not follow the selected traffic node" {
    const t = std.testing;
    var state: State = .{ .console_node = 7, .dashboard_node = 2 };
    var buffer: [32]u8 = undefined;
    try t.expectEqualStrings("Console node 7", context(&state, &buffer));
    state.reset();
    try t.expect(state.console_node == null);
    try t.expectEqualStrings("Node not reported", context(&state, &buffer));
}

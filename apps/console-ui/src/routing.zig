//! Bookmarkable page routes. Authentication gates precede route dispatch; history stores
//! only public page names, never query bodies, record identifiers or credentials.
const std = @import("std");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const shell = @import("shell.zig");

pub const Model = struct {
    pending: ?[]const u8 = null,
    current: ?[]const u8 = null,
    restoring: bool = false,
};

/// Intern the untrusted fragment against fixed navigation names. No borrowed event bytes
/// survive dispatch; unknown routes resolve to the statistics landing page.
pub fn request(model: *Model, fragment: []const u8) void {
    model.pending = "dashboard";
    for (shell.actions) |name| {
        if (std.mem.eql(u8, fragment, name)) model.pending = name;
    }
    model.restoring = true;
}

pub fn take(state: *State) ?[]const u8 {
    if (!state.fullAccess()) return null;
    const name = state.route.pending orelse return null;
    state.route.pending = null;
    if (state.kiosk) return null;
    if (std.mem.eql(u8, name, "tokens") and !state.allows(.manage_users)) return "dashboard";
    if (std.mem.eql(u8, name, "settings") and !state.allows(.manage_settings)) return "dashboard";
    if (state.route.current) |current| {
        if (std.mem.eql(u8, name, current)) return null;
    }
    return name;
}

pub fn sync(state: *State, out: Outbox) !void {
    if (!state.fullAccess() or state.kiosk) return;
    const model = &state.route;
    const name = if (state.phase == .security_overview)
        "security-overview"
    else
        shell.section(state.phase);
    const changed = model.current == null or !std.mem.eql(u8, model.current.?, name);
    if (changed or model.restoring) try out.emit(.{
        .op = "history",
        .value = name,
        .replace = model.restoring or model.current == null,
    });
    model.current = name;
    model.restoring = false;
}

test "routes are interned and deferred through authentication, with role and kiosk limits" {
    const t = std.testing;
    var state: State = .{};
    var untrusted = "nodes".*;
    request(&state.route, &untrusted);
    @memset(&untrusted, 0);
    try t.expect(take(&state) == null);
    try state.csrf.set("test");
    state.must_change = true;
    try t.expect(take(&state) == null);
    state.must_change = false;
    state.totp_required = true;
    try t.expect(take(&state) == null);
    state.totp_required = false;
    try t.expectEqualStrings("nodes", take(&state).?);
    try state.role.set("viewer");
    request(&state.route, "settings");
    try t.expectEqualStrings("dashboard", take(&state).?);
    request(&state.route, "https://other.invalid/#nodes");
    try t.expectEqualStrings("dashboard", take(&state).?);
    state.kiosk = true;
    request(&state.route, "events");
    try t.expect(take(&state) == null);
}

test "history replaces restored routes and pushes only actual page changes" {
    const t = std.testing;
    var state: State = .{ .phase = .dashboard };
    try state.csrf.set("test");
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = "test" };
    try sync(&state, out);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"replace\":true") != null);
    writer = .fixed(&buffer);
    try sync(&state, out);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    state.phase = .nodes;
    try sync(&state, out);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"replace\":false") != null);
    writer = .fixed(&buffer);
    request(&state.route, "dashboard");
    try t.expectEqualStrings("dashboard", take(&state).?);
    state.phase = .dashboard;
    try sync(&state, out);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"replace\":true") != null);
}

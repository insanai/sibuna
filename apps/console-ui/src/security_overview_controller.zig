const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const fields = @import("events_state.zig");
var serial: u64 = 0;

pub fn action(state: *State, name: []const u8, value: std.json.Value, out: Outbox) !bool {
    if (!state.fullAccess()) return false;
    const open = std.mem.eql(u8, name, "security-overview");
    if (!open and state.phase != .security_overview) return false;
    if (!open and !std.mem.eql(u8, name, "security-window") and
        !std.mem.eql(u8, name, "security-refresh")) return false;
    if (std.mem.eql(u8, name, "security-window")) {
        const hours = try std.fmt.parseInt(u16, fields.string(value, "hours"), 10);
        if (hours != 1 and hours != 24 and hours != 168 and hours != 720)
            return error.InvalidRequest;
        state.security_overview.hours = hours;
    }
    state.phase = .security_overview;
    try refresh(state, out);
    return true;
}

pub fn refresh(state: *State, out: Outbox) !void {
    if (!state.fullAccess() or state.phase != .security_overview) return;
    const model = &state.security_overview;
    const hours = model.hours;
    model.clear();
    model.hours = hours;
    model.request = .{
        .node = @import("dashboard_scope.zig").selectedNode(state) orelse 0,
        .from = state.browser_time -| @as(u64, hours) * 3600,
        .until = @max(1, state.browser_time),
    };
    state.message = .{};
    // Independent pages share a frozen scope, but expose their individual observation
    // times. Serial tickets survive sign-out; an older response cannot relabel a new view.
    for (0..@as(usize, if (state.kiosk) 1 else 3)) |index| {
        serial = std.math.add(u64, serial, 1) catch return error.Capacity;
        model.tickets[index] = serial;
        model.busy[index] = true;
        var id: [48]u8 = undefined;
        const name = try std.fmt.bufPrint(&id, "security-view-{d}-{d}", .{ index, serial });
        var request = model.request;
        request.view = @enumFromInt(index);
        try out.post(name, if (state.kiosk)
            "/console/api/security/trends"
        else
            "/console/api/security/query", request);
    }
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    var parts = std.mem.splitScalar(u8, id["security-view-".len..], '-');
    const index = std.fmt.parseInt(usize, parts.next() orelse return, 10) catch return;
    const ticket = std.fmt.parseInt(u64, parts.next() orelse return, 10) catch return;
    const model = &state.security_overview;
    if (index >= 3 or parts.next() != null or ticket == 0 or ticket != model.tickets[index] or
        !state.fullAccess() or state.phase != .security_overview) return;
    model.busy[index] = false;
    if (status == 401 or status == 403) {
        try @import("live_controller.zig").stop(out);
        state.reset();
        state.phase = .login;
        try state.message.set("Your access changed. Sign in to view security statistics.");
        return;
    }
    model.failed[index] = true;
    if (status != 200) return;
    var page: p.security.Page = undefined;
    @import("json_value.zig").into(&page, body, alloc) catch return;
    if (@intFromEnum(page.request.view) != index) return;
    model.accept(&page) catch return;
}

test "security replies cannot cross query generations, view changes or sign-out" {
    const t = std.testing;
    var state: State = .{};
    var commands: @import("test_transport.zig").Commands = .{};
    try t.expect(!try action(&state, "security-overview", .null, commands.out()));
    try state.csrf.set("test");
    state.browser_time = 3600;
    try t.expect(try action(&state, "security-overview", .null, commands.out()));
    const old = state.security_overview.tickets[0];
    state.dashboard_scope = .{ .count = 2, .selected = 1 };
    state.dashboard_node = 2;
    try refresh(&state, commands.out());
    try t.expectEqual(@as(u32, 2), state.security_overview.request.node);
    var buffer: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&buffer, "security-view-0-{d}", .{old});
    try response(&state, id, 401, .null, t.allocator, commands.out());
    try t.expectEqual(.security_overview, state.phase);
    try t.expect(state.security_overview.busy[0]);
    state.reset();
    try state.csrf.set("replacement");
    try t.expect(try action(&state, "security-overview", .null, commands.out()));
    try t.expect(state.security_overview.tickets[0] != old);
    try response(&state, id, 200, .null, t.allocator, commands.out());
    try t.expect(!state.security_overview.loaded[0]);
}

test "kiosk Security requests only aggregate trends and cannot drill into evidence" {
    const t = std.testing;
    var state: State = .{ .kiosk = true, .browser_time = 3600 };
    try state.csrf.set("kiosk");
    var commands: @import("test_transport.zig").Commands = .{};
    try t.expect(try action(&state, "security-overview", .null, commands.out()));
    try t.expectEqual(@as(usize, 1), commands.count);
    const sent = commands.writer.buffered();
    try t.expect(std.mem.indexOf(u8, sent, "/console/api/security/trends") != null);
    try t.expect(std.mem.indexOf(u8, sent, "/console/api/security/query") == null);
    try t.expect(!try @import("security_investigation.zig").open(
        &state,
        "security-module-0",
    ));
}

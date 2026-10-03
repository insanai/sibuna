const repeat = @import("text").repeat;
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const grant = @import("kiosk_grant.zig");
const Harness = @import("test_transport.zig").Commands;

fn account() State {
    return .{
        .phase = .password,
        .csrf = p.Bytes(64).init("test csrf") catch unreachable,
        .role = p.Bytes(16).init("operator") catch unreachable,
        .browser_time = 100,
    };
}

fn start(state: *State, h: *Harness) !void {
    const fields = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"label\":\"Lobby\"}",
        .{},
    );
    defer fields.deinit();
    try t.expect(try grant.action(state, "kiosk-grant", fields.value, h.out()));
}

fn reply(state: *State, id: []const u8, h: *Harness) !void {
    const fields = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"code\":\"" ++
            &repeat("a", 64) ++
            "\",\"use_by\":700,\"expires\":43300}",
        .{},
    );
    defer fields.deinit();
    try grant.response(state, id, 200, fields.value, t.allocator, h.out());
}

test "wall display grant requires operator account access and cannot duplicate a pending request" {
    var state = account();
    var h: Harness = .{};
    try state.role.set("viewer");
    try start(&state, &h);
    try t.expectEqual(@as(usize, 0), h.count);
    try state.role.set("operator");
    state.must_change = true;
    try start(&state, &h);
    try t.expectEqual(@as(usize, 0), h.count);
    state.must_change = false;
    try start(&state, &h);
    try t.expect(state.kiosk_grant.busy);
    try t.expect(std.mem.indexOf(u8, h.writer.buffered(), "/console/api/kiosk/token") != null);
    try start(&state, &h);
    try t.expectEqual(@as(usize, 0), h.count);
}

test "wall display codes are erased and late responses cannot reopen them" {
    var state = account();
    var h: Harness = .{};
    try start(&state, &h);
    const ticket = state.kiosk_grant.ticket;
    try reply(&state, ticket.slice(), &h);
    try t.expectEqualStrings(&repeat("a", 64), state.kiosk_grant.code.slice());
    state.hidden = true;
    grant.retain(&state);
    try t.expectEqualSlices(u8, &@as([64]u8, @splat(0)), &state.kiosk_grant.code.data);
    state.hidden = false;
    try start(&state, &h);
    try reply(&state, ticket.slice(), &h);
    try t.expect(state.kiosk_grant.busy and state.kiosk_grant.code.len == 0);
    const active = state.kiosk_grant.ticket;
    try reply(&state, active.slice(), &h);
    state.browser_time = 700;
    grant.retain(&state);
    try t.expect(state.kiosk_grant.code.len == 0);
    state.browser_time = 100;
    try start(&state, &h);
    const departed = state.kiosk_grant.ticket;
    state.phase = .dashboard;
    grant.retain(&state);
    try reply(&state, departed.slice(), &h);
    try t.expect(state.kiosk_grant.code.len == 0);
}

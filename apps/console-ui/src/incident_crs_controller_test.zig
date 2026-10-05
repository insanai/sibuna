//! Owned detail replies stay bound to a visible finding and the current session.
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const controller = @import("incident_crs_controller.zig");
const ctx = @import("controller_context.zig");
const Commands = @import("test_transport.zig").Commands;
const State = @import("state.zig").State;

fn setup(state: *State) !void {
    state.* = .{ .phase = .events };
    try state.csrf.set("test csrf");
    try state.role.set("admin");
    state.events.count = 1;
    state.events.rows[0] = .{ .id = 42, .crs = .{
        .rule_id = 942100,
        .phase = 2,
        .severity = 2,
        .revision = 1,
        .source_digest = @splat(1),
        .enforcing = true,
        .denied = true,
        .would_deny = true,
        .coverage = .local_response,
        .selected_status = 403,
        .blocking_paranoia = 1,
        .detection_paranoia = 1,
    } };
}

fn context(state: *State, commands: *Commands) ctx.Context {
    return .{ .state = state, .out = commands.out() };
}

fn deliver(c: ctx.Context, id: []const u8, value: p.incident_crs.Response) !void {
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, value, .{});
    defer t.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, bytes, .{});
    defer parsed.deinit();
    try controller.response(c, .{
        .id = id,
        .status = 200,
        .body = parsed.value,
        .allocator = t.allocator,
    });
}

test "incident detail copies escaped templates and preserves full signed score values" {
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    try setup(state);
    var commands: Commands = .{};
    try t.expect(try controller.action(context(state, &commands), "events-crs-42"));
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "/events/crs") != null);
    const ticket = state.incident_crs.ticket;
    var detail: p.incident_crs.api.Detail = .{ .rule_id = 942100, .phase = 2 };
    detail.message = p.incident_crs.api.Preview(96).copy("<script> %{MATCHED_VAR}");
    detail.score = .{};
    detail.score.?.buckets[0] = .{ .writes = 2, .delta = std.math.minInt(i64) };
    try deliver(context(state, &commands), ticket.slice(), .{ .id = 42, .detail = detail });
    try t.expectEqualDeep(detail, state.incident_crs.detail.?);
    try t.expect(state.incident_crs.loaded and !state.incident_crs.failed);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "#incident-crs-heading") != null);
    var bytes: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try @import("crs_detail_page.zig").render(&state.incident_crs, 42, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "-9223372036854775808") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<script>") == null);
    state.reset();
    try t.expectEqualDeep(controller.Model{}, state.incident_crs);
}

test "superseded detail cannot expire a later session or cross an incident identity" {
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    try setup(state);
    var commands: Commands = .{};
    _ = try controller.action(context(state, &commands), "events-crs-42");
    const old = state.incident_crs.ticket;
    state.reset();
    try setup(state);
    _ = try controller.action(context(state, &commands), "events-crs-42");
    try controller.response(context(state, &commands), .{
        .id = old.slice(),
        .status = 401,
        .body = .null,
        .allocator = t.allocator,
    });
    try t.expectEqual(.events, state.phase);
    try t.expect(state.incident_crs.busy);
    const current = state.incident_crs.ticket;
    try t.expectError(error.InvalidResponse, deliver(
        context(state, &commands),
        current.slice(),
        .{ .id = 43 },
    ));
    try t.expect(state.incident_crs.failed and !state.incident_crs.loaded);
    try deliver(context(state, &commands), current.slice(), .{ .id = 42 });
    try t.expect(state.incident_crs.loaded and state.incident_crs.detail == null);
    state.events.count = 0;
    try deliver(context(state, &commands), current.slice(), .{ .id = 42 });
    try t.expectEqualDeep(controller.Model{}, state.incident_crs);
}

const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const ctx = @import("controller_context.zig");
const Commands = @import("test_transport.zig").Commands;
const controller = @import("crs_sample_details_controller.zig");

fn setup(state: *State) !void {
    state.* = .{ .phase = .crs };
    try state.csrf.set("test csrf");
    try state.role.set("admin");
    @import("crs_fixture.zig").configure(state, false, false);
    const id = try p.crs_management.Id.init("44444444444444444444444444444444");
    state.crs.test_id = id;
    state.crs.test_result = .{
        .id = id,
        .state = .complete,
        .expected_revision = 1,
        .expires = 200,
        .report = .{ .mode = .audit, .profile = .full, .event_count = 1 },
    };
    state.crs.test_result.?.report.?.events[0] = .{
        .rule_id = 1,
        .phase = 2,
        .severity = 2,
        .would_deny = false,
        .saved = true,
        .audit_suppressed = false,
    };
}

test "private details reject mismatched tasks and copy templates before the parser disappears" {
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    try setup(state);
    var commands: Commands = .{};
    const c: ctx.Context = .{ .state = state, .out = commands.out() };
    try t.expect(try controller.action(c, "crs-test-details"));
    var page: p.crs_tasks.DetailPage = .{
        .id = state.crs.test_id.?,
        .expected_revision = 1,
        .expires = 200,
        .page = .{ .total = 1, .count = 1 },
    };
    page.page.rows[0] = .{
        .rule_id = 1,
        .phase = 2,
        .message = p.incident_crs.api.Preview(96).copy("literal %{MATCHED_VAR}"),
    };
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, page, .{});
    defer t.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, bytes, .{});
    defer parsed.deinit();
    try controller.response(c, parsed.value, t.allocator);
    try t.expectEqualDeep(page, state.crs.test_details.?);
    state.crs.test_result.?.expected_revision = 2;
    try t.expectError(error.InvalidResponse, controller.response(c, parsed.value, t.allocator));
    state.crs.clear();
    try t.expect(state.crs.test_details == null);
}

test "expired private detail reads preserve scalar results without making protection stale" {
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    try setup(state);
    var commands: Commands = .{};
    const c: ctx.Context = .{ .state = state, .out = commands.out() };
    _ = try controller.action(c, "crs-test-details");
    try @import("crs_controller.zig").response(c, .{
        .id = state.crs.ticket.slice(),
        .status = 410,
        .body = .null,
        .allocator = t.allocator,
    });
    try t.expect(state.crs.test_details_expired and state.crs.test_result != null);
    try t.expect(!state.crs.stale and state.crs.busy == .idle);
    commands.writer.end = 0;
    try @import("crs_sample_details_page.zig").render(&state.crs, &commands.writer);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "Run the sample again") != null);
}

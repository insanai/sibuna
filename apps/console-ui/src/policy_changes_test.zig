const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Controller = @import("managed_controller.zig").Controller;
const Commands = @import("test_transport.zig").Commands;
const baseline = "{\"id\":\"a\",\"name\":\"A\",\"action\":\"deny\",\"priority\":100}";
const fields = "{\"rule_id\":\"a\",\"rule_name\":\"A\",\"rule_action\":\"deny\"," ++
    "\"rule_priority\":\"101\",\"rule_enabled\":\"true\"}";

fn setup(state: *State) !void {
    state.* = .{ .phase = .policies };
    try state.csrf.set("test csrf");
    try state.role.set("operator");
    const manager = &state.policies.manager;
    manager.active = true;
    manager.view = .editor;
    try manager.committed.set("7");
    try manager.id.set("a");
    try manager.baseline.set(baseline);
    try manager.form.load(baseline);
}

fn action(state: *State, name: []const u8, value: std.json.Value, h: *Commands, gen: *u32) !void {
    const controller: Controller = .{ .state = state, .out = h.out(), .generation = gen };
    try t.expect(try controller.action(name, value));
}

test "policy save reviews an owned draft before confirmation and rejects duplicate submission" {
    var state: State = undefined;
    try setup(&state);
    var commands: Commands = .{};
    var generation: u32 = 0;
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, fields, .{});
    defer parsed.deinit();
    try action(&state, "managed-save", parsed.value, &commands, &generation);
    try t.expect(state.policies.manager.review.len != 0 and !state.policies.busy);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "/policies/edit") == null);
    const reviewed = state.policies.manager.review;
    try action(&state, "managed-confirm", .null, &commands, &generation);
    try t.expect(state.policies.busy);
    const post = commands.writer.buffered();
    try t.expect(std.mem.indexOf(u8, post, "/console/api/policies/edit") != null);
    try t.expect(std.mem.indexOf(u8, post, "\"expected_revision\":\"7\"") != null);
    try t.expectEqualStrings(reviewed.slice(), state.policies.manager.review.slice());
    try action(&state, "managed-confirm", .null, &commands, &generation);
    try t.expectEqual(@as(usize, 0), commands.writer.buffered().len);
    state.policies.busy = false;
    state.policies.stale = true;
    try action(&state, "managed-confirm", .null, &commands, &generation);
    try t.expectEqual(@as(usize, 0), commands.writer.buffered().len);
    try action(&state, "managed-back", .null, &commands, &generation);
    try t.expectEqual(@as(usize, 0), state.policies.manager.review.len);
    try t.expectEqualStrings("101", state.policies.manager.form.priority.slice());
}

test "historical comparison loads the current baseline with the same pinned revision" {
    var state: State = undefined;
    try setup(&state);
    state.policies.manager.view = .history;
    var commands: Commands = .{};
    var generation: u32 = 0;
    try action(&state, "managed-version:3", .null, &commands, &generation);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "managed-baseline-") != null);
    const response = "{\"committed\":\"7\",\"document\":" ++
        "\"{\\\"id\\\":\\\"a\\\",\\\"name\\\":\\\"A\\\",\\\"action\\\":\\\"allow\\\"}\"}";
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, response, .{});
    defer parsed.deinit();
    const controller: Controller = .{
        .state = &state,
        .out = commands.out(),
        .generation = &generation,
    };
    try controller.response("managed-baseline-1", parsed.value);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "\"revision\":\"3\"") != null);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "\"committed\":\"7\"") != null);
    try t.expect(std.mem.indexOf(u8, state.policies.manager.baseline.slice(), "allow") != null);
}

test "policy change table escapes values, omits unchanged fields and disables no-op save" {
    var state: State = undefined;
    try setup(&state);
    const manager = &state.policies.manager;
    try manager.review.set("{\"id\":\"a\",\"name\":\"<script>\",\"action\":\"deny\"}");
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("policy_changes.zig").render(&writer, manager, false);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<script>") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "scope=\"row\">Priority") == null);
    try manager.review.set(baseline);
    writer = .fixed(&buffer);
    try @import("policy_changes.zig").render(&writer, manager, false);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "No field changes") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "disabled>Confirm save") != null);
}

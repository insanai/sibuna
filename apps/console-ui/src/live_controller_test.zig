//! Real protocol envelopes exercise navigation and transactional publication natively.
const std = @import("std");
const p = @import("console_protocol");
const live = @import("live_controller.zig");
const State = @import("state.zig").State;
const Commands = @import("test_transport.zig").Commands;
const t = std.testing;

fn deliver(state: *State, bytes: []const u8, commands: *Commands) !void {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), bytes, .{});
    _ = try live.event(state, parsed, arena.allocator(), commands.out());
}

fn frame(
    state: *State,
    commands: *Commands,
    topic: p.Topic,
    op: []const u8,
    sequence: u64,
    data: ?[]const u8,
) !void {
    var bytes: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(.{ .state = "message", .body = .{
        .op = op,
        .topic = topic,
        .epoch = "a" ** 32 ++ ":1",
        .seq = sequence,
        .snapshot = true,
        .watermark = 0,
        .parts = 1,
        .part = 0,
        .data = data,
    } }, .{}, &writer);
    try deliver(state, writer.buffered(), commands);
}

fn ready(state: *State, commands: *Commands) !void {
    live.init();
    state.* = .{ .phase = .dashboard, .browser_time = 100 };
    try state.csrf.set("principal");
    try state.role.set("admin");
    try live.sync(state, commands.out());
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "/console/ws") != null);
    try deliver(state, "{\"state\":\"open\"}", commands);
    try live.sync(state, commands.out());
}

test "navigation retains one socket and policy publication never changes a reviewed draft" {
    var state: State = undefined;
    var commands: Commands = .{};
    try ready(&state, &commands);
    defer live.init();
    state.phase = .policies;
    try state.policies.manager.committed.set("4");
    try state.policies.body.set("unsaved request body");
    try live.sync(&state, commands.out());
    const emitted = commands.writer.buffered();
    try t.expect(std.mem.indexOf(u8, emitted, "connect") == null);
    try t.expect(std.mem.indexOf(u8, emitted, "\"policy\"") != null);
    try frame(&state, &commands, .policy, "snapshot_begin", 0, null);
    try frame(
        &state,
        &commands,
        .policy,
        "snapshot_chunk",
        1,
        "{\"committed\":\"9007199254740993\",\"applied\":4}",
    );
    try t.expectEqual(@as(u64, 0), state.live.committed);
    try frame(&state, &commands, .policy, "snapshot_end", 2, null);
    try t.expectEqual(@as(u64, 9007199254740993), state.live.committed);
    try t.expectEqualStrings("4", state.policies.manager.committed.slice());
    try t.expectEqualStrings("unsaved request body", state.policies.body.slice());
    state.phase = .nodes;
    try live.sync(&state, commands.out());
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "\"unsub\"") != null);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "connect") == null);
    try deliver(
        &state,
        "{\"state\":\"message\",\"body\":{\"error\":\"unauthorized\"}}",
        &commands,
    );
    try t.expectEqual(.login, state.phase);
    try t.expectEqual(@as(usize, 0), state.policies.body.len);
    try t.expectEqual(@as(usize, 0), state.csrf.len);
}

test "a filter changed during a snapshot cannot publish rows under the new filter" {
    var state: State = undefined;
    var commands: Commands = .{};
    try ready(&state, &commands);
    defer live.init();
    state.phase = .events;
    state.events.until = 90;
    try live.sync(&state, commands.out());
    try frame(&state, &commands, .events, "snapshot_begin", 0, null);
    try state.events.ip.set("8.8.8.8");
    try live.sync(&state, commands.out());
    try t.expectEqual(@as(usize, 0), commands.writer.buffered().len);
    try frame(
        &state,
        &commands,
        .events,
        "snapshot_chunk",
        1,
        "{\"rows\":[{\"id\":1,\"time\":100}],\"coverage\":{\"available\":true," ++
            "\"observed_at\":100,\"missing_ids\":3}}",
    );
    try frame(&state, &commands, .events, "snapshot_end", 2, null);
    try t.expectEqual(@as(u8, 0), state.live.topics[@intFromEnum(p.Topic.events)].newer);
    try live.sync(&state, commands.out());
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "\"filter\"") != null);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "8.8.8.8") != null);
    try deliver(&state, "{\"state\":\"closed\",\"entropy\":1234}", &commands);
    try t.expect(state.stale);
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "live-retry") != null);
    try live.sync(&state, commands.out());
    try t.expectEqual(@as(usize, 0), commands.writer.buffered().len);
    live.timer();
    try live.sync(&state, commands.out());
    try t.expect(std.mem.indexOf(u8, commands.writer.buffered(), "/console/ws") != null);
}

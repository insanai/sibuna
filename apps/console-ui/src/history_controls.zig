//! Paging pins the query scope so live snapshots cannot move an older page's boundary.
const std = @import("std");
const State = @import("state.zig").State;
const equal = std.mem.eql;
pub const Result = enum { none, changed, query };

pub fn action(state: *State, name: []const u8, fields: std.json.Value) !Result {
    if (!state.fullAccess() or state.phase != .dashboard) return .none;
    if (equal(u8, name, "timeline-values")) {
        state.timeline_open = !state.timeline_open;
        return if (state.timeline_open) .query else .changed;
    }
    if (!state.timeline_open) return .none;
    if (equal(u8, name, "timeline-seconds") or equal(u8, name, "timeline-minutes")) {
        state.history_minutes = equal(u8, name, "timeline-minutes");
        return .query;
    }
    if (state.history_minutes) return minutes(state, name, fields);
    const model = &state.timeline;
    if (equal(u8, name, "timeline-latest") or equal(u8, name, "timeline-older")) {
        if (model.busy or state.paused) return .changed;
        if (equal(u8, name, "timeline-older") and (model.next == 0 or model.conflict))
            return .changed;
        model.before = if (equal(u8, name, "timeline-latest")) 0 else model.next;
        return .query;
    }
    return .none;
}

fn minutes(state: *State, name: []const u8, fields: std.json.Value) !Result {
    const model = &state.minute_history;
    if (equal(u8, name, "minute-window")) {
        if (model.busy or state.paused) return .changed;
        const string = @import("events_state.zig").string;
        const hours = std.fmt.parseInt(u16, string(fields, "hours"), 10) catch
            return error.InvalidRequest;
        if (hours != 1 and hours != 24 and hours != 168 and hours != 2160)
            return error.InvalidRequest;
        model.hours = hours;
        model.all_nodes = equal(u8, string(fields, "all_nodes"), "true");
        model.before = null;
        model.next = null;
        model.count = 0;
        model.loaded = false;
        return .query;
    }
    if (equal(u8, name, "minute-latest") or equal(u8, name, "minute-older")) {
        if (model.busy or state.paused) return .changed;
        if (equal(u8, name, "minute-older") and model.next == null) return .changed;
        model.before = if (equal(u8, name, "minute-latest")) null else model.next;
        return .query;
    }
    return .none;
}

test "history controls pin pages and reject invalid window changes without partial edits" {
    const t = std.testing;
    var state: State = .{};
    try t.expectEqual(.none, try action(&state, "timeline-values", .null));
    state.csrf = try @import("console_protocol").Bytes(64).init("test");
    state.phase = .dashboard;
    try t.expectEqual(.query, try action(&state, "timeline-values", .null));
    try t.expectEqual(.query, try action(&state, "timeline-minutes", .null));
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"hours\":\"2160\",\"all_nodes\":\"true\"}",
        .{},
    );
    defer parsed.deinit();
    try t.expectEqual(.query, try action(&state, "minute-window", parsed.value));
    try t.expect(state.minute_history.all_nodes and state.minute_history.hours == 2160);
    const cursor = @import("console_protocol").minutes.Cursor{
        .minute = 100,
        .node = 3,
        .boot = @splat(2),
        .epoch = 1,
    };
    state.minute_history.next = cursor;
    try t.expectEqual(.query, try action(&state, "minute-older", .null));
    try t.expectEqualDeep(cursor, state.minute_history.before.?);
    state.minute_history.busy = true;
    try t.expectEqual(.changed, try action(&state, "minute-latest", .null));
    try t.expectEqualDeep(cursor, state.minute_history.before.?);
    state.minute_history.busy = false;
    parsed.value.object.getPtr("hours").?.* = .{ .string = "2161" };
    try t.expectError(error.InvalidRequest, action(&state, "minute-window", parsed.value));
    try t.expectEqualDeep(cursor, state.minute_history.before.?);
    try t.expectEqual(@as(u16, 2160), state.minute_history.hours);
    try t.expectEqual(.query, try action(&state, "timeline-seconds", .null));
    try t.expect(!state.history_minutes);
    try t.expectEqualDeep(cursor, state.minute_history.before.?);
}

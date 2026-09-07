const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const values = @import("events_state.zig");

pub fn act(state: *State, name: []const u8, fields: std.json.Value) !bool {
    if (!state.fullAccess()) return false;
    const model = &state.events;
    if (std.mem.eql(u8, name, "events")) {
        state.phase = .events;
        state.stats_busy = false;
        model.* = .{};
        model.until = state.browser_time;
    } else {
        if (state.phase != .events or model.busy) return false;
        if (std.mem.eql(u8, name, "events-filter")) {
            model.category = try p.Bytes(32).init(values.string(fields, "category"));
            model.ip = try p.Bytes(48).init(values.string(fields, "ip"));
            model.path = try p.Bytes(256).init(values.string(fields, "path_prefix"));
            const hours = try std.fmt.parseInt(u32, values.string(fields, "hours"), 10);
            if (hours != 0 and hours != 1 and hours != 24 and hours != 168)
                return error.InvalidRequest;
            model.hours = hours;
            model.page = 0;
            model.cursors = @splat(null);
            model.until = state.browser_time;
        } else if (std.mem.eql(u8, name, "events-next")) {
            if (model.next == null or model.page + 1 >= model.cursors.len) return false;
            model.page += 1;
            model.cursors[model.page] = model.next;
        } else if (std.mem.eql(u8, name, "events-prev")) {
            if (model.page == 0) return false;
            model.page -= 1;
        } else if (std.mem.eql(u8, name, "events-refresh")) {
            model.page = 0;
            model.cursors = @splat(null);
            model.until = state.browser_time;
        } else return false;
    }
    model.focus_results = !std.mem.eql(u8, name, "events");
    model.busy = true;
    model.count = 0;
    model.loaded = false;
    model.next = null;
    state.message = .{};
    return true;
}

test "incident navigation requires full authentication and preserves paging time bounds" {
    var state: State = .{};
    try std.testing.expect(!try act(&state, "events", .null));
    state.csrf = try p.Bytes(64).init("test");
    state.must_change = true;
    try std.testing.expect(!try act(&state, "events", .null));
    state.must_change = false;
    state.browser_time = 200;
    try std.testing.expect(try act(&state, "events", .null));
    state.events.busy = false;
    state.events.next = .{ .time = 150, .id = 9007199254740993 };
    try std.testing.expect(try act(&state, "events-next", .null));
    state.events.busy = false;
    state.browser_time = 300;
    try std.testing.expect(try act(&state, "events-prev", .null));
    try std.testing.expectEqual(@as(u64, 200), state.events.until);
}

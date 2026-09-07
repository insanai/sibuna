const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const values = @import("events_state.zig");

pub fn act(state: *State, name: []const u8, fields: std.json.Value) !bool {
    if (!state.fullAccess()) return false;
    if (try campaign(state, name)) return true;
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
            const node = values.string(fields, "node");
            model.node = if (node.len == 0) 0 else try std.fmt.parseInt(u32, node, 10);
            model.hours = hours;
            model.page = 0;
            model.cursors = @splat(null);
            model.until = state.browser_time;
        } else if (std.mem.eql(u8, name, "events-source") or
            std.mem.eql(u8, name, "events-raw"))
        {
            model.grouped = std.mem.eql(u8, name, "events-source");
            model.page = 0;
            model.cursors = @splat(null);
        } else if (std.mem.startsWith(u8, name, "events-source-")) {
            const value = name["events-source-".len..];
            const split = std.mem.indexOfScalar(u8, value, '/') orelse return error.InvalidRequest;
            model.node = try std.fmt.parseInt(u32, value[0..split], 10);
            model.ip = try p.Bytes(48).init(value[split + 1 ..]);
            model.grouped = false;
            model.page = 0;
            model.cursors = @splat(null);
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
    model.export_ready = false;
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

test "source drill-down retains node, address and the selected time boundary" {
    var state: State = .{};
    state.csrf = try p.Bytes(64).init("test");
    state.browser_time = 200;
    try std.testing.expect(try act(&state, "events", .null));
    state.events.busy = false;
    try std.testing.expect(try act(&state, "events-source", .null));
    try std.testing.expect(state.events.grouped);
    state.events.busy = false;
    state.browser_time = 300;
    try std.testing.expect(try act(&state, "events-source-7/2001:4860::1", .null));
    try std.testing.expect(!state.events.grouped);
    try std.testing.expectEqual(@as(u32, 7), state.events.node);
    try std.testing.expectEqualStrings("2001:4860::1", state.events.ip.slice());
    try std.testing.expectEqual(@as(u64, 200), state.events.until);
}

fn campaign(state: *State, name: []const u8) !bool {
    const prefix = "events-campaign-";
    const clear = std.mem.eql(u8, name, "events-clear-campaign");
    if (!clear and !std.mem.startsWith(u8, name, prefix)) return false;
    const model = &state.events;
    if (state.phase != .events or model.busy) return false;
    const id = if (clear) 0 else try std.fmt.parseInt(u64, name[prefix.len..], 10);
    if (id > std.math.maxInt(i64) or (!clear and id == 0)) return error.InvalidRequest;
    // Candidate membership spans addresses and nodes; retain only the reader's time boundary.
    model.* = .{
        .campaign = id,
        .until = model.until,
        .hours = model.hours,
        .busy = true,
        .focus_results = true,
    };
    state.message = .{};
    return true;
}

test "campaign navigation preserves exact identifiers and time boundaries across nodes" {
    var state: State = .{ .phase = .events };
    state.csrf = try p.Bytes(64).init("test");
    state.events.until = 200;
    state.events.node = 7;
    state.events.ip = try p.Bytes(48).init("8.8.8.8");
    try std.testing.expect(try act(&state, "events-campaign-9007199254740993", .null));
    try std.testing.expectEqual(@as(u64, 9007199254740993), state.events.campaign);
    try std.testing.expectEqual(@as(u64, 200), state.events.until);
    try std.testing.expectEqual(@as(u32, 0), state.events.node);
    try std.testing.expectEqual(@as(usize, 0), state.events.ip.len);
    state.events.busy = false;
    try std.testing.expect(try act(&state, "events-clear-campaign", .null));
    try std.testing.expectEqual(@as(u64, 0), state.events.campaign);
}

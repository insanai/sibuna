//! One outstanding summary read, with owned windows and a session-independent ticket.
//! Explicit retry delays preserve the read budget during storage outages or saturation.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const fields = @import("events_state.zig");
var serial: u64 = 0;

fn active(state: *const State) bool {
    return state.fullAccess() and !state.kiosk and state.phase == .dashboard and
        !state.paused and !state.hidden and state.traffic_period.hours != 0;
}

pub fn sync(state: *State, out: Outbox) !void {
    if (!active(state) or !@import("dashboard_scope.zig").historyAvailable(state)) return;
    const stats = state.stats orelse return;
    const model = &state.traffic_period;
    var nodes: [p.dashboard.max_sources]u32 = undefined;
    const count = sources(state, &nodes);
    if (count == 0) return;
    const changed = !std.mem.eql(u32, model.nodes[0..model.count], nodes[0..count]);
    if (changed or model.until == 0 or (model.completed_at != null and
        state.browser_time -| model.completed_at.? >= 60))
    {
        const published = if (changed) null else model.published;
        try model.configure(nodes[0..count], stats.timestamp / 60 -| 1);
        model.published = published;
    }
    if (model.busy or state.browser_time < model.retry_at) return;
    for (model.windows[0..model.count], 0..) |windows, node| {
        for (windows, 0..) |window, side| {
            if (window.finished) continue;
            try request(state, node, side, out);
            return;
        }
    }
    if (model.completed_at == null) {
        model.published = .{
            .totals = .{ try model.totals(0), try model.totals(1) },
            .until = model.until,
            .completed_at = state.browser_time,
        };
        model.completed_at = state.browser_time;
    }
}

fn sources(state: *const State, nodes: *[p.dashboard.max_sources]u32) usize {
    var count: usize = 0;
    if (state.dashboard_scope) |scope| {
        for (scope.sources) |entry| if (entry) |source| {
            if (source.node == 0 or
                (state.dashboard_node != null and state.dashboard_node.? != source.node)) continue;
            nodes[count] = source.node;
            count += 1;
        };
    } else if (state.stats) |stats| if (stats.node != 0) {
        nodes[0] = stats.node;
        return 1;
    };
    return count;
}

fn request(state: *State, node: usize, side: usize, out: Outbox) !void {
    const model = &state.traffic_period;
    const window = model.windows[node][side];
    serial = try std.math.add(u64, serial, 1);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "traffic-period-{d}", .{serial});
    try out.post(id, "/console/api/minutes/summary", p.minutes.Request{
        .node = window.node,
        .from_minute = window.from,
        .until_minute = window.until,
        .before = window.next,
        .limit = p.minute_summary.max_rows,
    });
    model.ticket = serial;
    model.target = node;
    model.side = side;
    model.busy = true;
}

pub fn action(state: *State, name: []const u8, input: std.json.Value) !bool {
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard) return false;
    if (!std.mem.eql(u8, name, "traffic-period") and
        !std.mem.eql(u8, name, "traffic-period-refresh")) return false;
    const model = &state.traffic_period;
    if (model.busy or state.paused) return true;
    if (std.mem.eql(u8, name, "traffic-period")) {
        const hours = try std.fmt.parseInt(u16, fields.string(input, "hours"), 10);
        if (hours != 0 and hours != 1 and hours != 24 and hours != 168 and
            hours != 2160)
            return error.InvalidWindow;
        model.hours = hours;
    } else if (!std.mem.eql(u8, name, "traffic-period-refresh")) return false;
    model.invalidate();
    return true;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    const ticket = std.fmt.parseInt(u64, id["traffic-period-".len..], 10) catch return;
    const model = &state.traffic_period;
    if (ticket == 0 or ticket != model.ticket or !model.busy or !state.fullAccess()) return;
    model.busy = false;
    if (status == 401 or status == 403) {
        try @import("live_controller.zig").stop(out);
        state.reset();
        state.phase = .login;
        try state.message.set("Your access changed. Sign in to read retained traffic.");
        return;
    }
    if (!active(state)) return;
    if (status != 200) {
        model.retry_at = state.browser_time +| @as(u64, if (status == 429) 60 else 5);
        return model.message.set(if (status == 429)
            "TRAFFIC429: Read allowance reached. This scan resumes in one minute."
        else
            "TRAFFIC002: Retained traffic is unavailable. Retrying after storage recovers.");
    }
    const part = @import("json_value.zig").decode(p.minute_summary.Part, body, alloc) catch
        return invalid(state);
    p.minute_summary.acceptPart(&model.windows[model.target][model.side], part) catch
        return invalid(state);
    model.message = .{};
}

fn invalid(state: *State) !void {
    state.traffic_period.retry_at = std.math.maxInt(u64);
    try state.traffic_period.message.set("TRAFFIC003: Retained data changed or was invalid. " ++
        "Refresh the period to restart; no incomplete percentage is shown.");
}

test "period requests are authenticated bounded and retain their scope across retries" {
    const t = std.testing;
    var state: State = .{};
    var commands: @import("test_transport.zig").Commands = .{};
    try sync(&state, commands.out());
    try t.expectEqual(@as(usize, 0), commands.count);
    state.phase = .dashboard;
    try state.csrf.set("test");
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.timestamp = 600000;
    state.stats.?.node = 1;
    state.stats.?.minute_history.available = true;
    try sync(&state, commands.out());
    try t.expectEqual(@as(usize, 1), commands.count);
    try t.expectEqual(@as(u16, 24), state.traffic_period.hours);
    try t.expectEqual(@as(u64, 8560), state.traffic_period.windows[0][0].from);
    const saved = state.traffic_period;
    try sync(&state, commands.out());
    try t.expectEqual(@as(usize, 0), commands.count);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "traffic-period-{d}", .{saved.ticket});
    try response(&state, id, 429, .null, t.allocator, commands.out());
    try t.expectEqual(@as(u64, 60), state.traffic_period.retry_at);
    try sync(&state, commands.out());
    try t.expectEqual(@as(usize, 0), commands.count);
    state.browser_time = 60;
    try sync(&state, commands.out());
    try t.expectEqual(@as(usize, 1), commands.count);
    try t.expectEqualDeep(saved.windows, state.traffic_period.windows);
    state.reset();
    try response(&state, id, 401, .null, t.allocator, commands.out());
    try t.expectEqual(.loading, state.phase);
    try t.expectEqual(@as(u16, 24), state.traffic_period.hours);
}

test "automatic refresh retains completed values and a source change discards them" {
    const t = std.testing;
    var state: State = .{ .phase = .dashboard, .browser_time = 20 };
    try state.csrf.set("test");
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.timestamp = 600000;
    state.stats.?.node = 1;
    state.stats.?.minute_history.available = true;
    try state.traffic_period.configure(&.{1}, 9999);
    for (&state.traffic_period.windows[0]) |*window| window.finished = true;
    var commands: @import("test_transport.zig").Commands = .{};
    try sync(&state, commands.out());
    const saved = state.traffic_period.published.?;
    state.browser_time = 80;
    state.stats.?.timestamp += 60;
    try sync(&state, commands.out());
    try t.expect(state.traffic_period.busy and state.traffic_period.completed_at == null);
    try t.expectEqualDeep(saved, state.traffic_period.published.?);
    try t.expectEqualDeep(saved.totals[0], try state.traffic_period.read(0));
    try t.expect(state.traffic_period.until > saved.until);
    state.stats.?.node = 2;
    try sync(&state, commands.out());
    try t.expect(state.traffic_period.published == null);
    try t.expectEqual(@as(u32, 2), state.traffic_period.windows[0][0].node);
}

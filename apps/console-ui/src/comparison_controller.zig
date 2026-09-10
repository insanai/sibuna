//! Historical comparisons reuse bounded, authorized minute pages. Each click permits
//! eight pages per side; continuation is explicit and retains its original UTC bounds.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Window = @import("minute_comparison.zig").Window;
const fields = @import("events_state.zig");
var serial: u64 = 0;
pub const Mode = enum { yesterday, previous, node };
pub const Model = struct {
    open: bool = false,
    started: bool = false,
    mode: Mode = .yesterday,
    minutes: u32 = 5,
    offset: u32 = 0,
    windows: [2]Window = @splat(.{}),
    tickets: [2]u64 = @splat(0),
    busy: [2]bool = @splat(false),
    pages_left: [2]u8 = @splat(0),
    failed: [2]bool = @splat(false),
    error_message: p.Bytes(192) = .{},

    pub fn clear(self: *Model) void {
        self.* = .{};
    }
};

pub fn action(state: *State, name: []const u8, input: std.json.Value, out: Outbox) !bool {
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or
        !std.mem.startsWith(u8, name, "compare-")) return false;
    const model = &state.comparison;
    if (std.mem.eql(u8, name, "compare-toggle")) {
        model.open = !model.open;
        if (!model.open) {
            model.tickets = @splat(0);
            model.busy = @splat(false);
        }
        return true;
    }
    if (!model.open or state.paused or state.hidden or model.busy[0] or model.busy[1]) return true;
    if (std.mem.eql(u8, name, "compare-start")) {
        var candidate = configure(state, input) catch {
            try model.error_message.set("COMPARISON001: Choose two nodes and a retained " ++
                "window of 1–129600 minutes. Both periods must end before the current minute.");
            return true;
        };
        candidate.pages_left = @splat(8);
        model.* = candidate;
    } else if (std.mem.eql(u8, name, "compare-more") and model.started) {
        model.pages_left = @splat(8);
        model.failed = @splat(false);
        model.error_message = .{};
    } else return true;
    for (0..2) |side| try request(state, side, out);
    return true;
}

fn configure(state: *const State, input: std.json.Value) !Model {
    const now = (state.stats orelse return error.Unavailable).timestamp / 60;
    const minutes = try number(u32, input, "minutes");
    const offset = try number(u32, input, "offset");
    const mode = std.meta.stringToEnum(Mode, fields.string(input, "mode")) orelse
        return error.InvalidInput;
    const first_node = try number(u32, input, "node");
    const other_node = if (mode == .node) try number(u32, input, "other_node") else first_node;
    if (!knownNode(state, first_node) or !knownNode(state, other_node) or minutes == 0 or
        minutes > 90 * 1440 or offset >= 90 * 1440 or now <= offset + minutes)
        return error.InvalidInput;
    const until = now - 1 - offset;
    const shift: u64 = switch (mode) {
        .yesterday => 1440,
        .previous => minutes,
        .node => 0,
    };
    if (until < shift + minutes - 1 or offset + minutes + shift > 90 * 1440)
        return error.InvalidInput;
    return .{
        .open = true,
        .started = true,
        .mode = mode,
        .minutes = minutes,
        .offset = offset,
        .windows = .{
            .{ .node = first_node, .from = until - minutes + 1, .until = until },
            .{ .node = other_node, .from = until - shift - minutes + 1, .until = until - shift },
        },
    };
}

fn number(comptime T: type, input: std.json.Value, key: []const u8) !T {
    return std.fmt.parseInt(T, fields.string(input, key), 10);
}

fn knownNode(state: *const State, node: u32) bool {
    if (node == 0) return false;
    if (state.dashboard_scope) |scope| {
        for (scope.sources) |entry| if (entry) |source| if (source.node == node) return true;
    }
    return if (state.stats) |stats| stats.node == node else false;
}

fn request(state: *State, side: usize, out: Outbox) !void {
    const model = &state.comparison;
    const window = &model.windows[side];
    if (window.finished or model.pages_left[side] == 0 or state.paused or state.hidden or
        state.phase != .dashboard or !model.open) return;
    serial = std.math.add(u64, serial, 1) catch return error.Capacity;
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "compare-{d}-{d}", .{ side, serial });
    try out.post(id, "/console/api/minutes", p.minutes.Request{
        .node = window.node,
        .from_minute = window.from,
        .until_minute = window.until,
        .before = window.next,
    });
    model.tickets[side] = serial;
    model.busy[side] = true;
    model.pages_left[side] -= 1;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    var parts = std.mem.splitScalar(u8, id["compare-".len..], '-');
    const side = std.fmt.parseInt(usize, parts.next() orelse return, 10) catch return;
    const ticket = std.fmt.parseInt(u64, parts.next() orelse return, 10) catch return;
    const model = &state.comparison;
    if (parts.next() != null or side >= 2 or ticket == 0 or ticket != model.tickets[side] or
        !model.busy[side] or !state.fullAccess() or state.kiosk) return;
    model.busy[side] = false;
    if (status == 401 or status == 403) {
        try @import("live_controller.zig").stop(out);
        state.reset();
        state.phase = .login;
        try state.message.set("Your access changed. Sign in to compare retained traffic.");
        return;
    }
    model.failed[side] = true;
    if (status != 200) {
        try model.error_message.set(if (status == 429)
            "COMPARISON429: Query allowance reached. Wait one minute, then continue."
        else
            "COMPARISON002: History could not be read. Continue after storage recovers.");
        return;
    }
    const page = @import("json_value.zig").decode(p.minutes.Reply, body, alloc) catch
        return invalid(model);
    model.windows[side].accept(page) catch return invalid(model);
    model.failed[side] = false;
    try request(state, side, out);
}

fn invalid(model: *Model) !void {
    try model.error_message.set("COMPARISON003: The retained page changed or was invalid. " ++
        "Start the comparison again; no incomplete percentage is shown.");
}

test "comparison freezes boundaries bounds work and discards old-session replies" {
    const t = std.testing;
    var state: State = .{};
    var commands: @import("test_transport.zig").Commands = .{};
    try t.expect(!try action(&state, "compare-toggle", .null, commands.out()));
    state.phase = .dashboard;
    try state.csrf.set("test");
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.timestamp = 600000;
    state.stats.?.node = 1;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"minutes\":\"5\",\"offset\":\"0\",\"node\":\"1\",\"mode\":\"yesterday\"}",
        .{},
    );
    defer parsed.deinit();
    try t.expect(try action(&state, "compare-toggle", .null, commands.out()));
    try t.expect(try action(&state, "compare-start", parsed.value, commands.out()));
    try t.expectEqual(@as(usize, 2), commands.count);
    try t.expectEqual(@as(u64, 9999), state.comparison.windows[0].until);
    try t.expectEqual(@as(u64, 8559), state.comparison.windows[1].until);
    try t.expectEqual(@as(u8, 7), state.comparison.pages_left[0]);
    const before = state.comparison;
    // Double clicks do not enqueue another scan.
    _ = try action(&state, "compare-start", parsed.value, commands.out());
    try t.expectEqual(@as(usize, 0), commands.count);
    try t.expectEqualDeep(before, state.comparison);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "compare-0-{d}", .{before.tickets[0]});
    state.reset();
    try response(&state, id, 401, .null, t.allocator, commands.out());
    try t.expectEqual(.loading, state.phase);
    try t.expectEqual(@as(usize, 0), commands.count);
    state.phase = .dashboard;
    state.kiosk = true;
    try state.csrf.set("test");
    try t.expect(!try action(&state, "compare-toggle", .null, commands.out()));
}

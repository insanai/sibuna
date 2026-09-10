//! Explicit scans have one outstanding read and sixteen archives per action.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const fields = @import("events_state.zig");
const history = @import("ranking_history_state.zig");
var serial: u64 = 0;

pub fn action(state: *State, name: []const u8, input: std.json.Value, out: Outbox) !bool {
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or
        !std.mem.startsWith(u8, name, "rank-history-")) return false;
    const model = &state.ranking_history;
    if (std.mem.eql(u8, name, "rank-history-toggle")) {
        model.open = !model.open;
        if (!model.open) {
            model.busy = false;
            model.ticket = 0;
        }
        return true;
    }
    if (!model.open or model.busy or state.paused or state.hidden) return true;
    if (std.mem.eql(u8, name, "rank-history-start")) {
        const candidate = configure(state, input) catch {
            try model.message.set("RANKHISTORY001: Choose a recorded node (0 for all), " ++
                "a duration of 1–129600 minutes and a closed reference period.");
            return true;
        };
        model.clear();
        model.open = true;
        model.started = true;
        model.inputs = candidate.inputs;
        for (&model.windows, candidate.queries) |*window, query| window.query = query;
    } else if (!std.mem.eql(u8, name, "rank-history-more") or !model.started) return true;
    model.remaining = 16;
    model.message = .{};
    try request(state, out);
    return true;
}

const Configuration = struct { inputs: history.Inputs, queries: [2]p.ranking_history.Request };

fn configure(state: *const State, input: std.json.Value) !Configuration {
    const now = (state.stats orelse return error.Unavailable).timestamp / 60;
    const minutes = try number(input, "minutes");
    const offset = try number(input, "offset");
    const node = try number(input, "node");
    const other = try number(input, "other_node");
    const mode = fields.string(input, "mode");
    const comparison = std.meta.stringToEnum(@FieldType(history.Inputs, "mode"), mode) orelse
        return error.InvalidInput;
    const shift: u64 = switch (comparison) {
        .previous => minutes,
        .yesterday => 1440,
        .node => 0,
    };
    if (minutes == 0 or minutes > 90 * 1440 or offset >= 90 * 1440 or
        now <= @as(u64, offset) + minutes + shift) return error.InvalidInput;
    const until = now - 1 - offset;
    var result: Configuration = .{ .inputs = .{
        .mode = comparison,
        .minutes = minutes,
        .offset = offset,
        .node = node,
        .other_node = other,
    }, .queries = undefined };
    for (&result.queries, 0..) |*query, side| {
        const selected = if (side == 1 and shift == 0) other else node;
        query.* = .{
            .from_minute = until - minutes + 1 - (if (side == 1) shift else 0),
            .until_minute = until - (if (side == 1) shift else 0),
            .node = if (selected == 0) null else selected,
        };
    }
    return result;
}

fn number(input: std.json.Value, key: []const u8) !u32 {
    return std.fmt.parseInt(u32, fields.string(input, key), 10);
}

fn request(state: *State, out: Outbox) !void {
    const model = &state.ranking_history;
    if (model.remaining == 0 or !model.open or state.phase != .dashboard or state.paused or
        state.hidden) return;
    const side: usize = if (!model.windows[0].finished) 0 else 1;
    if (model.windows[side].finished) return;
    serial = try std.math.add(u64, serial, 1);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "rank-history-{d}", .{serial});
    try out.post(id, "/console/api/rankings/history", model.windows[side].query);
    model.ticket = serial;
    model.side = side;
    model.busy = true;
    model.remaining -= 1;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    const ticket = std.fmt.parseInt(u64, id["rank-history-".len..], 10) catch return;
    const model = &state.ranking_history;
    if (ticket == 0 or ticket != model.ticket or !model.busy or !state.fullAccess()) return;
    model.busy = false;
    if (status == 401 or status == 403) {
        try @import("live_controller.zig").stop(out);
        state.reset();
        state.phase = .login;
        try state.message.set("Your access changed. Sign in to read retained rankings.");
        return;
    }
    if (state.phase != .dashboard or !model.open or state.paused or state.hidden) return;
    if (status != 200) return model.message.set(if (status == 429)
        "RANKHISTORY429: Read allowance reached. Wait one minute, then continue."
    else
        "RANKHISTORY002: History is unavailable. Check storage and access, then continue.");
    const reply = @import("json_value.zig").decode(history.Reply, body, alloc) catch
        return invalid(model);
    const work = try alloc.create(history.Workspace);
    defer alloc.destroy(work);
    model.windows[model.side].accept(reply, work) catch return invalid(model);
    try request(state, out);
}

fn invalid(model: *history.Model) !void {
    model.started = false;
    try model.message.set("RANKHISTORY003: Archive history changed or was invalid. " ++
        "Start a new comparison; the invalid archive was not merged.");
}

test "retained ranking actions preserve scope and discard responses after sign-out" {
    const t = std.testing;
    var state: State = .{};
    var commands: @import("test_transport.zig").Commands = .{};
    try t.expect(!try action(&state, "rank-history-toggle", .null, commands.out()));
    state.phase = .dashboard;
    try state.csrf.set("session");
    try t.expect(try action(&state, "rank-history-toggle", .null, commands.out()));
    state.ranking_history.started = true;
    state.ranking_history.windows[0].query = .{
        .node = 7,
        .from_minute = 1,
        .until_minute = 2,
    };
    try t.expect(try action(&state, "rank-history-more", .null, commands.out()));
    const ticket = state.ranking_history.ticket;
    try t.expectEqual(@as(u8, 15), state.ranking_history.remaining);
    const saved = state.ranking_history.windows[0].query;
    var id: [48]u8 = undefined;
    const text = try std.fmt.bufPrint(&id, "rank-history-{d}", .{ticket});
    try response(&state, text, 429, .null, t.allocator, commands.out());
    try t.expect(!state.ranking_history.busy);
    try t.expectEqualDeep(saved, state.ranking_history.windows[0].query);
    state.reset();
    try response(&state, text, 401, .null, t.allocator, commands.out());
    try t.expectEqual(.loading, state.phase);
    try t.expect(!state.ranking_history.open);
}

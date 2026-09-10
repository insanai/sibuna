//! One outstanding history read and sixteen pages per explicit action. Scope stays frozen
//! through pagination; navigation, sign-out and superseded tickets cannot publish stale replies.
const std = @import("std");
const p = @import("console_protocol");
const wire = p.rule_hit_history;
const history = @import("rule_hit_state.zig");
const Context = @import("controller_context.zig").Context;
const Response = @import("controller_context.zig").Response;
const fields = @import("events_state.zig");
var serial: u64 = 0;

pub fn action(ctx: Context, name: []const u8, input: std.json.Value) !bool {
    const state = ctx.state;
    if (!state.fullAccess() or state.kiosk or state.phase != .policies or
        !std.mem.startsWith(u8, name, "rule-hits-")) return false;
    const model = &state.rule_history;
    if (std.mem.eql(u8, name, "rule-hits-close")) {
        model.clear();
        return true;
    }
    if (std.mem.eql(u8, name, "rule-hits-open")) {
        model.clear();
        model.open = true;
        try model.inputs.key.set(fields.string(input, "key"));
        model.inputs.node = state.console_node orelse return error.Unavailable;
        const edit = fields.string(input, "edit_at");
        if (edit.len != 0) {
            model.inputs.edit_at = try std.fmt.parseInt(u64, edit, 10);
            model.inputs.mode = .edit;
            try model.inputs.after_revision.set(fields.string(input, "revision"));
        }
        try ctx.out.emit(.{ .op = "focus", .selector = "#rule-hit-history" });
        return true;
    }
    if (!model.open or model.busy or state.paused or state.hidden) return true;
    if (std.mem.eql(u8, name, "rule-hits-start")) {
        const configuration = configure(model.inputs, input, state.browser_time) catch {
            try model.message.set("RULEHITS002: Choose a recorded node, retained duration " ++
                "and valid revisions. An edit needs at least one later closed minute.");
            return true;
        };
        model.inputs = configuration.inputs;
        for (&model.windows, configuration.requests) |*window, query| window.* = .{
            .request = query,
        };
        model.started = true;
    } else if (!std.mem.eql(u8, name, "rule-hits-more") or !model.started) return true;
    model.remaining = 16;
    model.message = .{};
    try request(ctx);
    return true;
}

const Configuration = struct { inputs: history.Inputs, requests: [2]wire.Request };

fn configure(previous: history.Inputs, input: std.json.Value, now: u64) !Configuration {
    var selected = previous;
    selected.node = try number(u32, input, "node");
    selected.minutes = try number(u32, input, "minutes");
    selected.offset = try number(u32, input, "offset");
    const mode = fields.string(input, "mode");
    selected.mode = std.meta.stringToEnum(@FieldType(history.Inputs, "mode"), mode) orelse
        return error.InvalidInput;
    try selected.before_revision.set(fields.string(input, "before_revision"));
    try selected.after_revision.set(fields.string(input, "after_revision"));
    if (selected.minutes == 0 or selected.minutes > 90 * 1440 or
        selected.offset >= 90 * 1440 or now / 60 <= selected.offset + selected.minutes)
        return error.InvalidInput;
    var until = now / 60 - 1 - selected.offset;
    var before = until - selected.minutes;
    var duration = selected.minutes;
    if (selected.mode == .edit) {
        const edit = selected.edit_at / 60;
        if (edit == 0 or until <= edit) return error.InvalidInput;
        duration = @intCast(@min(duration, until - edit));
        until = edit + duration;
        before = edit - 1;
    }
    if (before + 1 < duration) return error.InvalidInput;
    var result: Configuration = .{ .inputs = selected, .requests = undefined };
    for (&result.requests, [_]u64{ before, until }, 0..) |*query, end, side| {
        const revision = if (side == 0) selected.before_revision else selected.after_revision;
        const version = try parseRevision(revision.slice());
        query.* = .{
            .key = selected.key,
            .node = selected.node,
            .from_minute = end - duration + 1,
            .until_minute = end,
            .revision = version,
        };
        try wire.validate(.{
            .request = query.*,
            .observed_at = now,
            .session_digest = @splat(0),
        });
    }
    return result;
}

fn parseRevision(text: []const u8) !?u64 {
    return if (text.len == 0) null else try std.fmt.parseInt(u64, text, 10);
}

fn number(comptime T: type, input: std.json.Value, key: []const u8) !T {
    return std.fmt.parseInt(T, fields.string(input, key), 10);
}

fn request(ctx: Context) !void {
    const model = &ctx.state.rule_history;
    if (model.remaining == 0 or !model.open or ctx.state.phase != .policies or
        ctx.state.paused or ctx.state.hidden) return;
    const side: usize = if (!model.windows[0].finished) 0 else 1;
    if (model.windows[side].finished) return;
    serial = try std.math.add(u64, serial, 1);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "rule-hits-{d}", .{serial});
    try ctx.out.post(id, "/console/api/policies/hits", model.windows[side].request);
    model.ticket = serial;
    model.side = side;
    model.busy = true;
    model.remaining -= 1;
}

pub fn response(ctx: Context, reply: Response) !void {
    const state = ctx.state;
    const ticket = std.fmt.parseInt(u64, reply.id["rule-hits-".len..], 10) catch return;
    const model = &state.rule_history;
    if (ticket == 0 or ticket != model.ticket or !model.busy or !state.fullAccess()) return;
    model.busy = false;
    if (reply.status == 401 or reply.status == 403) {
        try @import("live_controller.zig").stop(ctx.out);
        const appearance = state.appearance;
        state.reset();
        state.appearance = appearance;
        state.phase = .login;
        return;
    }
    if (state.phase != .policies or !model.open or state.paused or state.hidden) return;
    if (reply.status != 200) return model.message.set(if (reply.status == 429)
        "RULEHITS429: Read allowance reached. Wait one minute, then continue."
    else
        "RULEHITS001: History is unavailable. Check storage and access, then continue.");
    const part = @import("json_value.zig").decode(wire.Part, reply.body, reply.allocator) catch
        return invalid(model);
    wire.accept(&model.windows[model.side], part) catch return invalid(model);
    try request(ctx);
}

fn invalid(model: *history.Model) !void {
    model.started = false;
    try model.message.set("RULEHITS003: History changed or was invalid. " ++
        "Start a new comparison; the invalid page was not merged.");
}

test "rule edit comparisons exclude the cutover minute and bound equal closed periods" {
    const t = std.testing;
    const fields_json =
        \\{"node":"7","minutes":"60","offset":"0","mode":"edit",
        \\ "before_revision":"40","after_revision":"41"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, fields_json, .{});
    defer parsed.deinit();
    const input: history.Inputs = .{
        .key = try p.rule_hits.Key.init("m:edited"),
        .edit_at = 1000 * 60 + 17,
    };
    const result = try configure(input, parsed.value, 1010 * 60 + 30);
    try t.expectEqual(@as(u64, 991), result.requests[0].from_minute);
    try t.expectEqual(@as(u64, 999), result.requests[0].until_minute);
    try t.expectEqual(@as(u64, 1001), result.requests[1].from_minute);
    try t.expectEqual(@as(u64, 1009), result.requests[1].until_minute);
    try t.expectEqual(@as(?u64, 40), result.requests[0].revision);
    try t.expectEqual(@as(?u64, 41), result.requests[1].revision);
    try t.expectEqual(@as(u32, 7), result.requests[1].node);
    try t.expectError(error.InvalidInput, configure(input, parsed.value, 1001 * 60));
}

test "rule history drops superseded replies and expires a revoked active request" {
    const t = std.testing;
    var state: @import("state.zig").State = .{};
    var commands: @import("test_transport.zig").Commands = .{};
    const ctx: Context = .{ .state = &state, .out = commands.out() };
    try t.expect(!try action(ctx, "rule-hits-open", .null));
    state.phase = .policies;
    try state.csrf.set("session");
    state.rule_history.open = true;
    state.rule_history.started = true;
    try t.expect(try action(ctx, "rule-hits-more", .null));
    const ticket = state.rule_history.ticket;
    try t.expectEqual(@as(u8, 15), state.rule_history.remaining);
    var bytes: [48]u8 = undefined;
    const id = try std.fmt.bufPrint(&bytes, "rule-hits-{d}", .{ticket});
    try response(ctx, .{ .id = id, .status = 429, .body = .null, .allocator = t.allocator });
    try t.expect(!state.rule_history.busy);
    try t.expect(try action(ctx, "rule-hits-more", .null));
    try response(ctx, .{ .id = id, .status = 401, .body = .null, .allocator = t.allocator });
    try t.expectEqual(.policies, state.phase);
    const active = try std.fmt.bufPrint(&bytes, "rule-hits-{d}", .{state.rule_history.ticket});
    try response(ctx, .{ .id = active, .status = 403, .body = .null, .allocator = t.allocator });
    try t.expectEqual(.login, state.phase);
    try t.expect(!state.rule_history.open);
}

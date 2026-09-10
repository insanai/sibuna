//! Catalog paging and private-engine tests share the managed editor's event-local context.
//! The ABI owns the generation across navigation and sign-out; superseded replies are ignored.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Controller = @import("managed_controller.zig").Controller;
const field = @import("events_state.zig").field;
const string = @import("events_state.zig").string;

pub fn action(ctx: Controller, name: []const u8, fields: std.json.Value) !bool {
    const state = ctx.state;
    if (!state.fullAccess()) return false;
    const model = &state.policies;
    if (equal(name, "policies") or equal(name, "policies-refresh")) {
        if (state.phase == .policies and (model.busy or model.testing)) return true;
        model.testing = false;
        model.manager.active = false;
        state.rule_history.clear();
        model.inspection_draft = null;
        state.phase = .policies;
        state.message = .{};
        model.offset = 0;
        model.applied = .{};
        model.decision = .{};
        model.busy = true;
        try query(ctx, false, .{ .offset = @as(u8, 0) });
        state.reputation.clear();
        try @import("reputation_controller.zig").refresh(state, ctx.out);
    } else if (equal(name, "policies-next") and state.phase == .policies) {
        if (model.busy or model.testing or model.stale) return true;
        const offset = model.next orelse return true;
        model.offset = offset;
        model.busy = true;
        try query(ctx, false, .{
            .offset = offset,
            .applied = model.applied.slice(),
        });
    } else if (equal(name, "policy-run") and state.phase == .policies) {
        if (model.testing or model.busy or model.stale) return true;
        if (!model.manager.active and model.applied.len == 0) return true;
        if (model.manager.review.len != 0) return true;
        var draft: p.Bytes(4096) = undefined;
        if (model.manager.active and !try ctx.captureDocument(fields, &draft)) return true;
        try model.path.set(string(fields, "path"));
        model.ip = try p.Bytes(48).init(string(fields, "ip"));
        try model.query_string.set(string(fields, "query"));
        model.user_agent = try p.Bytes(256).init(string(fields, "user_agent"));
        try model.body.set(string(fields, "body"));
        try model.headers.set(string(fields, "headers"));
        var headers: [8]@import("request_headers.zig").Header = undefined;
        const request_headers = @import("request_headers.zig").parse(
            model.headers.slice(),
            &headers,
        ) catch {
            message(state, "Use up to eight unique request headers, one Name: value per line.");
            try ctx.out.emit(.{ .op = "focus", .selector = "#console-message" });
            return true;
        };
        model.testing = true;
        model.decision = .{};
        state.message = .{};
        try query(ctx, true, .{
            .applied = if (model.manager.active) null else model.applied.slice(),
            .draft = if (model.manager.active) draft.slice() else null,
            .committed = if (model.manager.active) model.manager.committed.slice() else null,
            .path = model.path.slice(),
            .ip = model.ip.slice(),
            .query = model.query_string.slice(),
            .user_agent = model.user_agent.slice(),
            .body = model.body.slice(),
            .headers = request_headers,
        });
    } else return false;
    return true;
}

pub fn response(ctx: Controller, id: []const u8, status: i64, body: std.json.Value) !void {
    const state = ctx.state;
    const separator = std.mem.lastIndexOfScalar(u8, id, '-') orelse return;
    const generation = std.fmt.parseInt(u32, id[separator + 1 ..], 10) catch return;
    if (generation != ctx.generation.*) return;
    const model = &state.policies;
    model.busy = false;
    model.testing = false;
    if (state.phase != .policies) return;
    if (status == 401 or status == 403) {
        const appearance = state.appearance;
        state.reset();
        state.phase = .login;
        state.appearance = appearance;
        try @import("live_controller.zig").stop(ctx.out);
        state.stats_busy = false;
        state.stale = true;
        return;
    }
    if (status != 200) {
        model.stale = status != 400 and status != 429;
        @import("workflow_controller.zig").failed(ctx, id);
        message(state, switch (status) {
            400 => "Check the request, rule settings, headers and networks, then try again.",
            409 => "Policy or reputation changed. Refresh and review the current rules.",
            429 => "Too many queries. Wait a minute before trying again.",
            else => "Policy data is unavailable. Refresh to retry; previous data may be stale.",
        });
        return ctx.out.emit(.{ .op = "focus", .selector = "#console-message" });
    }
    if (std.mem.startsWith(u8, id, "managed-")) return ctx.response(id, body);
    if (std.mem.startsWith(u8, id, "policies-")) {
        const applied = string(body, "applied");
        _ = try std.fmt.parseInt(u64, applied, 10);
        const next = field(body, "next") orelse return error.InvalidResponse;
        if (next != .null and (next != .integer or next.integer < 0 or next.integer > 128))
            return error.InvalidResponse;
        var output: p.Bytes(4096) = .{};
        var writer: std.Io.Writer = .fixed(&output.data);
        try std.json.Stringify.value(body, .{}, &writer);
        output.len = writer.buffered().len;
        model.page = output;
        model.applied = try p.Bytes(20).init(applied);
        model.next = if (next == .integer) @intCast(next.integer) else null;
        model.stale = false;
    } else {
        var writer: std.Io.Writer = .fixed(&model.decision.data);
        try std.json.Stringify.value(body, .{}, &writer);
        model.decision.len = writer.buffered().len;
        try ctx.out.emit(.{ .op = "focus", .selector = "#policy-result" });
    }
    state.message = .{};
}

fn query(ctx: Controller, testing: bool, body: anytype) !void {
    ctx.generation.* +%= 1;
    var id_buffer: [32]u8 = undefined;
    const id = try std.fmt.bufPrint(&id_buffer, "{s}-{d}", .{
        if (testing) "policy-test" else "policies", ctx.generation.*,
    });
    const path = if (testing) "/console/api/policies/test" else "/console/api/policies/query";
    try ctx.out.post(id, path, body);
}

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn message(state: *State, text: []const u8) void {
    state.message_success = false;
    state.message = p.Bytes(256).init(text) catch unreachable;
}

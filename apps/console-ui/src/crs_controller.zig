//! One outstanding page request and generation tickets reject stale responses.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const ctx = @import("controller_context.zig");
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("crs_state.zig").Kind;
const string = @import("events_state.zig").string;
var generation: u64 = 0;

pub fn action(c: ctx.Context, name: []const u8, fields: std.json.Value) !bool {
    const state = c.state;
    if (std.mem.eql(u8, name, "crs") and state.allows(.manage_settings)) {
        state.crs.clear();
        state.phase = .crs;
        state.message = .{};
        try get(c, .status);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "crs-")) return false;
    if (state.phase != .crs or !state.allows(.manage_settings)) return true;
    const model = &state.crs;
    if (model.busy != .idle) return true;
    if (std.mem.eql(u8, name, "crs-test")) {
        try @import("crs_test_controller.zig").submit(c, fields);
    } else if (std.mem.eql(u8, name, "crs-test-poll")) {
        try @import("crs_test_controller.zig").poll(c);
    } else if (std.mem.eql(u8, name, "crs-refresh")) {
        try get(c, .status);
    } else if (std.mem.eql(u8, name, "crs-reload-editor")) {
        try get(c, .configuration);
    } else if (std.mem.startsWith(u8, name, "crs-review-")) {
        const index = std.fmt.parseInt(usize, name[11..], 10) catch return true;
        const snapshot = model.snapshot orelse return true;
        if (index >= snapshot.count) return true;
        const candidate = snapshot.candidates[index].?;
        if (candidate.state != .verified) return true;
        model.reviewed = candidate;
        try c.out.emit(.{ .op = "focus", .selector = "#crs-review-heading" });
    } else if (std.mem.eql(u8, name, "crs-cancel-review")) {
        model.reviewed = null;
    } else if (std.mem.eql(u8, name, "crs-select") or std.mem.eql(u8, name, "crs-discard")) {
        try edit(c, std.mem.eql(u8, name, "crs-select"));
    } else if (std.mem.eql(u8, name, "crs-mode") or
        std.mem.eql(u8, name, "crs-check") or std.mem.eql(u8, name, "crs-update") or
        std.mem.eql(u8, name, "crs-rollback"))
    {
        try @import("crs_editor_controller.zig").prepare(c, name, fields);
    }
    return true;
}

pub fn ticket(c: ctx.Context, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &c.state.crs;
    const text = try std.fmt.bufPrint(&model.ticket.data, "crs-{d}", .{generation});
    model.ticket.len = text.len;
    model.busy = kind;
    model.attempted_at = c.state.browser_time;
    c.state.message = .{};
    c.state.message_success = false;
}

fn get(c: ctx.Context, kind: Kind) !void {
    try ticket(c, kind);
    errdefer c.state.crs.busy = .idle;
    const path = switch (kind) {
        .configuration => "/console/api/crs/configuration",
        else => "/console/api/crs/status",
    };
    try c.out.emit(.{
        .op = "request",
        .method = "GET",
        .id = c.state.crs.ticket.slice(),
        .path = path,
    });
}

fn edit(c: ctx.Context, select: bool) !void {
    const model = &c.state.crs;
    if (model.stale) return;
    const reviewed = model.reviewed orelse return;
    const snapshot = model.snapshot orelse return;
    if (reviewed.expected_revision != snapshot.revision) {
        model.reviewed = null;
        try c.state.message.set("The saved selection changed. Refresh and review again.");
        return;
    }
    try ticket(c, if (select) .select else .discard);
    errdefer model.busy = .idle;
    var revision: [20]u8 = undefined;
    const path = if (select) "/console/api/crs/select" else "/console/api/crs/discard";
    try c.out.post(model.ticket.slice(), path, .{
        .id = reviewed.id.slice(),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{snapshot.revision}),
    });
}

pub fn response(c: ctx.Context, reply: ctx.Response) !void {
    const state = c.state;
    const model = &state.crs;
    if (state.phase != .crs or !std.mem.eql(u8, reply.id, model.ticket.slice())) return;
    const kind = model.busy;
    model.busy = .idle;
    if (kind == .idle) return;
    if (reply.status == 401) {
        state.reset();
        state.phase = .login;
        try state.message.set("Your session ended. Sign in to continue.");
        return c.out.emit(.{ .op = "disconnect" });
    }
    if (reply.status != 200) {
        model.stale = true;
        try state.message.set("CRS request was not confirmed. Refresh to inspect candidates, " ++
            "the saved revision and node receipts before retrying.");
        return;
    }
    if (kind == .test_submit or kind == .test_read) {
        return @import("crs_test_controller.zig").response(c, kind, reply.body, reply.allocator);
    }
    if (kind == .status) {
        try model.accept(reply.body, reply.allocator);
        model.received_at = state.browser_time;
        if (!model.editor_loaded) try get(c, .configuration);
    } else if (kind == .configuration) {
        const text = string(reply.body, "configuration");
        const raw = @import("events_state.zig").field(reply.body, "revision") orelse
            return error.InvalidResponse;
        const revision = try @import("json_value.zig").decodeFixed(u64, raw);
        if (model.snapshot == null or revision != model.snapshot.?.revision)
            return error.InvalidResponse;
        try model.editor.set(text);
        model.editor_revision = revision;
        model.editor_loaded = true;
    } else {
        model.reviewed = null;
        try get(c, .status);
        try state.message.set(if (kind == .prepare)
            "Candidate queued. Review it after verification; protection has not changed."
        else if (kind == .select)
            "Selection committed. Check node receipts for application."
        else
            "Candidate discarded. Protection has not changed.");
        state.message_success = true;
    }
}

pub fn tick(state: *State, out: Outbox) !void {
    const model = &state.crs;
    if (!state.fullAccess() or model.busy != .idle) return;
    if (state.browser_time -| model.attempted_at < 5) return;
    const c: ctx.Context = .{ .state = state, .out = out };
    if (model.test_id != null) {
        const pending = if (model.test_result) |result|
            result.state == .queued or result.state == .running
        else
            true;
        if (pending) return @import("crs_test_controller.zig").poll(c);
    }
    if (model.reviewed == null) try get(c, .status);
}

test "CRS page tickets reject late replies and revoked sessions erase operator text" {
    const t = std.testing;
    var state: State = .{};
    try state.role.set("admin");
    try state.csrf.set("test");
    var bytes: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    var count: usize = 0;
    const c: ctx.Context = .{
        .state = &state,
        .out = .{ .writer = &writer, .count = &count, .csrf = "test" },
    };
    try t.expect(try action(c, "crs", .null));
    const old = state.crs.ticket;
    try t.expect(try action(c, "crs", .null));
    try response(c, .{
        .id = old.slice(),
        .status = 200,
        .body = .null,
        .allocator = t.allocator,
    });
    try t.expectEqual(Kind.status, state.crs.busy);
    try state.crs.editor.set("private operator rule");
    const current = state.crs.ticket;
    try response(c, .{
        .id = current.slice(),
        .status = 401,
        .body = .null,
        .allocator = t.allocator,
    });
    try t.expectEqual(@import("state.zig").Phase.login, state.phase);
    try t.expectEqual(@as(usize, 0), state.crs.editor.len);
    try t.expect(std.mem.allEqual(u8, &state.crs.editor.data, 0));
    try t.expect(state.crs.snapshot == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "disconnect") != null);
    try state.role.set("viewer");
    try state.csrf.set("test");
    try t.expect(!try action(c, "crs", .null));
}

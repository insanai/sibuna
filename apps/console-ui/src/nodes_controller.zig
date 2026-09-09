const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("nodes_state.zig").Kind;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, out: Outbox) !bool {
    const model = &state.nodes;
    if (std.mem.eql(u8, name, "nodes") and state.fullAccess()) {
        state.phase = .nodes;
        state.stats_busy = false;
        state.stale = true;
        model.busy = .idle;
        if (!model.attempted) model.pending = null;
        try out.emit(.{ .op = "disconnect" });
        try refresh(state, out);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "nodes-")) return false;
    if (state.phase != .nodes or !state.fullAccess() or model.busy != .idle) return true;
    if (std.mem.eql(u8, name, "nodes-refresh")) {
        if (!model.attempted) model.pending = null;
        try refresh(state, out);
    } else if (std.mem.startsWith(u8, name, "nodes-select-")) {
        if (!state.allows(.control_node) or !model.fresh(state.browser_time) or
            model.pending != null) return true;
        const kind = std.meta.stringToEnum(p.nodes.Kind, name[13..]) orelse return true;
        const current = model.status.?;
        if (current.completion_pending or current.control_revision >= std.math.maxInt(i64) or
            (kind == .drain and current.draining) or
            (kind == .@"resume" and !current.draining) or
            (kind == .clear_local_bans and current.active_ban_entries == 0)) return true;
        model.pending = .{
            .id = current.operation_id,
            .boot = current.boot,
            .node = current.node,
            .revision = current.control_revision,
            .kind = kind,
        };
        model.attempted = false;
        model.receipt = null;
        try out.emit(.{ .op = "focus", .selector = "#nodes-confirmation" });
    } else if (std.mem.eql(u8, name, "nodes-confirm")) {
        if (model.attempted) return true;
        if (!model.fresh(state.browser_time)) {
            model.pending = null;
            try refresh(state, out);
            try state.message.set("Preview expired. Review the refreshed node before confirming.");
        } else try submit(state, out);
    } else if (std.mem.eql(u8, name, "nodes-retry") and model.attempted) {
        try submit(state, out);
    } else if (std.mem.eql(u8, name, "nodes-receipt") and model.pending != null) {
        try ticket(state, .receipt);
        errdefer model.busy = .idle;
        try out.post(model.ticket.slice(), "/console/api/nodes/command/read", .{
            .id = model.pending.?.id.slice(),
        });
    } else if (std.mem.eql(u8, name, "nodes-cancel") and !model.attempted) {
        model.pending = null;
        try out.emit(.{ .op = "focus", .selector = "#page-heading", .top = true });
    } else if (std.mem.eql(u8, name, "nodes-acknowledge") and model.receipt != null and
        model.receipt.?.state == .uncertain)
    {
        model.pending = null;
        model.attempted = false;
        try refresh(state, out);
    }
    return true;
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.nodes;
    const text = try std.fmt.bufPrint(&model.ticket.data, "nodes-{d}", .{generation});
    model.ticket.len = text.len;
    model.busy = kind;
    state.message = .{};
    state.message_success = false;
}

pub fn refresh(state: *State, out: Outbox) !void {
    try ticket(state, .status);
    errdefer state.nodes.busy = .idle;
    state.nodes.loaded = false;
    state.nodes.last_attempt = state.browser_time;
    try out.emit(.{
        .op = "request",
        .id = state.nodes.ticket.slice(),
        .method = "GET",
        .path = "/console/api/nodes/local",
    });
}

fn submit(state: *State, out: Outbox) !void {
    const model = &state.nodes;
    if (!state.allows(.control_node)) return;
    const pending = model.pending orelse return;
    try ticket(state, .command);
    errdefer model.busy = .idle;
    model.attempted = true;
    model.loaded = false;
    var revision: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/nodes/command", .{
        .id = pending.id.slice(),
        .boot = pending.boot.slice(),
        .node = pending.node,
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{pending.revision}),
        .kind = pending.kind,
    });
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    const model = &state.nodes;
    if (state.phase != .nodes or !std.mem.eql(u8, id, model.ticket.slice())) return;
    const kind = model.busy;
    model.busy = .idle;
    if (kind == .idle) return;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        try state.message.set("Your session ended. Sign in to continue.");
        return out.emit(.{ .op = "disconnect" });
    }
    if (status != 200) {
        if (kind == .command and (status == 400 or status == 403 or status == 409)) {
            model.pending = null;
            model.attempted = false;
            try refresh(state, out);
            try state.message.set(
                "Command refused. Review the refreshed node before trying again.",
            );
            return;
        }
        try state.message.set(if (kind == .status)
            "Node status unavailable. Refresh to obtain a current snapshot."
        else
            "Outcome not confirmed. Inspect the receipt or retry the same operation.");
        return out.emit(.{ .op = "focus", .selector = "#console-message" });
    }
    if (kind == .status) {
        try model.statusValue(body, alloc);
        model.received_at = state.browser_time;
    } else {
        try model.receiptValue(body, alloc);
        if (model.pending == null) try refresh(state, out);
        try out.emit(.{ .op = "focus", .selector = "#nodes-receipt" });
    }
}

pub fn tick(state: *State, out: Outbox) !void {
    const model = &state.nodes;
    if (model.busy != .idle or model.pending != null or !state.fullAccess()) return;
    if (state.browser_time < model.last_attempt or state.browser_time - model.last_attempt >= 5)
        try refresh(state, out);
}

test {
    _ = @import("nodes_test.zig");
}

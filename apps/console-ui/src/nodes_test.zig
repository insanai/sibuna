const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Controller = @import("nodes_controller.zig");
const Model = @import("nodes_state.zig").Model;

fn snapshot() p.nodes.Status {
    return .{
        .operation_id = p.Bytes(32).init("11111111111111111111111111111111") catch unreachable,
        .boot = p.Bytes(32).init("22222222222222222222222222222222") catch unreachable,
        .node = 1,
        .control_revision = 7,
        .draining = false,
        .connections = 3,
        .active_ban_entries = 2,
        .committed = 9007199254740993,
        .applied = 9007199254740992,
        .observed_at = 100,
        .uptime_ms = 4000,
        .completion_pending = false,
    };
}

fn signedIn() State {
    return .{
        .phase = .nodes,
        .csrf = p.Bytes(64).init("test csrf") catch unreachable,
        .role = p.Bytes(16).init("operator") catch unreachable,
        .browser_time = 100,
        .nodes = .{ .status = snapshot(), .loaded = true, .received_at = 100 },
    };
}

const Harness = struct {
    memory: [8192]u8 = undefined,
    writer: std.Io.Writer = undefined,
    count: usize = 0,

    fn out(self: *Harness) @import("transport.zig").Outbox {
        self.writer = .fixed(&self.memory);
        self.count = 0;
        return .{ .writer = &self.writer, .count = &self.count, .csrf = "test csrf" };
    }
};

fn reply(state: *State, value: anytype, h: *Harness) !void {
    var bytes: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(value, .{}, &writer);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    const id = state.nodes.ticket;
    try Controller.response(state, id.slice(), 200, parsed.value, t.allocator, h.out());
}

test "node controls require a fresh preview and preserve operation identity after timeout" {
    var state = signedIn();
    var h: Harness = .{};
    try t.expect(try Controller.action(&state, "nodes-select-clear_local_bans", h.out()));
    const id = state.nodes.pending.?.id;
    try t.expect(!state.nodes.attempted);
    try t.expect(std.mem.indexOf(u8, h.writer.buffered(), "focus") != null);
    _ = try Controller.action(&state, "nodes-confirm", h.out());
    try t.expect(state.nodes.attempted and state.nodes.busy == .command);
    const ticket = state.nodes.ticket;
    try Controller.response(&state, ticket.slice(), 0, .null, t.allocator, h.out());
    try t.expectEqualStrings(id.slice(), state.nodes.pending.?.id.slice());
    _ = try Controller.action(&state, "nodes-retry", h.out());
    try t.expect(std.mem.indexOf(u8, h.writer.buffered(), id.slice()) != null);
    try t.expect(std.mem.indexOf(u8, h.writer.buffered(), "\"expected_revision\":\"7\"") != null);
    try t.expect(!std.mem.eql(u8, ticket.slice(), state.nodes.ticket.slice()));
    // A late successful response from the first attempt cannot consume the active retry.
    try Controller.response(&state, ticket.slice(), 200, .null, t.allocator, h.out());
    try t.expect(state.nodes.busy == .command and state.nodes.pending != null);
}

test "expired previews refresh before confirmation and viewer actions cannot mutate" {
    var state = signedIn();
    var h: Harness = .{};
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    state.browser_time = 111;
    _ = try Controller.action(&state, "nodes-confirm", h.out());
    try t.expect(state.nodes.pending == null and state.nodes.busy == .status);
    try t.expect(std.mem.indexOf(u8, h.writer.buffered(), "\"method\":\"GET\"") != null);
    state = signedIn();
    try state.role.set("viewer");
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    try t.expect(state.nodes.pending == null and h.count == 0);
}

test "typed node receipts release only matching completed operations and wipe on session expiry" {
    var state = signedIn();
    var h: Harness = .{};
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    _ = try Controller.action(&state, "nodes-confirm", h.out());
    const pending = state.nodes.pending.?;
    const receipt: p.nodes.Receipt = .{
        .id = pending.id,
        .boot = pending.boot,
        .node = pending.node,
        .kind = pending.kind,
        .state = .applied,
        .expected_revision = pending.revision,
        .applied_revision = pending.revision + 1,
        .requested_at = 100,
        .completed_at = 101,
        .completion_persisted = true,
    };
    try reply(&state, receipt, &h);
    try t.expect(state.nodes.pending == null and state.nodes.receipt.?.state == .applied);
    try t.expect(state.nodes.busy == .status);
    try reply(&state, snapshot(), &h);
    try t.expect(state.nodes.loaded);
    try t.expectEqual(snapshot().committed, state.nodes.status.?.committed);
    _ = try Controller.action(&state, "nodes-refresh", h.out());
    const ticket = state.nodes.ticket;
    try Controller.response(&state, ticket.slice(), 401, .null, t.allocator, h.out());
    try t.expect(state.phase == .login and state.nodes.status == null and state.csrf.len == 0);
}

test "node polling pauses around confirmation and navigation preserves unresolved operations" {
    var state = signedIn();
    var h: Harness = .{};
    state.nodes.last_attempt = 98;
    try Controller.tick(&state, h.out());
    try t.expectEqual(@as(usize, 0), h.count);
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    state.browser_time = 105;
    try Controller.tick(&state, h.out());
    try t.expectEqual(@as(usize, 0), h.count);
    _ = try Controller.action(&state, "nodes-confirm", h.out());
    state.phase = .policies;
    const old = state.nodes.ticket;
    try Controller.response(&state, old.slice(), 401, .null, t.allocator, h.out());
    try t.expect(state.phase == .policies and state.nodes.pending != null);
    _ = try Controller.action(&state, "nodes", h.out());
    try t.expect(state.nodes.pending != null and state.nodes.attempted);
    try t.expect(state.nodes.busy == .status);
}

test "node rendering keeps navigation, full-width revisions and explicit impact visible" {
    var state = signedIn();
    var h: Harness = .{};
    _ = try Controller.action(&state, "nodes-select-clear_local_bans", h.out());
    var buffer: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("render.zig").render(&state, &writer);
    const document = writer.buffered();
    for ([_][]const u8{
        "data-action=\"audit\"", "data-action=\"nodes\"", "9007199254740993",
        "Confirm change",        "Replicated policy",     "Peer coverage is unavailable",
    }) |text| try t.expect(std.mem.indexOf(u8, document, text) != null);
    state.reset();
    try t.expect(state.nodes.pending == null and state.nodes.receipt == null);
}

test "node receipts reject contradictory effects without releasing a pending operation" {
    var state = signedIn();
    var h: Harness = .{};
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    const pending = state.nodes.pending.?;
    const valid: p.nodes.Receipt = .{
        .id = pending.id,
        .boot = pending.boot,
        .node = pending.node,
        .kind = pending.kind,
        .state = .applied,
        .expected_revision = pending.revision,
        .applied_revision = pending.revision + 1,
        .requested_at = 100,
        .completed_at = 101,
        .completion_persisted = true,
    };
    for (0..7) |mutation| {
        var receipt = valid;
        switch (mutation) {
            0 => receipt.state = .uncertain,
            1 => receipt.state = .rejected,
            2 => receipt.completed_at = null,
            3 => receipt.cleared_entries = 1,
            4 => receipt.applied_revision = pending.revision,
            5 => receipt.boot = try p.Bytes(32).init("33333333333333333333333333333333"),
            6 => receipt.id = receipt.boot,
            else => unreachable,
        }
        _ = try Controller.action(&state, "nodes-confirm", h.out());
        try t.expectError(error.InvalidResponse, reply(&state, receipt, &h));
        try t.expect(state.nodes.pending != null and state.nodes.receipt == null);
        state.nodes.attempted = false;
        state.nodes.loaded = true;
    }
}

test "pending durable completion and exhausted revisions refuse new local effects" {
    var state = signedIn();
    var h: Harness = .{};
    state.nodes.status.?.completion_pending = true;
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    try t.expect(state.nodes.pending == null and h.count == 0);
    state.nodes.status.?.completion_pending = false;
    state.nodes.status.?.control_revision = std.math.maxInt(i64);
    _ = try Controller.action(&state, "nodes-select-drain", h.out());
    try t.expect(state.nodes.pending == null and h.count == 0);
}

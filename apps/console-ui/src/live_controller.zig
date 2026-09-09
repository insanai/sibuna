//! One connection survives navigation. Filters serialize through complete snapshots;
//! old in-flight frames can never be published under a newer filter's label.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const fields = @import("events_state.zig");
const decode = @import("json_value.zig").decode;
const Args = p.subscriptions.Args;
const Subscription = struct {
    active: bool = false,
    pending: bool = false,
    args: Args = .{},
};
var client: p.subscription_client.Client = undefined;
var subscriptions: [p.subscriptions.topic_count]Subscription = undefined;
var principal: p.Bytes(64) = .{};
var connected = false;
var opening = false;
var retry = false;
var suspended = false;

pub fn init() void {
    client.reset();
    subscriptions = @splat(.{});
    principal = .{};
    connected = false;
    opening = false;
    retry = false;
    suspended = false;
}

pub fn stop(out: Outbox) !void {
    if (connected or opening) try out.emit(.{ .op = "disconnect" });
    init();
}

pub fn signOut(out: Outbox) !void {
    try stop(out);
    suspended = true;
}

pub fn authenticated() void {
    suspended = false;
}

pub fn timer() void {
    retry = false;
}

pub fn sync(state: *State, out: Outbox) !void {
    if (!state.fullAccess() or state.hidden) {
        try stop(out);
        for (&state.live.topics) |*topic| topic.stale = true;
        state.stale = true;
        return;
    }
    if (suspended) return;
    if (principal.len != 0 and !std.mem.eql(u8, principal.slice(), state.csrf.slice()))
        try stop(out);
    if (!connected) {
        if (opening or retry) return;
        try principal.set(state.csrf.slice());
        opening = true;
        try out.emit(.{ .op = "connect", .path = "/console/ws" });
        return;
    }
    for (&subscriptions, 0..) |*subscription, index| {
        const topic: p.Topic = @enumFromInt(index);
        const args = desired(state, topic);
        if (args != null and !std.meta.eql(args.?, subscription.args))
            state.live.topics[index] = .{};
        if (args == null) {
            if (subscription.active) try send(out, "unsub", topic, .{});
            subscription.* = .{};
            state.live.topics[index].stale = true;
        } else if (!subscription.active or
            (!subscription.pending and !std.meta.eql(args.?, subscription.args)))
        {
            try send(out, if (subscription.active) "filter" else "sub", topic, args.?);
            subscription.* = .{ .active = true, .pending = true, .args = args.? };
            state.live.topics[index].stale = true;
        }
    }
}

fn desired(state: *const State, topic: p.Topic) ?Args {
    if (state.kiosk and topic != .stats) return null;
    return switch (topic) {
        .stats => if (state.paused) null else .{},
        .policy => if (state.phase == .policies) .{} else null,
        .nodes => if (state.phase == .nodes) .{} else null,
        .challenges => if (state.phase == .challenges) .{} else null,
        .events => if (state.phase == .events and state.events.path.len <= 128 and
            state.events.campaign == 0 and state.events.incident == 0) .{
            .node = if (state.events.node == 0) null else state.events.node,
            .category = state.events.category,
            .ip = state.events.ip,
            .path_prefix = p.Bytes(128).init(state.events.path.slice()) catch unreachable,
        } else null,
        .audit => if (state.phase == .audit) .{
            .actor = if (state.audit.actor.len == 0) null else std.fmt.parseInt(
                u64,
                state.audit.actor.slice(),
                10,
            ) catch return null,
            .action = state.audit.action,
        } else null,
    };
}

fn send(out: Outbox, op: []const u8, topic: p.Topic, args: Args) !void {
    try out.emit(.{ .op = "send", .body = .{ .op = op, .topic = topic, .args = args } });
}

/// Null means no completed current view. The returned JSON borrows this event's arena.
pub fn event(
    state: *State,
    value: std.json.Value,
    allocator: std.mem.Allocator,
    out: Outbox,
) !?std.json.Value {
    if (!state.fullAccess() or suspended or state.hidden) return null;
    const kind = fields.string(value, "state");
    if (std.mem.eql(u8, kind, "open")) {
        opening = false;
        connected = true;
        return null;
    }
    if (!std.mem.eql(u8, kind, "message")) {
        const code = fields.field(value, "code");
        if (code != null and code.? == .integer and code.?.integer == 1008) {
            try expire(state, out);
        } else try failed(state, value, out);
        return null;
    }
    const body = fields.field(value, "body") orelse return error.InvalidMessage;
    const result = client.receive(body, allocator) catch {
        try failed(state, value, out);
        return null;
    };
    switch (result) {
        .none => return null,
        .unauthorized => {
            try expire(state, out);
            return null;
        },
        .gap => |topic| {
            subscriptions[@intFromEnum(topic)].active = false;
            state.live.topics[@intFromEnum(topic)].stale = true;
            return null;
        },
        .changed => |topic| {
            const subscription = &subscriptions[@intFromEnum(topic)];
            subscription.pending = false;
            const args = desired(state, topic) orelse return null;
            if (!subscription.active or !std.meta.eql(args, subscription.args)) return null;
            const parsed = try std.json.parseFromSliceLeaky(
                std.json.Value,
                allocator,
                client.view(topic),
                .{},
            );
            publish(state, topic, parsed, allocator) catch {
                try failed(state, value, out);
                return null;
            };
            state.reconnect_ms = 1000;
            return if (topic == .stats and fields.field(parsed, "timestamp") != null)
                parsed
            else
                null;
        },
    }
}

pub fn failed(state: *State, value: std.json.Value, out: Outbox) !void {
    try stop(out);
    retry = true;
    for (&state.live.topics) |*topic| topic.stale = true;
    state.stale = true;
    state.challenges.stale = true;
    const entropy = fields.field(value, "entropy") orelse .null;
    const random: u32 = if (entropy == .integer and entropy.integer >= 0)
        @truncate(@as(u64, @intCast(entropy.integer)))
    else
        0;
    const delay = state.reconnect_ms / 2 + random % (state.reconnect_ms / 2 + 1);
    try out.emit(.{ .op = "timer", .id = "live-retry", .delay_ms = delay });
    state.reconnect_ms = @min(30000, state.reconnect_ms * 2);
}

fn expire(state: *State, out: Outbox) !void {
    try stop(out);
    state.reset();
    state.phase = .login;
    try state.message.set("Your session ended. Sign in to continue.");
}

fn publish(state: *State, topic: p.Topic, value: std.json.Value, alloc: std.mem.Allocator) !void {
    const observation = &state.live.topics[@intFromEnum(topic)];
    observation.received_at = state.browser_time;
    observation.stale = false;
    observation.available = fields.field(value, "available") == null or
        (try decode(bool, fields.field(value, "available").?, alloc));
    switch (topic) {
        .stats => {},
        .nodes => if (observation.available) {
            try state.nodes.membersValue(value, alloc);
            state.nodes.peers.received_at = state.browser_time;
        },
        .policy => if (observation.available) {
            state.live.committed = try number(value, "committed", alloc);
            state.live.applied = try number(value, "applied", alloc);
            // Draft revisions remain frozen; the server rejects conflicts on save.
        },
        .challenges => if (observation.available) try challenge(state, value, alloc),
        .events, .audit => try rows(state, topic, value, alloc),
    }
}

fn number(value: std.json.Value, key: []const u8, alloc: std.mem.Allocator) !u64 {
    return decode(u64, fields.field(value, key) orelse return error.InvalidResponse, alloc);
}

fn challenge(state: *State, value: std.json.Value, alloc: std.mem.Allocator) !void {
    var candidate = try decode(p.challenges.Snapshot, value, alloc);
    var timing_current = true;
    if (state.challenges.snapshot) |old| {
        if (state.challenges.selected != null and old.selected != candidate.selected) {
            timing_current = false;
            candidate.selected = old.selected;
            candidate.buckets = old.buckets;
            candidate.missing = old.missing;
            candidate.invalid = old.invalid;
            candidate.wasm = old.wasm;
            candidate.javascript = old.javascript;
            candidate.unknown_solver = old.unknown_solver;
        }
    }
    if (timing_current) state.challenges.timing_received_at = state.browser_time;
    state.challenges.snapshot = candidate;
    state.challenges.stale = false;
    state.challenges.received_at = state.browser_time;
}

fn rows(state: *State, topic: p.Topic, value: std.json.Value, alloc: std.mem.Allocator) !void {
    const observation = &state.live.topics[@intFromEnum(topic)];
    const coverage = fields.field(value, "coverage") orelse return error.InvalidResponse;
    observation.available = try decode(
        bool,
        fields.field(coverage, "available") orelse return error.InvalidResponse,
        alloc,
    );
    observation.observed_at = try number(coverage, "observed_at", alloc);
    observation.missing_ids = try number(coverage, "missing_ids", alloc);
    observation.newer = 0;
    const items = fields.field(value, "rows") orelse return error.InvalidResponse;
    if (items != .array or items.array.items.len > 64) return error.InvalidResponse;
    const boundary = if (topic == .events) state.events.until else state.audit.until;
    const time_key = if (topic == .events) "time" else "recorded_at";
    for (items.array.items) |row| {
        const time = try number(row, time_key, alloc);
        if (time > boundary) observation.newer += 1;
    }
}

test {
    _ = @import("live_controller_test.zig");
}

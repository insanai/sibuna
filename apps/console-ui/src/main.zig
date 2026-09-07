//! Browser state machine. JavaScript transports commands and DOM events only.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const render = @import("render.zig");
var state: State = .{};
var input: [16 * 1024]u8 = undefined;
var html: [512 * 1024]u8 = undefined;
var html_length: usize = 0;
var commands: [16 * 1024]u8 = undefined;
var command_writer: std.Io.Writer = undefined;
var command_count: usize = 0;
var commands_length: usize = 0;

export fn sb_input() [*]u8 {
    return &input;
}
export fn sb_input_capacity() usize {
    return input.len;
}
export fn sb_html() [*]const u8 {
    return &html;
}
export fn sb_html_length() usize {
    return html_length;
}
export fn sb_commands() [*]const u8 {
    return &commands;
}
export fn sb_commands_length() usize {
    return commands_length;
}

export fn sb_init() void {
    state = .{};
    begin();
    get("session", "/console/api/session") catch unreachable;
    finish();
}

export fn sb_event(kind: u32, length: usize) void {
    if (length > input.len) return;
    begin();
    var memory: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &memory);
    defer std.crypto.secureZero(u8, input[0..length]);
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        fixed.allocator(),
        input[0..length],
        .{},
    ) catch {
        setMessage("Could not read the response. Please reconnect.");
        finish();
        return;
    };
    defer parsed.deinit();
    dispatch(kind, parsed.value, fixed.allocator()) catch {
        setMessage("Could not complete the action. Please try again.");
        state.busy = false;
    };
    finish();
}

fn begin() void {
    std.crypto.secureZero(u8, &commands);
    command_writer = .fixed(&commands);
    command_count = 0;
    command_writer.writeByte('[') catch unreachable;
}

fn finish() void {
    command_writer.writeByte(']') catch unreachable;
    commands_length = command_writer.buffered().len;
    var writer: std.Io.Writer = .fixed(&html);
    render.render(&state, &writer) catch {
        html_length = 0;
        return;
    };
    html_length = writer.buffered().len;
}

fn command(value: anytype) !void {
    if (command_count > 0) try command_writer.writeByte(',');
    try std.json.Stringify.value(value, .{}, &command_writer);
    command_count += 1;
}

fn get(id: []const u8, path: []const u8) !void {
    try command(.{ .op = "request", .id = id, .method = "GET", .path = path });
}

fn post(id: []const u8, path: []const u8, body: std.json.Value) !void {
    try command(.{
        .op = "request",
        .id = id,
        .method = "POST",
        .path = path,
        .body = body,
        .csrf = state.csrf.slice(),
    });
}

fn dispatch(kind: u32, value: std.json.Value, alloc: std.mem.Allocator) !void {
    switch (kind) {
        1 => try action(value),
        2 => try response(value, alloc),
        3 => {
            if (state.phase == .dashboard and !state.paused) try refresh();
        },
        4 => try streamEvent(value, alloc),
        else => {},
    }
}

fn action(value: std.json.Value) !void {
    const name = string(value, "action");
    const fields = field(value, "fields") orelse .null;
    if (equal(name, "theme")) {
        state.dark = !state.dark;
        return command(.{ .op = "theme", .value = if (state.dark) "dark" else "light" });
    }
    if (equal(name, "pause")) {
        state.paused = !state.paused;
        if (state.paused) {
            state.stats_busy = false;
            try command(.{ .op = "disconnect" });
        } else try refresh();
        return;
    }
    if (equal(name, "dashboard") and state.csrf.len != 0 and !state.must_change) {
        state.phase = .dashboard;
        state.message = .{};
        return refresh();
    }
    if (equal(name, "account")) {
        state.phase = .password;
        state.stats_busy = false;
        try command(.{ .op = "disconnect" });
        return;
    }
    if (state.busy) return;
    state.message = .{};
    state.busy = true;
    if (equal(name, "login") or equal(name, "setup")) {
        state.username = try p.Bytes(64).init(string(fields, "username"));
        return post(
            name,
            if (equal(name, "login")) "/console/api/login" else "/console/api/setup",
            fields,
        );
    }
    if (equal(name, "password")) return post(name, "/console/api/password", fields);
    if (equal(name, "logout")) {
        try command(.{ .op = "disconnect" });
        return post(name, "/console/api/logout", .null);
    }
    state.busy = false;
}

fn response(value: std.json.Value, alloc: std.mem.Allocator) !void {
    const id = string(value, "id");
    const status_value = field(value, "status") orelse return;
    if (status_value != .integer) return;
    const status = status_value.integer;
    const body = field(value, "body") orelse return;
    if (equal(id, "stats")) return statsResponse(status, body, alloc);
    state.busy = false;
    if (equal(id, "session") and status == 401) return get("setup", "/console/api/setup");
    if (status != 200) {
        state.stale = status == 0;
        if (state.phase == .loading) state.phase = .login;
        const message = switch (status) {
            429 => "Too many attempts. Please wait a minute.",
            401 => "Sign-in failed. Check your credentials.",
            else => "Could not complete this action. Check your connection and try again.",
        };
        setMessage(message);
        return;
    }
    if (equal(id, "setup")) {
        const required = field(body, "setup_required");
        state.phase = if (required != null and required.? == .bool and required.?.bool)
            .setup
        else
            .login;
        return;
    }
    if (equal(id, "session") or equal(id, "login")) {
        state.csrf = try p.Bytes(64).init(string(body, "csrf"));
        state.role = try p.Bytes(16).init(string(body, "role"));
        const change = field(body, "must_change");
        state.must_change = change != null and change.? == .bool and change.?.bool;
        state.phase = if (state.must_change) .password else .dashboard;
        state.message = .{};
        if (state.phase == .dashboard) try refresh();
        return;
    }
    if (equal(id, "logout") or equal(id, "password")) {
        state.phase = .login;
        state.stats_busy = false;
        state.stats = null;
        state.csrf = .{};
        try command(.{ .op = "disconnect" });
        if (equal(id, "password")) setMessage("Password updated. Sign in with your new password.");
    }
}

fn refresh() !void {
    if (state.stats_busy or state.paused) return;
    state.stats_busy = true;
    state.epoch = .{};
    try command(.{ .op = "connect", .path = "/console/stream" });
}

fn streamEvent(value: std.json.Value, alloc: std.mem.Allocator) !void {
    if (state.phase != .dashboard or state.paused) return;
    const event = string(value, "state");
    if (equal(event, "open")) return command(.{
        .op = "send",
        .body = .{ .op = "subscribe", .topics = .{"stats"} },
    });
    if (equal(event, "message")) {
        const body = field(value, "body") orelse return error.InvalidMessage;
        const op = string(body, "op");
        const epoch = string(body, "epoch");
        const seq = field(body, "seq") orelse return error.InvalidMessage;
        if (seq != .integer or seq.integer < 0) return error.InvalidMessage;
        const sequence: u64 = @intCast(seq.integer);
        const snapshot = equal(op, "snapshot") and sequence == 0 and epoch.len == 32;
        const delta = equal(op, "delta") and equal(epoch, state.epoch.slice()) and
            sequence == state.sequence + 1;
        if ((!snapshot and !delta) or !equal(string(body, "topic"), "stats")) {
            try command(.{ .op = "disconnect" });
            return reconnect();
        }
        if (snapshot) {
            state.epoch = try p.Bytes(32).init(epoch);
            state.points = @splat(.{});
            state.stats = null;
        }
        state.sequence = sequence;
        state.reconnect_ms = 1000;
        try statsResponse(200, field(body, "data") orelse return error.InvalidMessage, alloc);
        state.stats_busy = true;
        return;
    }
    if (equal(event, "closed")) {
        const code = field(value, "code");
        if (code != null and code.? == .integer and code.?.integer == 1008)
            return statsResponse(401, .null, alloc);
    }
    try command(.{ .op = "disconnect" });
    try reconnect();
}

fn reconnect() !void {
    state.stats_busy = false;
    state.stale = true;
    setMessage("Connection lost. Showing the last received values while reconnecting.");
    try command(.{ .op = "timer", .id = "stats", .delay_ms = state.reconnect_ms });
    state.reconnect_ms = @min(30000, state.reconnect_ms * 2);
}

fn statsResponse(status: i64, body: std.json.Value, alloc: std.mem.Allocator) !void {
    state.stats_busy = false;
    if (state.phase != .dashboard) return;
    if (status == 401 or status == 403) {
        state.phase = .login;
        state.stats_busy = false;
        state.stats = null;
        state.csrf = .{};
        setMessage("Your session ended. Sign in to continue.");
        return command(.{ .op = "disconnect" });
    }
    state.stale = status != 200;
    if (state.stale) {
        setMessage("Connection lost. Showing the last received values.");
        return;
    }
    const parsed = try std.json.parseFromValue(p.StatsSnapshot, alloc, body, .{});
    defer parsed.deinit();
    var snapshot = parsed.value;
    snapshot.sample_probability = "1/64";
    if (state.stats) |previous| {
        if (snapshot.timestamp > previous.timestamp and snapshot.requests >= previous.requests)
            state.points[@intCast(snapshot.timestamp % 60)] = .{
                .second = snapshot.timestamp,
                .count = snapshot.requests - previous.requests,
            };
    }
    state.stats = snapshot;
    state.message = .{};
}

fn field(value: std.json.Value, key: []const u8) ?std.json.Value {
    return if (value == .object) value.object.get(key) else null;
}
fn string(value: std.json.Value, key: []const u8) []const u8 {
    const item = field(value, key) orelse return "";
    return if (item == .string) item.string else "";
}
fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn setMessage(message: []const u8) void {
    state.message = p.Bytes(256).init(message) catch unreachable;
}

test {
    _ = @import("render.zig");
    _ = @import("geography.zig");
}

test "required password changes cannot open subscriptions through navigation" {
    sb_init();
    const login =
        \\{"id":"session","status":200,"body":{"csrf":"test","role":"admin",
        \\"must_change":true}}
    ;
    @memcpy(input[0..login.len], login);
    sb_event(2, login.len);
    try std.testing.expectEqual(.password, state.phase);
    try std.testing.expect(std.mem.indexOf(u8, commands[0..commands_length], "connect") == null);
    const action_json = "{\"action\":\"dashboard\",\"fields\":{}}";
    @memcpy(input[0..action_json.len], action_json);
    sb_event(1, action_json.len);
    try std.testing.expectEqual(.password, state.phase);
    try std.testing.expect(std.mem.indexOf(u8, html[0..html_length], "<svg") == null);
}

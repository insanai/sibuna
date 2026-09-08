const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const controller = @import("users_controller.zig");
const Outbox = @import("transport.zig").Outbox;

fn signedIn() !State {
    return .{
        .phase = .users,
        .user_id = 1,
        .csrf = try p.Bytes(64).init("csrf"),
        .role = try p.Bytes(16).init("admin"),
    };
}

test "account navigation replaces request identity and rejects late responses" {
    var state = try signedIn();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    try t.expect(try controller.action(&state, "users", .null, out));
    const old = state.users.ticket;
    try t.expect(try controller.action(&state, "users", .null, out));
    const current = state.users.ticket;
    try t.expect(!std.mem.eql(u8, old.slice(), current.slice()));
    try controller.response(&state, old.slice(), 401, .null, t.allocator, out);
    try t.expect(state.fullAccess() and state.users.busy);
    try controller.response(&state, current.slice(), 503, .null, t.allocator, out);
    try t.expect(!state.users.busy and !state.users.loaded);
    state.must_change = true;
    const before = count;
    try t.expect(try controller.action(&state, "users-first", .null, out));
    try t.expectEqual(before, count);
}

test "revocation preserves access drafts and sends exact IDs with the selected revision" {
    var state = try signedIn();
    const model = &state.users;
    model.rows[0] = .{
        .id = 9007199254740993,
        .revision = 9007199254740995,
        .username = try p.Bytes(64).init("disabled-viewer"),
        .disabled = true,
    };
    model.count = 1;
    model.loaded = true;
    model.selected = 0;
    model.disabled = true;
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    const fields = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"confirmed\":\"on\"}",
        .{},
    );
    defer fields.deinit();
    try t.expect(try controller.action(&state, "users-revoke", fields.value, out));
    try t.expect(model.disabled);
    const command = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer command.deinit();
    const body = command.value.object.get("body").?.object;
    try t.expectEqualStrings("9007199254740993", body.get("target").?.string);
    try t.expectEqualStrings("9007199254740995", body.get("expected_revision").?.string);
    try t.expect(body.get("disabled").? == .null);
    try controller.response(&state, model.ticket.slice(), 409, .null, t.allocator, out);
    try t.expect(model.disabled and model.selected != null and !model.busy);
}

test "saved temporary passwords survive catalog refresh and explicit dismissal erases them" {
    var state = try signedIn();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    const fields = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"username\":\"new-viewer\",\"role\":\"viewer\",\"confirmed\":\"on\"}",
        .{},
    );
    defer fields.deinit();
    try t.expect(try controller.action(&state, "users-create", fields.value, out));
    const reply = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"saved\":true,\"password_expires\":1234,\"temporary_password\":\"" ++
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
        .{},
    );
    defer reply.deinit();
    const ticket = state.users.ticket;
    try controller.response(&state, ticket.slice(), 200, reply.value, t.allocator, out);
    try t.expect(state.users.busy and state.users.temporary.len == 64);
    try controller.response(&state, state.users.ticket.slice(), 503, .null, t.allocator, out);
    try t.expect(try controller.action(&state, "users-dismiss", .null, out));
    try t.expectEqual(@as(usize, 0), state.users.temporary.len);
    try t.expect(std.mem.allEqual(u8, &state.users.temporary.data, 0));
    try t.expectEqual(@as(usize, 0), state.users.username.len);
}

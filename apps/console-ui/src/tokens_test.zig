const repeat = @import("text").repeat;
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const controller = @import("tokens_controller.zig");
const Outbox = @import("transport.zig").Outbox;

fn signedIn() !State {
    return .{
        .phase = .tokens,
        .user_id = 1,
        .browser_time = 100,
        .csrf = try p.Bytes(64).init("csrf"),
        .role = try p.Bytes(16).init("admin"),
    };
}

test "token navigation fences late responses and preserves mandatory authentication" {
    var state = try signedIn();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    try t.expect(try controller.action(&state, "tokens", .null, out));
    const old = state.tokens.ticket;
    try t.expect(try controller.action(&state, "tokens", .null, out));
    try controller.response(&state, old.slice(), 401, .null, t.allocator, out);
    try t.expect(state.fullAccess() and state.tokens.busy);
    const current = state.tokens.ticket;
    try controller.response(&state, current.slice(), 503, .null, t.allocator, out);
    try t.expect(!state.tokens.busy and !state.tokens.loaded);
    const before = count;
    state.totp_required = true;
    try t.expect(try controller.action(&state, "tokens-create", .null, out));
    try t.expectEqual(before, count);
}

test "token mint selects bounded authority and keeps its one-time value until dismissal" {
    var state = try signedIn();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    const fields = try std.json.parseFromSlice(std.json.Value, t.allocator,
        \\{"label":"observer","role":"viewer","stats_read":"on","policy_write":"on",
        \\"days":"7","confirmed":"on"}
    , .{});
    defer fields.deinit();
    try t.expect(try controller.action(&state, "tokens-create", fields.value, out));
    const emitted = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer emitted.deinit();
    const body = emitted.value.object.get("body").?.object;
    try t.expectEqualStrings("604900", body.get("expires").?.string);
    const scopes = body.get("scopes").?.array.items;
    try t.expectEqual(@as(usize, 1), scopes.len);
    try t.expectEqualStrings("stats_read", scopes[0].string);
    const issued = "{\"saved\":true,\"id\":\"9007199254740993\",\"token\":\"" ++
        &repeat("b", 64) ++ "\",\"expires\":604900}";
    const reply = try std.json.parseFromSlice(std.json.Value, t.allocator, issued, .{});
    defer reply.deinit();
    const ticket = state.tokens.ticket;
    try controller.response(&state, ticket.slice(), 200, reply.value, t.allocator, out);
    try t.expect(state.tokens.busy and state.tokens.secret.len == 64);
    try t.expectEqual(@as(u64, 9007199254740993), state.tokens.issued_id);
    // Dismissal must erase the value even while its catalog refresh is outstanding.
    try t.expect(try controller.action(&state, "tokens-dismiss", .null, out));
    try t.expectEqual(@as(usize, 0), state.tokens.secret.len);
    try t.expect(std.mem.allEqual(u8, &state.tokens.secret.data, 0));
    state.tokens.secret = try p.Bytes(64).init("retained secret");
    state.reset();
    try t.expect(std.mem.allEqual(u8, &state.tokens.secret.data, 0));
}

test "token catalog owns authority and renders safe forms within the shared navigation" {
    var state = try signedIn();
    const row =
        \\{"id":"9007199254740993","revision":"2","label":"<script>","role":"viewer",
        \\"scopes":["stats_read"],"created_by":"1","created_at":12,"expires":null,
        \\"disabled":true,"active":false}
    ;
    const encoded = "{\"version\":1,\"rows\":[" ++ row ++ "],\"next\":null}";
    const page = try std.json.parseFromSlice(std.json.Value, t.allocator, encoded, .{});
    defer page.deinit();
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    try state.tokens.decode(page.value, arena.allocator());
    state.tokens.selected = 0;
    var buffer: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("render.zig").render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"tokens-remove\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "aria-current=\"page\"") != null);
    state.tokens.pages[0] = 9007199254740993;
    try t.expectError(error.InvalidResponse, state.tokens.decode(page.value, arena.allocator()));
    state.role = try p.Bytes(16).init("viewer");
    writer = .fixed(&buffer);
    try @import("render.zig").render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<form ") == null);
}

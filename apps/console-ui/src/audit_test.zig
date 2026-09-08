const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const State = @import("state.zig").State;
const controller = @import("audit_controller.zig");
const Outbox = @import("transport.zig").Outbox;
const row =
    \\{"id":"9007199254740993","actor":1,"subject":3,"recorded_at":100,
    \\"action":"user.create","target":"<img>","actor_role":null}
;

fn signedIn() !State {
    var state: State = .{
        .phase = .audit,
        .browser_time = 100,
        .csrf = try p.Bytes(64).init("csrf"),
        .role = try p.Bytes(16).init("viewer"),
    };
    state.audit.clear();
    return state;
}

test "audit pages own full-width cursors, escape summaries and reject mismatched details" {
    var state = try signedIn();
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const page = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"version\":1,\"rows\":[" ++ row ++ "],\"next\":null}",
        .{},
    );
    try state.audit.pageValue(page, allocator);
    try t.expectEqual(@as(u64, 9007199254740993), state.audit.rows[0].id);
    state.audit.selected = 9007199254740993;
    const value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"version\":1,\"row\":" ++ row ++ ",\"before\":null," ++
            "\"after\":\"</pre><script>\",\"before_truncated\":false," ++
            "\"after_truncated\":true,\"before_redacted\":false,\"after_redacted\":true}",
        .{},
    );
    try state.audit.detailValue(value, allocator);
    var buffer: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("render.zig").render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<script>") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Not recorded") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Summary text was truncated") != null);
    state.audit.selected += 1;
    try t.expectError(error.InvalidResponse, state.audit.detailValue(value, allocator));
    state.audit.pages[0] = 9007199254740992;
    try t.expectError(error.InvalidResponse, state.audit.pageValue(page, allocator));
    state.reset();
    try t.expect(!state.audit.has_detail and !state.audit.loaded and state.audit.count == 0);
}

test "audit response tickets preserve navigation and failures never relabel old rows" {
    var state = try signedIn();
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    try t.expect(try controller.action(&state, "audit", .null, out));
    const old = state.audit.ticket;
    try t.expect(try controller.action(&state, "audit", .null, out));
    try controller.response(&state, old.slice(), 401, .null, t.allocator, out);
    try t.expect(state.fullAccess() and state.audit.busy);
    const current = state.audit.ticket;
    try controller.response(&state, current.slice(), 503, .null, t.allocator, out);
    try t.expect(!state.audit.busy and !state.audit.loaded);
    state.phase = .dashboard;
    try controller.response(&state, current.slice(), 401, .null, t.allocator, out);
    try t.expect(state.fullAccess() and state.phase == .dashboard);
    state.must_change = true;
    const before = count;
    try t.expect(try controller.action(&state, "audit-export", .null, out));
    try t.expectEqual(before, count);
}

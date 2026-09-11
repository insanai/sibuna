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

const policy_row =
    \\{"id":"41","actor":1,"subject":18,"recorded_at":100,
    \\"action":"policy.edit","target":"api-rate","actor_role":"admin"}
;

test "audit revert confirms, reads the earlier document and edits against the audited revision" {
    var state = try signedIn();
    state.role = try p.Bytes(16).init("admin");
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var buffer: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = state.csrf.slice() };
    // No detail: revert actions are ignored and post nothing.
    try t.expect(try controller.action(&state, "audit-revert", .null, out));
    try t.expect(!state.audit.revert_open and count == 0);
    state.audit.selected = 41;
    const detail = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"version\":1," ++
        "\"row\":" ++ policy_row ++ ",\"before\":null,\"after\":null," ++
        "\"before_truncated\":false," ++
        "\"after_truncated\":false,\"before_redacted\":false,\"after_redacted\":false}", .{});
    try state.audit.detailValue(detail, allocator);
    try t.expect(try controller.action(&state, "audit-revert", .null, out));
    try t.expect(state.audit.revert_open);
    var rendered: [32768]u8 = undefined;
    var page: std.Io.Writer = .fixed(&rendered);
    try @import("render.zig").render(&state, &page);
    try t.expect(std.mem.indexOf(u8, page.buffered(), "id=\"audit-revert-confirm\"") != null);
    try t.expect(std.mem.indexOf(u8, page.buffered(), "name=\"confirmed\" required") != null);
    // The checkbox is required; an unticked submission posts nothing.
    const unticked = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{}", .{});
    try t.expect(try controller.action(&state, "audit-revert-confirm", unticked, out));
    try t.expect(count == 2 and !state.audit.busy);
    const ticked = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"confirmed\":\"on\"}",
        .{},
    );
    try t.expect(try controller.action(&state, "audit-revert-confirm", ticked, out));
    try t.expect(state.audit.busy and state.audit.kind == .revert_read);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"previous\":true") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"revision\":\"18\"") != null);
    const ticket = state.audit.ticket;
    // A newer rule set refuses the revert before any edit is posted.
    const moved = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"committed\":\"19\",\"document\":\"{}\"}",
        .{},
    );
    const posted = count;
    try controller.response(&state, ticket.slice(), 200, moved, allocator, out);
    try t.expect(!state.audit.busy and count == posted + 1);
    try t.expect(std.mem.indexOf(u8, state.message.slice(), "changed after this record") != null);
    try t.expect(try controller.action(&state, "audit-revert-confirm", ticked, out));
    const read = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"committed\":\"18\",\"document\":\"{\\\"id\\\":\\\"api-rate\\\"}\"}",
        .{},
    );
    try controller.response(&state, state.audit.ticket.slice(), 200, read, allocator, out);
    try t.expect(state.audit.busy and state.audit.kind == .revert_edit);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"expected_revision\":\"18\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "/console/api/policies/edit") != null);
    const conflict = state.audit.ticket;
    try controller.response(&state, conflict.slice(), 409, .null, allocator, out);
    try t.expect(!state.audit.busy and state.audit.revert_open);
    try t.expect(std.mem.indexOf(u8, state.message.slice(), "Policy history") != null);
    try t.expect(try controller.action(&state, "audit-revert-confirm", ticked, out));
    try controller.response(&state, state.audit.ticket.slice(), 200, read, allocator, out);
    const saved = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"committed\":\"19\",\"applied\":\"19\"}",
        .{},
    );
    try controller.response(&state, state.audit.ticket.slice(), 200, saved, allocator, out);
    try t.expect(state.message_success and !state.audit.revert_open and !state.audit.has_detail);
    try t.expect(state.audit.busy and state.audit.kind == .query);
    try t.expect(std.mem.indexOf(u8, state.message.slice(), "revision 19 records") != null);
}

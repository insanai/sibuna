const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const membership = @import("console_membership.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn rows(fx: *fixture.Fixture) !struct { count: usize, first: u64, last: u64, applied: u64 } {
    var result = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT first_seen,last_seen,applied_revision FROM console_nodes WHERE node=1",
        &.{},
    );
    defer result.deinit();
    if (result.rows.len == 0) return .{ .count = 0, .first = 0, .last = 0, .applied = 0 };
    return .{
        .count = result.rows.len,
        .first = try util.number(result.rows[0][0]),
        .last = try util.number(result.rows[0][1]),
        .applied = try util.number(result.rows[0][2]),
    };
}

test "membership rows announce the writer, preserve first_seen and follow applied rebuilds" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/members", .{tmp.sub_path}),
    );
    defer fx.close();
    try fixture.policySession(fx);
    const bad = try p.Bytes(p.nodes.max_url).init("javascript:x");
    try t.expect((try fx.run(.{ .node_advertise = bad })) == .failed);
    const url = try p.Bytes(p.nodes.max_url).init("http://127.0.0.1:9443");
    try t.expect((try fx.run(.{ .node_advertise = url })) == .command_recorded);
    membership.tick(fx.owner);
    const first = try rows(fx);
    try t.expectEqual(@as(usize, 1), first.count);
    try t.expectEqual(fx.owner.version, first.applied);
    // A repeated tick within the coalescing window changes nothing; an announcement after
    // the window rewrites last_seen but never first_seen.
    membership.tick(fx.owner);
    try t.expectEqual(first.last, (try rows(fx)).last);
    fx.owner.console_node.last_heartbeat -= 5;
    fx.owner.console_node.announce = true;
    membership.tick(fx.owner);
    const again = try rows(fx);
    try t.expectEqual(first.first, again.first);
    try t.expect(!fx.owner.console_node.announce);
    const result = try fx.run(.{ .nodes_query = auth });
    try t.expect(result == .nodes_page);
    const page = result.nodes_page;
    try t.expectEqual(@as(u8, 1), page.count);
    try t.expectEqual(@as(u32, 1), page.members[0].node);
    try t.expectEqualStrings("http://127.0.0.1:9443", page.members[0].console_url.slice());
    try t.expectEqualStrings("local", page.members[0].address.slice());
    try t.expectEqual(p.nodes.Role.single, page.storage.role);
    try t.expect(page.storage.quorum);
}

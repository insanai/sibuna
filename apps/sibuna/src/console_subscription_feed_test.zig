const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const f = p.subscription_feed;
const Fixture = @import("console_store_test.zig").Fixture;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

fn insert(fx: *Fixture, node: u32, sequence: u64) !void {
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
            "violation_category,offending_payload,recorded_at) VALUES(?,?,'8.8.8.8','','GET',?," ++
            "'honeypot','private evidence',100)",
        &.{
            util.integer((@as(u64, node) << 40) + sequence),
            util.integer(node),
            util.text("/public/" ++ "x" ** 128 ++ "?secret=hidden"),
        },
    );
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "INSERT INTO incidents_fts(rowid,path,offending_payload) " ++
            "SELECT id,path,offending_payload FROM security_incidents WHERE id=?",
        &.{util.integer((@as(u64, node) << 40) + sequence)},
    );
    var key: [48]u8 = undefined;
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "INSERT OR REPLACE INTO sibuna_meta(key,value) VALUES(?,?)",
        &.{
            util.text(try std.fmt.bufPrint(&key, "incident_cursor_{d}", .{node})),
            util.integer(sequence + 1),
        },
    );
}

fn read(fx: *Fixture, input: f.Request) !f.Page {
    const result = try fx.run(.{ .subscription_read = input });
    try t.expect(result == .subscription_page);
    return result.subscription_page;
}

test "subscription feed pages below a captured watermark independently for every issuer" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/subscription-cursors",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.setup_status);
    const base = @as(u64, 1) << 40;
    try insert(fx, 2, 1);
    const other = try read(fx, .{ .kind = .events, .node = 2 });
    try t.expectEqual(@as(u8, 1), other.count);
    for (1..13) |id| try insert(fx, 1, id);
    const first = try read(fx, .{ .kind = .events, .node = 1 });
    try t.expect(first.more and first.count == 8);
    try t.expectEqual(base + 12, first.through);
    try t.expect(first.rows[0].events.display_truncated);
    try t.expect(first.rows[0].events.query_redacted);
    try t.expect(std.mem.indexOf(u8, first.rows[0].events.path.slice(), "secret") == null);
    try insert(fx, 1, 13);
    const next = try read(fx, .{
        .kind = .events,
        .node = 1,
        .after = first.next,
        .through = first.through,
    });
    try t.expect(!next.more and next.count == 4);
    try t.expectEqual(base + 12, next.next);
    try t.expectEqual(base + 13, next.head);
    const delta = try read(fx, .{ .kind = .events, .node = 1, .after = next.next });
    try t.expectEqual(@as(u8, 1), delta.count);
    try fx.owner.db.exec(t.allocator, "DELETE FROM security_incidents WHERE node_id=1");
    const lost = try read(fx, .{ .kind = .events, .node = 1, .after = next.next });
    try t.expectEqual(@as(u8, 0), lost.count);
    try t.expectEqual(@as(u64, 1), lost.missing_ids);
    try t.expectEqual(delta.head, lost.head);
}

test "audit subscription receipt prevents cursor reuse after full retention and migration replay" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/subscription-audit",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.setup_status);
    const sql = "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
        "VALUES(1,'test',0,100)";
    for (0..10) |_| try fx.owner.db.exec(t.allocator, sql);
    const initial = try read(fx, .{ .kind = .audit });
    try fx.owner.db.exec(t.allocator, "DELETE FROM console_audit");
    try @import("console_migrations.zig").run(fx.owner);
    try fx.owner.db.exec(t.allocator, sql);
    const next = try read(fx, .{ .kind = .audit, .after = initial.head });
    try t.expectEqual(@as(u8, 1), next.count);
    try t.expectEqual(initial.head + 1, next.rows[0].audit.id);
    try t.expectEqual(@as(u64, 0), next.missing_ids);
}

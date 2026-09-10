const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const wire = p.rule_hit_history;
const Fixture = @import("console_store_test.zig").Fixture;
const storage = @import("console_store_rule_hits.zig");

fn write(fx: *Fixture, minute: u64, node: u32, hits: ?u64) !void {
    const span: p.rule_hits.Span = .{
        .node = node,
        .boot = @splat(1),
        .sequence = minute,
        .generation = 1,
        .revision = 1,
        .minute = minute,
        .utc_start = minute * 60 - 1,
        .utc_end = minute * 60 + 59,
        .start_ms = minute * 60000 - 1000,
        .end_ms = minute * 60000 + 59000,
        .observed_ms = 60000,
        .observations = 60,
        .complete = true,
    };
    const entries = [_]p.rule_hits.Entry{.{ .hits = hits, .identity = .{
        .key = try p.rule_hits.Key.init("m:retained"),
        .name = try p.rule_hits.Name.init("Rule"),
    } }};
    try storage.write(fx.owner, .{ .span = &span, .entries = &entries });
}

fn query() wire.Query {
    return .{ .session_digest = @splat(1), .observed_at = 10000, .request = .{
        .key = p.rule_hits.Key.init("m:retained") catch unreachable,
        .node = 7,
        .from_minute = 2,
        .until_minute = 50,
    } };
}

test "rule history bounds pages, pins owned cursors and rejects revoked access" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/hit-pages",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try @import("console_store_test.zig").policySession(fx);
    for (2..51) |minute| try write(fx, minute, 7, 1);
    var input = query();
    var window: wire.Window = .{ .request = input.request };
    const first = try fx.run(.{ .rule_hit_history = input });
    try t.expectEqual(@as(u32, 48), first.rule_hit_history.window.rows);
    try t.expect(first.rule_hit_history.window.next != null);
    try wire.accept(&window, first.rule_hit_history);
    input.request.before = window.next;
    const ticket = try fx.owner.console_mailbox.submit(
        t.io,
        .{ .rule_hit_history = input },
        .background,
    );
    input.request.key = try p.rule_hits.Key.init("m:mutated-after-submission");
    try fx.owner.tick();
    const last = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(@as(u32, 1), last.rule_hit_history.window.rows);
    try wire.accept(&window, last.rule_hit_history);
    try t.expect(window.covered());
    try t.expectEqual(@as(?u64, 49), window.hits);
    input = query();
    input.request.revision = 2;
    const absent = try fx.run(.{ .rule_hit_history = input });
    try t.expect(absent.rule_hit_history.window.finished);
    try t.expectEqual(@as(u32, 0), absent.rule_hit_history.window.rows);
    input.request.node = 0;
    const mailbox = &fx.owner.console_mailbox;
    try t.expectError(
        error.InvalidLimit,
        mailbox.submit(t.io, .{ .rule_hit_history = input }, .background),
    );
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET disabled=1");
    const revoked = try fx.run(.{ .rule_hit_history = query() });
    try t.expectEqual(p.Failure.unauthorized, revoked.failed);
}

test "today rollups keep unknown and future observations out of apparently complete totals" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/hit-today",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.setup_status);
    const key = try p.rule_hits.Key.init("m:retained");
    try write(fx, 120, 1, 3);
    try write(fx, 121, 1, 4);
    const today = @import("console_rule_hit_today.zig");
    const current = try today.readAt(fx.owner, key, 122 * 60);
    try t.expectEqual(@as(?u64, 7), current.hits);
    try t.expectEqual(@as(?u64, 7), current.hours[2]);
    try t.expect(!current.partial);
    try t.expectEqual(@as(?u64, null), current.hours[1]);
    try write(fx, 130, 1, 100);
    const future = try today.readAt(fx.owner, key, 122 * 60);
    try t.expect(future.partial);
    try t.expectEqual(@as(?u64, null), future.hours[2]);
    const later = try today.readAt(fx.owner, key, 131 * 60);
    try t.expectEqual(@as(?u64, 107), later.hits);
    try write(fx, 131, 1, null);
    const missing = try today.readAt(fx.owner, key, 132 * 60);
    try t.expectEqual(@as(?u64, null), missing.hits);
}

test "older rollups migrate without rewriting history and keep conservative open-hour bounds" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/hit-migration",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const schema = @import("console").schema;
    try fx.owner.db.exec(t.allocator, schema.sql);
    for (schema.migrations[0..30]) |migration|
        try fx.owner.db.exec(t.allocator, migration);
    try write(fx, 120, 1, 3);
    try @import("console_migrations.zig").run(fx.owner);
    try @import("console_migrations.zig").run(fx.owner);
    const today = @import("console_rule_hit_today.zig");
    const key = try p.rule_hits.Key.init("m:retained");
    const open = try today.readAt(fx.owner, key, 122 * 60);
    try t.expect(open.partial);
    try write(fx, 120, 1, 3);
    const closed = try today.readAt(fx.owner, key, 180 * 60);
    try t.expectEqual(@as(?u64, 3), closed.hits);
    try t.expectEqual(@as(u32, 1), closed.rows);
    try write(fx, 180, 1, 4);
    const fresh = try today.readAt(fx.owner, key, 181 * 60);
    try t.expect(!fresh.partial);
    try t.expectEqual(@as(?u64, 7), fresh.hits);
}

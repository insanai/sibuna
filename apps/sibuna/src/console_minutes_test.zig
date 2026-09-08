const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");

fn record() p.minutes.Record {
    return .{
        .node = 7,
        .boot = @splat(1),
        .epoch = 1,
        .minute = 2,
        .utc_start = 120,
        .utc_end = 121,
        .start_ms = 0,
        .end_ms = 1000,
        .observed_ms = 1000,
        .observations = 4,
        .counts = .{ .admitted = 9007199254740993, .denied = 2 },
    };
}

fn page(fx: *Fixture, before: ?p.minutes.Cursor) !p.minutes.Page {
    const result = try fx.run(.{ .minutes_query = .{
        .session_digest = @splat(1),
        .now = 300,
        .from_minute = 0,
        .until_minute = 5,
        .before = before,
        .limit = 2,
    } });
    return result.minute_page;
}

test "partial minute retries are owned, monotonic and restart safe; sealing keeps the endpoint" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        ".zig-cache/tmp/{s}/minutes",
        .{tmp.sub_path},
    );
    var input: p.StorageRequest = .{ .minutes_write = .{ .record = record(), .now = 200 } };
    {
        const fx = try Fixture.open(path);
        defer fx.close();
        try fixture.policySession(fx);
        const ticket = try fx.owner.console_mailbox.submit(t.io, input, .background);
        input.minutes_write.record.counts.admitted = 1;
        try fx.owner.tick();
        try t.expect((try fx.owner.console_mailbox.poll(t.io, ticket)).? == .command_recorded);
        try t.expectEqual(p.Failure.conflict, (try fx.run(input)).failed);
        input.minutes_write.record = record();
        try t.expect(try fx.run(input) == .command_recorded);
        const saved = try page(fx, null);
        try t.expectEqual(@as(u64, 9007199254740993), saved.rows[0].counts.admitted);
        input.minutes_write.record.end_ms += 250;
        input.minutes_write.record.observed_ms += 250;
        input.minutes_write.record.observations += 1;
        input.minutes_write.record.counts.denied += 1;
        try t.expect(try fx.run(input) == .command_recorded);
        try t.expect(try fx.run(.{ .minutes_write = .{ .record = record(), .now = 200 } }) ==
            .command_recorded);
        input.minutes_write.record.sealed = true;
        try t.expect(try fx.run(input) == .command_recorded);
        try t.expect(try fx.run(input) == .command_recorded);
        try @import("console_migrations.zig").run(fx.owner);
    }
    const fx = try Fixture.open(path);
    defer fx.close();
    const saved = try page(fx, null);
    try t.expectEqual(@as(u8, 1), saved.count);
    try t.expectEqualDeep(input.minutes_write.record, saved.rows[0]);
    input.minutes_write.record.end_ms += 250;
    input.minutes_write.record.observed_ms += 250;
    input.minutes_write.record.observations += 1;
    try t.expectEqual(p.Failure.conflict, (try fx.run(input)).failed);
}

test "minute pages separate boots and nodes, reject revoked readers and prune bounded batches" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/minute-pages",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    for (1..68) |node| {
        var input = record();
        input.node = @intCast(node);
        try t.expect(try fx.run(.{ .minutes_write = .{ .record = input, .now = 200 } }) ==
            .command_recorded);
    }
    var second_boot = record();
    second_boot.node = 67;
    second_boot.boot = @splat(2);
    try t.expect(try fx.run(.{ .minutes_write = .{ .record = second_boot, .now = 200 } }) ==
        .command_recorded);
    const first = try page(fx, null);
    try t.expectEqual(@as(u8, 2), first.count);
    try t.expectEqual(@as(u32, 67), first.rows[0].node);
    try t.expectEqualSlices(u8, &second_boot.boot, &first.rows[0].boot);
    const next = try page(fx, first.next);
    try t.expectEqual(@as(u32, 66), next.rows[0].node);
    _ = try fx.run(.{ .minutes_prune = 91 * 86400 });
    try t.expectEqual(@as(u64, 4), try count(fx));
    _ = try fx.run(.{ .minutes_prune = 91 * 86400 });
    try t.expectEqual(@as(u64, 0), try count(fx));
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    const denied = try fx.run(.{ .minutes_query = .{
        .session_digest = @splat(1),
        .now = 302,
        .from_minute = 0,
        .until_minute = 5,
    } });
    try t.expectEqual(p.Failure.unauthorized, denied.failed);
}

fn count(fx: *Fixture) !u64 {
    var result = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT count(*) FROM console_minutes",
        &.{},
    );
    defer result.deinit();
    return @import("console_store.zig").number(result.rows[0][0]);
}

test "a failed minute update rolls back and a node filter preserves both retained boots" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/minute-failure",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    var input = record();
    _ = try fx.run(.{ .minutes_write = .{ .record = input, .now = 200 } });
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_minute_update BEFORE UPDATE ON console_minutes " ++
            "BEGIN SELECT RAISE(ABORT,'test failure'); END;",
    );
    input.end_ms += 250;
    input.observed_ms += 250;
    input.observations += 1;
    input.counts.denied += 1;
    const failed = try fx.run(.{ .minutes_write = .{ .record = input, .now = 200 } });
    try t.expectEqual(p.Failure.unavailable, failed.failed);
    try t.expectEqualDeep(record(), (try page(fx, null)).rows[0]);
    input.boot = @splat(2);
    _ = try fx.run(.{ .minutes_write = .{ .record = input, .now = 200 } });
    var query: p.minutes.Query = .{
        .session_digest = @splat(1),
        .now = 300,
        .from_minute = 0,
        .until_minute = 5,
        .node = 7,
    };
    const found = (try fx.run(.{ .minutes_query = query })).minute_page;
    try t.expectEqual(@as(u8, 2), found.count);
    query.node = 8;
    try t.expectEqual(@as(u8, 0), (try fx.run(.{ .minutes_query = query })).minute_page.count);
    const expired = try fx.run(.{ .minutes_write = .{ .record = input, .now = 91 * 86400 } });
    try t.expectEqual(p.Failure.invalid_input, expired.failed);
}

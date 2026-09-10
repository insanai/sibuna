const std = @import("std");
const t = std.testing;
const console = @import("console");
const p = console.protocol;
const codec = console.rankings_archive;
const Fixture = @import("console_store_test.zig").Fixture;
const db = @import("console_database.zig");

fn scalar(fx: *Fixture, sql: []const u8) !u64 {
    var result = try db.query(fx.owner.db, t.allocator, sql, &.{});
    defer result.deinit();
    return @import("console_store.zig").number(result.rows[0][0]);
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn send(fx: *Fixture, id: [32]u8, bytes: []const u8, first: usize) !void {
    var offset = first;
    while (offset < bytes.len) {
        const count = @min(p.ranking_storage.chunk_bytes, bytes.len - offset);
        const result = try fx.run(.{ .rankings_chunk = .{
            .digest = id,
            .ordinal = @intCast(offset / p.ranking_storage.chunk_bytes),
            .bytes = try p.Bytes(2048).init(bytes[offset..][0..count]),
        } });
        try t.expect(result == .command_recorded);
        offset += count;
    }
}

test "complete ranking publication owns queued chunks and survives restart and migration replay" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const directory = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/ranks", .{tmp.sub_path});
    var archive: codec.Archive = .{
        .identity = .{ .node = 7, .boot = @splat(1) },
        .minute = .{ .minute = 2, .first_second = 120, .last_second = 121 },
    };
    for (0..512) |i| {
        var key: [128]u8 = @splat('p');
        std.mem.writeInt(u16, key[0..2], @intCast(i), .little);
        try archive.minute.paths.add(&key);
    }
    var bytes: [codec.max_bytes]u8 = undefined;
    const encoded = try codec.encode(&archive, &bytes);
    {
        const fx = try Fixture.open(directory);
        defer fx.close();
        try publish(fx, encoded);
        try @import("console_migrations.zig").run(fx.owner);
        try t.expectEqual(
            @as(u64, 1),
            try scalar(fx, "SELECT count(*) FROM console_rank_archives"),
        );
    }
    const fx = try Fixture.open(directory);
    defer fx.close();
    try @import("console_store_test.zig").policySession(fx);
    const query: p.ranking_history.Query = .{
        .session_digest = @splat(1),
        .observed_at = 400,
        .request = .{ .from_minute = 0, .until_minute = 5, .node = 7 },
    };
    const history = try fx.run(.{ .rankings_query = query });
    defer p.releaseResult(history, t.allocator);
    try t.expectEqualSlices(u8, encoded, history.ranking_history.payload.slice());
    try t.expect(history.ranking_history.next == null);
    try t.expectEqual(@as(u64, 2), history.ranking_history.cursor.?.minute);
    try canceledHistory(fx, query);
    try t.expectEqual(@as(u64, 19), try scalar(fx, "SELECT count(*) FROM console_rank_chunks"));
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT count(*) FROM console_rank_pending"));
    try t.expectEqual(
        p.ranking_storage.charge(@intCast(encoded.len)),
        try scalar(fx, "SELECT bytes FROM console_rank_usage WHERE id=1"),
    );
    const result = try fx.run(.{ .rankings_finish = .{ .digest = digest(encoded), .now = 400 } });
    try t.expect(result == .command_recorded);
    _ = try fx.run(.{ .rankings_prune = 8 * 86400 });
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT count(*) FROM console_rank_chunks"));
    try t.expectEqual(
        @as(u64, 0),
        try scalar(fx, "SELECT bytes FROM console_rank_usage WHERE id=1"),
    );
}

fn canceledHistory(fx: *Fixture, query: p.ranking_history.Query) !void {
    const ticket = try fx.owner.console_mailbox.submit(
        t.io,
        .{ .rankings_query = query },
        .background,
    );
    try fx.owner.tick();
    // Abandoning a completed result must free its full archive, not just the envelope.
    try fx.owner.console_mailbox.abandon(t.io, ticket);
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .rankings_query = query })).failed);
}

fn publish(fx: *Fixture, bytes: []const u8) !void {
    const id = digest(bytes);
    const begin: p.StorageRequest = .{ .rankings_begin = .{
        .digest = id,
        .total_bytes = @intCast(bytes.len),
        .now = 200,
    } };
    try t.expect(try fx.run(begin) == .command_recorded);
    try t.expect(try fx.run(begin) == .command_recorded);
    var chunk: p.StorageRequest = .{ .rankings_chunk = .{
        .digest = id,
        .ordinal = 0,
        .bytes = try p.Bytes(2048).init(bytes[0..2048]),
    } };
    const ticket = try fx.owner.console_mailbox.submit(t.io, chunk, .background);
    chunk.rankings_chunk.bytes.data[0] ^= 1;
    try fx.owner.tick();
    try t.expect((try fx.owner.console_mailbox.poll(t.io, ticket)).? == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(chunk)).failed);
    const finish: p.StorageRequest = .{ .rankings_finish = .{ .digest = id, .now = 201 } };
    try t.expectEqual(p.Failure.conflict, (try fx.run(finish)).failed);
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT count(*) FROM console_rank_archives"));
    try send(fx, id, bytes, 2048);
    try t.expect(try fx.run(finish) == .command_recorded);
    try t.expect(try fx.run(finish) == .command_recorded);
    chunk.rankings_chunk.bytes.data[0] ^= 1;
    try t.expect(try fx.run(chunk) == .command_recorded);
}

test "bad checksums stay unpublished and bounded pruning releases staged reservations" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rank-errors",
        .{tmp.sub_path},
    ));
    defer fx.close();
    var archive: codec.Archive = .{
        .identity = .{ .node = 7, .boot = @splat(1) },
        .minute = .{ .minute = 2 },
    };
    var buffer: [codec.max_bytes]u8 = undefined;
    const bytes = try codec.encode(&archive, &buffer);
    for (0..64) |i| {
        const id: [32]u8 = @splat(@intCast(i));
        const result = try fx.run(.{ .rankings_begin = .{
            .digest = id,
            .total_bytes = @intCast(bytes.len),
            .now = 200,
        } });
        try t.expect(result == .command_recorded);
    }
    const overflow = try fx.run(.{ .rankings_begin = .{
        .digest = @splat(255),
        .total_bytes = @intCast(bytes.len),
        .now = 200,
    } });
    try t.expectEqual(p.Failure.capacity, overflow.failed);
    try send(fx, @splat(0), bytes, 0);
    const result = try fx.run(.{ .rankings_finish = .{ .digest = @splat(0), .now = 201 } });
    try t.expectEqual(p.Failure.invalid_input, result.failed);
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT count(*) FROM console_rank_archives"));
    _ = try fx.run(.{ .rankings_prune = 1000 });
    try t.expectEqual(@as(u64, 62), try scalar(fx, "SELECT count(*) FROM console_rank_pending"));
    try t.expectEqual(
        62 * p.ranking_storage.charge(@intCast(bytes.len)),
        try scalar(fx, "SELECT bytes FROM console_rank_usage WHERE id=1"),
    );
    try fx.owner.db.exec(t.allocator, "UPDATE console_rank_usage SET bytes=536870912 WHERE id=1");
    const at_quota = try fx.run(.{ .rankings_begin = .{
        .digest = @splat(255),
        .total_bytes = @intCast(bytes.len),
        .now = 1000,
    } });
    try t.expectEqual(p.Failure.capacity, at_quota.failed);
}

test "a conflicting archive cannot replace the published node boot minute" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rank-conflict",
        .{tmp.sub_path},
    ));
    defer fx.close();
    var archive: codec.Archive = .{
        .identity = .{ .node = 7, .boot = @splat(1) },
        .minute = .{ .minute = 2, .first_second = 120, .last_second = 120 },
    };
    var buffer: [codec.max_bytes]u8 = undefined;
    for (0..2) |attempt| {
        try archive.minute.paths.add("/path");
        const bytes = try codec.encode(&archive, &buffer);
        const id = digest(bytes);
        try t.expect(try fx.run(.{ .rankings_begin = .{
            .digest = id,
            .total_bytes = @intCast(bytes.len),
            .now = 200,
        } }) == .command_recorded);
        try send(fx, id, bytes, 0);
        const result = try fx.run(.{ .rankings_finish = .{ .digest = id, .now = 201 } });
        if (attempt == 0) {
            try t.expect(result == .command_recorded);
        } else try t.expectEqual(p.Failure.conflict, result.failed);
    }
    try t.expectEqual(@as(u64, 1), try scalar(fx, "SELECT count(*) FROM console_rank_archives"));
    _ = try fx.run(.{ .rankings_prune = 1000 });
    try t.expectEqual(@as(u64, 1), try scalar(fx, "SELECT count(*) FROM console_rank_chunks"));
    try t.expectEqual(@as(u64, 9216), try scalar(fx, "SELECT bytes FROM console_rank_usage"));
}

test "ranking history pages equal minutes by digest and filters retired nodes" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rank-pages",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try @import("console_store_test.zig").policySession(fx);
    for ([_]u32{ 7, 8, 9 }) |node| try publishSmall(fx, node);
    var query: p.ranking_history.Query = .{
        .session_digest = @splat(1),
        .observed_at = 400,
        .request = .{ .from_minute = 1, .until_minute = 5 },
    };
    var seen: u16 = 0;
    for (0..3) |index| {
        const result = try fx.run(.{ .rankings_query = query });
        defer p.releaseResult(result, t.allocator);
        const page = result.ranking_history;
        const archive = try codec.decode(page.payload.slice());
        const bit = @as(u16, 1) << @as(u4, @intCast(archive.identity.node));
        try t.expect(seen & bit == 0);
        seen |= bit;
        try t.expectEqual(index < 2, page.next != null);
        query.request.before = page.next;
    }
    try t.expectEqual(@as(u16, 0b1110000000), seen);
    query.request.node = 8;
    const selected = try fx.run(.{ .rankings_query = query });
    defer p.releaseResult(selected, t.allocator);
    try t.expectEqual(@as(u32, 8), (try codec.decode(
        selected.ranking_history.payload.slice(),
    )).identity.node);
    try t.expect(selected.ranking_history.next == null);
    query.request.node = 10;
    const empty = try fx.run(.{ .rankings_query = query });
    defer p.releaseResult(empty, t.allocator);
    try t.expectEqual(@as(usize, 0), empty.ranking_history.payload.len);
    try t.expect(empty.ranking_history.cursor == null);
}

fn publishSmall(fx: *Fixture, node: u32) !void {
    var archive: codec.Archive = .{
        .identity = .{ .node = node, .boot = @splat(1) },
        .minute = .{ .minute = 2, .first_second = 120, .last_second = 120 },
    };
    try archive.minute.paths.add("/retained");
    var buffer: [codec.max_bytes]u8 = undefined;
    const bytes = try codec.encode(&archive, &buffer);
    const id = digest(bytes);
    try t.expect(try fx.run(.{ .rankings_begin = .{
        .digest = id,
        .total_bytes = @intCast(bytes.len),
        .now = 200,
    } }) == .command_recorded);
    try send(fx, id, bytes, 0);
    try t.expect(try fx.run(.{ .rankings_finish = .{
        .digest = id,
        .now = 201,
    } }) == .command_recorded);
}

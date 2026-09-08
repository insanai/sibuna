//! Only Persistent stages and publishes complete archives. Retries never overwrite chunks.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const wire = p.ranking_storage;
const codec = console.rankings_archive;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const text = util.text;
const integer = util.integer;

pub fn begin(owner: *Persistent, input: wire.Begin) !p.StorageResult {
    if (input.total_bytes < 92 or input.total_bytes > wire.max_bytes or
        input.now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_rank_pending(digest,total_bytes,charge,created_at) " ++
            "SELECT ?,?,?,? WHERE (SELECT count(*) FROM console_rank_pending)<64 " ++
            "AND (SELECT bytes FROM console_rank_usage WHERE id=1)+?<=? " ++
            "AND NOT EXISTS(SELECT 1 FROM console_rank_archives WHERE digest=?) " ++
            "ON CONFLICT(digest) DO NOTHING",
        &.{
            text(&digest),
            integer(input.total_bytes),
            integer(wire.charge(input.total_bytes)),
            integer(input.now),
            integer(wire.charge(input.total_bytes)),
            integer(wire.quota_bytes),
            text(&digest),
        },
    );
    if (changed > 0) return .command_recorded;
    var found = try db.query(
        owner.db,
        owner.gpa,
        "SELECT total_bytes FROM console_rank_pending WHERE digest=? UNION ALL " ++
            "SELECT total_bytes FROM console_rank_archives WHERE digest=? LIMIT 2",
        &.{
            text(&digest),
            text(&digest),
        },
    );
    defer found.deinit();
    if (found.rows.len == 0) return .{ .failed = .capacity };
    if (found.rows.len == 1 and try util.number(found.rows[0][0]) == input.total_bytes)
        return .command_recorded;
    return .{ .failed = .conflict };
}

pub fn chunk(owner: *Persistent, input: wire.Chunk) !p.StorageResult {
    if (input.ordinal >= 19 or input.bytes.len == 0 or input.bytes.len > wire.chunk_bytes)
        return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const hex = std.fmt.bytesToHex(input.bytes.data, .lower);
    const payload = hex[0 .. input.bytes.len * 2];
    const offset = @as(u64, input.ordinal) * wire.chunk_bytes;
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_rank_chunks(digest,ordinal,payload) SELECT ?,?,? " ++
            "FROM console_rank_pending WHERE digest=? AND total_bytes>? " ++
            "AND MIN(total_bytes-?,2048)=? ON CONFLICT(digest,ordinal) DO NOTHING",
        &.{
            text(&digest),
            integer(input.ordinal),
            text(payload),
            text(&digest),
            integer(offset),
            integer(offset),
            integer(input.bytes.len),
        },
    );
    if (changed > 0) return .command_recorded;
    var found = try db.query(
        owner.db,
        owner.gpa,
        "SELECT payload FROM console_rank_chunks WHERE digest=? AND ordinal=? LIMIT 1",
        &.{
            text(&digest),
            integer(input.ordinal),
        },
    );
    defer found.deinit();
    if (found.rows.len == 1 and std.mem.eql(u8, found.rows[0][0] orelse "", payload))
        return .command_recorded;
    return .{ .failed = .conflict };
}

pub fn finish(owner: *Persistent, input: wire.Finish) !p.StorageResult {
    if (input.now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    if (try published(owner, &digest)) return .command_recorded;
    var pending = try db.query(
        owner.db,
        owner.gpa,
        "SELECT total_bytes FROM console_rank_pending WHERE digest=? LIMIT 1",
        &.{
            text(&digest),
        },
    );
    defer pending.deinit();
    if (pending.rows.len == 0) return .{ .failed = .conflict };
    const total = try util.number(pending.rows[0][0]);
    if (total < 92 or total > codec.max_bytes) return .{ .failed = .invalid_input };
    var buffer: [codec.max_bytes]u8 = undefined;
    if (!try loadChunks(owner, &digest, buffer[0..@intCast(total)]))
        return .{ .failed = .conflict };
    const bytes = buffer[0..@intCast(total)];
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.mem.eql(u8, &actual, &input.digest)) return .{ .failed = .invalid_input };
    const archive = codec.decode(bytes) catch return .{ .failed = .invalid_input };
    const boot = std.fmt.bytesToHex(archive.identity.boot, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_rank_archives(digest,node,boot,minute," ++
            "total_bytes,charge,created_at) " ++
            "SELECT digest,?,?,?,total_bytes,charge,? FROM console_rank_pending " ++
            "WHERE digest=? ON CONFLICT DO NOTHING",
        &.{
            integer(archive.identity.node),
            text(&boot),
            integer(archive.minute.minute.?),
            integer(input.now),
            text(&digest),
        },
    );
    if (changed > 0 or try published(owner, &digest)) return .command_recorded;
    return .{ .failed = .conflict };
}

fn published(owner: *Persistent, digest: []const u8) !bool {
    var found = try db.query(
        owner.db,
        owner.gpa,
        "SELECT digest FROM console_rank_archives WHERE digest=? LIMIT 1",
        &.{
            text(digest),
        },
    );
    defer found.deinit();
    return found.rows.len == 1;
}

fn loadChunks(owner: *Persistent, digest: []const u8, output: []u8) !bool {
    var offset: usize = 0;
    var ordinal: u64 = 0;
    // At most 19 indexed queries, each below both native and replicated response limits.
    while (offset < output.len) : (ordinal += 1) {
        var result = try db.query(
            owner.db,
            owner.gpa,
            "SELECT payload FROM console_rank_chunks WHERE digest=? AND ordinal=? LIMIT 1",
            &.{
                text(digest),
                integer(ordinal),
            },
        );
        defer result.deinit();
        if (result.rows.len != 1) return false;
        const payload = result.rows[0][0] orelse return false;
        const count: usize = @min(wire.chunk_bytes, output.len - offset);
        if (payload.len != count * 2) return false;
        _ = std.fmt.hexToBytes(output[offset..][0..count], payload) catch return false;
        offset += count;
    }
    return true;
}

pub fn prune(owner: *Persistent, now: u64) !p.StorageResult {
    if (now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_rank_pending WHERE digest IN " ++
            "(SELECT digest FROM console_rank_pending WHERE created_at<? " ++
            "ORDER BY created_at,digest LIMIT 2)",
        &.{
            integer(now -| 600),
        },
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_rank_archives WHERE digest IN " ++
            "(SELECT digest FROM console_rank_archives WHERE minute<? OR " ++
            "(SELECT bytes FROM console_rank_usage WHERE id=1)>? " ++
            "ORDER BY minute,digest LIMIT 2)",
        &.{
            integer(now / 60 -| (7 * 24 * 60)),
            integer(wire.quota_bytes - wire.charge(wire.max_bytes)),
        },
    );
    return .{ .ranking_inventory = try inventory(owner, now) };
}

fn inventory(owner: *Persistent, now: u64) !p.rankings.Inventory {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT (SELECT count(*) FROM console_rank_archives)," ++
            "(SELECT minute FROM console_rank_archives ORDER BY minute,digest LIMIT 1)," ++
            "(SELECT minute FROM console_rank_archives " ++
            "ORDER BY minute DESC,digest DESC LIMIT 1)," ++
            "(SELECT bytes FROM console_rank_usage WHERE id=1)",
        &.{},
    );
    defer result.deinit();
    if (result.rows.len != 1) return error.InvalidInventory;
    const row = result.rows[0];
    return .{
        .available = true,
        .archives = try util.number(row[0]),
        .first_minute = if (row[1] != null) try util.number(row[1]) else null,
        .last_minute = if (row[2] != null) try util.number(row[2]) else null,
        .reserved_bytes = try util.number(row[3]),
        .observed_at = now,
    };
}

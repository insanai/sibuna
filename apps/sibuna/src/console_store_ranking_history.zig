//! One immutable archive per read. Two chunk scans stay under native and RPC result limits.
const std = @import("std");
const p = @import("console").protocol;
const wire = p.ranking_history;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_read_authorize.zig");
const settings = @import("console_store_settings.zig");

pub fn query(owner: *Persistent, input: wire.Query) !p.StorageResult {
    wire.validate(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    const retention = try settings.retention(owner, "retention.rankings");
    const payload = try owner.gpa.create(wire.Payload);
    errdefer owner.gpa.destroy(payload);
    payload.* = .{};
    var page: wire.Page = .{
        .from_minute = @max(input.request.from_minute, input.observed_at / 60 -|
            (@as(u64, retention.days) * 1440)),
        .until_minute = input.request.until_minute,
        .retention_days = retention.days,
        .observed_at = input.observed_at,
        .payload = payload,
    };
    if (page.from_minute <= page.until_minute) try read(owner, input.request, &page);
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason| {
        owner.gpa.destroy(payload);
        return .{ .failed = reason };
    }
    if (!std.meta.eql(retention, try settings.retention(owner, "retention.rankings"))) {
        owner.gpa.destroy(payload);
        return .{ .failed = .conflict };
    }
    return .{ .ranking_history = page };
}

fn read(owner: *Persistent, input: wire.Request, page: *wire.Page) !void {
    var sql: [768]u8 = undefined;
    const statement = try std.fmt.bufPrint(
        &sql,
        "SELECT digest,minute,total_bytes,node,boot FROM console_rank_archives " ++
            "WHERE minute>=? AND minute<=? {s} {s} ORDER BY minute DESC,digest DESC LIMIT 2",
        .{
            if (input.node != null) "AND node=?" else "",
            if (input.before != null) "AND (minute,digest)<(?,?)" else "",
        },
    );
    var values: [5]@import("zaxonlite").Value = undefined;
    values[0] = util.integer(page.from_minute);
    values[1] = util.integer(page.until_minute);
    var count: usize = 2;
    if (input.node) |node| {
        values[count] = util.integer(node);
        count += 1;
    }
    if (input.before) |*cursor| {
        values[count] = util.integer(cursor.minute);
        values[count + 1] = util.text(cursor.digest.slice());
        count += 2;
    }
    var rows = try db.query(owner.db, owner.gpa, statement, values[0..count]);
    defer rows.deinit();
    if (rows.rows.len == 0) return;
    const row = rows.rows[0];
    const cursor: wire.Cursor = .{
        .digest = try p.Bytes(64).init(row[0] orelse return error.InvalidStoredValue),
        .minute = try util.number(row[1]),
    };
    const size = try util.number(row[2]);
    if (size < 92 or size > p.ranking_storage.max_bytes) return error.InvalidStoredValue;
    page.payload.len = @intCast(size);
    try chunks(owner, cursor.digest.slice(), page.payload.data[0..page.payload.len]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(page.payload.slice(), &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), cursor.digest.slice()))
        return error.InvalidStoredValue;
    const archive = try p.rankings_archive.decode(page.payload.slice());
    const boot = std.fmt.bytesToHex(archive.identity.boot, .lower);
    if (archive.minute.minute != cursor.minute or
        archive.identity.node != try util.number(row[3]) or
        !std.mem.eql(u8, &boot, row[4] orelse ""))
        return error.InvalidStoredValue;
    page.cursor = cursor;
    if (rows.rows.len > 1) page.next = cursor;
}

fn chunks(owner: *Persistent, digest: []const u8, output: []u8) !void {
    var ordinal: usize = 0;
    var offset: usize = 0;
    // Ten 4-KiB hex rows fit below the 64-KiB RPC envelope, including JSON framing.
    // Published chunks are immutable. Concurrent retention can only make this read fail.
    while (offset < output.len) {
        var result = try db.query(
            owner.db,
            owner.gpa,
            "SELECT ordinal,payload FROM console_rank_chunks WHERE digest=? AND ordinal>=? " ++
                "ORDER BY ordinal LIMIT 10",
            &.{ util.text(digest), util.integer(ordinal) },
        );
        defer result.deinit();
        if (result.rows.len == 0) return error.InvalidStoredValue;
        for (result.rows) |row| {
            if (try util.number(row[0]) != ordinal or offset == output.len)
                return error.InvalidStoredValue;
            const hex = row[1] orelse return error.InvalidStoredValue;
            const length: usize = @min(p.ranking_storage.chunk_bytes, output.len - offset);
            if (hex.len != length * 2) return error.InvalidStoredValue;
            _ = try std.fmt.hexToBytes(output[offset..][0..length], hex);
            offset += length;
            ordinal += 1;
        }
    }
}

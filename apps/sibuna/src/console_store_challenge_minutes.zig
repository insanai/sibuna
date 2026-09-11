//! The sole storage owner validates and upserts challenge-minute records and sums bounded
//! windows of them. Aggregation stays on the storage owner; no database handle escapes.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const wire = p.challenge_minutes;
const codec = console.challenge_archive;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const settings = @import("console_store_settings.zig");
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const text = util.text;
const integer = util.integer;
const table = "console_challenge_minutes";
/// Statements per summary request: at most 16 pages of 96 rows, each page within the
/// 100-row / 64 KiB statement envelope; a longer window continues from `next`.
const max_pages = 16;

pub fn write(owner: *Persistent, input: wire.Write) !p.StorageResult {
    const record = &input.record;
    var bytes: [codec.max_len]u8 = undefined;
    const encoded = codec.encode(record, &bytes) catch return .{ .failed = .invalid_input };
    if (input.now > std.math.maxInt(i64) or record.minute > input.now / 60 or
        record.minute < input.now / 60 -| (wire.retention_days * 1440))
        return .{ .failed = .invalid_input };
    const boot = std.fmt.bytesToHex(record.boot, .lower);
    var hex: [codec.max_len * 2]u8 = undefined;
    const payload = std.fmt.bufPrint(&hex, "{x}", .{encoded}) catch unreachable;
    var existing = try db.query(
        owner.db,
        owner.gpa,
        "SELECT payload FROM " ++ table ++ " WHERE node=? AND boot=? AND epoch=? AND minute=?",
        &.{ integer(record.node), text(&boot), integer(record.epoch), integer(record.minute) },
    );
    defer existing.deinit();
    const previous = if (existing.rows.len == 0) "" else existing.rows[0][0] orelse
        return error.InvalidStoredValue;
    if (std.mem.eql(u8, previous, payload)) return .command_recorded;
    if (previous.len != 0) {
        const old = try decode(previous);
        // A sealed minute never changes; an older in-progress snapshot is obsolete.
        if (old.sealed or old.start_ms != record.start_ms) return .{ .failed = .conflict };
        if (record.end_ms < old.end_ms) return .command_recorded;
    }
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO " ++ table ++ "(node,boot,epoch,minute,start_ms,end_ms,sealed,payload) " ++
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node,boot,epoch,minute) DO UPDATE SET " ++
            "end_ms=excluded.end_ms,sealed=excluded.sealed,payload=excluded.payload " ++
            "WHERE " ++ table ++ ".payload=?",
        &.{
            integer(record.node),                 text(&boot),
            integer(record.epoch),                integer(record.minute),
            integer(record.start_ms),             integer(record.end_ms),
            integer(@intFromBool(record.sealed)), text(payload),
            text(previous),
        },
    );
    return if (changed == 1) .command_recorded else .{ .failed = .conflict };
}

pub fn decode(payload: []const u8) !wire.Record {
    if (payload.len % 2 != 0 or payload.len > codec.max_len * 2) return error.InvalidStoredValue;
    var bytes: [codec.max_len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(bytes[0 .. payload.len / 2], payload) catch
        return error.InvalidStoredValue;
    return codec.decode(decoded) catch error.InvalidStoredValue;
}

pub fn prune(owner: *Persistent, now: u64) !p.StorageResult {
    if (now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM " ++ table ++ " WHERE (node,boot,epoch,minute) IN " ++
            "(SELECT node,boot,epoch,minute FROM " ++ table ++ " WHERE minute<?-" ++
            settings.daysSql("retention.minutes") ++ "*1440 LIMIT 64)",
        &.{integer(now / 60)},
    );
    return .command_recorded;
}

pub fn summary(owner: *Persistent, input: wire.Query) !p.StorageResult {
    wire.validate(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    const retained = try settings.retention(owner, "retention.minutes");
    var bounded = input;
    bounded.from_minute = @max(input.from_minute, input.observed_at / 60 -|
        (@as(u64, retained.days) * 1440));
    var result: wire.Summary = .{
        .coverage = .{
            .node = input.node,
            .from = input.from_minute,
            .until = input.until_minute,
            .retention_days = retained.days,
            .retention_changed = bounded.from_minute != input.from_minute,
        },
        .totals = .{ .selected = input.selected, .timestamp = input.observed_at },
    };
    if (bounded.from_minute <= bounded.until_minute) try scan(owner, bounded, &result);
    result.coverage.finished = result.coverage.next == null;
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    if (!std.meta.eql(retained, try settings.retention(owner, "retention.minutes")))
        return .{ .failed = .conflict };
    return .{ .challenge_summary = result };
}

fn scan(owner: *Persistent, input: wire.Query, result: *wire.Summary) !void {
    var page = input;
    for (0..max_pages) |_| {
        var rows = try readPage(owner, page);
        defer rows.deinit();
        const count = @min(rows.rows.len, page.limit);
        for (rows.rows[0..count]) |row| {
            const record = try decode(row[0] orelse return error.InvalidStoredValue);
            wire.add(result, &record) catch return error.InvalidStoredValue;
        }
        result.coverage.next = if (rows.rows.len > page.limit) result.coverage.last else null;
        if (result.coverage.next == null) return;
        page.before = result.coverage.next;
    }
}

fn readPage(owner: *Persistent, input: wire.Query) !@import("zaxonlite").QueryResult {
    var bytes: [512]u8 = undefined;
    var sql: std.Io.Writer = .fixed(&bytes);
    var values: [8]@import("zaxonlite").Value = undefined;
    var count: usize = 0;
    try sql.writeAll("SELECT payload FROM " ++ table ++ " WHERE ");
    if (input.node) |node| {
        try sql.writeAll("node=? AND ");
        values[count] = integer(node);
        count += 1;
    }
    try sql.writeAll("minute>=? AND minute<=? ");
    values[count] = integer(input.from_minute);
    values[count + 1] = integer(input.until_minute);
    count += 2;
    var boot: [32]u8 = undefined;
    if (input.before) |cursor| {
        try sql.writeAll("AND (minute,node,boot,epoch)<(?,?,?,?) ");
        boot = std.fmt.bytesToHex(cursor.boot, .lower);
        values[count] = integer(cursor.minute);
        values[count + 1] = integer(cursor.node);
        values[count + 2] = text(&boot);
        values[count + 3] = integer(cursor.epoch);
        count += 4;
    }
    try sql.writeAll("ORDER BY minute DESC,node DESC,boot DESC,epoch DESC LIMIT ?");
    values[count] = integer(input.limit + 1);
    count += 1;
    return db.query(owner.db, owner.gpa, sql.buffered(), values[0..count]);
}

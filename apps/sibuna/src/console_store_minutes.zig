//! The sole storage owner validates, compares and upserts immutable-prefix minute records.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const codec = console.minute_archive;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const Persistent = @import("persistent.zig").Persistent;
const text = util.text;
const integer = util.integer;

pub fn write(owner: *Persistent, input: p.minutes.Write) !p.StorageResult {
    const record = &input.record;
    var encoded: [codec.bytes_len]u8 = undefined;
    codec.encode(record, &encoded) catch return .{ .failed = .invalid_input };
    if (input.now > std.math.maxInt(i64) or record.minute > input.now / 60 or
        record.minute < input.now / 60 -| (p.minutes.retention_days * 1440))
        return .{ .failed = .invalid_input };
    const boot = std.fmt.bytesToHex(record.boot, .lower);
    const payload = std.fmt.bytesToHex(encoded, .lower);
    var existing = try db.query(
        owner.db,
        owner.gpa,
        "SELECT payload FROM console_minutes WHERE node=? AND boot=? AND epoch=? AND minute=?",
        &.{ integer(record.node), text(&boot), integer(record.epoch), integer(record.minute) },
    );
    defer existing.deinit();
    const previous = if (existing.rows.len == 0) "" else existing.rows[0][0] orelse
        return error.InvalidStoredValue;
    if (std.mem.eql(u8, previous, &payload)) return .command_recorded;
    if (previous.len != 0) {
        const old = try decode(previous);
        switch (progress(&old, record)) {
            .obsolete => return .command_recorded,
            .conflict => return .{ .failed = .conflict },
            .advance => {},
        }
    }
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_minutes(node,boot,epoch,minute,start_ms,end_ms,sealed,payload) " ++
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node,boot,epoch,minute) DO UPDATE SET " ++
            "end_ms=excluded.end_ms,sealed=excluded.sealed,payload=excluded.payload " ++
            "WHERE console_minutes.payload=?",
        &.{
            integer(record.node),                 text(&boot),
            integer(record.epoch),                integer(record.minute),
            integer(record.start_ms),             integer(record.end_ms),
            integer(@intFromBool(record.sealed)), text(&payload),
            text(previous),
        },
    );
    // Expected bytes fence a concurrent replicated update after our read. Retrying is safe.
    return if (changed == 1) .command_recorded else .{ .failed = .conflict };
}

fn decode(payload: []const u8) !p.minutes.Record {
    if (payload.len != codec.bytes_len * 2) return error.InvalidStoredValue;
    var bytes: [codec.bytes_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, payload);
    return codec.decode(&bytes);
}

fn progress(old: *const p.minutes.Record, next: *const p.minutes.Record) enum {
    advance,
    obsolete,
    conflict,
} {
    if (old.node != next.node or old.epoch != next.epoch or old.minute != next.minute or
        !std.mem.eql(u8, &old.boot, &next.boot) or old.start_ms != next.start_ms or
        old.utc_start != next.utc_start) return .conflict;
    if (next.end_ms < old.end_ms) {
        if (next.sealed or next.observations > old.observations or next.utc_end > old.utc_end or
            (next.gap and !old.gap))
            return .conflict;
        inline for (p.minutes.counter_fields) |name| {
            if (@field(next.counts, name) > @field(old.counts, name)) return .conflict;
        }
        return .obsolete;
    }
    if (old.sealed or (old.gap and !next.gap) or next.observations < old.observations or
        next.utc_end < old.utc_end) return .conflict;
    inline for (p.minutes.counter_fields) |name| {
        if (@field(next.counts, name) < @field(old.counts, name)) return .conflict;
    }
    if (next.end_ms == old.end_ms) {
        var sealed = old.*;
        sealed.sealed = next.sealed;
        sealed.complete = next.complete;
        if (!next.sealed or !std.meta.eql(sealed, next.*)) return .conflict;
    }
    return .advance;
}

pub fn prune(owner: *Persistent, now: u64) !p.StorageResult {
    if (now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const cutoff = now / 60 -| (p.minutes.retention_days * 1440);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_minutes WHERE (node,boot,epoch,minute) IN " ++
            "(SELECT node,boot,epoch,minute FROM console_minutes WHERE minute<? LIMIT 64)",
        &.{integer(cutoff)},
    );
    return .command_recorded;
}

pub fn query(owner: *Persistent, input: p.minutes.Query) !p.StorageResult {
    p.minutes.validate(input) catch return .{ .failed = .invalid_input };
    if ((try util.authorize(owner, input.session_digest, input.now)) != .authorized)
        return .{ .failed = .unauthorized };
    var bounded = input;
    const cutoff = input.now / 60 -| (p.minutes.retention_days * 1440);
    bounded.from_minute = @max(input.from_minute, cutoff);
    if (bounded.from_minute > bounded.until_minute) return .{ .minute_page = .{} };
    var result = try readQuery(owner, bounded);
    defer result.deinit();
    var page: p.minutes.Page = .{};
    page.count = @intCast(@min(input.limit, result.rows.len));
    for (result.rows[0..page.count], 0..) |row, i|
        page.rows[i] = try decode(row[0] orelse return error.InvalidStoredValue);
    if (result.rows.len > input.limit) page.next = page.rows[page.count - 1].cursor();
    return .{ .minute_page = page };
}

fn readQuery(owner: *Persistent, input: p.minutes.Query) !@import("zaxonlite").QueryResult {
    var bytes: [512]u8 = undefined;
    var sql: std.Io.Writer = .fixed(&bytes);
    var values: [8]@import("zaxonlite").Value = undefined;
    var count: usize = 0;
    try sql.writeAll("SELECT payload FROM console_minutes WHERE ");
    // Avoid optional-filter OR clauses: both node and all-node reads must seek their index.
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

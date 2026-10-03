//! The storage owner appends bounded per-address challenge records and difficulty
//! transitions, pages them for the Challenges page and prunes them at seven days. Each
//! append first removes up to twice its batch of expired records, so retention keeps pace
//! with ingestion (a 32-record batch every collector tick); the periodic prune is catch-up.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const wire = p.challenge_records;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const text = util.text;
const integer = util.integer;
const columns = "id,node,second,ip,outcome,cause,algorithm,parameter,openings,duration_ms";

pub fn write(owner: *Persistent, input: wire.Batch) !p.StorageResult {
    if (input.count == 0 or input.count > wire.max_batch or input.now > std.math.maxInt(i64))
        return .{ .failed = .invalid_input };
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_challenge_records WHERE id IN " ++
            "(SELECT id FROM console_challenge_records WHERE second<? LIMIT 64)",
        &.{integer(input.now -| wire.retention_days * 86400)},
    );
    const boot = std.fmt.bytesToHex(input.boot, .lower);
    var sql: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&sql);
    try writer.writeAll("INSERT INTO console_challenge_records(node,boot,second,ip,outcome," ++
        "cause,algorithm,parameter,openings,duration_ms) VALUES");
    var values: [wire.max_batch * 10]@import("zaxonlite").Value = undefined;
    var count: usize = 0;
    for (input.records[0..input.count], 0..) |*record, i| {
        if (record.ip.len == 0 or record.second > input.now) return .{ .failed = .invalid_input };
        try writer.writeAll(if (i == 0) "(?,?,?,?,?,?,?,?,?,?)" else ",(?,?,?,?,?,?,?,?,?,?)");
        values[count..][0..10].* = .{
            integer(input.node),                  text(&boot),
            integer(record.second),               text(record.ip.slice()),
            integer(@backingInt(record.outcome)), integer(record.cause),
            integer(record.algorithm),            integer(record.parameter),
            integer(record.openings),
            if (record.duration_ms) |ms|
                integer(ms)
            else
                .null_value,
        };
        count += 10;
    }
    _ = try db.exec(owner.db, owner.gpa, writer.buffered(), values[0..count]);
    return .command_recorded;
}

pub fn transition(owner: *Persistent, input: wire.Transition) !p.StorageResult {
    if (input.second > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const boot = std.fmt.bytesToHex(input.boot, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_challenge_difficulty(node,boot,second,previous_bits,bits," ++
            "rate_256) " ++
            "VALUES(?,?,?,?,?,?) ON CONFLICT(node,boot,second) DO UPDATE SET " ++
            "bits=excluded.bits,rate_256=excluded.rate_256",
        &.{
            integer(input.node),          text(&boot),         integer(input.second),
            integer(input.previous_bits), integer(input.bits), integer(input.rate_256),
        },
    );
    return .command_recorded;
}

/// Seven-day retention for both tables, bounded per call like the minute prunes.
pub fn prune(owner: *Persistent, now: u64) !void {
    if (now > std.math.maxInt(i64)) return;
    const cutoff = now -| wire.retention_days * 86400;
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_challenge_records WHERE id IN " ++
            "(SELECT id FROM console_challenge_records WHERE second<? LIMIT 256)",
        &.{integer(cutoff)},
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_challenge_difficulty WHERE (node,boot,second) IN " ++
            "(SELECT node,boot,second FROM console_challenge_difficulty WHERE second<? LIMIT 256)",
        &.{integer(cutoff)},
    );
}

pub fn query(owner: *Persistent, input: wire.Query) !p.StorageResult {
    wire.validate(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    var sql: [640]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&sql);
    var values: [10]@import("zaxonlite").Value = undefined;
    var count: usize = 0;
    try writer.writeAll("SELECT " ++ columns ++ " FROM console_challenge_records " ++
        "WHERE second>=? AND second<=? ");
    values[0] = integer(input.from);
    values[1] = integer(input.until);
    count = 2;
    if (input.node) |node| {
        try writer.writeAll("AND node=? ");
        values[count] = integer(node);
        count += 1;
    }
    if (input.outcome) |outcome| {
        try writer.writeAll("AND outcome=? ");
        values[count] = integer(@backingInt(outcome));
        count += 1;
    }
    if (input.cause) |cause| {
        try writer.writeAll("AND cause=? ");
        values[count] = integer(cause);
        count += 1;
    }
    if (input.address.len != 0) {
        try writer.writeAll("AND ip=? ");
        values[count] = text(input.address.slice());
        count += 1;
    }
    if (input.before) |cursor| {
        try writer.writeAll("AND (second,id)<(?,?) ");
        values[count] = integer(cursor.second);
        values[count + 1] = integer(cursor.id);
        count += 2;
    }
    try writer.writeAll("ORDER BY second DESC,id DESC LIMIT ?");
    values[count] = integer(input.limit + 1);
    count += 1;
    var rows = try db.query(owner.db, owner.gpa, writer.buffered(), values[0..count]);
    defer rows.deinit();
    var page: wire.Page = .{
        .observed_at = input.observed_at,
        .from = input.from,
        .until = input.until,
        .dropped_since_boot = if (owner.state.telemetry) |telemetry|
            telemetry.challenge_dropped.load(.monotonic)
        else
            0,
    };
    page.count = @intCast(@min(rows.rows.len, input.limit));
    for (rows.rows[0..page.count], 0..) |row, i| page.rows[i] = try decode(row);
    if (rows.rows.len > input.limit) page.next = .{
        .second = page.rows[page.count - 1].second,
        .id = page.rows[page.count - 1].id,
    };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    return .{ .challenge_records = page };
}

fn decode(row: []const ?[]const u8) !wire.Row {
    if (row.len < 10) return error.InvalidStoredValue;
    const outcome = try util.number(row[4]);
    const duration: ?u32 = if (row[9]) |value|
        @intCast(@min(std.fmt.parseInt(u64, value, 10) catch
            return error.InvalidStoredValue, std.math.maxInt(u32)))
    else
        null;
    return .{
        .id = try util.number(row[0]),
        .node = @intCast(try util.number(row[1])),
        .second = try util.number(row[2]),
        .ip = try p.Bytes(48).init(row[3] orelse return error.InvalidStoredValue),
        .outcome = if (outcome <= 2) @fromBackingInt(
            @intCast(outcome),
        ) else return error.InvalidStoredValue,
        .cause = @intCast(@min(try util.number(row[5]), 255)),
        .algorithm = @intCast(@min(try util.number(row[6]), 255)),
        .parameter = @intCast(@min(try util.number(row[7]), 255)),
        .openings = @intCast(@min(try util.number(row[8]), 255)),
        .duration_ms = duration,
    };
}

pub fn difficulty(owner: *Persistent, input: wire.DifficultyQuery) !p.StorageResult {
    wire.validateDifficulty(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    var sql: [320]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&sql);
    var values: [4]@import("zaxonlite").Value = undefined;
    try writer.writeAll("SELECT node,second,previous_bits,bits,rate_256 FROM " ++
        "console_challenge_difficulty WHERE second>=? AND second<=? ");
    values[0] = integer(input.from);
    values[1] = integer(input.until);
    var count: usize = 2;
    if (input.node) |node| {
        try writer.writeAll("AND node=? ");
        values[count] = integer(node);
        count += 1;
    }
    try writer.writeAll("ORDER BY second DESC,node DESC LIMIT ?");
    values[count] = integer(input.limit + 1);
    count += 1;
    var rows = try db.query(owner.db, owner.gpa, writer.buffered(), values[0..count]);
    defer rows.deinit();
    var page: wire.DifficultyPage = .{
        .observed_at = input.observed_at,
        .from = input.from,
        .until = input.until,
        .current_bits = if (owner.state.telemetry) |telemetry|
            @intCast(@min(telemetry.adaptive_bits.load(.monotonic), 255))
        else
            null,
    };
    page.count = @intCast(@min(rows.rows.len, input.limit));
    page.truncated = rows.rows.len > input.limit;
    for (rows.rows[0..page.count], 0..) |row, i| page.rows[i] = .{
        .node = @intCast(try util.number(row[0])),
        .second = try util.number(row[1]),
        .previous_bits = @intCast(@min(try util.number(row[2]), 255)),
        .bits = @intCast(@min(try util.number(row[3]), 255)),
        .rate_256 = try util.number(row[4]),
    };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    return .{ .challenge_difficulty = page };
}

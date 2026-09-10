//! Fixed 49-row reads leave headroom for typed-v1's per-cell JSON envelopes on peers.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const wire = @import("console").protocol.rule_hit_history;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_read_authorize.zig");
const settings = @import("console_store_settings.zig");

pub fn query(owner: *Persistent, input: wire.Query) !p.StorageResult {
    wire.validate(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .policy_read)) |reason|
        return .{ .failed = reason };
    const retained = try settings.retention(owner, "retention.minutes");
    const cutoff = input.observed_at / 60 -| (@as(u64, retained.days) * 1440);
    var part: wire.Part = .{ .observed_at = input.observed_at, .window = .{
        .request = input.request,
        .retention_days = retained.days,
        .clipped = input.request.from_minute < cutoff,
    } };
    if (input.request.until_minute >= cutoff) try scan(owner, &part, cutoff);
    part.window.finished = part.window.next == null;
    if (try access.check(owner, input.session_digest, input.require_totp, .policy_read)) |reason|
        return .{ .failed = reason };
    if (!std.meta.eql(retained, try settings.retention(owner, "retention.minutes")))
        return .{ .failed = .conflict };
    return .{ .rule_hit_history = part };
}

fn scan(owner: *Persistent, part: *wire.Part, cutoff: u64) !void {
    var rows = try read(owner, part.window.request, cutoff);
    defer rows.deinit();
    for (rows.rows[0..@min(rows.rows.len, wire.page_rows)]) |cells|
        try part.window.add(try decode(cells, part.window.request.node));
    if (rows.rows.len > wire.page_rows) part.window.next = part.window.last;
}

fn read(owner: *Persistent, request: wire.Request, cutoff: u64) !zx.QueryResult {
    var bytes: [1024]u8 = undefined;
    var sql: std.Io.Writer = .fixed(&bytes);
    var values: [8]zx.Value = undefined;
    var count: usize = 4;
    try sql.writeAll("SELECT boot,sequence,generation,revision,minute,utc_start,utc_end," ++
        "start_ms,end_ms,observations,complete,gap,unconfirmed,hits " ++
        "FROM console_rule_hits WHERE rule_key=? AND node=? AND minute>=? AND minute<=?");
    values[0..4].* = .{
        util.text(request.key.slice()),                  util.integer(request.node),
        util.integer(@max(cutoff, request.from_minute)), util.integer(request.until_minute),
    };
    if (request.revision) |revision| {
        try sql.writeAll(" AND revision=?");
        values[count] = util.integer(revision);
        count += 1;
    }
    var boot: [32]u8 = undefined;
    if (request.before) |cursor| {
        try sql.writeAll(" AND (minute,boot,sequence)<(?,?,?)");
        boot = std.fmt.bytesToHex(cursor.boot, .lower);
        values[count..][0..3].* = .{
            util.integer(cursor.minute), util.text(&boot), util.integer(cursor.sequence),
        };
        count += 3;
    }
    try sql.writeAll(" ORDER BY minute DESC,boot DESC,sequence DESC LIMIT 49");
    return db.query(owner.db, owner.gpa, sql.buffered(), values[0..count]);
}

fn decode(row: []const ?[]const u8, node: u32) !wire.Row {
    if (row.len != 14) return error.InvalidStoredValue;
    var span: p.rule_hits.Span = .{ .node = node };
    const boot = row[0] orelse return error.InvalidStoredValue;
    if (boot.len != 32) return error.InvalidStoredValue;
    _ = try std.fmt.hexToBytes(&span.boot, boot);
    const numbers = .{
        "sequence",  "generation", "revision", "minute",
        "utc_start", "utc_end",    "start_ms", "end_ms",
    };
    inline for (numbers, 1..) |name, index| @field(span, name) = try util.number(row[index]);
    span.observed_ms = span.end_ms -| span.start_ms;
    span.observations = std.math.cast(u32, try util.number(row[9])) orelse
        return error.InvalidStoredValue;
    span.complete = try boolean(row[10]);
    span.gap = try boolean(row[11]);
    span.unconfirmed = try util.number(row[12]);
    try span.validate();
    return .{ .span = span, .hits = if (row[13] != null) try util.number(row[13]) else null };
}

fn boolean(cell: ?[]const u8) !bool {
    return switch (try util.number(cell)) {
        0 => false,
        1 => true,
        else => error.InvalidStoredValue,
    };
}

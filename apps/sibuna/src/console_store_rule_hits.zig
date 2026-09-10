//! Bounded, idempotent observation writes through the existing storage facade.
const std = @import("std");
const zx = @import("zaxonlite");
const console = @import("console");
const p = console.protocol.rule_hits;
const schema = console.schema.rule_hits;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn write(owner: *Persistent, batch: console.RuleHitJournal.Batch) !void {
    try batch.span.validate();
    if (batch.entries.len == 0 or batch.entries.len > p.batch_rows)
        return error.InvalidRuleHitBatch;
    var bytes: [4096]u8 = undefined;
    var sql: std.Io.Writer = .fixed(&bytes);
    var values: [p.batch_rows * 18]zx.Value = undefined;
    const boot = std.fmt.bytesToHex(batch.span.boot, .lower);
    try sql.writeAll("INSERT INTO console_rule_hits(" ++ schema.columns ++ ") VALUES");
    for (batch.entries, 0..) |*entry, index| {
        if (entry.identity.key.len == 0 or
            !std.unicode.utf8ValidateSlice(entry.identity.key.slice()) or
            !std.unicode.utf8ValidateSlice(entry.identity.name.slice()))
            return error.InvalidRuleHitBatch;
        if (index != 0) try sql.writeByte(',');
        try sql.writeAll("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        fill(values[index * 18 ..][0..18], batch.span, entry, &boot);
    }
    try sql.writeAll(schema.conflict);
    _ = try db.exec(owner.db, owner.gpa, sql.buffered(), values[0 .. batch.entries.len * 18]);
}

fn fill(values: *[18]zx.Value, span: *const p.Span, entry: *const p.Entry, boot: []const u8) void {
    const integer = util.integer;
    const text = util.text;
    const lost = @min(span.unconfirmed, std.math.maxInt(i64));
    const hits: zx.Value = if (entry.hits) |count|
        if (count <= std.math.maxInt(i64)) integer(count) else .null_value
    else
        .null_value;
    values.* = .{
        integer(span.node),                   text(boot),
        integer(span.sequence),               text(entry.identity.key.slice()),
        integer(span.generation),             integer(span.revision),
        text(entry.identity.name.slice()),    integer(span.minute),
        integer(span.utc_start),              integer(span.utc_end),
        integer(span.start_ms),               integer(span.end_ms),
        integer(span.observed_ms),            integer(span.observations),
        integer(@intFromBool(span.complete)), integer(@intFromBool(span.gap)),
        integer(lost),                        hits,
    };
}

/// Small indexed retention slices share the existing minute-history maintenance cadence.
pub fn prune(owner: *Persistent, now: u64) !void {
    const days = @import("console_store_settings.zig").daysSql("retention.minutes");
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_rule_hits WHERE rowid IN " ++
            "(SELECT rowid FROM console_rule_hits WHERE minute<?-" ++ days ++ "*1440 LIMIT 64)",
        &.{util.integer(now / 60)},
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_rule_hit_rollups WHERE rowid IN " ++
            "(SELECT rowid FROM console_rule_hit_rollups WHERE bucket<?-" ++ days ++
            "*1440 AND bucket+grain<=?-" ++ days ++ "*1440 LIMIT 64)",
        &.{ util.integer(now / 60), util.integer(now / 60) },
    );
}

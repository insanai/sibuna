//! An indexed, bounded rollup read for each visible rule; no request-thread SQL or callbacks.
const std = @import("std");
const p = @import("console").protocol;
const wire = p.rule_hit_history;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn read(owner: *Persistent, key: p.rule_hits.Key) !wire.Today {
    return readAt(owner, key, owner.nowSeconds());
}

/// Production obtains the instant from the owner; deterministic storage tests supply it.
pub fn readAt(owner: *Persistent, key: p.rule_hits.Key, now: u64) !wire.Today {
    const from = now / 86400 * 1440;
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT bucket,hits,intervals,complete,unconfirmed,through_minute " ++
            "FROM console_rule_hit_rollups " ++
            "WHERE rule_key=? AND node=? AND grain=60 AND bucket>=? AND bucket<? " ++
            "ORDER BY bucket DESC,boot DESC,generation DESC LIMIT 49",
        &.{
            util.text(key.slice()), util.integer(owner.node_id),
            util.integer(from),     util.integer(now / 60),
        },
    );
    defer result.deinit();
    var today: wire.Today = .{
        .observed_at = now,
        .from_minute = from,
        .partial = result.rows.len > wire.page_rows,
    };
    var seen: std.bit_set.Static(24) = .empty;
    if (result.rows.len != 0) today.hits = 0;
    for (result.rows[0..@min(result.rows.len, wire.page_rows)]) |row| {
        if (row.len != 6) return error.InvalidStoredValue;
        const bucket = try util.number(row[0]);
        if (bucket < from or bucket >= from + 1440 or bucket % 60 != 0)
            return error.InvalidStoredValue;
        const through = try util.number(row[5]);
        const last = if (through == 0) bucket + 59 else through;
        if (last < bucket or last >= bucket + 60) return error.InvalidStoredValue;
        if (last >= now / 60) {
            today.partial = true;
            continue;
        }
        const hour = (bucket - from) / 60;
        const hits = if (row[1] != null) try util.number(row[1]) else null;
        today.hits = sum(today.hits, hits);
        if (!seen.isSet(hour)) today.hours[hour] = 0;
        today.hours[hour] = sum(today.hours[hour], hits);
        seen.set(hour);
        const rows = std.math.cast(u32, try util.number(row[2])) orelse
            return error.InvalidStoredValue;
        const complete = std.math.cast(u32, try util.number(row[3])) orelse
            return error.InvalidStoredValue;
        if (complete > rows) return error.InvalidStoredValue;
        today.rows = try std.math.add(u32, today.rows, rows);
        today.complete = try std.math.add(u32, today.complete, complete);
        today.unconfirmed = @max(today.unconfirmed, try util.number(row[4]));
    }
    if (owner.console_hits.journal) |journal|
        today.unconfirmed = @max(today.unconfirmed, journal.status.unconfirmed);
    return today;
}

fn sum(a: ?u64, b: ?u64) ?u64 {
    return std.math.add(u64, a orelse return null, b orelse return null) catch null;
}

//! Bounded replacement summaries preserve separately managed prefixes and show removed rows.
const std = @import("std");
const p = @import("console").protocol;
const w = p.workflows;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn describe(
    owner: *Persistent,
    input: w.CountryPreflight,
    source: []const u8,
) !w.CountrySummary {
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    var counts = try db.query(
        owner.db,
        owner.gpa,
        "SELECT COUNT(*),COUNT(DISTINCT c.prefix),COUNT(r.ip_or_cidr)," ++
            "COALESCE(SUM(CASE WHEN r.source=? THEN 1 ELSE 0 END),0) " ++
            "FROM console_country_stage c LEFT JOIN ip_reputation r ON r.ip_or_cidr=c.prefix " ++
            "WHERE c.digest=?",
        &.{ util.text(source), util.text(&digest) },
    );
    defer counts.deinit();
    if (counts.rows.len != 1 or try util.number(counts.rows[0][0]) != input.count or
        try util.number(counts.rows[0][1]) != input.count) return error.IncompleteStage;
    var summary: w.CountrySummary = .{
        .prefixes = input.count,
        .overlaps = @intCast(try util.number(counts.rows[0][2])),
        .retained = @intCast(try util.number(counts.rows[0][3])),
    };
    // Replacing a country's own rows must never take ownership of independent edits.
    if (summary.overlaps != summary.retained) return error.Conflict;
    var previous = try db.query(
        owner.db,
        owner.gpa,
        "SELECT COUNT(*),MIN(geo_generation),MAX(geo_generation) FROM ip_reputation " ++
            "WHERE source=?",
        &.{util.text(source)},
    );
    defer previous.deinit();
    const count = try util.number(previous.rows[0][0]);
    if (count > w.max_country_prefixes) return error.TrieFull;
    summary.previous = @intCast(count);
    summary.added = input.count - summary.retained;
    summary.removed = summary.previous - summary.retained;
    if (input.count == 0 and count == 0) return error.IncompleteStage;
    if (previous.rows[0][1]) |first| {
        const last = previous.rows[0][2] orelse return error.InvalidStoredPolicy;
        try summary.previous_generation.set(if (std.mem.eql(u8, first, last)) first else "mixed");
    }
    var removed = try db.query(
        owner.db,
        owner.gpa,
        "SELECT r.ip_or_cidr FROM ip_reputation r WHERE r.source=? AND NOT EXISTS " ++
            "(SELECT 1 FROM console_country_stage c WHERE c.digest=? " ++
            "AND c.prefix=r.ip_or_cidr) " ++
            "ORDER BY r.ip_or_cidr LIMIT 8",
        &.{ util.text(source), util.text(&digest) },
    );
    defer removed.deinit();
    for (removed.rows) |row| {
        try summary.removed_sample[summary.removed_count].set(row[0] orelse
            return error.InvalidStoredPolicy);
        summary.removed_count += 1;
    }
    try changes(owner, input, source, &summary);
    return summary;
}

fn changes(
    owner: *Persistent,
    input: w.CountryPreflight,
    source: []const u8,
    summary: *w.CountrySummary,
) !void {
    if (input.diff_offset > 2 * w.max_country_prefixes) return error.IncompleteStage;
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT c.prefix,CASE WHEN r.ip_or_cidr IS NULL THEN 'added' ELSE 'retained' END " ++
            "FROM console_country_stage c LEFT JOIN ip_reputation r ON c.prefix=r.ip_or_cidr " ++
            "WHERE c.digest=? UNION ALL SELECT r.ip_or_cidr,'removed' FROM ip_reputation r " ++
            "WHERE r.source=? AND NOT EXISTS(SELECT 1 FROM console_country_stage c " ++
            "WHERE c.digest=? AND c.prefix=r.ip_or_cidr) ORDER BY 1 LIMIT 9 OFFSET ?",
        &.{
            util.text(&digest), util.text(source),
            util.text(&digest), util.integer(input.diff_offset),
        },
    );
    defer rows.deinit();
    for (rows.rows[0..@min(rows.rows.len, summary.changes.len)]) |row| {
        const change = &summary.changes[summary.change_count];
        try change.prefix.set(row[0] orelse return error.InvalidStoredPolicy);
        change.kind = std.meta.stringToEnum(@TypeOf(change.kind), row[1] orelse
            return error.InvalidStoredPolicy) orelse return error.InvalidStoredPolicy;
        summary.change_count += 1;
    }
    if (rows.rows.len > summary.changes.len)
        summary.next_offset = input.diff_offset + summary.change_count;
}

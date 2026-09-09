//! Executed only by Persistent. Lease checks fence every deletion in its write transaction.
const std = @import("std");
const p = @import("console").protocol;
const r = p.retention;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const value = @import("console_store.zig");
const integer = value.integer;
const text = value.text;

pub fn acquire(owner: *Persistent, holder: r.Holder, now: u64) !p.StorageResult {
    holder.validate() catch return .{ .failed = .invalid_input };
    if (now > std.math.maxInt(i64) - r.lease_seconds) return .{ .failed = .invalid_input };
    const boot = std.fmt.bytesToHex(holder.boot, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_job_leases(job,node,boot,fence,expires) " ++
            "VALUES('retention',?,?,1,?) ON CONFLICT(job) DO UPDATE SET " ++
            "node=excluded.node,boot=excluded.boot,expires=excluded.expires," ++
            "fence=console_job_leases.fence+CASE WHEN console_job_leases.expires<=? " ++
            "OR console_job_leases.node!=excluded.node " ++
            "OR console_job_leases.boot!=excluded.boot " ++
            "THEN 1 ELSE 0 END WHERE console_job_leases.fence<9223372036854775807 " ++
            "AND (console_job_leases.expires<=? OR (console_job_leases.node=excluded.node " ++
            "AND console_job_leases.boot=excluded.boot))",
        &.{
            integer(holder.node), text(&boot),  integer(now + r.lease_seconds),
            integer(now),         integer(now),
        },
    );
    // A takeover between commit and read is a normal standby result, not ownership.
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT fence,expires FROM console_job_leases WHERE job='retention' " ++
            "AND node=? AND boot=? AND expires>? LIMIT 1",
        &.{ integer(holder.node), text(&boot), integer(now) },
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return .{ .failed = .conflict };
    const lease: r.Lease = .{
        .holder = holder,
        .fence = try value.number(rows.rows[0][0]),
        .expires = try value.number(rows.rows[0][1]),
    };
    try lease.validate();
    if (changed == 0) return .{ .failed = .capacity };
    return .{ .retention_lease = lease };
}

pub fn prune(owner: *Persistent, input: r.Prune, now: u64) !p.StorageResult {
    input.lease.validate() catch return .{ .failed = .invalid_input };
    if (now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const seconds: u64 = switch (input.kind) {
        .incidents => r.incident_days * std.time.s_per_day,
        .audit => r.audit_days * std.time.s_per_day,
        .sessions, .kiosk_grants => 0,
    };
    const cutoff = now -| seconds;
    const boot = std.fmt.bytesToHex(input.lease.holder.boot, .lower);
    _ = try db.exec(owner.db, owner.gpa, statement(input.kind), &.{
        integer(cutoff), integer(input.lease.fence), integer(input.lease.holder.node),
        text(&boot),     integer(now),
    });
    // Zaxonlite counts trigger/index mutations as well; this acknowledges the bounded
    // command, not a row count or a claim that an expired/stale holder deleted anything.
    return .command_recorded;
}

fn statement(kind: r.Kind) []const u8 {
    const guard = " AND EXISTS(SELECT 1 FROM console_job_leases WHERE job='retention' " ++
        "AND fence=? AND node=? AND boot=? AND expires>?)";
    return switch (kind) {
        .incidents => "DELETE FROM security_incidents WHERE id IN(SELECT id " ++
            "FROM security_incidents WHERE recorded_at<? " ++
            "ORDER BY recorded_at,id LIMIT 16)" ++ guard,
        .audit => "DELETE FROM console_audit WHERE id IN(SELECT id FROM console_audit " ++
            "WHERE recorded_at<? ORDER BY recorded_at,id LIMIT 16)" ++ guard,
        .sessions => "DELETE FROM console_sessions WHERE digest IN(SELECT digest " ++
            "FROM console_sessions WHERE MIN(expires,idle_expires)<=? " ++
            "ORDER BY MIN(expires,idle_expires),digest LIMIT 16)" ++ guard,
        .kiosk_grants => "DELETE FROM console_kiosk_grants WHERE digest IN(SELECT digest " ++
            "FROM console_kiosk_grants WHERE use_by<=? OR consumed_at IS NOT NULL " ++
            "ORDER BY use_by,digest LIMIT 16)" ++ guard,
    };
}

//! One owned destination per claim. Every state transition rechecks the lease in SQL;
//! network effects are at-least-once, while retries and completed destinations are durable.
const std = @import("std");
const p = @import("console").protocol;
const n = p.notifications;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const destinations = @import("console_store_notifications.zig");
const Value = @import("zaxonlite").Value;
const integer = util.integer;
const text = util.text;
const guard = " AND EXISTS(SELECT 1 FROM console_job_leases WHERE job='notifier' " ++
    "AND fence=? AND node=? AND boot=? AND expires>? AND expires>=?)";

/// Own the formatted identity for the entire prepared operation, including remote calls.
const Fence = struct {
    lease: p.retention.Lease,
    now: u64,

    fn exec(self: Fence, owner: *Persistent, sql: []const u8, input: []const Value) !i64 {
        std.debug.assert(input.len <= 16);
        var values: [21]Value = undefined;
        @memcpy(values[0..input.len], input);
        const boot = std.fmt.bytesToHex(self.lease.holder.boot, .lower);
        @memcpy(values[input.len..][0..5], &[_]Value{
            integer(self.lease.fence),   integer(self.lease.holder.node),
            text(&boot),                 integer(self.now),
            integer(self.lease.expires),
        });
        return db.exec(owner.db, owner.gpa, sql, values[0 .. input.len + 5]);
    }
};

pub fn enqueue(owner: *Persistent, input: n.Enqueue) !p.StorageResult {
    const boot = std.fmt.bytesToHex(input.boot, .lower);
    // Avoid firing the capacity trigger for a replay when the queue is already full.
    _ = db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_notification_events(node,boot,sequence,event,raised_at,detail) " ++
            "SELECT ?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM console_notification_events " ++
            "WHERE node=? AND boot=? AND sequence=?)",
        &.{
            integer(input.node),
            text(&boot),
            integer(input.sequence),
            text(@tagName(input.event)),
            integer(input.raised_at),
            text(input.detail.slice()),
            integer(input.node),
            text(&boot),
            integer(input.sequence),
        },
    ) catch return .{ .failed = .capacity };
    return .command_recorded;
}

pub fn claim(owner: *Persistent, input: n.Claim, now: u64) !p.StorageResult {
    input.lease.validate() catch return .{ .failed = .invalid_input };
    if (input.lease.expires -| now < n.claim_margin_seconds or
        !try destinations.leased(owner, input.lease, now)) return .{ .failed = .conflict };
    const fence: Fence = .{ .lease = input.lease, .now = now };
    try recover(owner, fence);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT d.id,d.destination_id,d.revision,d.attempts,e.id,e.node,e.event,e.raised_at," ++
            "e.detail FROM console_notification_deliveries d JOIN console_notification_events " ++
            "e ON e.id=d.event_id JOIN console_notifications n ON n.id=d.destination_id " ++
            "AND n.revision=d.revision WHERE d.state='pending' AND d.attempts<3 " ++
            "AND d.next_attempt_at<=? AND n.enabled=1 AND " ++
            "(n.last_attempt_at IS NULL OR n.last_attempt_at+n.cooldown_seconds<=?) " ++
            "ORDER BY d.next_attempt_at,d.id LIMIT 1",
        &.{ integer(now), integer(now) },
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return .{ .notification_claimed = null };
    const cells = rows.rows[0];
    const destination = try readDestination(owner, try util.number(cells[1])) orelse
        return .{ .notification_claimed = null };
    if (destination.revision != try util.number(cells[2]))
        return .{ .notification_claimed = null };
    const id = try util.number(cells[0]);
    const attempt = try util.number(cells[3]);
    const changed = try fence.exec(
        owner,
        "UPDATE console_notification_deliveries SET state='sending',attempts=attempts+1," ++
            "claim_fence=?,claim_expires=?,updated_at=? WHERE id=? AND state='pending' " ++
            "AND attempts=? AND EXISTS(SELECT 1 FROM console_notifications n WHERE " ++
            "n.id=destination_id AND n.revision=console_notification_deliveries.revision " ++
            "AND n.enabled=1 AND (n.last_attempt_at IS NULL OR " ++
            "n.last_attempt_at+n.cooldown_seconds<=?))" ++ guard,
        &.{
            integer(input.lease.fence),
            integer(input.lease.expires),
            integer(now),
            integer(id),
            integer(attempt),
            integer(now),
        },
    );
    if (changed == 0) return .{ .failed = .conflict };
    return .{ .notification_claimed = .{
        .delivery_id = id,
        .destination = destination,
        .event = .{
            .id = try util.number(cells[4]),
            .node = @intCast(try util.number(cells[5])),
            .event = std.meta.stringToEnum(n.Event, cells[6].?) orelse
                return error.InvalidStoredValue,
            .raised_at = try util.number(cells[7]),
            .detail = try p.Bytes(n.max_detail).init(cells[8] orelse ""),
            .attempts = @intCast(attempt + 1),
        },
    } };
}

fn readDestination(owner: *Persistent, id: u64) !?n.Destination {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT " ++ destinations.columns ++ " FROM console_notifications WHERE id=? LIMIT 1",
        &.{integer(id)},
    );
    defer rows.deinit();
    return if (rows.rows.len == 1) try destinations.row(rows.rows[0]) else null;
}

fn recover(owner: *Persistent, fence: Fence) !void {
    // A lost response is uncertain, never a proven failure. Bound recovery and retries;
    // the stable webhook idempotency key lets a receiver suppress a repeated effect.
    _ = try fence.exec(
        owner,
        "UPDATE console_notification_deliveries SET state=CASE WHEN attempts<3 THEN " ++
            "'pending' ELSE 'failed' END,updated_at=?,detail='previous attempt unconfirmed' " ++
            "WHERE id IN(SELECT id FROM console_notification_deliveries WHERE " ++
            "state='sending' AND claim_expires<=? ORDER BY id LIMIT 16)" ++ guard,
        &.{ integer(fence.now), integer(fence.now) },
    );
}

pub fn record(owner: *Persistent, input: n.Record, now: u64) !p.StorageResult {
    input.lease.validate() catch return .{ .failed = .invalid_input };
    if (input.attempt == 0 or input.attempt > n.max_attempts)
        return .{ .failed = .invalid_input };
    const fence: Fence = .{ .lease = input.lease, .now = now };
    const state = if (input.delivered) "delivered" else if (input.attempt < n.max_attempts)
        "pending"
    else
        "failed";
    const changed = try fence.exec(
        owner,
        "UPDATE console_notification_deliveries SET state=?,updated_at=?,detail=?," ++
            "next_attempt_at=? WHERE id=? AND state='sending' AND attempts=? " ++
            "AND claim_fence=? AND claim_expires>?" ++ guard,
        &.{
            text(state),
            integer(now),
            text(input.detail.slice()),
            integer(now +| (if (input.attempt == 1) @as(u64, 2) else 8)),
            integer(input.delivery_id),
            integer(input.attempt),
            integer(input.lease.fence),
            integer(now),
        },
    );
    return if (changed == 0) .{ .failed = .conflict } else .command_recorded;
}

//! Destinations, the replicated event queue and delivery records execute on the storage
//! owner. Destination mutations need administrator cookie authority; queue writes are
//! internal; delivery records are fenced by the notifier lease.
const std = @import("std");
const p = @import("console").protocol;
const n = p.notifications;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const settings = @import("console_store_settings.zig");
pub const columns = "id,revision,kind,label,target,target_host,secret_envelope IS NOT NULL," ++
    "events,cooldown_seconds,enabled,last_attempt_at,last_outcome,last_detail,transport";

pub fn row(cells: []const ?[]const u8) !n.Destination {
    return .{
        .id = try util.number(cells[0]),
        .revision = try util.number(cells[1]),
        .kind = std.meta.stringToEnum(n.Kind, cells[2].?) orelse return error.InvalidStoredValue,
        .label = try p.Bytes(n.max_label).init(cells[3] orelse ""),
        .target = try p.Bytes(n.max_target).init(cells[4] orelse ""),
        .target_host = try p.Bytes(n.max_host).init(cells[5] orelse ""),
        .secret_set = (try util.number(cells[6])) != 0,
        .events = @intCast(try util.number(cells[7])),
        .cooldown_seconds = @intCast(try util.number(cells[8])),
        .enabled = (try util.number(cells[9])) != 0,
        .last_attempt_at = if (cells[10] != null) try util.number(cells[10]) else null,
        .last_outcome = if (cells[11]) |value| std.meta.stringToEnum(n.Outcome, value) else null,
        .last_detail = try p.Bytes(n.max_detail).init(cells[12] orelse ""),
        .transport = std.meta.stringToEnum(n.Transport, cells[13].?) orelse
            return error.InvalidStoredValue,
    };
}

/// Pages of four destinations; the notifier reads them without a session under its lease.
pub fn page(owner: *Persistent, after: u64) !n.Page {
    var result: n.Page = .{};
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT " ++ columns ++ " FROM console_notifications WHERE id>? ORDER BY id LIMIT 5",
        &.{util.integer(after)},
    );
    defer rows.deinit();
    for (rows.rows) |cells| {
        if (result.count == n.page_rows) {
            result.next = result.rows[result.count - 1].id;
            break;
        }
        result.rows[result.count] = try row(cells);
        result.count += 1;
    }
    return result;
}

pub fn query(owner: *Persistent, input: n.Query, now: u64) !p.StorageResult {
    if (!try authorized(owner, input.auth, input.lease, now)) return .{ .failed = .forbidden };
    return .{ .notifications_page = try page(owner, input.after) };
}

/// The notifier's lease or an administrator session; a lease that lost its fence reads
/// nothing, so a superseded holder cannot open a secret.
fn authorized(owner: *Persistent, auth: p.users.Auth, lease: ?p.retention.Lease, now: u64) !bool {
    if (lease) |held| {
        held.validate() catch return false;
        return leased(owner, held, now);
    }
    return (try settings.admin(owner, auth, now)) != null;
}

pub fn save(owner: *Persistent, input: n.Save, now: u64) !p.StorageResult {
    n.validateSave(input) catch return .{ .failed = .invalid_input };
    const actor = try settings.admin(owner, input.auth, now) orelse
        return .{ .failed = .forbidden };
    const envelope: ?[]const u8 = if (input.secret_envelope) |value| value.slice() else null;
    if (input.id) |id| {
        const changed = try db.exec(
            owner.db,
            owner.gpa,
            // An envelope is bound to its target: a retarget without a new secret drops it.
            "UPDATE console_notifications SET kind=?,transport=?,label=?," ++
                "target=?,target_host=?," ++
                "secret_envelope=CASE WHEN ?=1 THEN NULL WHEN ? IS NULL THEN " ++
                "(CASE WHEN target=excluded_target.value THEN secret_envelope ELSE NULL END) " ++
                "ELSE ? END,events=?,cooldown_seconds=?,enabled=?,revision=revision+1," ++
                "modified_by=?,modified_at=?,client_ip=? " ++
                "FROM (SELECT ? AS value) AS excluded_target " ++
                "WHERE id=? AND revision=?",
            &.{
                util.text(@tagName(input.kind)),
                util.text(@tagName(input.transport)),
                util.text(input.label.slice()),
                util.text(input.target.slice()),
                util.text(input.target_host.slice()),
                util.integer(@intFromBool(input.clear_secret)),
                optional(envelope),
                optional(envelope),
                util.integer(input.events),
                util.integer(input.cooldown_seconds),
                util.integer(@intFromBool(input.enabled)),
                util.integer(actor),
                util.integer(now),
                util.address(&input.auth.client),
                util.text(input.target.slice()),
                util.integer(id),
                util.integer(input.expected_revision),
            },
        );
        return if (changed == 0) .{ .failed = .conflict } else .{ .notification_saved = id };
    }
    if (input.expected_revision != 0) return .{ .failed = .invalid_input };
    _ = db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_notifications(kind,transport,label,target,target_host," ++
            "secret_envelope," ++
            "events,cooldown_seconds,enabled,created_by,created_at,modified_by,modified_at," ++
            "client_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        &.{
            util.text(@tagName(input.kind)),           util.text(@tagName(input.transport)),
            util.text(input.label.slice()),            util.text(input.target.slice()),
            util.text(input.target_host.slice()),      optional(envelope),
            util.integer(input.events),                util.integer(input.cooldown_seconds),
            util.integer(@intFromBool(input.enabled)), util.integer(actor),
            util.integer(now),                         util.integer(actor),
            util.integer(now),                         util.address(&input.auth.client),
        },
    ) catch return .{ .failed = .capacity };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id FROM console_notifications WHERE created_by=? ORDER BY id DESC LIMIT 1",
        &.{util.integer(actor)},
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return .{ .failed = .unavailable };
    return .{ .notification_saved = try util.number(rows.rows[0][0]) };
}

pub fn remove(owner: *Persistent, input: n.Remove, now: u64) !p.StorageResult {
    const actor = try settings.admin(owner, input.auth, now) orelse
        return .{ .failed = .forbidden };
    // Stamp the actor first so the removal audit names who removed the destination.
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_notifications SET modified_by=?,modified_at=?,client_ip=? " ++
            "WHERE id=? AND revision=?",
        &.{
            util.integer(actor),
            util.integer(now),
            util.address(&input.auth.client),
            util.integer(input.id),
            util.integer(input.expected_revision),
        },
    );
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_notifications WHERE id=? AND revision=?",
        &.{ util.integer(input.id), util.integer(input.expected_revision) },
    );
    return if (changed == 0) .{ .failed = .conflict } else .command_recorded;
}

/// The sealed secret for a delivery or a test.
pub fn read(owner: *Persistent, input: n.Read, now: u64) !p.StorageResult {
    if (!try authorized(owner, input.auth, input.lease, now)) return .{ .failed = .forbidden };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT kind,target,secret_envelope FROM console_notifications " ++
            "WHERE id=? AND revision=? LIMIT 1",
        &.{ util.integer(input.id), util.integer(input.revision) },
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return .{ .failed = .conflict };
    const cells = rows.rows[0];
    return .{ .notification_secret = .{
        .kind = std.meta.stringToEnum(n.Kind, cells[0].?) orelse return error.InvalidStoredValue,
        .target = try p.Bytes(n.max_target).init(cells[1] orelse ""),
        .envelope = if (cells[2]) |value| try p.Bytes(n.max_envelope).init(value) else null,
    } };
}

pub fn leased(owner: *Persistent, lease: p.retention.Lease, now: u64) !bool {
    const boot = std.fmt.bytesToHex(lease.holder.boot, .lower);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT 1 FROM console_job_leases WHERE job='notifier' AND fence=? AND node=? " ++
            "AND boot=? AND expires>? LIMIT 1",
        &.{
            util.integer(lease.fence),
            util.integer(lease.holder.node),
            util.text(&boot),
            util.integer(now),
        },
    );
    defer rows.deinit();
    return rows.rows.len == 1;
}

fn optional(value: ?[]const u8) @import("zaxonlite").Value {
    return if (value) |text| .{ .text = text } else .null_value;
}

/// Storage-owner dispatch for every settings and notification request.
pub fn execute(owner: *Persistent, request: p.StorageRequest) !p.StorageResult {
    const now = owner.nowSeconds();
    const retention = @import("console_store_retention.zig");
    const queue = @import("console_store_deliveries.zig");
    return switch (request) {
        .settings_query => |auth| settings.query(owner, auth, now),
        .settings_change => |input| settings.change(owner, input, now),
        .notifications_query => |input| query(owner, input, now),
        .notifications_save => |input| save(owner, input, now),
        .notifications_remove => |input| remove(owner, input, now),
        .notifications_read => |input| read(owner, input, now),
        .notifier_acquire => |holder| retention.acquireJob(owner, "notifier", holder, now),
        .notifications_enqueue => |input| queue.enqueue(owner, input),
        .notifications_claim => |input| queue.claim(owner, input, now),
        .notifications_record => |input| queue.record(owner, input, now),
        .notifications_test_audit => |input| testAudit(owner, input, now),
        else => unreachable,
    };
}

/// A network test is not atomic with storage. Keep separate correlated intent and outcome
/// rows; an unconfirmed completion leaves the intent available for investigation.
fn testAudit(owner: *Persistent, input: n.TestAudit, now: u64) !p.StorageResult {
    if (input.revision == 0 or input.revision > std.math.maxInt(i64) or
        input.destination > std.math.maxInt(i64) or
        std.mem.allEqual(u8, &input.operation, 0)) return .{ .failed = .invalid_input };
    const actor = try settings.admin(owner, input.auth, now) orelse
        return .{ .failed = .forbidden };
    const operation = std.fmt.bytesToHex(input.operation, .lower);
    const outcome = if (input.outcome) |value| @tagName(value) else "started";
    const action = if (input.outcome == null) "notification.test" else "notification.test_result";
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
            "after_summary,client_ip) SELECT ?,'admin',?,id,label,?,json_object('operation',?," ++
            "'revision',revision,'outcome',?,'detail',?),? FROM console_notifications " ++
            "WHERE id=? AND revision=?",
        &.{
            util.integer(actor),
            util.text(action),
            util.integer(now),
            util.text(&operation),
            util.text(outcome),
            util.text(input.detail.slice()),
            util.address(&input.auth.client),
            util.integer(input.destination),
            util.integer(input.revision),
        },
    );
    return if (changed == 0) .{ .failed = .conflict } else .command_recorded;
}

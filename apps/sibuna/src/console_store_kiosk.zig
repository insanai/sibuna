//! Kiosk grants and exchanges run on the storage owner. A grant needs an operator or
//! administrator cookie session with a matching CSRF digest; the exchange consumes the grant
//! before inserting the read-only session, so a lost reply can cost a code, never grant two.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn grant(owner: *Persistent, input: p.kiosk.Grant, now: u64) !p.StorageResult {
    if (now > std.math.maxInt(i64) - p.kiosk.lifetime_seconds)
        return .{ .failed = .invalid_input };
    const identity = try util.authorize(owner, input.auth.session_digest, now);
    if (identity != .authorized) return .{ .failed = .unauthorized };
    const actor = identity.authorized;
    if (actor.must_change or actor.kiosk or actor.token_id != null or
        !actor.role.allows(.open_kiosk) or
        (input.auth.require_totp and actor.role == .admin and !actor.totp_enabled) or
        !std.crypto.timing_safe.eql([32]u8, actor.csrf_digest, input.auth.csrf_digest))
        return .{ .failed = .forbidden };
    const digest = std.fmt.bytesToHex(input.code_digest, .lower);
    const use_by = now + p.kiosk.use_seconds;
    const expires = now + p.kiosk.lifetime_seconds;
    const changes = db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_kiosk_grants(digest,user_id,revision,label,created_at,use_by," ++
            "expires) SELECT ?,u.id,u.revision,?,?,?,? FROM console_users u " ++
            "WHERE u.id=? AND u.revision=? AND u.disabled=0",
        &.{
            util.text(&digest),
            util.text(input.label.slice()),
            util.integer(now),
            util.integer(use_by),
            util.integer(expires),
            util.integer(actor.actor),
            util.integer(actor.revision),
        },
    ) catch return .{ .failed = .capacity };
    if (changes == 0) return .{ .failed = .conflict };
    return .{ .kiosk_granted = .{ .use_by = use_by, .expires = expires } };
}

pub fn exchange(owner: *Persistent, input: p.kiosk.Exchange, now: u64) !p.StorageResult {
    if (now > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    const code = std.fmt.bytesToHex(input.code_digest, .lower);
    const consumed = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_kiosk_grants SET consumed_at=? WHERE digest=? AND consumed_at IS NULL " ++
            "AND use_by>? AND EXISTS(SELECT 1 FROM console_users u " ++
            "WHERE u.id=console_kiosk_grants.user_id " ++
            "AND u.revision=console_kiosk_grants.revision AND u.disabled=0)",
        &.{ util.integer(now), util.text(&code), util.integer(now) },
    );
    if (consumed == 0) return .{ .failed = .unauthorized };
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    const inserted = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_sessions(digest,user_id,revision,csrf_digest,created_at,expires," ++
            "idle_expires,kind) SELECT ?,g.user_id,g.revision,?,?,g.expires,g.expires,'kiosk' " ++
            "FROM console_kiosk_grants g WHERE g.digest=? AND g.consumed_at=? AND g.expires>? " ++
            "AND (SELECT COUNT(*) FROM console_sessions WHERE MIN(expires,idle_expires)>?)<4096",
        &.{
            util.text(&digest), util.text(&csrf),  util.integer(now), util.text(&code),
            util.integer(now),  util.integer(now), util.integer(now),
        },
    );
    if (inserted == 0) return .{ .failed = .unavailable };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT expires FROM console_kiosk_grants WHERE digest=? LIMIT 1",
        &.{util.text(&code)},
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return .{ .failed = .unavailable };
    return .{ .kiosk_session = .{ .expires = try util.number(rows.rows[0][0]) } };
}

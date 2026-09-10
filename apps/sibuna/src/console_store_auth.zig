const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;
const number = store.number;

pub fn bootstrap(owner: *Persistent, input: p.auth.Bootstrap, now: u64) !p.StorageResult {
    const username = input.username.slice();
    const password_hash = input.password_hash.slice();
    if (input.password_expires != 0 and (input.password_expires <= now or
        input.password_expires - now > 3600)) return .{ .failed = .invalid_input };
    if (username.len == 0 or password_hash.len == 0) return .{ .failed = .invalid_input };
    // Conditional insert plus its audit trigger commit as one replicated transaction.
    // Concurrent initializers cannot create a second bootstrap administrator.
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_users(username,password_hash,role,modified_at," ++
            "must_change,password_expires) SELECT ?,?,'admin',?,?,? " ++
            "WHERE NOT EXISTS(SELECT 1 FROM console_users)",
        &.{
            text(username),
            text(password_hash),
            integer(now),
            integer(@intFromBool(input.must_change)),
            integer(input.password_expires),
        },
    );
    return if (changes == 0) .{ .failed = .conflict } else .command_recorded;
}

pub fn user(owner: *Persistent, username: []const u8) !p.StorageResult {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,username,password_hash,role,revision,must_change," ++
            "EXISTS(SELECT 1 FROM console_totp WHERE user_id=console_users.id AND enabled=1)," ++
            "password_expires " ++
            "FROM console_users " ++
            "WHERE username=? AND disabled=0 LIMIT 1",
        &.{text(username)},
    );
    defer result.deinit();
    if (result.rows.len != 1) return .{ .failed = .unauthorized };
    const row = result.rows[0];
    return .{ .auth_user = .{
        .id = try number(row[0]),
        .username = try p.Bytes(64).init(row[1].?),
        .password_hash = try p.Bytes(255).init(row[2].?),
        .role = std.meta.stringToEnum(p.Role, row[3].?) orelse return error.InvalidStoredValue,
        .revision = try number(row[4]),
        .must_change = try number(row[5]) != 0,
        .totp_enabled = try number(row[6]) != 0,
        .password_expires = try number(row[7]),
    } };
}

/// A refused sign-in is audited against the named account when it exists and otherwise
/// against subject 0; the attempted name is the target and no credential is recorded.
pub fn denied(owner: *Persistent, username: []const u8, now: u64) !p.StorageResult {
    if (username.len == 0 or username.len > 64) return .{ .failed = .invalid_input };
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_audit(actor,action,subject,target,recorded_at) " ++
            "VALUES(0,'session.denied'," ++
            "COALESCE((SELECT id FROM console_users WHERE username=?),0),?,?)",
        &.{ text(username), text(username), integer(now) },
    );
    return .command_recorded;
}

pub fn logout(owner: *Persistent, input: p.auth.Logout, now: u64) !p.StorageResult {
    const hex = std.fmt.bytesToHex(input.digest, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_sessions SET ended_at=? WHERE digest=?",
        &.{ integer(now), text(&hex) },
    );
    return .command_recorded;
}

pub fn password(owner: *Persistent, input: p.auth.PasswordChange, now: u64) !p.StorageResult {
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    const replacement = std.fmt.bytesToHex(input.replacement_digest, .lower);
    const replacement_csrf = std.fmt.bytesToHex(input.replacement_csrf, .lower);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_password_rotation " ++
            "SELECT 1,u.id,?,?,?,? FROM console_users u " ++
            "JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE u.disabled=0 AND u.revision=? AND s.revision=u.revision " ++
            "AND s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>?",
        &.{
            text(input.password_hash.slice()),
            text(&replacement),
            text(&replacement_csrf),
            integer(now),
            integer(input.expected_revision),
            text(&digest),
            text(&csrf),
            integer(now),
        },
    );
    // Insertion, old-session revocation, replacement and audit either all commit or roll back.

    return if (changes == 0) .{ .failed = .unauthorized } else .command_recorded;
}

/// Only authenticated HTTP activity refreshes idle lifetime. Subscription heartbeats
/// recheck authorization without touching it; absolute expiry is never extended.
pub fn touch(owner: *Persistent, digest: [32]u8, now: u64) !void {
    const hex = std.fmt.bytesToHex(digest, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_sessions SET idle_expires=MIN(expires,?) WHERE digest=? " ++
            "AND token_id IS NULL AND MIN(expires,idle_expires)>? " ++
            "AND EXISTS(SELECT 1 FROM console_users u " ++
            "WHERE u.id=user_id AND u.revision=console_sessions.revision AND u.disabled=0)",
        &.{ integer(now + 1800), text(&hex), integer(now) },
    );
}

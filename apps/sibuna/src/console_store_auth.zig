const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;
const number = store.number;

pub fn bootstrap(
    owner: *Persistent,
    username: []const u8,
    password_hash: []const u8,
    now: u64,
) !p.StorageResult {
    if (username.len == 0 or password_hash.len == 0) return .{ .failed = .invalid_input };
    // Conditional insert plus its audit trigger commit as one replicated transaction.
    // Concurrent initializers cannot create a second bootstrap administrator.
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_users(username,password_hash,role,modified_at) " ++
            "SELECT ?,?,'admin',? WHERE NOT EXISTS(SELECT 1 FROM console_users)",
        &.{ text(username), text(password_hash), integer(now) },
    );
    return if (changes == 0) .{ .failed = .conflict } else .command_recorded;
}

pub fn user(owner: *Persistent, username: []const u8) !p.StorageResult {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,username,password_hash,role,revision,must_change," ++
            "EXISTS(SELECT 1 FROM console_totp WHERE user_id=console_users.id AND enabled=1) " ++
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
    } };
}

pub fn logout(owner: *Persistent, digest: [32]u8) !p.StorageResult {
    const hex = std.fmt.bytesToHex(digest, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_sessions WHERE digest=?",
        &.{text(&hex)},
    );
    return .command_recorded;
}

pub fn password(owner: *Persistent, input: anytype) !p.StorageResult {
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_users SET password_hash=?,revision=revision+1,must_change=0," ++
            "modified_at=?,modified_by=id WHERE disabled=0 AND id=(SELECT user_id " ++
            "FROM console_sessions WHERE digest=? AND csrf_digest=? AND expires>? " ++
            "AND idle_expires>? AND revision=console_users.revision)",
        &.{
            text(input.password_hash.slice()),
            integer(input.now),
            text(&digest),
            text(&csrf),
            integer(input.now),
            integer(input.now),
        },
    );
    // The user-update trigger audits and deletes every old session in the same commit.
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
            "AND MIN(expires,idle_expires)>? AND EXISTS(SELECT 1 FROM console_users u " ++
            "WHERE u.id=user_id AND u.revision=console_sessions.revision AND u.disabled=0)",
        &.{ integer(now + 1800), text(&hex), integer(now) },
    );
}

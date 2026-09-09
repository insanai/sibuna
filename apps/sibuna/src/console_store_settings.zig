//! Operator settings execute on the storage owner under administrator cookie authority.
//! Keys are a fixed catalog; values are bounded text audited in full because they are
//! never secrets.
const std = @import("std");
const p = @import("console").protocol;
const n = p.notifications;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const authority = @import("console_store_tokens.zig").authority;

pub fn query(owner: *Persistent, auth: p.users.Auth, now: u64) !p.StorageResult {
    if (try admin(owner, auth, now) == null) return .{ .failed = .forbidden };
    var page: n.SettingsPage = .{};
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT key,value,revision,updated_at,updated_by FROM console_settings " ++
            "ORDER BY key LIMIT 8",
        &.{},
    );
    defer rows.deinit();
    for (rows.rows) |row| {
        if (page.count == page.rows.len) break;
        page.rows[page.count] = .{
            .key = try p.Bytes(n.max_setting_key).init(row[0] orelse ""),
            .value = try p.Bytes(n.max_setting_value).init(row[1] orelse ""),
            .revision = try util.number(row[2]),
            .updated_at = try util.number(row[3]),
            .updated_by = try util.number(row[4]),
        };
        page.count += 1;
    }
    return .{ .settings_page = page };
}

pub fn change(owner: *Persistent, input: n.SettingChange, now: u64) !p.StorageResult {
    if (!n.knownSetting(input.key.slice()) or input.expected_revision >= std.math.maxInt(i64))
        return .{ .failed = .invalid_input };
    const actor = try admin(owner, input.auth, now) orelse return .{ .failed = .forbidden };
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_settings(key,value,revision,updated_at,updated_by) " ++
            "SELECT ?,?,1,?,? WHERE ?=0 " ++
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=revision+1," ++
            "updated_at=excluded.updated_at,updated_by=excluded.updated_by " ++
            "WHERE console_settings.revision=?",
        &.{
            util.text(input.key.slice()),
            util.text(input.value.slice()),
            util.integer(now),
            util.integer(actor),
            util.integer(input.expected_revision),
            util.integer(input.expected_revision),
        },
    );
    if (changed == 0) {
        // A fresh key with a nonzero expected revision or a stale revision on an
        // existing key both end here; the update path handles existing keys.
        const updated = try db.exec(
            owner.db,
            owner.gpa,
            "UPDATE console_settings SET value=?,revision=revision+1,updated_at=?," ++
                "updated_by=? WHERE key=? AND revision=?",
            &.{
                util.text(input.value.slice()),        util.integer(now),
                util.integer(actor),                   util.text(input.key.slice()),
                util.integer(input.expected_revision),
            },
        );
        if (updated == 0) return .{ .failed = .conflict };
    }
    return .command_recorded;
}

/// Administrator cookie session with a matching CSRF digest; returns the actor id.
pub fn admin(owner: *Persistent, auth: p.users.Auth, now: u64) !?u64 {
    const digest = std.fmt.bytesToHex(auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(auth.csrf_digest, .lower);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        authority ++ "SELECT id FROM a LIMIT 1",
        &.{
            util.text(&digest),                            util.text(&csrf), util.integer(now),
            util.integer(@intFromBool(auth.require_totp)),
        },
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return null;
    return try util.number(rows.rows[0][0]);
}

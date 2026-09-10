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
        if (page.count == page.rows.len) return error.InvalidStoredValue;
        if (!p.settings.valid(row[0] orelse "", row[1] orelse ""))
            return error.InvalidStoredValue;
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
    const entry = p.settings.definition(input.key.slice()) orelse
        return .{ .failed = .invalid_input };
    if (!p.settings.valid(input.key.slice(), input.value.slice()) or
        input.expected_revision >= std.math.maxInt(i64) or
        (entry.group == .retention and !input.confirmed)) return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    const creating = input.expected_revision == 0;
    const statement = if (creating)
        authority ++ "INSERT INTO console_settings(key,value,revision,updated_at,updated_by) " ++
            "SELECT ?,?,1,?,id FROM a WHERE NOT EXISTS(SELECT 1 FROM console_settings WHERE key=?)"
    else
        authority ++ "UPDATE console_settings SET value=?,updated_at=?," ++
            "updated_by=(SELECT id FROM a),revision=revision+1 WHERE key=? AND revision=? " ++
            "AND EXISTS(SELECT 1 FROM a)";
    const shared = [_]@import("zaxonlite").Value{
        util.text(&digest),                                  util.text(&csrf), util.integer(now),
        util.integer(@intFromBool(input.auth.require_totp)),
    };
    const tail = if (creating) [_]@import("zaxonlite").Value{
        util.text(input.key.slice()), util.text(input.value.slice()), util.integer(now),
        util.text(input.key.slice()),
    } else [_]@import("zaxonlite").Value{
        util.text(input.value.slice()),        util.integer(now), util.text(input.key.slice()),
        util.integer(input.expected_revision),
    };
    // Authority, expected revision, the setting and its audit trigger share one statement.
    var parameters: [8]@import("zaxonlite").Value = undefined;
    @memcpy(parameters[0..4], &shared);
    @memcpy(parameters[4..], &tail);
    const changed = try db.exec(owner.db, owner.gpa, statement, &parameters);
    if (changed != 0) return .command_recorded;
    return .{ .failed = if (try admin(owner, input.auth, now) == null) .forbidden else .conflict };
}

pub const Retention = struct { days: u16, revision: u64 = 0 };

/// Readers capture one bounded setting and recheck it before publishing historical pages.
pub fn retention(owner: *Persistent, comptime key: []const u8) !Retention {
    const entry = comptime p.settings.definition(key).?;
    comptime std.debug.assert(entry.group == .retention);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT value,revision FROM console_settings WHERE key=? LIMIT 1",
        &.{util.text(key)},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return .{ .days = @intCast(entry.maximum) };
    const value = rows.rows[0][0] orelse return error.InvalidStoredValue;
    if (!p.settings.valid(key, value)) return error.InvalidStoredValue;
    return .{
        .days = try std.fmt.parseInt(u16, value, 10),
        .revision = try util.number(rows.rows[0][1]),
    };
}

/// A cleanup statement reads its cutoff transactionally, including after a peer edit.
pub inline fn daysSql(comptime key: []const u8) []const u8 {
    const entry = comptime p.settings.definition(key).?;
    comptime std.debug.assert(entry.group == .retention);
    return "COALESCE((SELECT CAST(value AS INTEGER) FROM console_settings WHERE key='" ++
        key ++ "')," ++ entry.default ++ ")";
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

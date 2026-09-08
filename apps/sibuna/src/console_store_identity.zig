//! The registry is authoritative for both credential kinds. A bearer cannot authenticate
//! as a cookie, and a browser cookie cannot become an automation token. User revision
//! changes remove both kinds in the existing account transaction.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn authorize(
    owner: *Persistent,
    digest: [32]u8,
    now: u64,
    kind: ?p.CredentialKind,
) !p.StorageResult {
    if (now > std.math.maxInt(i64)) return .{ .failed = .unauthorized };
    const hex = std.fmt.bytesToHex(digest, .lower);
    const mode: zx.Value = .{ .integer = if (kind) |value| @intFromEnum(value) else -1 };
    var result = try db.query(owner.db, owner.gpa, sql, &.{
        util.integer(p.tokens.known_scopes), util.text(&hex), util.integer(now),
        util.integer(now),                   mode,            mode,
    });
    defer result.deinit();
    if (result.rows.len != 1) return .{ .failed = .unauthorized };
    return .{ .authorized = try principal(result.rows[0]) };
}

fn principal(row: []const ?[]const u8) !p.Principal {
    var csrf: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&csrf, row[4] orelse return error.InvalidStoredValue);
    const role = std.meta.stringToEnum(p.Role, row[1].?) orelse return error.InvalidStoredValue;
    const scopes = try util.number(row[9]);
    const token_id = if (row[8] != null) try util.number(row[8]) else null;
    if (scopes > p.tokens.known_scopes or
        (token_id != null and !p.tokens.validScopes(@intCast(scopes), role)))
        return error.InvalidStoredValue;
    return .{
        .actor = try util.number(row[0]),
        .username = try p.Bytes(64).init(row[6].?),
        .role = role,
        .account_role = std.meta.stringToEnum(p.Role, row[10].?) orelse
            return error.InvalidStoredValue,
        .revision = try util.number(row[2]),
        .expires = try util.number(row[3]),
        .csrf_digest = csrf,
        .must_change = try util.number(row[5]) != 0,
        .totp_enabled = try util.number(row[7]) != 0,
        .token_id = token_id,
        .scopes = @intCast(scopes),
    };
}

const sql =
    "SELECT u.id,COALESCE(t.role,u.role),u.revision,s.expires,s.csrf_digest," ++
    "u.must_change,u.username," ++
    "EXISTS(SELECT 1 FROM console_totp m WHERE m.user_id=u.id AND m.enabled=1)," ++
    "s.token_id,CASE WHEN s.token_id IS NULL THEN ? ELSE t.scopes END,u.role " ++
    "FROM console_sessions s JOIN console_users u ON u.id=s.user_id " ++
    "LEFT JOIN console_tokens t ON t.id=s.token_id " ++
    "WHERE s.digest=? AND s.expires>? AND s.idle_expires>? AND s.revision=u.revision " ++
    "AND u.disabled=0 AND (?=-1 OR (s.token_id IS NOT NULL)=?) " ++
    "AND (s.token_id IS NULL OR (t.id IS NOT NULL AND t.digest=s.digest " ++
    "AND t.created_by=u.id AND t.auth_revision=u.revision AND t.disabled=0 " ++
    "AND u.role='admin')) LIMIT 1";

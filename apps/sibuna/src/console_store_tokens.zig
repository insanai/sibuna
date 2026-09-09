//! Persistent alone manages tokens. Issuance requires a full administrator cookie session;
//! bearer credentials cannot mint more credentials. Authority is immutable after issuance.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const token = p.tokens;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const columns = "t.id,t.revision,t.label,t.role,t.scopes,t.created_by,t.created_at," ++
    "t.expires_at,t.disabled,";
const active = "(t.disabled=0 AND (t.expires_at IS NULL OR t.expires_at>?) AND " ++
    "EXISTS(SELECT 1 FROM console_sessions r JOIN console_users u ON u.id=r.user_id " ++
    "WHERE r.token_id=t.id AND r.digest=t.digest AND r.revision=u.revision " ++
    "AND MIN(r.expires,r.idle_expires)>? " ++
    "AND u.revision=t.auth_revision AND u.disabled=0 AND u.must_change=0 AND u.role='admin'))";
pub const authority = "WITH a AS (SELECT u.id,u.revision FROM console_users u " ++
    "JOIN console_sessions s ON s.user_id=u.id WHERE s.digest=? AND s.csrf_digest=? " ++
    "AND s.token_id IS NULL AND MIN(s.expires,s.idle_expires)>? " ++
    "AND u.revision=s.revision AND u.disabled=0 AND u.must_change=0 AND u.role='admin' " ++
    "AND (?=0 OR EXISTS(SELECT 1 FROM console_totp m WHERE m.user_id=u.id AND m.enabled=1))) ";

const Credentials = struct {
    digest: [64]u8,
    csrf: [64]u8,
    require_totp: bool,
    now: u64,

    fn init(input: p.users.Auth, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .require_totp = input.require_totp,
            .now = now,
        };
    }

    fn values(self: *const Credentials) [4]zx.Value {
        return .{
            util.text(&self.digest),
            util.text(&self.csrf),
            util.integer(self.now),
            util.integer(@intFromBool(self.require_totp)),
        };
    }
};

fn identity(owner: *Persistent, input: p.users.Auth) !?p.Failure {
    const result = try util.authorize(owner, input.session_digest, owner.nowSeconds());
    if (result != .authorized or result.authorized.must_change) return .unauthorized;
    const actor = result.authorized;
    if (actor.role != .admin or actor.token_id != null or
        (input.require_totp and !actor.totp_enabled)) return .forbidden;
    if (!std.crypto.timing_safe.eql([32]u8, actor.csrf_digest, input.csrf_digest))
        return .forbidden;
    return null;
}

pub fn query(owner: *Persistent, input: token.Query) !p.StorageResult {
    try p.users.validateQuery(.{ .auth = input.auth, .after = input.after, .limit = input.limit });
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    const credentials = Credentials.init(input.auth, owner.nowSeconds());
    var rows = try db.query(
        owner.db,
        owner.gpa,
        authority ++ "SELECT " ++ columns ++ active ++
            " FROM console_tokens t WHERE EXISTS(SELECT 1 FROM a) " ++
            "AND t.id>? ORDER BY t.id LIMIT ?",
        &(credentials.values() ++ [_]zx.Value{
            util.integer(credentials.now),
            util.integer(credentials.now),
            util.integer(input.after),
            util.integer(input.limit + 1),
        }),
    );
    defer rows.deinit();
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    var page: token.Page = .{};
    page.count = @min(rows.rows.len, input.limit);
    for (rows.rows[0..page.count], page.rows[0..page.count]) |row, *item| item.* = try decode(row);
    if (rows.rows.len > page.count) page.next = page.rows[page.count - 1].id;
    return .{ .tokens_page = page };
}

pub fn create(owner: *Persistent, input: token.Create) !p.StorageResult {
    try token.validateCreate(input);
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    const credentials = Credentials.init(input.auth, owner.nowSeconds());
    if (input.expires) |expires| {
        if (expires <= credentials.now) return .{ .failed = .invalid_input };
    }
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        authority ++
            "INSERT INTO console_tokens(digest,label,role,scopes,auth_revision,created_by," ++
            "created_at,expires_at,modified_by,modified_at) " ++
            "SELECT ?,?,?,?,a.revision,a.id,?,?,a.id,? " ++
            "FROM a WHERE (SELECT count(*) FROM console_tokens)<? AND " ++
            "(SELECT count(*) FROM console_sessions WHERE MIN(expires,idle_expires)>?)<4096 " ++
            "ON CONFLICT(digest) DO NOTHING",
        &(credentials.values() ++ [_]zx.Value{
            util.text(&digest),
            util.text(input.label.slice()),
            util.text(@tagName(input.role)),
            util.integer(input.scopes),
            util.integer(credentials.now),
            if (input.expires) |expires| util.integer(expires) else .null_value,
            util.integer(credentials.now),
            util.integer(token.capacity),
            util.integer(credentials.now),
        }),
    );
    if (changed == 0) {
        if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = if (try identifier(owner, &digest) != null) .conflict else .capacity };
    }
    // The digest identifies this acknowledged insert across the supported storage facade.
    // Failure to retrieve its id leaves the caller with an unknown outcome, not a rollback.
    const id = try identifier(owner, &digest) orelse return error.InvalidStoredValue;
    return .{ .token_saved = id };
}

fn identifier(owner: *Persistent, digest: []const u8) !?u64 {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id FROM console_tokens WHERE digest=? LIMIT 1",
        &.{util.text(digest)},
    );
    defer result.deinit();
    return if (result.rows.len == 1) try util.number(result.rows[0][0]) else null;
}

pub fn revoke(owner: *Persistent, input: token.Revoke) !p.StorageResult {
    try token.validateRevoke(input);
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    const credentials = Credentials.init(input.auth, owner.nowSeconds());
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        authority ++
            "UPDATE console_tokens AS t SET disabled=1,revision=revision+1," ++
            "modified_by=(SELECT id FROM a),modified_at=?,remove_requested=? " ++
            "WHERE EXISTS(SELECT 1 FROM a) AND t.id=? AND t.revision=? " ++
            "AND ((?=0 AND t.disabled=0) OR (?=1 AND NOT " ++ active ++ "))",
        &(credentials.values() ++ [_]zx.Value{
            util.integer(credentials.now),
            util.integer(@intFromBool(input.remove)),
            util.integer(input.target),
            util.integer(input.expected_revision),
            util.integer(@intFromBool(input.remove)),
            util.integer(@intFromBool(input.remove)),
            util.integer(credentials.now),
            util.integer(credentials.now),
        }),
    );
    if (changed == 0) {
        if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .token_saved = input.target };
}

fn decode(row: []const ?[]const u8) !token.Row {
    const role = std.meta.stringToEnum(p.Role, row[3].?) orelse return error.InvalidStoredValue;
    const scopes = try util.number(row[4]);
    if (scopes > token.known_scopes or !token.validScopes(@intCast(scopes), role))
        return error.InvalidStoredValue;
    const label = try p.Bytes(64).init(row[2].?);
    if (!token.validLabel(label.slice())) return error.InvalidStoredValue;
    return .{
        .id = try util.number(row[0]),
        .revision = try util.number(row[1]),
        .label = label,
        .role = role,
        .scopes = @intCast(scopes),
        .created_by = try util.number(row[5]),
        .created_at = try util.number(row[6]),
        .expires = if (row[7] != null) try util.number(row[7]) else null,
        .disabled = try util.number(row[8]) != 0,
        .active = try util.number(row[9]) != 0,
    };
}

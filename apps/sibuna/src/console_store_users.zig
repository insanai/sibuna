//! Persistent executes all account operations. Conditional SQL rechecks authorization in
//! the same transaction as mutation, redacted audit and affected-session revocation.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const u = p.users;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");

const authorization =
    "WITH a AS (SELECT u.id FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
    "WHERE s.digest=? AND (?=0 OR s.csrf_digest=?) AND MIN(s.expires,s.idle_expires)>? " ++
    "AND (?=0 OR u.role!='admin' OR EXISTS(SELECT 1 FROM console_totp t " ++
    "WHERE t.user_id=u.id AND t.enabled=1)) AND (?=0 OR u.role='admin') " ++
    "AND u.disabled=0 AND u.must_change=0 AND s.revision=u.revision) ";

const Credentials = struct {
    digest: [64]u8,
    csrf: [64]u8,
    now: u64,
    require_totp: bool,

    fn init(input: u.Auth, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .now = now,
            .require_totp = input.require_totp,
        };
    }

    // Values borrow this object's hex buffers only for the synchronous owner call.
    fn values(self: *const Credentials, manage: bool) [6]zx.Value {
        return .{
            util.text(&self.digest),                       util.integer(@intFromBool(manage)),
            util.text(&self.csrf),                         util.integer(self.now),
            util.integer(@intFromBool(self.require_totp)), util.integer(@intFromBool(manage)),
        };
    }
};

fn identity(owner: *Persistent, input: u.Auth, now: u64, manage: bool) !p.StorageResult {
    if (now > std.math.maxInt(i64) - u.temporary_seconds)
        return .{ .failed = .invalid_input };
    const result = try util.authorize(owner, input.session_digest, now);
    if (result != .authorized or result.authorized.must_change)
        return .{ .failed = .unauthorized };
    const actor = result.authorized;
    const account_role = actor.account_role orelse actor.role;
    if (input.require_totp and account_role == .admin and !actor.totp_enabled)
        return .{ .failed = .forbidden };
    if (manage and (!actor.role.allows(.manage_users) or
        !std.crypto.timing_safe.eql([32]u8, input.csrf_digest, actor.csrf_digest)))
        return .{ .failed = .forbidden };
    return result;
}

pub fn query(owner: *Persistent, input: u.Query, now: u64) !p.StorageResult {
    try u.validateQuery(input);
    const actor = try identity(owner, input.auth, now, false);
    if (actor != .authorized) return actor;
    const credentials = Credentials.init(input.auth, now);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        authorization ++
            "SELECT u.id,u.username,u.role,u.revision,u.disabled,u.must_change," ++
            "u.password_expires," ++
            "EXISTS(SELECT 1 FROM console_totp t WHERE t.user_id=u.id AND t.enabled=1)," ++
            "(SELECT last_login FROM console_user_activity WHERE user_id=u.id) " ++
            "FROM console_users u WHERE EXISTS(SELECT 1 FROM a) AND u.id>? ORDER BY u.id LIMIT ?",
        &(credentials.values(false) ++ [_]zx.Value{
            util.integer(input.after), util.integer(@as(u64, input.limit) + 1),
        }),
    );
    defer rows.deinit();
    // A revocation between the preliminary check and read must not look like an empty catalog.
    const current = try identity(owner, input.auth, now, false);
    if (current != .authorized) return current;
    var page: u.Page = .{};
    page.count = @min(rows.rows.len, input.limit);
    for (rows.rows[0..page.count], page.rows[0..page.count]) |row, *item| item.* = .{
        .id = try util.number(row[0]),
        .username = try p.Bytes(64).init(row[1].?),
        .role = std.meta.stringToEnum(p.Role, row[2].?) orelse return error.InvalidStoredValue,
        .revision = try util.number(row[3]),
        .disabled = try util.number(row[4]) != 0,
        .must_change = try util.number(row[5]) != 0,
        .password_expires = try util.number(row[6]),
        .totp_enabled = try util.number(row[7]) != 0,
        .last_login = if (row[8] != null) try util.number(row[8]) else null,
    };
    if (rows.rows.len > page.count) page.next = page.rows[page.count - 1].id;
    return .{ .users_page = page };
}

pub fn create(owner: *Persistent, input: u.Create, now: u64) !p.StorageResult {
    try u.validateCreate(input);
    const actor = try identity(owner, input.auth, now, true);
    if (actor != .authorized) return actor;
    const credentials = Credentials.init(input.auth, now);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        authorization ++
            "INSERT INTO console_users(username,password_hash,role,must_change," ++
            "password_expires," ++
            "modified_at,modified_by,client_ip) SELECT ?,?,?,1,?,?,a.id,? FROM a " ++
            "WHERE (SELECT COUNT(*) FROM console_users)<1024 " ++
            "AND NOT EXISTS(SELECT 1 FROM console_users WHERE username=?)",
        &(credentials.values(true) ++ [_]zx.Value{
            util.text(input.username.slice()), util.text(input.password_hash.slice()),
            util.text(@tagName(input.role)),   util.integer(now + u.temporary_seconds),
            util.integer(now),                 util.address(&input.auth.client),
            util.text(input.username.slice()),
        }),
    );
    if (changes != 0) return .{ .users_saved = now + u.temporary_seconds };
    const current = try identity(owner, input.auth, now, true);
    if (current != .authorized) return current;
    var count = try db.query(owner.db, owner.gpa, "SELECT COUNT(*) FROM console_users", &.{});
    defer count.deinit();
    return .{ .failed = if (try util.number(count.rows[0][0]) >= u.capacity)
        .capacity
    else
        .conflict };
}

pub fn change(owner: *Persistent, input: u.Change, now: u64) !p.StorageResult {
    try u.validateChange(input);
    const actor = try identity(owner, input.auth, now, true);
    if (actor != .authorized) return actor;
    if (input.target == actor.authorized.actor and input.operation != .revoke)
        return .{ .failed = .forbidden };
    const credentials = Credentials.init(input.auth, now);
    if (input.operation == .factor) {
        const reset = try db.exec(
            owner.db,
            owner.gpa,
            factor_sql,
            &(credentials.values(true) ++ [_]zx.Value{
                util.integer(input.target), util.integer(input.expected_revision),
                util.integer(now),          util.address(&input.auth.client),
            }),
        );
        if (reset != 0) return .{ .users_saved = 0 };
        const current = try identity(owner, input.auth, now, true);
        return if (current == .authorized) .{ .failed = .conflict } else current;
    }
    const role: zx.Value = if (input.operation == .access)
        util.text(@tagName(input.operation.access.role))
    else
        .null_value;
    const disabled: zx.Value = if (input.operation == .access)
        util.integer(@intFromBool(input.operation.access.disabled))
    else
        .null_value;
    const password: zx.Value = if (input.operation == .password)
        util.text(input.operation.password.slice())
    else
        .null_value;
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        change_sql,
        &(credentials.values(true) ++ [_]zx.Value{
            util.integer(input.target),       util.integer(input.expected_revision),
            role,                             disabled,
            password,                         util.integer(now),
            util.address(&input.auth.client),
        }),
    );
    if (changes != 0) return .{ .users_saved = if (input.operation == .password)
        now + u.temporary_seconds
    else
        0 };
    const current = try identity(owner, input.auth, now, true);
    return if (current == .authorized) .{ .failed = .conflict } else current;
}

// Turning the factor off fires the audited user-revision bump that ends the target's sessions.
// Clearing the enrollment deadline stops a stale pending seed from being confirmed again.
const factor_sql = authorization ++
    ", i AS (SELECT ? target,? revision,? now,? client) " ++
    "UPDATE console_totp SET enabled=0,recovery_digests='',recovery_used=0,last_step=NULL," ++
    "expires=0,revision=console_totp.revision+1,modified_at=i.now,modified_by=a.id," ++
    "client_ip=i.client FROM a,i WHERE console_totp.user_id=i.target " ++
    "AND console_totp.user_id!=a.id AND console_totp.enabled=1 " ++
    "AND EXISTS(SELECT 1 FROM console_users v WHERE v.id=i.target AND v.revision=i.revision)";

const change_sql = authorization ++
    ", i AS (SELECT ? target,? revision,? role,? disabled,? password_hash,? now,? client) " ++
    "UPDATE console_users SET role=COALESCE(i.role,console_users.role)," ++
    "disabled=COALESCE(i.disabled,console_users.disabled)," ++
    "password_hash=COALESCE(i.password_hash,console_users.password_hash)," ++
    "password_expires=CASE WHEN i.password_hash IS NULL THEN console_users.password_expires " ++
    "ELSE i.now+3600 END,must_change=CASE WHEN i.password_hash IS NULL " ++
    "THEN console_users.must_change ELSE 1 END,revision=console_users.revision+1," ++
    "modified_at=i.now,modified_by=a.id,client_ip=i.client FROM a,i " ++
    "WHERE console_users.id=i.target " ++
    "AND console_users.revision=i.revision " ++
    // An authorized admin distinct from the target survives every access/password mutation.
    // Concurrent administrators cannot disable each other: the second actor no longer matches a.
    "AND (console_users.id!=a.id OR (i.role IS NULL AND i.password_hash IS NULL))";

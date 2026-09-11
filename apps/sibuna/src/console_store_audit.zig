//! Audit readers run only on Persistent, with bounded prepared queries and owned results.
const std = @import("std");
const p = @import("console").protocol;
const a = p.audit;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
/// Shared by the page, detail and live-feed readers so every decoder sees one layout.
pub const columns = "id,actor,subject,recorded_at,action,target,actor_role,client_ip";

fn identity(owner: *Persistent, auth: p.users.Auth) !?p.Failure {
    const result = try util.authorize(owner, auth.session_digest, owner.nowSeconds());
    if (result != .authorized or result.authorized.must_change) return .unauthorized;
    const actor = result.authorized;
    if (actor.token_id != null or (auth.require_totp and actor.role == .admin and
        !actor.totp_enabled)) return .forbidden;
    if (!std.crypto.timing_safe.eql([32]u8, actor.csrf_digest, auth.csrf_digest))
        return .forbidden;
    return null;
}

pub fn query(owner: *Persistent, input: a.Query) !p.StorageResult {
    try a.validate(input);
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    var rows = try db.query(owner.db, owner.gpa, "SELECT " ++ columns ++
        " FROM console_audit WHERE id<=? AND recorded_at>=? AND recorded_at<=? " ++
        "AND (? IS NULL OR actor=?) AND (?='' OR action=?) ORDER BY id DESC LIMIT 9", &.{
        util.integer(input.before),
        util.integer(input.since),
        util.integer(input.until),
        if (input.actor) |actor| util.integer(actor) else .null_value,
        if (input.actor) |actor| util.integer(actor) else .null_value,
        util.text(input.action.slice()),
        util.text(input.action.slice()),
    });
    defer rows.deinit();
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    var page: a.Page = .{};
    page.count = @min(rows.rows.len, page.rows.len);
    for (rows.rows[0..page.count], page.rows[0..page.count]) |row, *item| try decode(row, item);
    if (rows.rows.len > page.count) page.next = page.rows[page.count - 1].id - 1;
    if (input.export_page and !try exportAudit(owner, input.auth, page.count))
        return .{ .failed = .unauthorized };
    return .{ .audit_page = page };
}

pub fn read(owner: *Persistent, input: a.Read) !p.StorageResult {
    if (input.id == 0 or input.id > a.last_id) return .{ .failed = .invalid_input };
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    var rows = try db.query(owner.db, owner.gpa, "SELECT " ++ columns ++
        ",before_summary,after_summary FROM console_audit WHERE id=? LIMIT 1", &.{
        util.integer(input.id),
    });
    defer rows.deinit();
    if (try identity(owner, input.auth)) |reason| return .{ .failed = reason };
    if (rows.rows.len == 0) return .{ .failed = .conflict };
    var detail: a.Detail = .{ .row = .{} };
    const row = rows.rows[0];
    try decode(row, &detail.row);
    inline for (.{ "before", "after" }, 8..) |field, index| {
        if (row[index]) |source| {
            @field(detail, field) = .{};
            const summary = @import("console_audit_summary.zig");
            var coverage: summary.Coverage = .{};
            try summary.copy(
                &@field(detail, field).?,
                source,
                &coverage,
                detail.row.action.slice(),
            );
            @field(detail, field ++ "_truncated") = coverage.truncated;
            @field(detail, field ++ "_redacted") = coverage.redacted;
        }
    }
    return .{ .audit_detail = detail };
}

pub fn decode(row: []const ?[]const u8, output: *a.Row) !void {
    output.* = .{
        .id = try util.number(row[0]),
        .actor = try util.number(row[1]),
        .subject = try util.number(row[2]),
        .recorded_at = try util.number(row[3]),
    };
    if (output.id == 0) return error.InvalidStoredValue;
    try output.action.set(row[4] orelse return error.InvalidStoredValue);
    if (row[5]) |target| {
        output.target = .{};
        try output.target.?.set(target);
    }
    if (row[6]) |role| output.actor_role = std.meta.stringToEnum(p.Role, role) orelse
        return error.InvalidStoredValue;
    if (row.len < 8) return error.InvalidStoredValue;
    if (row[7]) |client| {
        output.client_ip = .{};
        try output.client_ip.?.set(client);
    }
}

fn exportAudit(owner: *Persistent, auth: p.users.Auth, count: usize) !bool {
    const digest = std.fmt.bytesToHex(auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(auth.csrf_digest, .lower);
    // Authorization and the export event commit together. The response can still be lost.
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_audit(actor,actor_role,action,subject,recorded_at,client_ip) " ++
            "SELECT u.id,u.role,'audit.export',?,?,? FROM console_users u " ++
            "JOIN console_sessions s ON s.user_id=u.id WHERE s.digest=? " ++
            "AND s.csrf_digest=? AND s.token_id IS NULL AND s.revision=u.revision " ++
            "AND MIN(s.expires,s.idle_expires)>? AND u.disabled=0 AND u.must_change=0 " ++
            "AND (?=0 OR u.role!='admin' OR EXISTS(SELECT 1 FROM console_totp m " ++
            "WHERE m.user_id=u.id AND m.enabled=1))",
        &.{
            util.integer(count),
            util.integer(owner.nowSeconds()),
            util.address(&auth.client),
            util.text(&digest),
            util.text(&csrf),
            util.integer(owner.nowSeconds()),
            util.integer(@intFromBool(auth.require_totp)),
        },
    );
    // Zaxonlite includes trigger writes in its change count. The unique session join
    // inserts at most one audit row; zero alone means authorization did not match.
    return changes > 0;
}

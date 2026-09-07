//! Runs exclusively on Persistent's storage thread. HTTP handlers own no database handle.
const std = @import("std");
const zx = @import("zaxonlite");
const console = @import("console");
const p = console.protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const auth = @import("console_store_auth.zig");

pub fn tick(owner: *Persistent) void {
    // Cap work per tick so console saturation cannot starve incidents and policy reload.
    for (0..4) |_| {
        const work = owner.console_mailbox.take(owner.io) orelse return;
        const result = execute(owner, work.request) catch |err| result: {
            std.log.warn("console storage operation failed: {t}", .{err});
            break :result p.StorageResult{ .failed = .unavailable };
        };
        owner.console_mailbox.complete(owner.io, work.ticket, result) catch |err| {
            // A ticket cannot disappear while executing, even after disconnect/shutdown.
            std.debug.panic("console mailbox invariant: {t}", .{err});
        };
    }
}

fn migrate(owner: *Persistent) !void {
    var tables = try db.query(
        owner.db,
        owner.gpa,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='console_schema' LIMIT 1",
        &.{},
    );
    defer tables.deinit();
    if (tables.rows.len != 0) {
        var versions = try db.query(
            owner.db,
            owner.gpa,
            "SELECT version FROM console_schema LIMIT 2",
            &.{},
        );
        defer versions.deinit();
        if (versions.rows.len != 1 or try number(versions.rows[0][0]) != console.schema.version)
            return error.UnsupportedConsoleSchema;
    }
    try owner.db.exec(
        owner.gpa,
        console.schema.sql,
    );
    owner.console_initialized = true;
}

pub fn execute(owner: *Persistent, request: p.StorageRequest) !p.StorageResult {
    if (!owner.console_initialized) try migrate(owner);
    return switch (request) {
        .setup_status => blk: {
            var result = try db.query(
                owner.db,
                owner.gpa,
                "SELECT id FROM console_users LIMIT 1",
                &.{},
            );
            defer result.deinit();
            break :blk .{ .setup_required = result.rows.len == 0 };
        },
        .bootstrap => |input| auth.bootstrap(
            owner,
            input.username.slice(),
            input.password_hash.slice(),
            input.now,
        ),
        .auth_user => |username| auth.user(owner, username.slice()),
        .session_create => |input| auth.session(owner, input),
        .authorize => |input| authorize(owner, input.session_digest, input.now),
        .logout => |digest| auth.logout(owner, digest),
        .password_change => |input| auth.password(owner, input),
        else => .{ .failed = .invalid_input },
    };
}

pub fn authorize(owner: *Persistent, digest: [32]u8, now: u64) !p.StorageResult {
    const hex = std.fmt.bytesToHex(digest, .lower);
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT u.id,u.role,u.revision,s.expires,s.csrf_digest,u.must_change,u.username " ++
            "FROM console_sessions s JOIN console_users u ON u.id=s.user_id " ++
            "WHERE s.digest=? AND s.expires>? AND s.revision=u.revision " ++
            "AND u.disabled=0 LIMIT 1",
        &.{ text(&hex), integer(now) },
    );
    defer result.deinit();
    if (result.rows.len != 1) return .{ .failed = .unauthorized };
    const row = result.rows[0];
    var csrf: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&csrf, row[4] orelse return error.InvalidStoredValue);
    return .{ .authorized = .{
        .actor = try number(row[0]),
        .username = try p.Bytes(64).init(row[6].?),
        .role = std.meta.stringToEnum(p.Role, row[1].?) orelse return error.InvalidStoredValue,
        .revision = try number(row[2]),
        .expires = try number(row[3]),
        .csrf_digest = csrf,
        .must_change = try number(row[5]) != 0,
    } };
}

pub fn number(cell: ?[]const u8) !u64 {
    return std.fmt.parseInt(u64, cell orelse return error.InvalidStoredValue, 10);
}

pub fn text(value: []const u8) zx.Value {
    return .{ .text = value };
}

pub fn integer(value: u64) zx.Value {
    std.debug.assert(value <= std.math.maxInt(i64));
    return .{ .integer = @intCast(value) };
}

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
    for (0..16) |_| {
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

pub fn execute(owner: *Persistent, request: p.StorageRequest) !p.StorageResult {
    if (!owner.console_initialized) try @import("console_migrations.zig").run(owner);
    return switch (request) {
        .rankings_begin => |input| @import("console_store_rankings.zig").begin(owner, input),
        .rankings_chunk => |input| @import("console_store_rankings.zig").chunk(owner, input),
        .rankings_finish => |input| @import("console_store_rankings.zig").finish(owner, input),
        .rankings_prune => |now| @import("console_store_rankings.zig").prune(owner, now),
        .policy_read => |input| @import("console_policy_read.zig").read(owner, input),
        .policy_edit => |input| @import("console_policy_write.zig").edit(owner, input),
        .policies_query => |input| @import("console_store_policies.zig").query(owner, input),
        .policies_test => |input| @import("console_store_policies.zig").testRequest(owner, input),
        .events_similar => |input| @import("console_similarity.zig").query(owner, input),
        .events_query => |input| @import("console_store_events.zig").query(owner, input),
        .totp_read => |user| @import("console_store_totp.zig").read(owner, user),
        .totp_begin => |input| @import("console_store_totp.zig").begin(owner, input),
        .totp_confirm => |input| @import("console_store_totp.zig").confirm(owner, input),
        .geo_prune => |now| @import("console_store_geo.zig").prune(owner, now),
        .geo_metadata => @import("console_store_geo.zig").metadata(owner),
        .geo_begin => |input| @import("console_store_geo.zig").begin(owner, input),
        .geo_batch => |input| @import("console_store_geo.zig").batch(owner, input),
        .geo_activate => |input| @import("console_store_geo.zig").activate(owner, input),
        .geo_read => |input| @import("console_store_geo.zig").read(owner, input),
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
        .bootstrap => |input| auth.bootstrap(owner, input),
        .auth_user => |username| auth.user(owner, username.slice()),
        .session_create => |input| @import("console_store_session.zig").create(owner, input),
        .authorize => |input| blk: {
            if (input.touch) try auth.touch(owner, input.session_digest, input.now);
            break :blk try authorize(owner, input.session_digest, input.now);
        },
        .logout => |input| auth.logout(owner, input),
        .password_change => |input| auth.password(owner, input),
        else => .{ .failed = .invalid_input },
    };
}

pub fn authorize(owner: *Persistent, digest: [32]u8, now: u64) !p.StorageResult {
    const hex = std.fmt.bytesToHex(digest, .lower);
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT u.id,u.role,u.revision,s.expires,s.csrf_digest,u.must_change,u.username," ++
            "EXISTS(SELECT 1 FROM console_totp m WHERE m.user_id=u.id AND m.enabled=1) " ++
            "FROM console_sessions s JOIN console_users u ON u.id=s.user_id " ++
            "WHERE s.digest=? AND s.expires>? AND s.idle_expires>? AND s.revision=u.revision " ++
            "AND u.disabled=0 LIMIT 1",
        &.{ text(&hex), integer(now), integer(now) },
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
        .totp_enabled = try number(row[7]) != 0,
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

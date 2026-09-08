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
    const retention = @import("console_store_retention.zig");
    const geo = @import("console_store_geo.zig");
    const tokens = @import("console_store_tokens.zig");
    return switch (request) {
        .tokens_query => |input| tokens.query(owner, input),
        .tokens_create => |input| tokens.create(owner, input),
        .tokens_revoke => |input| tokens.revoke(owner, input),
        .users_query => |input| @import("console_store_users.zig").query(
            owner,
            input,
            owner.nowSeconds(),
        ),
        .users_create => |input| @import("console_store_users.zig").create(
            owner,
            input,
            owner.nowSeconds(),
        ),
        .users_change => |input| @import("console_store_users.zig").change(
            owner,
            input,
            owner.nowSeconds(),
        ),
        .retention_acquire => |input| retention.acquire(owner, input, owner.nowSeconds()),
        .retention_prune => |input| retention.prune(owner, input, owner.nowSeconds()),
        .minutes_write => |input| @import("console_store_minutes.zig").write(owner, input),
        .minutes_query => |input| @import("console_store_minutes.zig").query(owner, input),
        .minutes_prune => |now| @import("console_store_minutes.zig").prune(owner, now),
        .rankings_begin => |input| @import("console_store_rankings.zig").begin(owner, input),
        .rankings_chunk => |input| @import("console_store_rankings.zig").chunk(owner, input),
        .rankings_finish => |input| @import("console_store_rankings.zig").finish(owner, input),
        .rankings_prune => |now| @import("console_store_rankings.zig").prune(owner, now),
        .policy_read => |input| @import("console_policy_read.zig").read(owner, input),
        .policy_edit => |input| @import("console_policy_write.zig").edit(owner, input),
        .inspection_edit => |input| @import("console_inspection.zig").edit(owner, input),
        .policies_query => |input| @import("console_store_policies.zig").query(owner, input),
        .policies_test => |input| @import("console_store_policies.zig").testRequest(owner, input),
        .events_similar => |input| @import("console_similarity.zig").query(owner, input),
        .events_query => |input| @import("console_store_events.zig").query(owner, input),
        .totp_read => |user| @import("console_store_totp.zig").read(owner, user),
        .totp_begin => |input| @import("console_store_totp.zig").begin(owner, input),
        .totp_confirm => |input| @import("console_store_totp.zig").confirm(owner, input),
        .geo_prune => |now| @import("console_store_geo.zig").prune(owner, now),
        .geo_metadata => @import("console_store_geo.zig").metadata(owner),
        .geo_begin => |input| geo.begin(owner, input, owner.nowSeconds()),
        .geo_batch => |input| geo.batch(owner, input, owner.nowSeconds()),
        .geo_activate => |input| geo.activate(owner, input, owner.nowSeconds()),
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
        .authorize => |input| authorizeRequest(owner, input),
        .logout => |input| auth.logout(owner, input),
        .password_change => |input| auth.password(owner, input),
        else => .{ .failed = .invalid_input },
    };
}

fn authorizeRequest(owner: *Persistent, input: p.AuthorizationCheck) !p.StorageResult {
    const now = owner.nowSeconds();
    if (input.touch and input.kind == .session) try auth.touch(owner, input.session_digest, now);
    return @import("console_store_identity.zig").authorize(
        owner,
        input.session_digest,
        now,
        input.kind,
    );
}

pub fn authorize(owner: *Persistent, digest: [32]u8, now: u64) !p.StorageResult {
    return @import("console_store_identity.zig").authorize(owner, digest, now, null);
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

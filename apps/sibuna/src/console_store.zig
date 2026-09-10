//! Runs exclusively on Persistent's storage thread. HTTP handlers own no database handle.
const std = @import("std");
const zx = @import("zaxonlite");
const console = @import("console");
const p = console.protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");

pub fn tick(owner: *Persistent) void {
    @import("console_node_commands.zig").flush(owner) catch |err| {
        std.log.warn("console command completion pending: {t}", .{err});
    };
    @import("console_node_storage.zig").refresh(owner, owner.nowSeconds());
    @import("console_membership.zig").tick(owner);
    // Cap work per tick so console saturation cannot starve incidents and policy reload.
    for (0..16) |_| {
        const work = owner.console_mailbox.take(owner.io) orelse return;
        const result = execute(owner, work.request) catch |err| result: {
            std.log.warn("console storage operation failed: {t}", .{err});
            break :result p.StorageResult{ .failed = .unavailable };
        };
        p.releaseRequest(work.request, owner.gpa);
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
    const kiosk = @import("console_store_kiosk.zig");
    const users = @import("console_store_users.zig");
    return switch (request) {
        .subscription_read => |input| @import("console_subscription_feed.zig").read(owner, input),
        .subscription_nodes => .{ .nodes_page = try @import("console_node_read.zig")
            .memberSnapshot(owner) },
        .subscription_policy => .{ .revision = .{
            .committed = try @import("console_policy_candidate.zig").revision(owner),
            .applied = owner.version,
        } },
        .node_status => |auth| @import("console_node_read.zig").status(owner, auth),
        .node_command_read => |input| @import("console_node_read.zig").read(owner, input),
        .node_command => |input| @import("console_node_commands.zig").execute(owner, input),
        .nodes_query => |auth| @import("console_node_read.zig").members(owner, auth),
        .node_advertise => |url| @import("console_node_read.zig").advertise(owner, url),
        .kiosk_grant => |input| kiosk.grant(owner, input, owner.nowSeconds()),
        .kiosk_exchange => |input| kiosk.exchange(owner, input, owner.nowSeconds()),
        .settings_query,
        .settings_change,
        .notifications_query,
        .notifications_save,
        .notifications_remove,
        .notifications_read,
        .notifier_acquire,
        .notifications_enqueue,
        .notifications_claim,
        .notifications_record,
        .notifications_test_audit,
        => @import("console_store_notifications.zig").execute(owner, request),
        .audit_query => |input| @import("console_store_audit.zig").query(owner, input),
        .audit_read => |input| @import("console_store_audit.zig").read(owner, input),
        .tokens_query => |input| tokens.query(owner, input),
        .tokens_create => |input| tokens.create(owner, input),
        .tokens_revoke => |input| tokens.revoke(owner, input),
        .users_query => |input| users.query(owner, input, owner.nowSeconds()),
        .users_create => |input| users.create(owner, input, owner.nowSeconds()),
        .users_change => |input| users.change(owner, input, owner.nowSeconds()),
        .retention_acquire => |input| retention.acquire(owner, input, owner.nowSeconds()),
        .retention_prune => |input| retention.prune(owner, input, owner.nowSeconds()),
        .minutes_write => |input| @import("console_store_minutes.zig").write(owner, input),
        .minutes_query => |input| @import("console_store_minutes.zig").query(owner, input),
        .minutes_summary => |input| @import("console_store_minute_summary.zig")
            .query(owner, input),
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
        .geo_prune => |now| @import("console_store_geo.zig").prune(owner, now),
        .geo_metadata => @import("console_store_geo.zig").metadata(owner),
        .geo_begin => |input| geo.begin(owner, input, owner.nowSeconds()),
        .geo_batch => |input| geo.batch(owner, input, owner.nowSeconds()),
        .geo_activate => |input| geo.activate(owner, input, owner.nowSeconds()),
        .geo_read => |input| @import("console_store_geo.zig").read(owner, input),
        else => executeMore(owner, request),
    };
}

/// Templates, setup and authentication; unknown requests fail closed.
fn executeMore(owner: *Persistent, request: p.StorageRequest) !p.StorageResult {
    const pages = @import("console_store_pages.zig");
    const reputation = @import("console_reputation.zig");
    const country = @import("console_country.zig");
    const import_set = @import("console_policy_import.zig");
    const now = owner.nowSeconds();
    return switch (request) {
        .security_query => |input| @import("console_store_security.zig").query(owner, input),
        .page_read => |input| pages.read(owner, input, now),
        .page_edit => |input| pages.edit(owner, input, now),
        .policy_order => |input| @import("console_policy_order.zig").order(owner, input, now),
        .policy_replay => |input| @import("console_policy_replay.zig").replay(owner, input, now),
        .reputation_query => |input| reputation.query(owner, input, now),
        .reputation_edit => |input| reputation.edit(owner, input, now),
        .reputation_remove => |input| reputation.remove(owner, input, now),
        .country_chunk => |input| country.chunk(owner, input, now),
        .country_preflight => |input| country.preflight(owner, input, now),
        .country_apply => |input| country.apply(owner, input, now),
        .import_chunk => |input| import_set.chunk(owner, input, now),
        .import_commit => |input| import_set.commit(owner, input, now),
        .setup_status => setupStatus(owner),
        .bootstrap,
        .auth_user,
        .session_create,
        .authorize,
        .logout,
        .password_change,
        .totp_read,
        .totp_begin,
        .totp_confirm,
        => @import("console_auth_commands.zig").execute(owner, request),
        else => .{ .failed = .invalid_input },
    };
}

fn setupStatus(owner: *Persistent) !p.StorageResult {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id FROM console_users LIMIT 1",
        &.{},
    );
    defer result.deinit();
    return .{ .setup_required = result.rows.len == 0 };
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

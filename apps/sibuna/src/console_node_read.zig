//! Current-node snapshots and durable command receipts are bounded owner-only reads.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const access = @import("console_node_access.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");

pub fn status(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.check(owner, auth, false)) |reason| return .{ .failed = reason };
    const committed = try @import("console_policy_candidate.zig").revision(owner);
    const now = owner.nowSeconds();
    const uptime = std.Io.Clock.awake.now(owner.io).nanoseconds - owner.console_node.started_ns;
    var operation_id: [16]u8 = @splat(0);
    while (std.mem.allEqual(u8, &operation_id, 0)) owner.io.random(&operation_id);
    const result: p.nodes.Status = .{
        .operation_id = try p.Bytes(32).init(&std.fmt.bytesToHex(operation_id, .lower)),
        .node = owner.node_id,
        .boot = try p.Bytes(32).init(&std.fmt.bytesToHex(owner.console_node.boot, .lower)),
        .control_revision = owner.console_node.revision,
        .draining = owner.state.draining.load(.acquire),
        .connections = owner.state.connections.load(.monotonic),
        .active_ban_entries = owner.state.bans.activeCount(now),
        .committed = committed,
        .applied = owner.version,
        .observed_at = now,
        .uptime_ms = @intCast(@max(0, @divTrunc(uptime, std.time.ns_per_ms))),
        .completion_pending = owner.console_node.pending != null,
    };
    if (try access.check(owner, auth, false)) |reason| return .{ .failed = reason };
    return .{ .node_status = result };
}

/// Every replicated member row plus this member's storage snapshot. Rows are facts written
/// by their own node; a console link is rendered only when it is a plain origin.
pub fn members(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.check(owner, auth, false)) |reason| return .{ .failed = reason };
    var page: p.nodes.Page = .{
        .self = owner.node_id,
        .committed = try @import("console_policy_candidate.zig").revision(owner),
        .storage = owner.console_node.storage,
    };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT node,address,console_url,version,boot,first_seen,last_seen," ++
            "applied_revision,control_revision,applied_slot,decided_slot,draining " ++
            "FROM console_nodes ORDER BY node LIMIT 9",
        &.{},
    );
    defer rows.deinit();
    for (rows.rows) |row| {
        const url = row[2] orelse "";
        page.members[page.count] = .{
            .node = @intCast(try util.number(row[0])),
            .address = try p.Bytes(p.nodes.max_address).init(row[1] orelse ""),
            .console_url = try p.Bytes(p.nodes.max_url).init(
                if (p.nodes.safeUrl(url)) url else "",
            ),
            .version = try p.Bytes(32).init(row[3] orelse ""),
            .boot = try p.Bytes(32).init(row[4] orelse ""),
            .first_seen = try util.number(row[5]),
            .last_seen = try util.number(row[6]),
            .applied_revision = try util.number(row[7]),
            .control_revision = try util.number(row[8]),
            .applied_slot = try util.number(row[9]),
            .decided_slot = try util.number(row[10]),
            .draining = (try util.number(row[11])) != 0,
        };
        page.count += 1;
    }
    if (try access.check(owner, auth, false)) |reason| return .{ .failed = reason };
    return .{ .nodes_page = page };
}

/// The console's advertised origin reaches the owner thread through the mailbox so the
/// membership writer never reads a field another thread may still be initializing.
pub fn advertise(owner: *Persistent, url: p.Bytes(p.nodes.max_url)) !p.StorageResult {
    if (url.len != 0 and !p.nodes.safeUrl(url.slice())) return .{ .failed = .invalid_input };
    owner.console_node.advertise = url;
    owner.console_node.announce = true;
    return .command_recorded;
}

pub fn read(owner: *Persistent, input: p.nodes.Read) !p.StorageResult {
    if (try access.check(owner, input.auth, false)) |reason| return .{ .failed = reason };
    const result = try load(owner, input.id) orelse return .{ .failed = .conflict };
    if (try access.check(owner, input.auth, false)) |reason| return .{ .failed = reason };
    return .{ .node_receipt = result };
}

pub fn load(owner: *Persistent, id: [16]u8) !?p.nodes.Receipt {
    const hex = std.fmt.bytesToHex(id, .lower);
    if (owner.console_node.pending) |pending|
        if (std.mem.eql(u8, pending.id.slice(), &hex)) return pending;
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,node,boot,kind,expected_revision,state,requested_at,completed_at," ++
            "applied_revision,cleared_entries FROM console_commands WHERE id=? AND node=? LIMIT 1",
        &.{ util.text(&hex), util.integer(owner.node_id) },
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    const row = rows.rows[0];
    const state = std.meta.stringToEnum(p.nodes.State, row[5].?) orelse
        return error.InvalidStoredValue;
    return .{
        .id = try p.Bytes(32).init(row[0].?),
        .node = @intCast(try util.number(row[1])),
        .boot = try p.Bytes(32).init(row[2].?),
        .kind = std.meta.stringToEnum(p.nodes.Kind, row[3].?) orelse
            return error.InvalidStoredValue,
        .expected_revision = try util.number(row[4]),
        // An intent left without a completion cannot establish that an effect occurred.
        .state = if (state == .intent) .uncertain else state,
        .requested_at = try util.number(row[6]),
        .completed_at = if (row[7] != null) try util.number(row[7]) else null,
        .applied_revision = if (row[8] != null) try util.number(row[8]) else null,
        .cleared_entries = if (row[9] != null) @intCast(try util.number(row[9])) else null,
        .completion_persisted = state != .intent,
    };
}

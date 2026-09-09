//! Rule ordering: one revision-checked mutation moves a managed rule past its neighbour in
//! `(priority, name, id)` order. Equal priorities are nudged by one; otherwise the two
//! priorities swap. Both rules gain a history row and the audit names the moved rule.
const std = @import("std");
const p = @import("console").protocol;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const auth = @import("console_policy_authorization.zig");
const Row = struct { id: p.Bytes(128), name: p.Bytes(256), priority: i32 };

pub fn order(owner: *Persistent, input: p.workflows.Order, now: u64) !p.StorageResult {
    try p.validate(.{ .policy_order = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    if (try candidates.revision(owner) != input.expected_revision)
        return .{ .failed = .conflict };
    const moving = try lookup(owner, input.id.slice()) orelse
        return .{ .failed = .invalid_input };
    const other = try neighbour(owner, moving, input.direction) orelse
        return .{ .failed = .invalid_input };
    var priority = other.priority;
    var other_priority = moving.priority;
    if (moving.priority == other.priority) {
        if (input.direction == .up) priority -|= 1 else priority +|= 1;
        other_priority = other.priority;
    }
    const document = try candidates.documentWithPriority(
        owner,
        moving.id.slice(),
        priority,
    ) orelse return .{ .failed = .conflict };
    const other_document = try candidates.documentWithPriority(
        owner,
        other.id.slice(),
        other_priority,
    ) orelse return .{ .failed = .conflict };
    const credentials = auth.Credentials.fromAuth(input.auth, now);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_policy_order_stage SELECT 1,u.id," ++ auth.role ++
            ",?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &([_]zx.Value{
            util.integer(now),
            util.integer(input.expected_revision),
            util.text(moving.id.slice()),
            .{ .integer = priority },
            util.text(document.slice()),
            util.text(other.id.slice()),
            .{ .integer = other_priority },
            util.text(other_document.slice()),
        } ++ credentials.values() ++ [_]zx.Value{util.integer(input.expected_revision)}),
    );
    if (changes == 0) {
        if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

fn lookup(owner: *Persistent, id: []const u8) !?Row {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,name,priority FROM policies WHERE id=? LIMIT 1",
        &.{util.text(id)},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    return try row(rows.rows[0]);
}

fn neighbour(owner: *Persistent, moving: Row, direction: p.workflows.Direction) !?Row {
    const sql = switch (direction) {
        .up => "SELECT id,name,priority FROM policies WHERE priority<? OR (priority=? AND " ++
            "(name<? OR (name=? AND id<?))) ORDER BY priority DESC,name DESC,id DESC LIMIT 1",
        .down => "SELECT id,name,priority FROM policies WHERE priority>? OR (priority=? AND " ++
            "(name>? OR (name=? AND id>?))) ORDER BY priority,name,id LIMIT 1",
    };
    var rows = try db.query(owner.db, owner.gpa, sql, &.{
        .{ .integer = moving.priority },
        .{ .integer = moving.priority },
        util.text(moving.name.slice()),
        util.text(moving.name.slice()),
        util.text(moving.id.slice()),
    });
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    return try row(rows.rows[0]);
}

fn row(cells: []const ?[]const u8) !Row {
    return .{
        .id = try p.Bytes(128).init(cells[0] orelse return error.InvalidStoredPolicy),
        .name = try p.Bytes(256).init(cells[1] orelse return error.InvalidStoredPolicy),
        .priority = try std.fmt.parseInt(
            i32,
            cells[2] orelse return error.InvalidStoredPolicy,
            10,
        ),
    };
}

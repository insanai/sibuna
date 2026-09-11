//! Prepared operations used only by the Persistent owner on its storage thread.
const std = @import("std");
const zx = @import("zaxonlite");
const Db = @import("database.zig").Db;
const remote = @import("console_database_remote.zig");
const clustered = @import("build_options").cluster;

/// Every statement has a virtual-machine step budget so the storage owner never stalls.
/// Point reads and pages keep this fixed light budget; a period aggregate over retained
/// incidents may scan a day of rows and receives the configured, still bounded, allowance
/// (`--console-query-steps`) before it fails as unavailable.
pub const light_steps: u64 = 100_000;

pub fn query(
    db: Db,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
) !zx.QueryResult {
    return queryWithSteps(db, gpa, sql, values, light_steps);
}

/// The clustered facade forwards to the local node's RPC, whose own server-side budget
/// (ten million steps in Zaxonlite 0.6) bounds every statement instead.
pub fn queryWithSteps(
    db: Db,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
    steps: u64,
) !zx.QueryResult {
    return switch (db) {
        .node => |node| node.queryPreparedWithLimits(gpa, sql, values, .{
            .max_rows = 100,
            .max_bytes = 65536,
            .max_vm_steps = steps,
        }),
        .embedded => |embedded| if (clustered)
            remote.query(embedded, gpa, sql, values)
        else
            unreachable,
    };
}

pub fn exec(db: Db, gpa: std.mem.Allocator, sql: []const u8, values: []const zx.Value) !i64 {
    return switch (db) {
        .node => |node| (try node.execPrepared(sql, values)).changes,
        .embedded => |embedded| if (clustered)
            remote.exec(embedded, gpa, sql, values)
        else
            unreachable,
    };
}

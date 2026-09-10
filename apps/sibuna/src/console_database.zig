//! Prepared operations used only by the Persistent owner on its storage thread.
const std = @import("std");
const zx = @import("zaxonlite");
const Db = @import("database.zig").Db;
const remote = @import("console_database_remote.zig");
const clustered = @import("build_options").cluster;

/// Every statement has a virtual-machine step budget so the storage owner never stalls.
/// Point reads and pages stay light; a period aggregate over retained incidents may scan a
/// day of rows and receives a larger, still fixed, allowance before it fails as unavailable.
pub const Weight = enum {
    light,
    heavy,

    fn steps(self: Weight) u64 {
        return switch (self) {
            .light => 100_000,
            .heavy => 4_000_000,
        };
    }
};

pub fn query(
    db: Db,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
) !zx.QueryResult {
    return queryWeighted(db, gpa, sql, values, .light);
}

pub fn queryWeighted(
    db: Db,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
    weight: Weight,
) !zx.QueryResult {
    return switch (db) {
        .node => |node| node.queryPreparedWithLimits(gpa, sql, values, .{
            .max_rows = 100,
            .max_bytes = 65536,
            .max_vm_steps = weight.steps(),
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

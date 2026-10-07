//! Persistent alone invokes migrations. Zaxonlite wraps each SQL batch in a replicated
//! transaction; never issue nested BEGIN or expose a partially upgraded schema marker.
const std = @import("std");
const console = @import("console");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");

fn current(owner: *Persistent) !u64 {
    var tables = try db.query(
        owner.db,
        owner.gpa,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='console_schema' LIMIT 1",
        &.{},
    );
    defer tables.deinit();
    if (tables.rows.len == 0) return 0;
    var versions = try db.query(
        owner.db,
        owner.gpa,
        "SELECT version FROM console_schema LIMIT 2",
        &.{},
    );
    defer versions.deinit();
    if (versions.rows.len != 1) return error.UnsupportedConsoleSchema;
    return std.fmt.parseInt(u64, versions.rows[0][0] orelse
        return error.UnsupportedConsoleSchema, 10);
}

pub fn run(owner: *Persistent) !void {
    var version = try current(owner);
    if (version > console.schema.version) return error.UnsupportedConsoleSchema;
    if (version == 0) {
        try owner.db.exec(owner.gpa, console.schema.sql);
        version = try current(owner);
    }
    inline for (console.schema.migrations, 2..) |sql, target| {
        if (version == target - 1) {
            version = try advance(owner, target, sql);
        }
    }
    if (version != console.schema.version) return error.UnsupportedConsoleSchema;
    owner.console_initialized = true;
}

/// The earlier read is advisory: another owner can upgrade before our write reaches the
/// leader. Check the exact predecessor inside the captured transaction, before any DDL.
/// The temporary guard creates no persistent schema or wire-format change. Both success
/// and rollback remove it before the connection can serve another owner operation.
pub fn advance(owner: *Persistent, comptime target: u64, comptime sql: []const u8) !u64 {
    std.debug.assert(target >= 2 and target <= console.schema.version);
    const guard = std.fmt.comptimePrint(
        "CREATE TEMP TABLE sibuna_console_migration_guard(" ++
            "version INTEGER NOT NULL CHECK(version={d}));" ++
            "INSERT INTO temp.sibuna_console_migration_guard " ++
            "SELECT CASE WHEN COUNT(*)=1 THEN MIN(version) END FROM main.console_schema;" ++
            "DROP TABLE temp.sibuna_console_migration_guard;",
        .{target - 1},
    );
    owner.db.exec(owner.gpa, guard ++ sql) catch |err| {
        const observed = try current(owner);
        if (observed > console.schema.version) return error.UnsupportedConsoleSchema;
        if (observed < target) return err;
        // A competing owner already committed this migration, or a later one. The
        // rejected transaction changed nothing; continue from its authoritative marker.
        return observed;
    };
    return current(owner);
}

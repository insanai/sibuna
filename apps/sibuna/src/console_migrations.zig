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
    const migrations = .{
        console.schema.auth_v2,
        console.schema.bootstrap_v3,
        console.schema.rotation_v4,
        console.schema.events_v5,
        console.schema.evidence_v6,
        console.schema.campaign_v7,
        console.schema.policy_v8,
        console.schema.rankings_v9,
    };
    inline for (migrations, 2..) |sql, target| {
        if (version == target - 1) {
            owner.db.exec(owner.gpa, sql) catch |err| {
                // Another node may have committed this upgrade after our read.
                const observed = try current(owner);
                if (observed < target or observed > console.schema.version) return err;
            };
            version = try current(owner);
        }
    }
    if (version != console.schema.version) return error.UnsupportedConsoleSchema;
    owner.console_initialized = true;
}

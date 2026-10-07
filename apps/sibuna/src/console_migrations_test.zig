//! Competing startup owners must never replay stale DDL or regress a committed marker.
const std = @import("std");
const t = std.testing;
const console = @import("console");
const db = @import("console_database.zig");
const migrations = @import("console_migrations.zig");
const Fixture = @import("console_store_test.zig").Fixture;

fn open(tmp: *std.testing.TmpDir) !*Fixture {
    var path: [160]u8 = undefined;
    return Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/migration-race",
        .{tmp.sub_path},
    ));
}

fn scalar(fx: *Fixture, sql: []const u8) !u64 {
    var rows = try db.query(fx.owner.db, t.allocator, sql, &.{});
    defer rows.deinit();
    try t.expectEqual(@as(usize, 1), rows.rows.len);
    return std.fmt.parseInt(u64, rows.rows[0][0].?, 10);
}

fn cleanGuard(fx: *Fixture) !void {
    // readLease must reuse this live writer. A fresh read connection would hide its
    // temporary objects and make the ownership assertion meaningless.
    try t.expect(fx.owner.db == .node);
    try t.expect(fx.owner.db.node.db_open);
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT COUNT(*) FROM sqlite_temp_master " ++
        "WHERE name='sibuna_console_migration_guard'"));
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT COUNT(*) FROM sqlite_master " ++
        "WHERE name='sibuna_console_migration_guard'"));
}

fn seedMinute(fx: *Fixture) !void {
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO console_minutes VALUES(1,'00000000000000000000000000000000'," ++
            "1,7,7000,8000,1,lower(hex(zeroblob(176))))",
    );
}

fn preservedMinute(fx: *Fixture) !void {
    const query = "SELECT COUNT(*) FROM console_minutes WHERE node=1 AND " ++
        "boot='00000000000000000000000000000000' AND epoch=1 AND minute=7 AND " ++
        "start_ms=7000 AND end_ms=8000 AND sealed=1 AND payload=lower(hex(zeroblob(176)))";
    try t.expectEqual(@as(u64, 1), try scalar(fx, query));
}

test "console migration stale index and table rebuild preserve the committed schema and data" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const fx = try open(&tmp);
    defer fx.close();
    try migrations.run(fx.owner);
    try seedMinute(fx);
    // Migration 5 has idempotent index DDL. Migration 37 rebuilds a table through a
    // temporary name which no longer exists. Both formerly succeeded on version 45.
    try t.expectEqual(@as(u64, console.schema.version), try migrations.advance(
        fx.owner,
        5,
        console.schema.events_v5,
    ));
    try t.expectEqual(@as(u64, console.schema.version), try migrations.advance(
        fx.owner,
        37,
        console.schema.migrations[35],
    ));
    try preservedMinute(fx);
    try cleanGuard(fx);
    const rebuilt = "SELECT COUNT(*) FROM sqlite_master WHERE name='console_minutes_v37'";
    try t.expectEqual(@as(u64, 0), try scalar(fx, rebuilt));
}

test "console migration every stale catalog entry is rejected without persistent effects" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    {
        const fx = try open(&tmp);
        defer fx.close();
        try migrations.run(fx.owner);
        try seedMinute(fx);
        inline for (console.schema.migrations, 2..) |sql, target| {
            try t.expectEqual(
                @as(u64, console.schema.version),
                try migrations.advance(fx.owner, target, sql),
            );
            try cleanGuard(fx);
        }
        try preservedMinute(fx);
    }
    // Reopen the actual captured store, not a second SQLite connection. Chosen data
    // and the marker survive recovery; rejected guards added no persistent objects.
    const restored = try open(&tmp);
    defer restored.close();
    try migrations.run(restored.owner);
    try t.expectEqual(
        @as(u64, console.schema.version),
        try scalar(restored, "SELECT version FROM console_schema"),
    );
    try preservedMinute(restored);
    try t.expectEqual(@as(u64, console.schema.version), try migrations.advance(
        restored.owner,
        5,
        console.schema.events_v5,
    ));
    try cleanGuard(restored);
}

test "console migration valid predecessor advances once and stale retry adopts the result" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const fx = try open(&tmp);
    defer fx.close();
    try fx.owner.db.exec(t.allocator, console.schema.sql);
    inline for (console.schema.migrations[0..4], 2..) |sql, target| {
        try t.expectEqual(@as(u64, target), try migrations.advance(fx.owner, target, sql));
        try cleanGuard(fx);
    }
    try t.expectEqual(@as(u64, 5), try migrations.advance(fx.owner, 5, console.schema.events_v5));
    try cleanGuard(fx);
    try migrations.run(fx.owner);
    try t.expect(fx.owner.console_initialized);
    try t.expectEqual(
        @as(u64, console.schema.version),
        try scalar(fx, "SELECT version FROM console_schema"),
    );
}

test "console migration failure rolls back all body effects and temporary ownership" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const fx = try open(&tmp);
    defer fx.close();
    try fx.owner.db.exec(t.allocator, console.schema.sql);
    const failed = "CREATE TABLE console_migration_fixture(value INTEGER);" ++
        "INSERT INTO console_migration_fixture VALUES(7);" ++
        "INSERT INTO nonexistent_migration_target VALUES(8);";
    try t.expectError(error.SqliteError, migrations.advance(fx.owner, 2, failed));
    try t.expectEqual(@as(u64, 1), try scalar(fx, "SELECT version FROM console_schema"));
    const absent = "SELECT COUNT(*) FROM sqlite_master WHERE name='console_migration_fixture'";
    try t.expectEqual(@as(u64, 0), try scalar(fx, absent));
    try cleanGuard(fx);
    try t.expectEqual(@as(u64, 2), try migrations.advance(fx.owner, 2, console.schema.auth_v2));
    try cleanGuard(fx);
}

test "console migration malformed markers fail closed without DDL or leaked guards" {
    inline for (.{
        "",
        "INSERT INTO console_schema VALUES(NULL);",
        "INSERT INTO console_schema VALUES(44),(45);",
    }) |rows| {
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        const fx = try open(&tmp);
        defer fx.close();
        try migrations.run(fx.owner);
        try fx.owner.db.exec(t.allocator, "DROP TABLE console_schema;" ++
            "CREATE TABLE console_schema(version INTEGER);" ++ rows);
        const count = try scalar(fx, "SELECT COUNT(*) FROM console_schema");
        const forbidden = "CREATE TABLE console_migration_fixture(value INTEGER);";
        try t.expectError(
            error.UnsupportedConsoleSchema,
            migrations.advance(fx.owner, 45, forbidden),
        );
        try t.expectEqual(count, try scalar(fx, "SELECT COUNT(*) FROM console_schema"));
        const absent = "SELECT COUNT(*) FROM sqlite_master WHERE name='console_migration_fixture'";
        try t.expectEqual(@as(u64, 0), try scalar(fx, absent));
        try cleanGuard(fx);
    }
}

test "console migration future marker after advisory read remains explicitly incompatible" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const fx = try open(&tmp);
    defer fx.close();
    try migrations.run(fx.owner);
    const future = console.schema.version + 1;
    const changed = std.fmt.comptimePrint("DROP TABLE console_schema;" ++
        "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version={d}));" ++
        "INSERT INTO console_schema VALUES({d});", .{ future, future });
    try fx.owner.db.exec(t.allocator, changed);
    try t.expectError(
        error.UnsupportedConsoleSchema,
        migrations.advance(fx.owner, 37, console.schema.migrations[35]),
    );
    try t.expectEqual(@as(u64, future), try scalar(fx, "SELECT version FROM console_schema"));
    try cleanGuard(fx);
}

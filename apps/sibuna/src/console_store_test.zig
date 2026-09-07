const std = @import("std");
const core = @import("core");
const policy = @import("policy");
const server = @import("server.zig");
const Persistent = @import("persistent.zig").Persistent;
const p = @import("console").protocol;
const db = @import("console_database.zig");
const t = std.testing;

const Fixture = struct {
    engine: policy.Engine,
    slot: server.EngineSlot,
    state: server.AppState,
    owner: *Persistent,

    fn open(path: []const u8) !*Fixture {
        const self = try t.allocator.create(Fixture);
        errdefer t.allocator.destroy(self);
        var cfg = core.Config.default();
        cfg.data_dir = path;
        self.engine.initInPlace(cfg.default_difficulty);
        self.slot = .{ .engine = &self.engine };
        self.state.init(cfg, &self.slot, &(@as([32]u8, @splat(1))));
        self.owner = try Persistent.open(t.allocator, t.io, cfg, &self.state, null);
        return self;
    }

    fn close(self: *Fixture) void {
        self.owner.stop();
        t.allocator.destroy(self);
    }

    fn run(self: *Fixture, request: p.StorageRequest) !p.StorageResult {
        const ticket = try self.owner.console_mailbox.submit(t.io, request, .urgent);
        try self.owner.tick();
        return (try self.owner.console_mailbox.poll(t.io, ticket)).?;
    }
};

test "console storage ticks bootstrap, audit, authenticate and revoke atomically" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try t.expect((try fx.run(.setup_status)).setup_required);
    const bootstrap: p.StorageRequest = .{ .bootstrap = .{
        .username = try p.Bytes(64).init("admin' OR 1=1 --"),
        .password_hash = try p.Bytes(255).init("test-only-opaque-hash"),
        .now = 100,
    } };
    try t.expect((try fx.run(bootstrap)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(bootstrap)).failed);
    try t.expect(!(try fx.run(.setup_status)).setup_required);
    const user = (try fx.run(.{ .auth_user = bootstrap.bootstrap.username })).auth_user;
    try t.expectEqual(p.Role.admin, user.role);
    const session: p.StorageRequest = .{ .session_create = .{
        .user = user.id,
        .revision = user.revision,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 100,
        .expires = 200,
    } };
    try t.expect((try fx.run(session)) == .command_recorded);
    const principal = (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 101,
    } })).authorized;
    try t.expectEqual(user.id, principal.actor);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 200,
    } })).failed);
    try t.expect((try fx.run(.{ .password_change = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("replacement-test-hash"),
        .now = 110,
    } })) == .command_recorded);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 111,
    } })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(session)).failed);
    var audit = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT action FROM console_audit ORDER BY id LIMIT 100",
        &.{},
    );
    defer audit.deinit();
    try t.expectEqual(@as(usize, 3), audit.rows.len);
    fx.owner.console_initialized = false;
    try t.expect(!(try fx.run(.setup_status)).setup_required);
}

test "console SQL VM budget interrupts a recursive query" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console",
        .{tmp.sub_path},
    ));
    defer fx.close();
    // LIMIT alone does not bound aggregation work. The VM budget must stop this query.
    if (db.query(
        fx.owner.db,
        t.allocator,
        "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<10000000) " ++
            "SELECT SUM(x) FROM n LIMIT 1",
        &.{},
    )) |result| {
        var owned = result;
        owned.deinit();
        return error.ExpectedQueryInterruption;
    } else |_| {}
}

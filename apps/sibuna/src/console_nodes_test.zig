const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");
const commands = @import("console_node_commands.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn setup(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn operation(fx: *Fixture, byte: u8, kind: p.nodes.Kind) p.nodes.Command {
    return .{
        .auth = auth,
        .id = @splat(byte),
        .boot = fx.owner.console_node.boot,
        .node = fx.owner.node_id,
        .expected_revision = fx.owner.console_node.revision,
        .kind = kind,
        .expires = fx.owner.nowSeconds() + p.nodes.command_seconds,
    };
}

fn apply(fx: *Fixture, input: p.nodes.Command) !p.nodes.Receipt {
    const result = try fx.run(.{ .node_command = input });
    try t.expect(result == .node_receipt);
    return result.node_receipt;
}

fn rejectCompletion(fx: *Fixture) !void {
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_completion BEFORE UPDATE ON console_commands " ++
            "BEGIN SELECT RAISE(ABORT,'test completion failure'); END;",
    );
}

test "local drain commands fence boot and revision and retain durable idempotent receipts" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/drain", .{tmp.sub_path}));
    defer fx.close();
    const input = operation(fx, 1, .drain);
    const receipt = try apply(fx, input);
    try t.expect(receipt.state == .applied and receipt.completion_persisted);
    try t.expectEqual(@as(?u64, 1), receipt.applied_revision);
    try t.expect(fx.state.draining.load(.acquire));
    try t.expectEqualDeep(receipt, try apply(fx, input));
    var stale = operation(fx, 2, .@"resume");
    stale.expected_revision = 0;
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .node_command = stale })).failed);
    stale.expected_revision = 1;
    stale.boot = @splat(0x77);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .node_command = stale })).failed);
    stale = input;
    stale.kind = .@"resume";
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .node_command = stale })).failed);
    _ = try apply(fx, operation(fx, 3, .@"resume"));
    const status = (try fx.run(.{ .node_status = auth })).node_status;
    try t.expect(!status.draining and status.control_revision == 2 and !status.completion_pending);
}

test "a failed completion retains the clear result and cannot clear a later ban on retry" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/clear", .{tmp.sub_path}));
    defer fx.close();
    const now = fx.owner.nowSeconds();
    fx.state.bans.ban("8.8.8.8", now + 1000, now);
    try rejectCompletion(fx);
    const input = operation(fx, 1, .clear_local_bans);
    var receipt = try apply(fx, input);
    try t.expect(receipt.state == .applied and !receipt.completion_persisted);
    try t.expectEqual(@as(?u32, 1), receipt.cleared_entries);
    try t.expect(!fx.state.bans.isBanned("8.8.8.8", now));
    fx.state.bans.ban("8.8.8.8", now + 2000, now);
    try t.expectEqualDeep(receipt, try apply(fx, input));
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{
        .node_command = operation(fx, 2, .drain),
    })).failed);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_completion");
    receipt = try apply(fx, input);
    try t.expect(receipt.completion_persisted);
    try t.expect(fx.state.bans.isBanned("8.8.8.8", now));
    // Replaying the identical completion models an acknowledgment lost after commit.
    receipt.completion_persisted = false;
    fx.owner.console_node.pending = receipt;
    try commands.flush(fx.owner);
    try t.expect(fx.owner.console_node.pending == null);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT COUNT(*) FROM console_audit WHERE action LIKE 'node.command.%'",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("2", rows.rows[0][0].?);
}

test "intent failure and revocation during its commit cannot cause a local effect" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/intent",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_intent BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='node.command.intent' " ++
            "BEGIN SELECT RAISE(ABORT,'test intent failure'); END;",
    );
    const input = operation(fx, 1, .drain);
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .node_command = input })).failed);
    try t.expect(!fx.state.draining.load(.acquire));
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_intent");
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER revoke_after_intent AFTER INSERT ON console_commands " ++
            "BEGIN UPDATE console_sessions SET idle_expires=0; END;",
    );
    const receipt = try apply(fx, input);
    try t.expect(receipt.state == .rejected and receipt.completion_persisted);
    try t.expect(!fx.state.draining.load(.acquire));
    try t.expectEqual(@as(u64, 0), fx.owner.console_node.revision);
}

test "unresolved old-boot intents stay uncertain across restart and are never replayed" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/restart", .{tmp.sub_path});
    var input: p.nodes.Command = undefined;
    {
        const fx = try setup(path);
        defer fx.close();
        try rejectCompletion(fx);
        input = operation(fx, 1, .drain);
        try t.expect((try apply(fx, input)).state == .applied);
        try t.expect(fx.state.draining.load(.acquire));
    }
    const fx = try Fixture.open(path);
    defer fx.close();
    try t.expect(!std.mem.eql(u8, &input.boot, &fx.owner.console_node.boot));
    const receipt = try apply(fx, input);
    try t.expect(receipt.state == .uncertain and !receipt.completion_persisted);
    try t.expect(receipt.completed_at == null and receipt.applied_revision == null);
    try t.expect(!fx.state.draining.load(.acquire));
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_completion");
    try t.expect((try apply(fx, operation(fx, 2, .drain))).completion_persisted);
}

test "queued commands recheck expiry and viewers cannot control the local node" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/access",
        .{tmp.sub_path},
    ));
    defer fx.close();
    var input = operation(fx, 1, .drain);
    input.auth.csrf_digest = @splat(9);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .node_command = input })).failed);
    input.auth = auth;
    input.auth.require_totp = true;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .node_command = input })).failed);
    input.auth = auth;
    input.expires = fx.owner.nowSeconds() - 1;
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(.{ .node_command = input })).failed);
    input.expires = fx.owner.nowSeconds() + p.nodes.command_seconds;
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .node_command = input }, .urgent);
    try fx.owner.db.exec(t.allocator, "UPDATE console_sessions SET idle_expires=0");
    try fx.owner.tick();
    const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(p.Failure.unauthorized, result.failed);
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET role='viewer'");
    try fixture.policySession(fx);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .node_command = input })).failed);
    try t.expect((try fx.run(.{ .node_status = auth })) == .node_status);
    try t.expect(!fx.state.draining.load(.acquire));
}

test "command capacity fails closed and expired receipts prune only a bounded batch" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/command-capacity",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4096) " ++
            "INSERT INTO console_commands(id,node,boot,actor,actor_role,kind," ++
            "expected_revision,requested_at) SELECT printf('%032x',x),1," ++
            "'11111111111111111111111111111111',1,'admin','drain',0,? FROM n",
        &.{.{ .integer = @intCast(fx.owner.nowSeconds()) }},
    );
    const input = operation(fx, 0x77, .drain);
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .node_command = input })).failed);
    try t.expect(!fx.state.draining.load(.acquire));
    try fx.owner.db.exec(t.allocator, "UPDATE console_commands SET requested_at=0");
    try t.expect((try apply(fx, input)).completion_persisted);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT COUNT(*) FROM console_commands)," ++
            "(SELECT COUNT(*) FROM console_audit WHERE action LIKE 'node.command.%')",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("4081", rows.rows[0][0].?);
    try t.expectEqualStrings("4098", rows.rows[0][1].?);
}

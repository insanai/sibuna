const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const m = p.crs_management;
const crs = @import("crs");
const fixtures = @import("console_store_test.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

const Fixture = struct {
    temporary: t.TmpDir,
    storage: *fixtures.Fixture,

    fn open() !Fixture {
        var temporary = t.tmpDir(.{});
        errdefer temporary.cleanup();
        var name: [160]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, ".zig-cache/tmp/{s}/crs-management", .{
            temporary.sub_path,
        });
        const storage = try fixtures.Fixture.open(path);
        errdefer storage.close();
        try fixtures.policySession(storage);
        return .{ .temporary = temporary, .storage = storage };
    }

    fn close(self: *Fixture) void {
        self.storage.close();
        self.temporary.cleanup();
    }

    fn run(self: *Fixture, request: m.Request) !p.StorageResult {
        return self.storage.run(.{ .crs_management = request });
    }

    fn begin(self: *Fixture, number: u128, revision: u64, clone: ?m.Id) !p.StorageResult {
        return self.run(.{ .begin = .{
            .auth = auth,
            .id = id(number),
            .kind = if (clone == null) .check else .rollback,
            .expected_revision = revision,
            .expires = self.storage.owner.nowSeconds() + 120,
            .clone = clone,
        } });
    }

    fn prepare(self: *Fixture, number: u128, revision: u64, clone: ?m.Id) !void {
        try t.expect((try self.begin(number, revision, clone)).crs_job != null);
        if (clone == null) {
            _ = try self.run(.{ .chunk = .{
                .auth = auth,
                .id = id(number),
                .file = .archive,
                .ordinal = 0,
                .bytes = try p.Bytes(m.chunk_bytes).init("abc"),
            } });
            _ = try self.run(.{ .chunk = .{
                .auth = auth,
                .id = id(number),
                .file = .signature,
                .ordinal = 0,
                .bytes = try p.Bytes(m.chunk_bytes).init("de"),
            } });
        }
        try t.expectEqual(
            m.State.verified,
            (try self.run(.{ .verify = .{
                .auth = auth,
                .id = id(number),
                .manifest = manifest(revision),
            } })).crs_job.?.state,
        );
    }

    fn select(self: *Fixture, number: u128, revision: u64) !p.StorageResult {
        return self.run(.{ .select = .{
            .auth = auth,
            .id = id(number),
            .expected_revision = revision,
        } });
    }

    fn count(self: *Fixture, sql: []const u8) !u64 {
        var rows = try self.storage.owner.db.query(t.allocator, sql);
        defer rows.deinit();
        return std.fmt.parseInt(u64, rows.rows[0][0].?, 10);
    }
};

fn id(number: u128) m.Id {
    var value: [32]u8 = undefined;
    const encoded = std.fmt.bufPrint(&value, "{x:0>32}", .{number}) catch unreachable;
    return m.Id.init(encoded) catch unreachable;
}

// These tests exercise the storage contract's native verification witness, not
// authenticity. Only the preparation service can produce that operation. Signed
// loading is qualified separately with the unmodified CRS archive and signature.
fn manifest(previous: u64) m.Manifest {
    const value: crs.artifact_manifest.Manifest = .{
        .revision = previous + 1,
        .previous_revision = previous,
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .archive_digest = @splat(7),
        .operator_digest = @splat(8),
        .signed_at = 1,
        .archive_bytes = 3,
        .signature_bytes = 2,
        .configuration_bytes = 0,
        .conditions = 1,
        .compiled_peak = 1,
        .activation = .{ .mode = .off, .profile = .headers },
        .thresholds = .{},
        .limits = .{},
        .slots = 1,
        .reservation = 128 * 1024 * 1024,
    };
    var bytes: [512]u8 = undefined;
    return m.Manifest.init(value.encode(&bytes) catch unreachable) catch unreachable;
}

fn nativePackage(source: crs.artifact_manifest.Manifest) !*crs.release_package.Package {
    const package = try t.allocator.create(crs.release_package.Package);
    errdefer t.allocator.destroy(package);
    package.* = .{
        .allocator = t.allocator,
        .bounded = .{ .parent = t.allocator, .limit = crs.release_package.compiled_capacity },
        .program = undefined,
        .receipt = .{
            .digest = source.archive_digest,
            .created = source.signed_at,
            .archive_bytes = source.archive_bytes,
        },
        .operator_digest = source.operator_digest,
        .version = source.version,
    };
    var compiler = crs.compiler.Compiler.init(t.allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("test.conf", "SecAction \"id:1,setvar:tx.example=1\"");
    var plan = try compiler.finish();
    defer plan.deinit();
    package.program = try crs.rule_program.compile(package.bounded.allocator(), &plan, &.{}, .{});
    return package;
}

fn nativeGeneration(source: crs.artifact_manifest.Manifest) !*crs.generation.Generation {
    const prepared = try nativePackage(source);
    errdefer prepared.deinit();
    return crs.generation.Generation.create(
        t.allocator,
        prepared,
        try source.options(.request_response),
    );
}

test "CRS management selects atomically and survives lost replies and migration replay" {
    var fx = try Fixture.open();
    defer fx.close();
    try fx.prepare(1, 0, null);
    try fx.storage.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_crs_selection BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='crs.select' BEGIN SELECT RAISE(ABORT,'injected'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.select(1, 0)).failed);
    try t.expectEqual(@as(u64, 0), (try fx.run(.selected)).crs_selection.revision);
    try t.expectEqual(
        m.State.verified,
        (try fx.run(.{ .job = .{
            .auth = auth,
            .id = id(1),
        } })).crs_job.?.state,
    );
    try fx.storage.owner.db.exec(t.allocator, "DROP TRIGGER reject_crs_selection");
    _ = try fx.select(1, 0);
    const retried = (try fx.select(1, 0)).crs_selection;
    try t.expectEqual(@as(u64, 1), retried.revision);
    try t.expectEqualDeep(id(1), retried.current.?.id);
    try t.expectEqual(
        @as(u64, 1),
        try fx.count(
            "SELECT COUNT(*) FROM console_audit WHERE action='crs.select'",
        ),
    );
    try @import("console_migrations.zig").run(fx.storage.owner);
    try t.expectEqual(@as(u64, 1), (try fx.run(.selected)).crs_selection.revision);
    const jobs = (try fx.run(.{ .jobs = auth })).crs_jobs;
    try t.expectEqual(@as(usize, 1), jobs.count);
    try t.expectEqualDeep(id(1), jobs.rows[0].?.id);
    try t.expectEqual(p.Failure.conflict, (try fx.begin(2, 0, null)).failed);
    try fx.prepare(2, 1, null);
    _ = try fx.select(2, 1);
    try t.expectEqual(p.Failure.conflict, (try fx.select(1, 0)).failed);
}

test "CRS management owns chunks and rejects gaps changed retries and incomplete witnesses" {
    var fx = try Fixture.open();
    defer fx.close();
    _ = try fx.begin(1, 0, null);
    var input: m.Chunk = .{
        .auth = auth,
        .id = id(1),
        .file = .archive,
        .ordinal = 1,
        .bytes = try p.Bytes(m.chunk_bytes).init("abc"),
    };
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .chunk = input })).failed);
    input.ordinal = 0;
    const ticket = try fx.storage.owner.console_mailbox.submit(t.io, .{
        .crs_management = .{ .chunk = input },
    }, .background);
    input.bytes.data[0] = 'z';
    try fx.storage.owner.tick();
    const result = (try fx.storage.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expect(result == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .chunk = input })).failed);
    input.bytes.data[0] = 'a';
    _ = try fx.run(.{ .chunk = input });
    input.ordinal = 1;
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .chunk = input })).failed);
    try t.expectEqual(
        p.Failure.invalid_input,
        (try fx.run(.{ .verify = .{
            .auth = auth,
            .id = id(1),
            .manifest = manifest(0),
        } })).failed,
    );
    input.ordinal = 0;
    input.file = .signature;
    input.bytes = try p.Bytes(m.chunk_bytes).init("de");
    _ = try fx.run(.{ .chunk = input });
    _ = try fx.run(.{ .verify = .{ .auth = auth, .id = id(1), .manifest = manifest(0) } });
    const source = (try fx.run(.{ .source = .{
        .id = id(1),
        .file = .archive,
        .ordinal = 0,
    } })).crs_source;
    try t.expectEqualStrings("abc", source.slice());
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .chunk = input })).failed);
}

test "CRS management rechecks authorization after queued revocation and limits candidates" {
    var fx = try Fixture.open();
    defer fx.close();
    for (1..5) |number| _ = try fx.begin(number, 0, null);
    try t.expectEqual(p.Failure.capacity, (try fx.begin(5, 0, null)).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.begin(5, 1, null)).failed);
    _ = try fx.run(.{ .discard = .{ .auth = auth, .id = id(4) } });
    try t.expectEqual(
        @as(u64, 0),
        try fx.count(
            "SELECT COUNT(*) FROM console_crs_chunks WHERE job='00000000000000000000000000000004'",
        ),
    );
    const request: p.StorageRequest = .{ .crs_management = .{ .begin = .{
        .auth = auth,
        .id = id(5),
        .kind = .update,
        .expected_revision = 0,
        .expires = fx.storage.owner.nowSeconds() + 120,
    } } };
    const ticket = try fx.storage.owner.console_mailbox.submit(t.io, request, .urgent);
    try fx.storage.owner.db.exec(t.allocator, "UPDATE console_users SET revision=revision+1");
    try fx.storage.owner.tick();
    try t.expectEqual(
        p.Failure.forbidden,
        (try fx.storage.owner.console_mailbox.poll(t.io, ticket)).?.failed,
    );
    try t.expectEqual(@as(u64, 4), try fx.count("SELECT COUNT(*) FROM console_crs_jobs"));
}

test "CRS management rollback is a new revision with immutable retained source" {
    var fx = try Fixture.open();
    defer fx.close();
    try fx.prepare(1, 0, null);
    _ = try fx.select(1, 0);
    try fx.prepare(2, 1, null);
    _ = try fx.select(2, 1);
    try fx.prepare(3, 2, id(1));
    const selected = (try fx.select(3, 2)).crs_selection;
    try t.expectEqual(@as(u64, 3), selected.revision);
    try t.expectEqualDeep(id(2), selected.previous.?.id);
    try t.expectEqual(
        p.Failure.conflict,
        (try fx.run(.{ .discard = .{
            .auth = auth,
            .id = id(3),
        } })).failed,
    );
    _ = try fx.begin(4, 3, null);
    try t.expectEqual(
        @as(u64, 0),
        try fx.count(
            "SELECT COUNT(*) FROM console_crs_chunks WHERE job='00000000000000000000000000000001'",
        ),
    );
    try t.expectEqualStrings("abc", (try fx.run(.{ .source = .{
        .id = id(3),
        .file = .archive,
        .ordinal = 0,
    } })).crs_source.slice());
    try t.expectEqual(p.Failure.conflict, (try fx.begin(5, 3, id(1))).failed);
}

test "CRS management applied receipts require real publication and remain boot fenced" {
    var fx = try Fixture.open();
    defer fx.close();
    try fx.prepare(1, 0, null);
    _ = try fx.select(1, 0);
    try t.expectEqual(
        p.Failure.conflict,
        (try fx.run(.{ .applied = .{
            .revision = 1,
            .applied = true,
        } })).failed,
    );
    _ = try fx.run(.{ .applied = .{ .revision = 1, .applied = false, .reason = .capacity } });
    var publisher: crs.publication.Publisher = .{};
    defer {
        fx.storage.state.crs = null;
        publisher.close() catch unreachable;
        publisher.deinit();
    }
    const selected = try crs.artifact_manifest.decode(manifest(0).slice());
    const generation = try nativeGeneration(selected);
    try publisher.publish(generation);
    fx.storage.state.crs = &publisher;
    _ = try fx.run(.{ .applied = .{ .revision = 1, .applied = true } });
    _ = try fx.run(.{ .applied = .{ .revision = 1, .applied = true } });
    try t.expectEqual(
        @as(u64, 2),
        try fx.count(
            "SELECT COUNT(*) FROM console_audit WHERE action='crs.applied'",
        ),
    );
    try t.expectEqual(
        @as(u64, 1),
        try fx.count(
            "SELECT applied FROM console_crs_applied WHERE node=1",
        ),
    );
    fx.storage.owner.console_node.boot = @splat(9);
    _ = try fx.run(.{ .applied = .{ .revision = 1, .applied = true } });
    try t.expectEqual(
        @as(u64, 3),
        try fx.count(
            "SELECT COUNT(*) FROM console_audit WHERE action='crs.applied'",
        ),
    );
    try t.expectEqual(
        p.Failure.conflict,
        (try fx.run(.{ .applied = .{
            .revision = 2,
            .applied = true,
        } })).failed,
    );
}

test "CRS management adopts filesystem startup only while the durable selection is empty" {
    var fx = try Fixture.open();
    defer fx.close();
    const input: m.Startup = .{ .id = id(1), .manifest = manifest(0) };
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .startup_begin = input })).failed);
    var publisher: crs.publication.Publisher = .{};
    defer {
        fx.storage.state.crs = null;
        publisher.close() catch unreachable;
        publisher.deinit();
    }
    const selected = try crs.artifact_manifest.decode(manifest(0).slice());
    try publisher.publish(try nativeGeneration(selected));
    fx.storage.state.crs = &publisher;
    _ = try fx.run(.{ .startup_begin = input });
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .startup_commit = id(1) })).failed);
    const source: m.SourceWrite = .{
        .id = id(1),
        .file = .archive,
        .ordinal = 0,
        .bytes = try p.Bytes(m.chunk_bytes).init("abc"),
    };
    _ = try fx.run(.{ .startup_chunk = source });
    _ = try fx.run(.{ .startup_chunk = source });
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .chunk = .{
        .auth = auth,
        .id = id(1),
        .file = .signature,
        .ordinal = 0,
        .bytes = try p.Bytes(m.chunk_bytes).init("de"),
    } })).failed);
    _ = try fx.run(.{ .startup_chunk = .{
        .id = id(1),
        .file = .signature,
        .ordinal = 0,
        .bytes = try p.Bytes(m.chunk_bytes).init("de"),
    } });
    _ = try fx.run(.{ .startup_commit = id(1) });
    const result = (try fx.run(.{ .startup_commit = id(1) })).crs_selection;
    try t.expectEqual(@as(u64, 1), result.revision);
    try t.expectEqualDeep(id(1), result.current.?.id);
    try t.expectEqual(@as(u64, 1), try fx.count(
        "SELECT COUNT(*) FROM console_audit WHERE action='crs.select' AND actor=0",
    ));
    _ = try fx.run(.{ .applied = .{ .revision = 1, .applied = true } });
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .applied = .{
        .revision = 1,
        .applied = false,
        .reason = .storage,
    } })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .startup_begin = .{
        .id = id(2),
        .manifest = manifest(0),
    } })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .startup_chunk = source })).failed);
    try fx.prepare(2, 1, id(1));
    _ = try fx.select(2, 1);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .applied = .{
        .revision = 2,
        .applied = true,
    } })).failed);
}

test "CRS management bounds stale operations factors and observable profiles" {
    var fx = try Fixture.open();
    defer fx.close();
    var input: m.Begin = .{
        .auth = auth,
        .id = id(1),
        .kind = .check,
        .expected_revision = 0,
        .expires = fx.storage.owner.nowSeconds() + 301,
    };
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(.{ .begin = input })).failed);
    input.expires -= 181;
    input.auth.require_totp = true;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .begin = input })).failed);
    input.auth = auth;
    input.auth.csrf_digest = @splat(3);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .begin = input })).failed);
    input.auth = auth;
    _ = try fx.run(.{ .begin = input });
    try fx.storage.owner.db.exec(t.allocator, "UPDATE console_crs_jobs SET expires=0");
    try t.expectEqual(
        p.Failure.conflict,
        (try fx.run(.{ .chunk = .{
            .auth = auth,
            .id = id(1),
            .file = .archive,
            .ordinal = 0,
            .bytes = try p.Bytes(m.chunk_bytes).init("abc"),
        } })).failed,
    );
    _ = try fx.begin(2, 0, null);
    try t.expectEqual(
        m.State.failed,
        (try fx.run(.{ .job = .{
            .auth = auth,
            .id = id(1),
        } })).crs_job.?.state,
    );
    try t.expectEqual(
        @as(u64, 1),
        try fx.count(
            "SELECT COUNT(*) FROM console_audit WHERE action='crs.failed'",
        ),
    );
    try t.expectError(error.InvalidLimit, m.validate(.{ .begin = .{
        .auth = auth,
        .id = id(0),
        .kind = .check,
        .expected_revision = 0,
        .expires = 1,
    } }));
    try t.expectError(error.InvalidLimit, m.validate(.{ .source = .{
        .id = id(1),
        .file = .signature,
        .ordinal = 8,
    } }));
}

test "CRS failure diagnostics are committed with the failure audit and retained on replay" {
    var fx = try Fixture.open();
    defer fx.close();
    _ = try fx.begin(1, 0, null);
    const diagnostic = m.Diagnostic.capture(
        error.UnknownOperator,
        "sibuna-operator.conf",
        2,
        null,
    );
    const operation: m.Request = .{ .failed = .{
        .id = id(1),
        .reason = .incompatible,
        .diagnostic = diagnostic,
    } };
    try fx.storage.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_crs_failure BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='crs.failed' BEGIN SELECT RAISE(ABORT,'injected'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(operation)).failed);
    const before = (try fx.run(.{ .job = .{ .auth = auth, .id = id(1) } })).crs_job.?;
    try t.expectEqual(m.State.preparing, before.state);
    try t.expect(before.diagnostic == null);
    try fx.storage.owner.db.exec(t.allocator, "DROP TRIGGER reject_crs_failure");
    const result = (try fx.run(operation)).crs_job.?;
    try t.expectEqualDeep(diagnostic, result.diagnostic.?);
    try t.expectEqual(m.State.failed, result.state);
    _ = try fx.run(operation);
    try t.expectEqual(@as(u64, 1), try fx.count(
        "SELECT count(*) FROM console_audit WHERE action='crs.failed'",
    ));
    try @import("console_migrations.zig").run(fx.storage.owner);
    const retained = (try fx.run(.{ .job = .{ .auth = auth, .id = id(1) } })).crs_job.?;
    try t.expectEqualDeep(diagnostic, retained.diagnostic.?);
}

test "CRS management private tests bind authority revision and audit without changing selection" {
    var fx = try Fixture.open();
    defer fx.close();
    try fx.prepare(1, 0, null);
    const request: m.Select = .{ .auth = auth, .id = id(1), .expected_revision = 0 };
    try fx.storage.owner.db.exec(t.allocator, "CREATE TEMP TRIGGER refuse_test_audit " ++
        "BEFORE INSERT ON console_audit WHEN NEW.action='crs.test' " ++
        "BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END");
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .test_begin = request })).failed);
    try t.expectEqual(@as(u64, 0), try fx.count(
        "SELECT COUNT(*) FROM console_audit WHERE action='crs.test'",
    ));
    try fx.storage.owner.db.exec(t.allocator, "DROP TRIGGER refuse_test_audit");
    const result = try fx.run(.{ .test_begin = request });
    try t.expectEqual(m.State.verified, result.crs_job.?.state);
    try t.expectEqual(@as(u64, 0), (try fx.run(.{ .status = auth })).crs_selection.revision);
    try t.expectEqual(@as(u64, 1), try fx.count(
        "SELECT COUNT(*) FROM console_audit WHERE action='crs.test' " ++
            "AND target='00000000000000000000000000000001' AND actor=1",
    ));
    var invalid = request;
    invalid.auth.csrf_digest = @splat(9);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .test_begin = invalid })).failed);
    _ = try fx.select(1, 0);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .test_begin = request })).failed);
    invalid = request;
    invalid.expected_revision = 1;
    try t.expectEqual(m.State.selected, (try fx.run(.{ .test_begin = invalid })).crs_job.?.state);
}

test "CRS management rule reviews bind authority revision and audit without changing selection" {
    var fx = try Fixture.open();
    defer fx.close();
    try fx.prepare(1, 0, null);
    const request: m.Select = .{ .auth = auth, .id = id(1), .expected_revision = 0 };
    try fx.storage.owner.db.exec(t.allocator, "CREATE TEMP TRIGGER refuse_review_audit " ++
        "BEFORE INSERT ON console_audit WHEN NEW.action='crs.review' " ++
        "BEGIN SELECT RAISE(ABORT,'review audit unavailable'); END");
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .review_begin = request })).failed);
    try t.expectEqual(@as(u64, 0), try fx.count(
        "SELECT COUNT(*) FROM console_audit WHERE action='crs.review'",
    ));
    try fx.storage.owner.db.exec(t.allocator, "DROP TRIGGER refuse_review_audit");
    const result = try fx.run(.{ .review_begin = request });
    try t.expectEqual(m.State.verified, result.crs_job.?.state);
    try t.expectEqual(@as(u64, 0), (try fx.run(.{ .status = auth })).crs_selection.revision);
    try t.expectEqual(@as(u64, 1), try fx.count(
        "SELECT COUNT(*) FROM console_audit WHERE action='crs.review' " ++
            "AND target='00000000000000000000000000000001' AND actor=1",
    ));
    var invalid = request;
    invalid.auth.csrf_digest = @splat(9);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .review_begin = invalid })).failed);
    _ = try fx.select(1, 0);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .review_begin = request })).failed);
    invalid = request;
    invalid.expected_revision = 1;
    const selected = try fx.run(.{ .review_begin = invalid });
    try t.expectEqual(m.State.selected, selected.crs_job.?.state);
}

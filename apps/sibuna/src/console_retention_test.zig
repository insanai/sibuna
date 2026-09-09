const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const r = p.retention;
const Fixture = @import("console_store_test.zig").Fixture;
const storage = @import("console_store_retention.zig");
const holder: r.Holder = .{ .node = 1, .boot = @splat(1) };
const now = 45 * std.time.s_per_day;

test "fenced incident retention is bounded, keeps cutoffs and atomically removes search indexes" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/retention", .{tmp.sub_path});
    const fx = try Fixture.open(path);
    defer fx.close();
    _ = try fx.run(.setup_status);
    try @import("console_migrations.zig").run(fx.owner);
    const cutoff = now - r.incident_days * std.time.s_per_day;
    for (0..37) |i| fx.state.hooks.record_incident.?(fx.state.hooks.context, .{
        .client_ip = "198.51.100.1",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "retainedneedle",
        .now = if (i < 35) cutoff - 1 else cutoff + (i - 35),
        .evidence = .{ .version = 1, .selected_status = 403 },
    });
    try fx.owner.tick();
    try fx.owner.tick();
    const lease = (try storage.acquire(fx.owner, holder, now)).retention_lease;
    const input: r.Prune = .{ .kind = .incidents, .lease = lease };
    try counts(fx, 37);
    // Abort a sidecar deletion after other index effects have been attempted.
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER fail_retention BEFORE DELETE " ++
        "ON console_incident_evidence BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
    try t.expectError(error.SqliteError, storage.prune(fx.owner, input, now));
    try counts(fx, 37);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_retention");
    try t.expect(try storage.prune(fx.owner, input, now) == .command_recorded);
    try counts(fx, 21);
    try t.expect(try storage.prune(fx.owner, input, now) == .command_recorded);
    try counts(fx, 5);
    try t.expect(try storage.prune(fx.owner, input, now) == .command_recorded);
    try counts(fx, 2);
    try t.expect(try storage.prune(fx.owner, input, now) == .command_recorded);
    var metadata = try fx.owner.db.query(
        t.allocator,
        "SELECT (SELECT value FROM sibuna_meta WHERE key='incident_cursor_1')," ++
            "(SELECT value FROM sibuna_meta WHERE key='policy_format')",
    );
    defer metadata.deinit();
    try t.expectEqualStrings("38", metadata.rows[0][0].?);
    try t.expectEqualStrings("2", metadata.rows[0][1].?);
}

fn counts(fx: *Fixture, expected: u64) !void {
    var rows = try fx.owner.db.query(t.allocator, "SELECT " ++
        "(SELECT COUNT(*) FROM security_incidents)," ++
        "(SELECT COUNT(*) FROM incidents_vec)," ++
        "(SELECT COUNT(*) FROM incidents_fts WHERE incidents_fts MATCH 'retainedneedle')," ++
        "(SELECT COUNT(*) FROM console_incident_evidence)");
    defer rows.deinit();
    for (rows.rows[0]) |cell| try t.expectEqual(expected, try std.fmt.parseInt(u64, cell.?, 10));
}

test "lease renewal keeps its fence; takeover and expiry fence every late deletion" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/lease", .{tmp.sub_path});
    const fx = try Fixture.open(path);
    defer fx.close();
    _ = try fx.run(.setup_status);
    const first = (try storage.acquire(fx.owner, holder, now)).retention_lease;
    const renewed = (try storage.acquire(fx.owner, holder, now + 1)).retention_lease;
    try t.expectEqual(first.fence, renewed.fence);
    const peer: r.Holder = .{ .node = 2, .boot = @splat(2) };
    try t.expectEqual(p.Failure.conflict, (try storage.acquire(fx.owner, peer, now + 1)).failed);
    const next = (try storage.acquire(fx.owner, peer, renewed.expires)).retention_lease;
    try t.expectEqual(first.fence + 1, next.fence);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO console_audit(actor,action,subject,recorded_at) VALUES(1,'test',1,0)",
    );
    const later = 400 * std.time.s_per_day;
    const active = (try storage.acquire(fx.owner, peer, later)).retention_lease;
    try t.expectEqual(next.fence + 1, active.fence);
    const stale: r.Prune = .{ .kind = .audit, .lease = first };
    try t.expect(try storage.prune(fx.owner, stale, later) == .command_recorded);
    const valid: r.Prune = .{ .kind = .audit, .lease = active };
    try t.expect(try storage.prune(fx.owner, valid, active.expires) == .command_recorded);
    try kindCount(fx, .audit, 1);
    try t.expect(try storage.prune(fx.owner, valid, later) == .command_recorded);
    try kindCount(fx, .audit, 0);
    try fx.owner.db.exec(t.allocator, "UPDATE console_job_leases SET fence=9223372036854775807");
    try t.expectEqual(p.Failure.capacity, (try storage.acquire(fx.owner, peer, later)).failed);
}

test "audit and session cleanup respect separate deadlines and bounded owner mailboxes" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/deadlines", .{tmp.sub_path});
    const fx = try Fixture.open(path);
    defer fx.close();
    var input: p.StorageRequest = .{ .retention_acquire = holder };
    const ticket = try fx.owner.console_mailbox.submit(t.io, input, .background);
    input.retention_acquire.boot = @splat(0);
    try fx.owner.tick();
    const lease = (try fx.owner.console_mailbox.poll(t.io, ticket)).?.retention_lease;
    try t.expectEqualDeep(holder, lease.holder);
    const current = fx.owner.nowSeconds();
    const cutoff = current - r.audit_days * std.time.s_per_day;
    var sql_buffer: [2048]u8 = undefined;
    const sql = try std.fmt.bufPrint(
        &sql_buffer,
        "WITH RECURSIVE n(i) AS(VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<18) " ++
            "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
            "SELECT 1,'test',i,CASE WHEN i=18 THEN {d} ELSE 0 END FROM n;" ++
            "WITH RECURSIVE n(i) AS(VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<18) " ++
            "INSERT INTO console_sessions(digest,user_id,revision,csrf_digest,created_at," ++
            "expires,idle_expires) SELECT printf('%064x',i),1,1,'test',{d},{d}," ++
            "CASE WHEN i=18 THEN {d} ELSE 0 END FROM n;",
        .{ cutoff, current, current + 120, current + 120 },
    );
    try fx.owner.db.exec(t.allocator, sql);
    inline for (.{ r.Kind.audit, r.Kind.sessions }) |kind| {
        const prune: r.Prune = .{ .lease = lease, .kind = kind };
        for ([_]u64{ 2, 1, 1 }) |expected| {
            try t.expect(try storage.prune(fx.owner, prune, current) == .command_recorded);
            try kindCount(fx, kind, expected);
        }
        if (kind == .sessions) try t.expect(try fx.run(.{ .retention_prune = prune }) ==
            .command_recorded);
    }
}

fn kindCount(fx: *Fixture, kind: r.Kind, expected: u64) !void {
    const sql = switch (kind) {
        .audit => "SELECT COUNT(*) FROM console_audit WHERE action='test'",
        .sessions => "SELECT COUNT(*) FROM console_sessions",
        .kiosk_grants => "SELECT COUNT(*) FROM console_kiosk_grants",
        .stages => "SELECT COUNT(*) FROM console_country_stage",
        .import_stages => "SELECT COUNT(*) FROM console_policy_import_stage",
        .incidents => unreachable,
    };
    var rows = try fx.owner.db.query(t.allocator, sql);
    defer rows.deinit();
    try t.expectEqual(expected, try std.fmt.parseInt(u64, rows.rows[0][0].?, 10));
}

test "collector scheduling and owner ticks retire history without changing lifetime metrics" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/scheduled", .{tmp.sub_path});
    const fx = try Fixture.open(path);
    defer fx.close();
    _ = try fx.run(.setup_status);
    fx.state.hooks.record_incident.?(fx.state.hooks.context, .{
        .client_ip = "198.51.100.1",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "retainedneedle",
        .now = 1,
        .evidence = .{ .version = 1, .selected_status = 403 },
    });
    try fx.owner.tick();
    try counts(fx, 1);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO console_audit(actor,action,subject,recorded_at) VALUES(1,'test',1,0)",
    );
    var job: @import("console").RetentionJob = .{ .holder = holder };
    defer job.stop(t.io, &fx.owner.console_mailbox);
    for (0..80) |i| {
        try t.expect(!job.tick(t.io, &fx.owner.console_mailbox, i * 250));
        try fx.owner.tick();
    }
    try counts(fx, 0);
    try kindCount(fx, .audit, 0);
    try t.expectEqual(@as(u64, 1), fx.state.metrics.incidents_persisted.load(.monotonic));
    try t.expectEqual(@as(u64, 2), fx.owner.next_incident);
}

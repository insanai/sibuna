//! Single-process durability integration tests for zaxonlite.
//!
//! These drive the real node host against real files: restart recovery,
//! journal-authoritative rebuild, torn-tail truncation, idempotent session
//! retry, durable state anchors, and materialized-image convergence.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const testing = std.testing;
const Node = zaxonlite.Node;

const TestDir = struct {
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init(gpa: std.mem.Allocator) !TestDir {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const path = try gpa.dupe(u8, buffer[0..len]);
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TestDir, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
        self.tmp.cleanup();
    }

    fn nodeDir(self: *const TestDir, gpa: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}/node", .{self.path});
    }
};

fn openNode(directory: []const u8) !*Node {
    return Node.open(testing.allocator, testing.io, .{ .directory = directory });
}

fn countItems(node: *Node) !i64 {
    var result = try node.query(testing.allocator, "select count(*) from items");
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.rows.len);
    return std.fmt.parseInt(i64, result.rows[0][0].?, 10);
}

fn readTrimBytes(gpa: std.mem.Allocator, directory: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/consensus/TRIM", .{directory});
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        path,
        gpa,
        .limited(4096),
    );
}

fn expectTrimStateEqual(
    expected: zaxonlite.trim.State,
    actual: zaxonlite.trim.State,
) !void {
    try testing.expectEqual(expected.decision_slot, actual.decision_slot);
    try testing.expectEqual(expected.through_slot, actual.through_slot);
    try testing.expectEqual(expected.history_hash, actual.history_hash);
    try testing.expectEqual(expected.configuration_id, actual.configuration_id);
    try testing.expectEqual(expected.lease_count, actual.lease_count);
}

test "node persists across close and reopen" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        const result = try node.exec("insert into items(v) values ('tea'), ('coffee')");
        try testing.expectEqual(@as(i64, 2), result.changes);
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 2), try countItems(node));
        _ = try node.exec("insert into items(v) values ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));

        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "fresh later-configuration voter requires an enrollment JOIN descriptor" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    try test_dir.tmp.dir.createDirPath(testing.io, "node");
    try test_dir.tmp.dir.writeFile(testing.io, .{
        .sub_path = "node/identity",
        .data = "format=3\nnode_id=1\n" ++
            "database_id=00000000000000000000000000000001\n" ++
            "configuration_id=2\nrole=data-voter\n",
    });
    const member = try zaxonlite.registry.NodeRecord.init(
        1,
        .data_voter,
        "127.0.0.1:1",
    );
    try testing.expectError(
        error.JoinDescriptorRequired,
        Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 1,
            .database_id = 1,
            .registry_nodes = &.{member},
        }),
    );
}

test "an enrollment JOIN descriptor requires the data-voter role" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    try zaxonlite.node.writeJoinDescriptor(testing.io, dir, .{
        .database_id = 1,
        .configuration_id = 2,
        .registry_digest = @as([32]u8, @splat(0x5a)),
    });
    const voter = try zaxonlite.registry.NodeRecord.init(
        1,
        .data_voter,
        "127.0.0.1:1",
    );

    try testing.expectError(
        error.JoinRequiresDataVoter,
        Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 4,
            .database_id = 1,
            .role = .read_replica,
            .members = &.{1},
            .registry_nodes = &.{voter},
        }),
    );
}

test "prepared explicit transaction is one durable replicated transition" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec(
            "create table items(id integer primary key, v text, amount real, raw blob)",
        );
        var transaction = zaxonlite.Transaction.init(gpa);
        defer transaction.deinit();
        try transaction.exec(
            "insert into items(v, amount, raw) values (?1, ?2, ?3)",
            &.{
                .{ .text = "tea" },
                .{ .real = 2.5 },
                .{ .blob = &.{ 0, 1, 2, 255 } },
            },
        );
        try transaction.exec(
            "insert into items(v, amount, raw) values (?1, ?2, ?3)",
            &.{
                .{ .text = "coffee" },
                .{ .null_value = {} },
                .{ .blob = "beans" },
            },
        );
        const result = try node.execTransaction(&transaction);
        try testing.expectEqual(@as(i64, 2), result.changes);

        var query = try node.queryPrepared(
            gpa,
            "select v, hex(raw) from items where amount > ?1 order by id",
            &.{.{ .real = 2.0 }},
        );
        defer query.deinit();
        try testing.expectEqual(@as(usize, 1), query.rows.len);
        try testing.expectEqualStrings("tea", query.rows[0][0].?);
        try testing.expectEqualStrings("000102FF", query.rows[0][1].?);
    }

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(i64, 2), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "remote-style query budgets bound rows bytes and SQLite work" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const node = try openNode(dir);
    defer node.close();

    try testing.expectError(
        error.QueryRowLimit,
        node.queryWithLimits(
            gpa,
            "with recursive n(x) as (values(1) union all " ++
                "select x+1 from n where x<10) select x from n",
            .{ .max_rows = 3 },
        ),
    );
    try testing.expectError(
        error.QueryResultTooLarge,
        node.queryWithLimits(gpa, "select printf('%100s', 'x')", .{
            .max_bytes = 16,
        }),
    );
    try testing.expectError(
        error.SqliteInterrupted,
        node.queryWithLimits(
            gpa,
            "with recursive n(x) as (values(1) union all " ++
                "select x+1 from n where x<1000000) select sum(x) from n",
            .{ .max_vm_steps = 1_000 },
        ),
    );

    // Clearing the progress handler after interruption is part of the
    // contract: subsequent ordinary embedded reads remain unlimited.
    var result = try node.query(gpa, "select 42");
    defer result.deinit();
    try testing.expectEqualStrings("42", result.rows[0][0].?);
}

test "one MiB payload survives journal-only image recovery" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const payload = try gpa.alloc(u8, 1024 * 1024);
    defer gpa.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 131);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table large_payload(value blob)");
        _ = try node.execPrepared(
            "insert into large_payload values (?1)",
            &.{.{ .blob = payload }},
        );
    }
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");

    const recovered = try openNode(dir);
    defer recovered.close();
    var result = try recovered.query(
        gpa,
        "select length(value), hex(substr(value, 1, 4)) from large_payload",
    );
    defer result.deinit();
    try testing.expectEqualStrings("1048576", result.rows[0][0].?);
    try testing.expectEqualStrings("00830689", result.rows[0][1].?);
    try testing.expect((try recovered.integrityCheck()).ok());
}

test "a data directory cannot silently change learner role" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const voters = [_]u32{ 1, 2 };
    {
        const node = try Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 3,
            .members = &voters,
            .database_id = 77,
            .role = .standby,
        });
        node.close();
    }
    try testing.expectError(
        error.NodeRoleMismatch,
        Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 3,
            .members = &voters,
            .database_id = 77,
            .role = .read_replica,
        }),
    );
}

test "journal is authoritative: materialized image rebuilds across sealed segments" {
    const saved_rotation = zaxonlite.segment.rotation_records;
    zaxonlite.segment.rotation_records = 4;
    defer zaxonlite.segment.rotation_records = saved_rotation;
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea'), ('coffee'), ('water')");
        _ = try node.exec("update items set v = v || '!' where id = 2");
        _ = try node.exec("delete from items where id = 3");
        try testing.expect(node.journal.segments.items.len > 0);
        // Leadership loss rebuilds in-process; restart below exercises the
        // same retained iterator after the materialized image has been lost.
        try node.resyncImage();
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }

    // Destroy the materialized SQLite image; only journal + payloads remain.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 2), try countItems(node));
        var result = try node.query(gpa, "select v from items order by id");
        defer result.deinit();
        try testing.expectEqualStrings("tea", result.rows[0][0].?);
        try testing.expectEqualStrings("coffee!", result.rows[1][0].?);
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "a stale materialized image converges to the journal state" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var node_dir_handle: ?std.Io.Dir = null;
    defer if (node_dir_handle) |*handle| handle.close(testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea')");
    }

    // Save an old copy of the image, write more, then put the old copy back:
    // the equivalent of a crash that lost recent checkpointed pages.
    node_dir_handle = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    const node_dir = node_dir_handle.?;
    try node_dir.copyFile("current.db", node_dir, "stale.db", testing.io, .{});

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("insert into items(v) values ('coffee'), ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));
    }

    try node_dir.deleteFile(testing.io, "current.db");
    try node_dir.rename("stale.db", node_dir, "current.db", testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 3), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "torn journal tail is truncated and the node reopens" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea')");
    }

    // Append a partial record to the active journal segment, as a
    // crashed append would leave behind.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    const journal_name = "consensus/0000000000000001.zxj";
    const file = try node_dir.openFile(testing.io, journal_name, .{ .mode = .read_write });
    const end = try file.length(testing.io);
    try file.writePositionalAll(testing.io, &.{ 0x4a, 0x58, 0x01 }, end);
    file.close(testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 1), try countItems(node));
        _ = try node.exec("insert into items(v) values ('coffee')");
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
}

test "idempotent sessions execute a sequence exactly once" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");

        const session = try node.openSession();
        const first = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");
        try testing.expectEqual(@as(i64, 1), first.changes);
        try testing.expect(!first.replayed);

        // An ambiguous retry of the same sequence returns the recorded
        // result and never applies twice.
        const retry = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");
        try testing.expect(retry.replayed);
        try testing.expectEqual(@as(i64, 1), retry.changes);
        try testing.expectEqual(@as(i64, 1), try countItems(node));

        try testing.expectError(
            error.SequenceGap,
            node.execIdempotent(session, 5, "insert into items(v) values ('x')"),
        );
        try testing.expectError(
            error.UnknownSession,
            node.execIdempotent(session + 999, 1, "insert into items(v) values ('x')"),
        );

        _ = try node.execIdempotent(session, 2, "insert into items(v) values ('coffee')");
        try testing.expectError(
            error.ResultExpired,
            node.execIdempotent(session, 1, "insert into items(v) values ('x')"),
        );
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }

    // Retry safety must survive restart: session state is replicated.
    {
        const node = try openNode(dir);
        defer node.close();
        const retry = try node.execIdempotent(1, 2, "insert into items(v) values ('coffee')");
        try testing.expect(retry.replayed);
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
}

test "admission arithmetic refuses at and beyond the reserve boundary" {
    // The pure check, exercised with synthetic numbers so the boundary
    // cases stay visible: a cap at or below the reserve refuses
    // everything, and admission flips exactly where usage plus the
    // reserve reaches the cap.
    try testing.expect(Node.admissionOverCap(0, 100, 100));
    try testing.expect(Node.admissionOverCap(0, 100, 50));
    try testing.expect(!Node.admissionOverCap(0, 100, 101));
    try testing.expect(!Node.admissionOverCap(49, 100, 150));
    try testing.expect(Node.admissionOverCap(50, 100, 150));
    try testing.expect(Node.admissionOverCap(
        std.math.maxInt(u64),
        100,
        std.math.maxInt(u64),
    ));
}

test "the storage ceiling refuses writes instead of deleting history" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    // The production reserve stays in force; the cap grants a small
    // budget above it, so refusal arrives after a handful of writes.
    // The invariant under test: admitted usage never lands above the
    // cap, and the refusal is RecoveryRetentionExceeded, never a
    // deletion of unproven history.
    const cap: u64 = Node.admission_reserve_bytes + 256 * 1024;
    const node = try Node.open(gpa, testing.io, .{
        .directory = dir,
        .journal_cap_bytes = cap,
    });
    defer node.close();
    _ = try node.exec("create table t(id integer primary key, v text)");
    const schema_usage = node.journal.stats().journal_bytes +
        node.store.retained_bytes;
    try testing.expect(schema_usage <= cap);
    var refused = false;
    var index: usize = 0;
    while (index < 400) : (index += 1) {
        _ = node.exec("insert into t(v) values ('row')") catch |err| {
            try testing.expectEqual(error.RecoveryRetentionExceeded, err);
            refused = true;
            break;
        };
        const usage = node.journal.stats().journal_bytes +
            node.store.retained_bytes;
        try testing.expect(usage <= cap);
    }
    try testing.expect(refused);
    const final_usage = node.journal.stats().journal_bytes +
        node.store.retained_bytes;
    try testing.expect(final_usage <= cap);
    try testing.expect(node.journal.retainedFirstSlot() == 1);
}

test "the retention horizon keeps recent history below the chosen trim" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const saved_rotation = zaxonlite.segment.rotation_records;
    zaxonlite.segment.rotation_records = 128;
    defer zaxonlite.segment.rotation_records = saved_rotation;

    // A horizon wider than all history pins physical reclamation at
    // genesis even though the chosen trim advances past whole segments.
    const node = try Node.open(gpa, testing.io, .{
        .directory = dir,
        .retention_slots = 1_000_000,
    });
    defer node.close();
    _ = try node.exec("create table t(id integer primary key, v text)");
    var index: usize = 0;
    while (index < 300) : (index += 1) {
        _ = try node.exec("insert into t(v) values ('r')");
    }
    try node.createStateAnchor();
    try node.reclaim();
    try testing.expect(node.trim_state.through_slot > 0);
    try testing.expectEqual(@as(u64, 1), node.journal.retainedFirstSlot());
}

test "the time cadence anchors again after a restart" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table t(id integer primary key, v text)");
        _ = try node.exec("insert into t(v) values ('a')");
        try node.createStateAnchor();
    }

    const saved_interval = Node.anchor_interval_ns;
    Node.anchor_interval_ns = 1;
    defer Node.anchor_interval_ns = saved_interval;

    // The restarted node has an anchor but a zero clock; the first
    // cadence check starts the clock and must not anchor, the second
    // sees the elapsed interval and must.
    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("insert into t(v) values ('b')");
    const before = node.durable_state_slot;
    try testing.expect(!try node.maybeCreateStateAnchor());
    try testing.expect(try node.maybeCreateStateAnchor());
    try testing.expect(node.durable_state_slot > before);
}

test "a state anchor bounds recovery and survives image loss" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea'), ('coffee')");

        try node.createStateAnchor();
        try testing.expectEqual(@as(u64, 1), node.identity.configuration_id);
        try testing.expect(node.durable_state_slot > 0);
        // The one-member configuration trims itself to the fresh anchor;
        // the trim entry itself occupies the slot after the anchor.
        try testing.expectEqual(node.durable_state_slot + 1, node.applied_slot);
        try testing.expectEqual(node.applied_slot, node.trim_state.decision_slot);
        try testing.expectEqual(node.durable_state_slot, node.trim_state.through_slot);
        try testing.expectEqual(
            node.trim_state.through_slot,
            node.log.trimAnchor().chosen_trim_slot,
        );

        _ = try node.exec("insert into items(v) values ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));
    }

    // Restart resumes from the anchor plus the journal suffix, and the
    // adopted trim anchor survives replay.
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 3), try countItems(node));
        try testing.expect(node.log.trimAnchor().chosen_trim_slot > 0);
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
        try node.createStateAnchor();
        _ = try node.exec("insert into items(v) values ('mate')");
        try testing.expectEqual(@as(i64, 4), try countItems(node));
    }

    // Losing the image invalidates the anchor; the retained journal still
    // rebuilds everything from genesis.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 4), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "adopting chosen trims counts safe skips and latches on divergence" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var durable_before: []u8 = undefined;
    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('anchor')");
        try node.createStateAnchor();

        const adopted = node.trim_state;
        try testing.expect(adopted.decision_slot > 0);
        try testing.expect(adopted.through_slot > 0);
        durable_before = try readTrimBytes(gpa, dir);

        zaxonlite.trim.test_options.suppress_adoption_log = true;
        defer zaxonlite.trim.test_options.suppress_adoption_log = false;

        const stale = zaxonlite.command.TrimRecord{
            .through_slot = adopted.through_slot - 1,
            .history_hash = adopted.history_hash,
            .configuration_id = adopted.configuration_id,
            .policy = 0,
        };
        try zaxonlite.trim.adoptChosen(node, adopted.decision_slot + 5, stale);
        try testing.expectEqual(@as(u64, 1), node.trim_ignored_count);
        try expectTrimStateEqual(adopted, node.trim_state);
        try testing.expect(!node.storageFailed());

        const duplicate = zaxonlite.command.TrimRecord{
            .through_slot = adopted.through_slot,
            .history_hash = adopted.history_hash,
            .configuration_id = adopted.configuration_id,
            .policy = 0,
        };
        try zaxonlite.trim.adoptChosen(
            node,
            adopted.decision_slot + 6,
            duplicate,
        );
        try testing.expectEqual(@as(u64, 2), node.trim_ignored_count);
        try expectTrimStateEqual(adopted, node.trim_state);

        try zaxonlite.trim.adoptChosen(node, adopted.decision_slot, duplicate);
        try testing.expectEqual(@as(u64, 2), node.trim_ignored_count);

        const durable_after_skips = try readTrimBytes(gpa, dir);
        defer gpa.free(durable_after_skips);
        try testing.expectEqualSlices(u8, durable_before, durable_after_skips);

        var diverged = duplicate;
        diverged.history_hash[0] ^= 1;
        try testing.expectError(
            error.TrimRegression,
            zaxonlite.trim.adoptChosen(
                node,
                adopted.decision_slot + 7,
                diverged,
            ),
        );
        try testing.expect(node.storageFailed());
        try testing.expectError(
            error.StorageFailed,
            node.exec("insert into items(v) values ('refused')"),
        );
    }
    defer gpa.free(durable_before);

    const durable_after_reopen = try readTrimBytes(gpa, dir);
    defer gpa.free(durable_after_reopen);
    try testing.expectEqualSlices(u8, durable_before, durable_after_reopen);
    const reopened = try openNode(dir);
    defer reopened.close();
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "recovery discards a corrupt materialized image even with an empty suffix" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('anchor-only')");
        try node.createStateAnchor();
    }

    // Damage a page in the non-authoritative working image. The retained
    // journal suffix has no entries that could happen to overwrite it.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    const file = try node_dir.openFile(
        testing.io,
        "current.db",
        .{ .mode = .read_write },
    );
    try file.writePositionalAll(testing.io, "not sqlite", 0);
    try file.sync(testing.io);
    file.close(testing.io);

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "writes continue past the consensus window with no rollover" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");

    // Push well past the 2048-cell window: slots are global and the
    // configuration never changes (ZDS 0011).
    var buffer: [96]u8 = undefined;
    for (0..2075) |index| {
        const sql = try std.mem.printSentinel(
            &buffer,
            "insert into items(v) values ('row-{d}')",
            .{index},
            0,
        );
        _ = try node.exec(sql);
    }
    try testing.expectEqual(@as(i64, 2075), try countItems(node));
    try testing.expectEqual(@as(u64, 1), node.identity.configuration_id);
    try testing.expect(node.log.decidedThrough() > 2075);
    const report = try node.integrityCheck();
    try testing.expect(report.ok());
}

test "failed SQL rolls back and replicates nothing" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text not null)");
        const decided_before = node.log.decidedThrough();
        try testing.expectError(
            error.SqliteError,
            node.exec("insert into items(v) values (null)"),
        );
        try testing.expectEqual(decided_before, node.log.decidedThrough());
        _ = try node.exec("insert into items(v) values ('tea')");
        try testing.expectEqual(@as(i64, 1), try countItems(node));
    }
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 1), try countItems(node));
    }
}

test "write statements are rejected on the read path" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    try testing.expectError(
        error.WriteInReadQuery,
        node.query(gpa, "insert into items(v) values ('nope')"),
    );
}

test "a second process cannot open a locked node directory" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    try testing.expectError(error.NodeLocked, openNode(dir));
}

test "idle sessions expire after the retention window" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var idle_session: u64 = 0;
    var busy_session: u64 = 0;
    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");

        idle_session = try node.openSession();
        _ = try node.execIdempotent(idle_session, 1, "insert into items(v) values ('old')");

        // A busy session generates activity while the idle one stays quiet.
        busy_session = try node.openSession();
        var sequence: u64 = 1;
        while (sequence <= 8) : (sequence += 1) {
            _ = try node.execIdempotent(
                busy_session,
                sequence,
                "insert into items(v) values ('busy')",
            );
        }

        // Retain only the most recent 3 session-write activities: the idle
        // session falls outside the window and is deleted; the busy stays.
        const expired = try node.expireSessions(3);
        try testing.expectEqual(@as(i64, 1), expired.changes);

        try testing.expectError(
            error.UnknownSession,
            node.execIdempotent(idle_session, 2, "insert into items(v) values ('x')"),
        );
        _ = try node.execIdempotent(
            busy_session,
            9,
            "insert into items(v) values ('still-live')",
        );
    }

    // Expiry is itself replicated: it survives restart.
    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectError(
        error.UnknownSession,
        reopened.execIdempotent(idle_session, 2, "insert into items(v) values ('x')"),
    );
    const replay = try reopened.execIdempotent(
        busy_session,
        9,
        "insert into items(v) values ('still-live')",
    );
    try testing.expect(replay.replayed);
}

test "application SQL cannot break the replication contract" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");

    // Transaction control, attachment, reserved metadata, and capture
    // pragmas are denied through the public write surface without leaving
    // side effects; ordinary SQL keeps working afterwards.
    const denied = [_][:0]const u8{
        "commit",
        "rollback",
        "savepoint s1",
        "attach database ':memory:' as extra",
        "insert into __zaxon_meta values ('k', 'v')",
        "delete from __zaxon_sessions",
        "drop table __zaxon_meta",
        "pragma wal_autocheckpoint = 100",
        "pragma wal_checkpoint",
        "pragma journal_mode = delete",
        "insert into items(v) values ('a'); commit",
    };
    for (denied) |sql| {
        try testing.expectError(error.SqliteError, node.exec(sql));
    }
    try testing.expectEqual(@as(i64, 0), try countItems(node));

    // Read queries observe the same boundary.
    try testing.expectError(
        error.SqliteError,
        node.query(gpa, "select * from __zaxon_meta"),
    );

    _ = try node.exec("insert into items(v) values ('tea')");
    try testing.expectEqual(@as(i64, 1), try countItems(node));

    // Sessions still work: their metadata writes are internal scope.
    const session = try node.openSession();
    _ = try node.execIdempotent(session, 1, "insert into items(v) values ('b')");
    try testing.expectEqual(@as(i64, 2), try countItems(node));

    const report = try node.integrityCheck();
    try testing.expect(report.ok());
}

const registry = zaxonlite.registry;

fn testRegistryRecords() [3]registry.NodeRecord {
    return .{
        registry.NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
        registry.NodeRecord.init(2, .data_voter, "127.0.0.1:9902") catch unreachable,
        registry.NodeRecord.init(3, .data_voter, "127.0.0.1:9903") catch unreachable,
    };
}

test "network bootstrap persists the decided registry and pins flags" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const voters = [_]u32{ 1, 2, 3 };
    const records = testRegistryRecords();

    var digest: [32]u8 = undefined;
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        const decided = node.decidedRegistry().?;
        try testing.expectEqual(@as(u64, 1), decided.configuration_id);
        try testing.expectEqual(@as(u128, 77), decided.database_id);
        try testing.expectEqual(@as(u32, 3), decided.highest_allocated_node_id);
        digest = decided.digest();
    }
    try test_dir.tmp.dir.access(io, "node/REGISTRY", .{});
    try test_dir.tmp.dir.access(io, "node/registries/0000000000000001", .{});

    // Reopen with matching flags: the same decided registry loads.
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }

    // Once the registry exists, the database identity comes from it: a
    // conflicting derived flag is ignored, never re-derived.
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 88,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqual(
            @as(u128, 77),
            node.decidedRegistry().?.database_id,
        );
    }

    // Once present, the durable registry also owns membership. Stale
    // bootstrap flags cannot prevent crash recovery or alter its digest.
    var moved = records;
    moved[2] = registry.NodeRecord.init(3, .data_voter, "127.0.0.1:9999") catch
        unreachable;
    for ([_][]const registry.NodeRecord{ &moved, records[0..2] }) |stale| {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = stale,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }

    // Crash window: a missing pointer after the blob write re-runs the
    // idempotent bootstrap and converges to the same digest.
    try test_dir.tmp.dir.deleteFile(io, "node/REGISTRY");
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }
    try test_dir.tmp.dir.access(io, "node/REGISTRY", .{});

    // A present but corrupt pointer fails closed instead of re-deriving.
    try test_dir.tmp.dir.writeFile(io, .{
        .sub_path = "node/REGISTRY",
        .data = "zz",
    });
    try testing.expectError(error.CorruptRegistryPointer, Node.open(gpa, io, .{
        .directory = dir,
        .node_id = 1,
        .members = &voters,
        .database_id = 77,
        .registry_nodes = &records,
    }));
}

test "embedded and local nodes write no registry" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    try testing.expect(node.decidedRegistry() == null);
    try testing.expectError(
        error.FileNotFound,
        test_dir.tmp.dir.access(io, "node/REGISTRY", .{}),
    );
}

test "flag membership is canonicalized to ascending node ids" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    // Checkpoint proofs and the decided registry encode voter sets in
    // ascending order; flag order must not decide whether rollover works.
    const node = try Node.open(gpa, testing.io, .{
        .directory = dir,
        .node_id = 2,
        .members = &.{ 3, 1, 2 },
        .database_id = 42,
    });
    defer node.close();
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, node.memberIds());
}

fn openRegistryNode(dir: []const u8) !*Node {
    const records = [_]registry.NodeRecord{
        registry.NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
    };
    return Node.open(testing.allocator, testing.io, .{
        .directory = dir,
        .node_id = 1,
        .members = &.{1},
        .database_id = 42,
        .registry_nodes = &records,
    });
}

test "a transaction above the protocol hard limit is rejected" {
    // The 64 MiB - 73 byte protocol payload bound (ZDS 0009): a single
    // oversized transaction is refused before it reaches the journal, and
    // the node keeps serving afterwards.
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table big(b blob)");
    try testing.expectError(
        error.TransactionTooLarge,
        node.exec("insert into big values (randomblob(70000000))"),
    );
    const after = try node.exec("insert into big values (randomblob(16))");
    try testing.expectEqual(@as(i64, 1), after.changes);
}

test "replicated multimodal search state survives restart" {
    // FTS5 tokens, float vectors, and coarse bit vectors commit in one
    // replicated transaction; a reopened node rebuilds its image from the
    // journal and answers the hybrid query identically (ZDS 0009).
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const hybrid_sql =
        \\with coarse as (
        \\  select item_id, embedding from media_vec
        \\  where embedding_coarse match
        \\    vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))
        \\  and k = 2)
        \\select item_id,
        \\  zaxon_vec_distance_cosine(embedding, vec_f32('[1,0,0,0,0,0,0,0]'))
        \\    as exact_distance
        \\from coarse order by exact_distance, item_id
    ;

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec(
            \\create table media(id integer primary key, title text);
            \\create virtual table media_fts using fts5(
            \\  title, content='media', content_rowid='id');
            \\create virtual table media_vec using vec0(
            \\  item_id integer primary key,
            \\  embedding float[8],
            \\  embedding_coarse bit[8]);
        );
        _ = try node.exec(
            \\insert into media(id, title) values
            \\  (1, 'paxos replicates sqlite'),
            \\  (2, 'vectors rank media'),
            \\  (3, 'hamming coarse scan');
            \\insert into media_fts(rowid, title) select id, title from media;
            \\insert into media_vec(item_id, embedding, embedding_coarse) values
            \\  (1, vec_f32('[1,0,0,0,0,0,0,0]'),
            \\      vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))),
            \\  (2, vec_f32('[0,1,0,0,0,0,0,0]'),
            \\      vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]'))),
            \\  (3, vec_f32('[1,1,0,0,0,0,0,0]'),
            \\      vec_quantize_binary(vec_f32('[1,1,-1,-1,-1,-1,-1,-1]')));
        );
        var result = try node.query(gpa, hybrid_sql);
        defer result.deinit();
        try testing.expectEqual(@as(usize, 2), result.rows.len);
        try testing.expectEqualStrings("1", result.rows[0][0].?);
        try testing.expectEqualStrings("3", result.rows[1][0].?);
    }

    // Reopen: the journal-authoritative rebuild must reproduce the same
    // search state, and the search-feature version keeps serving.
    const node = try openNode(dir);
    defer node.close();
    var result = try node.query(gpa, hybrid_sql);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.rows.len);
    try testing.expectEqualStrings("1", result.rows[0][0].?);
    try testing.expectEqualStrings("3", result.rows[1][0].?);

    var fts = try node.query(
        gpa,
        "select rowid from media_fts where media_fts match 'paxos'",
    );
    defer fts.deinit();
    try testing.expectEqual(@as(usize, 1), fts.rows.len);
    try testing.expectEqualStrings("1", fts.rows[0][0].?);
}

test "typed search matches the hand-written hybrid statement" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec(
        \\create table media(id integer primary key, title text);
        \\create virtual table media_fts using fts5(
        \\  title, content='media', content_rowid='id');
        \\create virtual table media_vec using vec0(
        \\  item_id integer primary key,
        \\  embedding float[8],
        \\  embedding_coarse bit[8]);
        \\insert into media(id, title) values
        \\  (1, 'paxos replicates sqlite'),
        \\  (2, 'vectors rank media'),
        \\  (3, 'sqlite stores vectors');
        \\insert into media_fts(rowid, title) select id, title from media;
        \\insert into media_vec(item_id, embedding, embedding_coarse) values
        \\  (1, vec_f32('[1,0,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))),
        \\  (2, vec_f32('[0,1,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]'))),
        \\  (3, vec_f32('[1,1,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[1,1,-1,-1,-1,-1,-1,-1]')));
    );

    const query_embedding = [_]f32{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const embedding_bytes = std.mem.sliceAsBytes(&query_embedding);

    // The typed API result must match the ZDS hybrid CTE run as raw SQL
    // with the same parameters bound.
    var typed = try node.search(gpa, .{
        .fts_table = "media_fts",
        .vec_table = "media_vec",
        .text = "sqlite",
        .embedding = embedding_bytes,
        .k = 3,
        .candidate_count = 64,
        .metadata_table = "media",
        .metadata_columns = &.{"title"},
    }, .{});
    defer typed.deinit();

    var raw = try node.queryPrepared(gpa,
        \\with lexical as (
        \\  select rowid as item_id,
        \\    row_number() over (order by bm25(media_fts), rowid) as rank
        \\  from media_fts where media_fts match ?1
        \\  order by bm25(media_fts), rowid limit ?2),
        \\coarse as (
        \\  select item_id, embedding from media_vec
        \\  where embedding_coarse match vec_quantize_binary(?3) and k = ?2),
        \\reranked as (
        \\  select item_id,
        \\    zaxon_vec_distance_cosine(embedding, ?3) as exact_distance
        \\  from coarse order by exact_distance, item_id limit ?4),
        \\semantic as (
        \\  select item_id,
        \\    row_number() over (order by exact_distance, item_id) as rank
        \\  from reranked),
        \\contributions as (
        \\  select item_id, rrf(rank, 60, ?5) as score from lexical
        \\  union all
        \\  select item_id, rrf(rank, 60, ?6) as score from semantic)
        \\select item_id, sum(score) as fused_score
        \\from contributions group by item_id
        \\order by fused_score desc, item_id limit ?4
    , &.{
        .{ .text = "sqlite" },
        .{ .integer = 64 },
        .{ .blob = embedding_bytes },
        .{ .integer = 3 },
        .{ .real = 1.0 },
        .{ .real = 1.0 },
    });
    defer raw.deinit();

    try testing.expectEqual(raw.rows.len, typed.rows.len);
    for (raw.rows, typed.rows) |raw_row, typed_row| {
        try testing.expectEqualStrings(raw_row[0].?, typed_row[0].?);
        try testing.expectEqualStrings(raw_row[1].?, typed_row[1].?);
    }
    try testing.expectEqualStrings("title", typed.columns[2]);
    for (typed.rows) |row| {
        const expected_title: []const u8 = if (std.mem.eql(u8, row[0].?, "1"))
            "paxos replicates sqlite"
        else if (std.mem.eql(u8, row[0].?, "2"))
            "vectors rank media"
        else
            "sqlite stores vectors";
        try testing.expectEqualStrings(expected_title, row[2].?);
    }

    // Single-branch requests skip fusion (ZDS fusion-selection flow).
    var vector_only = try node.search(gpa, .{
        .vec_table = "media_vec",
        .embedding = embedding_bytes,
        .k = 2,
    }, .{});
    defer vector_only.deinit();
    try testing.expectEqual(@as(usize, 2), vector_only.rows.len);
    try testing.expectEqualStrings("1", vector_only.rows[0][0].?);

    var text_only = try node.search(gpa, .{
        .fts_table = "media_fts",
        .text = "vectors",
        .k = 5,
    }, .{});
    defer text_only.deinit();
    try testing.expectEqual(@as(usize, 2), text_only.rows.len);

    // The candidate cap is enforced before any SQL exists.
    try testing.expectError(error.InvalidCandidateCount, node.search(gpa, .{
        .vec_table = "media_vec",
        .embedding = embedding_bytes,
        .k = 2,
        .candidate_count = 4097,
    }, .{}));
}

test "live transaction: read-your-writes, returning, savepoints, durability" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");

        try node.beginLive();
        try testing.expect(node.inLiveTransaction());

        // Insert with RETURNING before commit.
        var returning: ?zaxonlite.TypedResult = null;
        const first = try node.liveExec(
            gpa,
            "insert into items(v) values (?1) returning id",
            &.{.{ .text = "tea" }},
            &returning,
        );
        try testing.expectEqual(@as(i64, 1), first.changes);
        try testing.expect(first.last_insert_rowid != null);
        try testing.expect(returning != null);
        try testing.expectEqual(
            first.last_insert_rowid.?,
            returning.?.rows[0][0].integer,
        );
        returning.?.deinit();

        // Read-your-writes on the same connection before commit.
        var count_rows: ?zaxonlite.TypedResult = null;
        _ = try node.liveExec(
            gpa,
            "select count(*) from items",
            &.{},
            &count_rows,
        );
        try testing.expectEqual(@as(i64, 1), count_rows.?.rows[0][0].integer);
        count_rows.?.deinit();

        // Savepoint, insert, roll back to the savepoint.
        try node.liveSavepoint(1);
        var discard: ?zaxonlite.TypedResult = null;
        _ = try node.liveExec(
            gpa,
            "insert into items(v) values ('discarded')",
            &.{},
            &discard,
        );
        try node.liveRollbackToSavepoint(1);
        try node.liveReleaseSavepoint(1);

        // A one-shot write is refused while the transaction is open.
        try testing.expectError(
            error.TransactionOpen,
            node.exec("insert into items(v) values ('blocked')"),
        );

        // Total-changes semantics: the savepoint-discarded insert still
        // counts toward the transaction total; the table itself holds one
        // row. Per-statement counts from liveExec stay precise.
        const committed = try node.commitLive();
        try testing.expectEqual(@as(i64, 2), committed.changes);
        try testing.expect(!node.inLiveTransaction());
        try testing.expectEqual(@as(i64, 1), try countItems(node));
    }

    // Commit survives close and reopen.
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 1), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "live transaction: rollback publishes nothing" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");

    try node.beginLive();
    var discard: ?zaxonlite.TypedResult = null;
    _ = try node.liveExec(
        gpa,
        "insert into items(v) values ('vanishes')",
        &.{},
        &discard,
    );
    try node.rollbackLive();
    try testing.expect(!node.inLiveTransaction());
    try testing.expectEqual(@as(i64, 0), try countItems(node));

    // The node is fully usable afterwards.
    _ = try node.exec("insert into items(v) values ('kept')");
    try testing.expectEqual(@as(i64, 1), try countItems(node));
    try testing.expectError(error.NoTransaction, node.commitLive());
    try testing.expectError(error.NoTransaction, node.rollbackLive());
}

test "live transaction refuses work after the storage latch" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    try node.beginLive();
    node.markFailed();

    var returning: ?zaxonlite.TypedResult = null;
    try testing.expectError(
        error.StorageFailed,
        node.liveExec(
            gpa,
            "insert into items(v) values ('refused')",
            &.{},
            &returning,
        ),
    );
    try testing.expectError(error.StorageFailed, node.liveSavepoint(1));
    try testing.expectError(error.StorageFailed, node.liveReleaseSavepoint(1));
    try testing.expectError(error.StorageFailed, node.liveRollbackToSavepoint(1));
    try testing.expectError(error.StorageFailed, node.commitLive());

    // Cleanup remains available after failure so hosts can release SQLite's
    // writer transaction deterministically.
    try node.rollbackLive();
    try testing.expect(!node.inLiveTransaction());
}

// ----------------------------------------------------------------------
// Checked transactions (KDS 0018 WP1)
// ----------------------------------------------------------------------

test "checked transaction commits when every expectation passes" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    _ = try node.exec("insert into items(v) values ('tea')");

    var failure: ?zaxonlite.CheckedFailure = null;
    const result = try node.execCheckedTransaction(&.{
        .{
            .sql = "update items set v = 'green tea' where v = ?1",
            .values = &.{.{ .text = "tea" }},
            .expectation = .{ .changes_exactly = 1 },
        },
        .{
            .sql = "select count(*) from items",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .integer = 1 } },
        },
        .{
            .sql = "insert into items(v) values (?1)",
            .values = &.{.{ .text = "coffee" }},
            .expectation = .{ .changes_exactly = 1 },
        },
        .{
            .sql = "select v from items order by id",
            .values = &.{},
            .expectation = .{ .rows_exactly = 2 },
        },
    }, &failure);
    try testing.expect(failure == null);
    try testing.expectEqual(@as(i64, 2), result.changes);
    try testing.expectEqual(@as(i64, 2), try countItems(node));
}

test "a failed changes expectation rolls back before capture and appends no journal record" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea')");

        const decided_before = node.log.decidedThrough();
        const journal_before = node.status().journal_records;
        var failure: ?zaxonlite.CheckedFailure = null;
        try testing.expectError(error.ExpectationFailed, node.execCheckedTransaction(&.{
            .{
                .sql = "insert into items(v) values ('speculative')",
                .values = &.{},
                .expectation = .{ .changes_exactly = 1 },
            },
            .{
                .sql = "update items set v = 'renamed' where v = 'missing'",
                .values = &.{},
                .expectation = .{ .changes_exactly = 1 },
            },
        }, &failure));
        // Nothing was decided or journaled: the rollback fired before any
        // WAL frame was captured or appended.
        try testing.expectEqual(decided_before, node.log.decidedThrough());
        try testing.expectEqual(journal_before, node.status().journal_records);
        try testing.expectEqual(@as(i64, 1), try countItems(node));
        // The node keeps serving writes afterwards.
        _ = try node.exec("insert into items(v) values ('kept')");
    }
    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(i64, 2), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "checked failure reports the failing statement index and observed count" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    _ = try node.exec("insert into items(v) values ('tea'), ('coffee'), ('water')");

    var failure: ?zaxonlite.CheckedFailure = null;
    try testing.expectError(error.ExpectationFailed, node.execCheckedTransaction(&.{
        .{
            .sql = "select v from items",
            .values = &.{},
            .expectation = .{ .rows_exactly = 3 },
        },
        .{
            .sql = "delete from items where v like ?1",
            .values = &.{.{ .text = "%e%" }},
            .expectation = .{ .changes_exactly = 1 },
        },
    }, &failure));
    const reported = failure.?;
    try testing.expectEqual(@as(u32, 1), reported.statement_index);
    // 'tea', 'coffee', and 'water' all match '%e%'.
    try testing.expectEqual(@as(i64, 3), reported.observed_changes);
    try testing.expectEqual(@as(i64, 3), try countItems(node));
}

test "scalar guard compares typed values" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table meta(k text primary key, n integer, r real, b blob)");
    _ = try node.exec("insert into meta values ('row', 7, 2.5, x'00ff')");

    // Every storage class matches its own typed expectation.
    var failure: ?zaxonlite.CheckedFailure = null;
    _ = try node.execCheckedTransaction(&.{
        .{
            .sql = "select n from meta where k = 'row'",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .integer = 7 } },
        },
        .{
            .sql = "select r from meta where k = 'row'",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .real = 2.5 } },
        },
        .{
            .sql = "select k from meta where k = 'row'",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .text = "row" } },
        },
        .{
            .sql = "select b from meta where k = 'row'",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .blob = &.{ 0x00, 0xff } } },
        },
    }, &failure);
    try testing.expect(failure == null);

    // Storage classes stay strict: integer 7 is not text '7'.
    try testing.expectError(error.ExpectationFailed, node.execCheckedTransaction(&.{.{
        .sql = "select n from meta where k = 'row'",
        .values = &.{},
        .expectation = .{ .scalar_equals = .{ .text = "7" } },
    }}, &failure));
    try testing.expectEqual(@as(u32, 0), failure.?.statement_index);
    try testing.expectEqual(@as(u64, 1), failure.?.observed_rows);

    // A scalar expectation needs exactly one row.
    try testing.expectError(error.ExpectationFailed, node.execCheckedTransaction(&.{.{
        .sql = "select k from meta where 1 = 0",
        .values = &.{},
        .expectation = .{ .scalar_equals = .{ .text = "row" } },
    }}, &failure));
    try testing.expectEqual(@as(u64, 0), failure.?.observed_rows);

    // Oversized text expectations are rejected before any SQL runs.
    const oversized = @as([4097]u8, @splat('x'));
    try testing.expectError(
        error.ScalarExpectationTooLarge,
        node.execCheckedTransaction(&.{.{
            .sql = "select k from meta",
            .values = &.{},
            .expectation = .{ .scalar_equals = .{ .text = &oversized } },
        }}, &failure),
    );
}

// ----------------------------------------------------------------------
// Batched reads (KDS 0018 WP1)
// ----------------------------------------------------------------------

test "query batch returns tagged sets from one snapshot" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    _ = try node.exec("insert into items(v) values ('tea'), ('coffee')");

    var batch = try node.queryBatch(gpa, &.{
        .{ .tag = 11, .sql = "select v from items order by id", .values = &.{} },
        .{
            .tag = 22,
            .sql = "select count(*) from items where v = ?1",
            .values = &.{.{ .text = "tea" }},
        },
    }, .{});
    defer batch.deinit();

    try testing.expectEqual(@as(usize, 2), batch.sets.len);
    try testing.expectEqual(@as(u32, 11), batch.sets[0].tag);
    try testing.expectEqualStrings("v", batch.sets[0].columns[0]);
    try testing.expectEqual(@as(usize, 2), batch.sets[0].rows.len);
    try testing.expectEqualStrings("tea", batch.sets[0].rows[0][0].text);
    try testing.expectEqualStrings("coffee", batch.sets[0].rows[1][0].text);
    try testing.expectEqual(@as(u32, 22), batch.sets[1].tag);
    try testing.expectEqual(@as(i64, 1), batch.sets[1].rows[0][0].integer);

    // The statement cap is enforced before any SQL runs.
    var too_many: [zaxonlite.batch_queries_max + 1]zaxonlite.BatchQuery = undefined;
    for (&too_many) |*entry| {
        entry.* = .{ .tag = 0, .sql = "select 1", .values = &.{} };
    }
    try testing.expectError(
        error.TooManyQueries,
        node.queryBatch(gpa, &too_many, .{}),
    );
}

test "query batch budgets bound rows across statements" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    _ = try node.exec("insert into items(v) values ('a'), ('b'), ('c')");

    // Three rows land in the first set; the shared budget of four admits
    // only one more row before the second statement trips the limit.
    try testing.expectError(error.QueryRowLimit, node.queryBatch(gpa, &.{
        .{ .tag = 1, .sql = "select v from items", .values = &.{} },
        .{ .tag = 2, .sql = "select v from items", .values = &.{} },
    }, .{ .max_rows = 4 }));

    // The same statements fit once the budget covers all six rows, and a
    // shared byte budget trips across statements too.
    var batch = try node.queryBatch(gpa, &.{
        .{ .tag = 1, .sql = "select v from items", .values = &.{} },
        .{ .tag = 2, .sql = "select v from items", .values = &.{} },
    }, .{ .max_rows = 6 });
    batch.deinit();
    try testing.expectError(error.QueryResultTooLarge, node.queryBatch(gpa, &.{
        .{ .tag = 1, .sql = "select printf('%20s', v) from items", .values = &.{} },
        .{ .tag = 2, .sql = "select printf('%20s', v) from items", .values = &.{} },
    }, .{ .max_bytes = 70 }));
}

// ----------------------------------------------------------------------
// SharedNode facade (KDS 0018 WP1)
// ----------------------------------------------------------------------

const SharedNode = zaxonlite.SharedNode;

const ReaderWorker = struct {
    shared: *SharedNode,
    iterations: usize,
    failures: usize = 0,
    rows_seen: usize = 0,

    fn run(self: *ReaderWorker) void {
        var index: usize = 0;
        while (index < self.iterations) : (index += 1) {
            var result = self.shared.queryPrepared(
                testing.allocator,
                "select count(*) from items",
                &.{},
            ) catch {
                self.failures += 1;
                continue;
            };
            defer result.deinit();
            if (result.rows.len == 1) {
                self.rows_seen += 1;
            } else {
                self.failures += 1;
            }
        }
    }
};

const SlowWriter = struct {
    shared: *SharedNode,
    ok: bool = false,

    fn run(self: *SlowWriter) void {
        _ = self.shared.execPrepared(
            "insert into items(v) values ('slow')",
            &.{},
        ) catch return;
        self.ok = true;
    }
};

test "shared node adopt, open, and close lifecycle" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    // The host opens and migrates single-threaded first, then adopts.
    const node = try openNode(dir);
    _ = try node.exec("create table items(id integer primary key, v text)");
    _ = try node.exec("insert into items(v) values ('tea')");

    // Invalid options leave node ownership with the caller.
    try testing.expectError(
        error.InvalidReadConnections,
        SharedNode.adopt(gpa, node, .{ .read_connections = 0 }),
    );
    try testing.expectError(
        error.InvalidWriteQueueDepth,
        SharedNode.adopt(gpa, node, .{ .write_queue_depth = 0 }),
    );

    const adopted = try SharedNode.adopt(gpa, node, .{});
    _ = try adopted.execPrepared(
        "insert into items(v) values (?1)",
        &.{.{ .text = "coffee" }},
    );
    var batch = try adopted.queryBatch(gpa, &.{
        .{ .tag = 7, .sql = "select v from items order by id", .values = &.{} },
        .{ .tag = 8, .sql = "select count(*) from items", .values = &.{} },
    }, .{});
    try testing.expectEqual(@as(u32, 7), batch.sets[0].tag);
    try testing.expectEqual(@as(usize, 2), batch.sets[0].rows.len);
    try testing.expectEqual(@as(i64, 2), batch.sets[1].rows[0][0].integer);
    batch.deinit();
    const report = try adopted.integrityCheck();
    try testing.expect(report.ok());
    // Close owns the node: the directory lock is released below.
    adopted.close();

    // The one-call constructor serves the same data afterwards.
    const reopened = try SharedNode.open(gpa, testing.io, .{ .directory = dir }, .{});
    var result = try reopened.queryPrepared(
        gpa,
        "select count(*) from items",
        &.{},
    );
    try testing.expectEqualStrings("2", result.rows[0][0].?);
    result.deinit();
    reopened.close();
}

test "concurrent read leases proceed while a write commits" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const shared = try SharedNode.open(gpa, testing.io, .{ .directory = dir }, .{});
    defer shared.close();
    _ = try shared.execPrepared(
        "create table items(id integer primary key, v text)",
        &.{},
    );
    _ = try shared.execPrepared("insert into items(v) values ('seed')", &.{});

    var workers = [_]ReaderWorker{
        .{ .shared = shared, .iterations = 40 },
        .{ .shared = shared, .iterations = 40 },
        .{ .shared = shared, .iterations = 40 },
    };
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        thread.* = try std.Thread.spawn(.{}, ReaderWorker.run, .{worker});
    }
    var writes: usize = 0;
    while (writes < 20) : (writes += 1) {
        _ = try shared.execPrepared("insert into items(v) values ('w')", &.{});
    }
    for (&threads) |*thread| thread.join();
    for (workers) |worker| {
        try testing.expectEqual(@as(usize, 0), worker.failures);
        try testing.expectEqual(worker.iterations, worker.rows_seen);
    }
    var result = try shared.queryPrepared(gpa, "select count(*) from items", &.{});
    defer result.deinit();
    try testing.expectEqualStrings("21", result.rows[0][0].?);
}

test "write queue at capacity returns WriteQueueFull" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    // The injected storage delay keeps the first write's admission ticket
    // held long enough for the second write to observe a full queue.
    const shared = try SharedNode.open(gpa, testing.io, .{
        .directory = dir,
        .test_storage_delay_ms = 600,
    }, .{ .write_queue_depth = 1 });
    defer shared.close();
    _ = try shared.execPrepared(
        "create table items(id integer primary key, v text)",
        &.{},
    );

    var slow = SlowWriter{ .shared = shared };
    const thread = try std.Thread.spawn(.{}, SlowWriter.run, .{&slow});
    try testing.io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(
        error.WriteQueueFull,
        shared.execPrepared("insert into items(v) values ('rejected')", &.{}),
    );
    thread.join();
    try testing.expect(slow.ok);

    // The queue drains: the next write is admitted normally.
    _ = try shared.execPrepared("insert into items(v) values ('after')", &.{});
    var result = try shared.queryPrepared(gpa, "select count(*) from items", &.{});
    defer result.deinit();
    try testing.expectEqualStrings("2", result.rows[0][0].?);
}

test "checkpoint drains pooled readers and readers resume afterward" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const shared = try SharedNode.open(gpa, testing.io, .{ .directory = dir }, .{});
    defer shared.close();
    _ = try shared.execPrepared(
        "create table items(id integer primary key, v text)",
        &.{},
    );
    _ = try shared.execPrepared("insert into items(v) values ('tea')", &.{});

    // Populate the pool so the anchor's checkpoint has live reader
    // connections to drain, and keep readers running across it.
    var warm = try shared.queryPrepared(gpa, "select v from items", &.{});
    warm.deinit();
    var worker = ReaderWorker{ .shared = shared, .iterations = 30 };
    const thread = try std.Thread.spawn(.{}, ReaderWorker.run, .{&worker});
    try shared.createStateAnchor();
    thread.join();
    try testing.expectEqual(@as(usize, 0), worker.failures);

    // The anchor published and reads and writes still serve.
    const after = try shared.status();
    try testing.expect(after.durable_state_slot > 0);
    _ = try shared.execPrepared("insert into items(v) values ('post')", &.{});
    var result = try shared.queryPrepared(gpa, "select count(*) from items", &.{});
    defer result.deinit();
    try testing.expectEqualStrings("2", result.rows[0][0].?);
}

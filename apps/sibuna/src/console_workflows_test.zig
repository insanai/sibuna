const repeat = @import("text").repeat;
const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const w = p.workflows;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

test {
    _ = @import("console_country_test.zig");
}

fn open(sub: []const u8, buffer: *[160]u8, tmp: *std.testing.TmpDir) !*fixture.Fixture {
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub }),
    );
    try fixture.policySession(fx);
    return fx;
}

fn rule(fx: *fixture.Fixture, id: []const u8, priority: i32, path: []const u8) !u64 {
    var text: [512]u8 = undefined;
    const document = try std.fmt.bufPrint(&text, "{{\"id\":\"{s}\",\"name\":\"{s}\"," ++
        "\"action\":\"deny\",\"priority\":{d},\"path\":\"{s}\"}}", .{ id, id, priority, path });
    const result = try fx.run(.{ .policy_edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = fx.owner.version,
        .document = try p.Bytes(4096).init(document),
    } });
    try t.expect(result == .revision);
    return result.revision.committed;
}

fn priorities(fx: *fixture.Fixture, buffer: []u8) ![]const u8 {
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT group_concat(id||':'||priority,' ') " ++
            "FROM (SELECT id,priority FROM policies ORDER BY priority,name,id)",
        &.{},
    );
    defer rows.deinit();
    const text = rows.rows[0][0] orelse "";
    @memcpy(buffer[0..text.len], text);
    return buffer[0..text.len];
}

test "ordering swaps or nudges adjacent rules in one audited revision" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("order", &path, &tmp);
    defer fx.close();
    _ = try rule(fx, "a", 10, "/a");
    _ = try rule(fx, "b", 20, "/b");
    const revision = try rule(fx, "c", 20, "/c");
    var text: [128]u8 = undefined;
    try t.expectEqualStrings("a:10 b:20 c:20", try priorities(fx, &text));
    // A tie moves by one; the neighbour keeps its priority.
    const moved = try fx.run(.{ .policy_order = .{
        .auth = auth,
        .expected_revision = revision,
        .id = try p.Bytes(128).init("c"),
        .direction = .up,
    } });
    try t.expect(moved == .revision and moved.revision.committed == revision + 1);
    try t.expectEqualStrings("a:10 c:19 b:20", try priorities(fx, &text));
    // Different priorities swap.
    const swapped = try fx.run(.{ .policy_order = .{
        .auth = auth,
        .expected_revision = revision + 1,
        .id = try p.Bytes(128).init("a"),
        .direction = .down,
    } });
    try t.expect(swapped == .revision);
    try t.expectEqualStrings("c:10 a:19 b:20", try priorities(fx, &text));
    // Nothing above the first rule; a stale revision conflicts; audit and history recorded.
    const edge = try fx.run(.{ .policy_order = .{
        .auth = auth,
        .expected_revision = revision + 2,
        .id = try p.Bytes(128).init("c"),
        .direction = .up,
    } });
    try t.expect(edge == .failed and edge.failed == .invalid_input);
    const stale = try fx.run(.{ .policy_order = .{
        .auth = auth,
        .expected_revision = revision,
        .id = try p.Bytes(128).init("b"),
        .direction = .up,
    } });
    try t.expect(stale == .failed and stale.failed == .conflict);
    const util = @import("console_store.zig");
    var counts = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT COUNT(*) FROM console_audit WHERE action='policy.order')," ++
            "(SELECT COUNT(*) FROM console_policy_history WHERE revision=?)," ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')",
        &.{util.integer(revision + 1)},
    );
    defer counts.deinit();
    try t.expectEqualStrings("2", counts.rows[0][0].?);
    try t.expectEqualStrings("2", counts.rows[0][1].?);
    try t.expectEqual(revision + 2, try @import("console_store.zig").number(counts.rows[0][2]));
}

test "reputation prefixes preflight capacity, commit with audit and remove by revision" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("reputation", &path, &tmp);
    defer fx.close();
    const bad = try fx.run(.{ .reputation_edit = .{
        .auth = auth,
        .expected_revision = fx.owner.version,
        .prefix = try p.Bytes(w.max_prefix).init("not-a-prefix"),
        .action = .deny,
    } });
    try t.expect(bad == .failed and bad.failed == .invalid_input);
    const denied = try fx.run(.{ .reputation_edit = .{
        .auth = auth,
        .expected_revision = fx.owner.version,
        .prefix = try p.Bytes(w.max_prefix).init("203.0.113.0/24"),
        .action = .deny,
        .note = try p.Bytes(w.max_note).init("scanner range"),
    } });
    try t.expect(denied == .revision);
    try fx.owner.tick();
    var page = try fx.run(.{ .reputation_query = .{ .auth = auth } });
    try t.expect(page == .reputation_page and page.reputation_page.count == 1);
    const row = page.reputation_page.rows[0];
    try t.expectEqualStrings("203.0.113.0/24", row.prefix.slice());
    try t.expectEqual(@as(i32, -100), row.score);
    try t.expectEqualStrings("console", row.source.slice());
    try t.expectEqualStrings("scanner range", row.note.slice());
    try t.expect(fx.engine.ip_trie.node_count > 1);
    // The trie fills: /128 prefixes far apart each cost many nodes.
    var revision = denied.revision.committed;
    var outcome: ?p.Failure = null;
    var index: u32 = 0;
    while (index < 200) : (index += 1) {
        var text: [48]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&text, "2001:db8:{x}:{x}::1/128", .{
            index * 7919 % 65536,
            index * 104729 % 65536,
        });
        const result = try fx.run(.{ .reputation_edit = .{
            .auth = auth,
            .expected_revision = revision,
            .prefix = try p.Bytes(w.max_prefix).init(prefix),
            .action = .deny,
        } });
        if (result == .failed) {
            outcome = result.failed;
            break;
        }
        revision = result.revision.committed;
    }
    try t.expectEqual(p.Failure.capacity, outcome.?);
    const removed = try fx.run(.{ .reputation_remove = .{
        .auth = auth,
        .expected_revision = revision,
        .prefix = try p.Bytes(w.max_prefix).init("203.0.113.0/24"),
    } });
    try t.expect(removed == .revision);
    page = try fx.run(.{ .reputation_query = .{ .auth = auth } });
    for (page.reputation_page.rows[0..page.reputation_page.count]) |entry|
        try t.expect(!std.mem.eql(u8, entry.prefix.slice(), "203.0.113.0/24"));
    var audit = try db.query(fx.owner.db, t.allocator, "SELECT COUNT(*) FROM console_audit " ++
        "WHERE action IN ('reputation.edit','reputation.remove')", &.{});
    defer audit.deinit();
    try t.expect(try @import("console_store.zig").number(audit.rows[0][0]) >= 3);
}

test "replay counts conclusive matches against the live engine and a draft" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("replay", &path, &tmp);
    defer fx.close();
    const revision = try rule(fx, "replay-deny", 5, "/replay");
    try fx.owner.tick();
    const now = fx.owner.nowSeconds();
    inline for (.{
        .{ 1, "/replay", 1, 0, 0, 0 },
        .{ 2, "/replay", 1, 4, 0, 0 },
        .{ 3, "/elsewhere", 1, 0, 0, 0 },
        .{ 4, "/replay", 1, 0, 0, 1 },
    }) |row| {
        var sql: [512]u8 = undefined;
        const incident = try std.fmt.bufPrint(
            &sql,
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
                "violation_category,offending_payload,recorded_at) VALUES({d},1," ++
                "'198.51.100.{d}','Mozilla','GET','{s}','waf:sqli','x',{d})",
            .{ row[0], row[0], row[1], now },
        );
        _ = try db.exec(fx.owner.db, t.allocator, incident, &.{});
        var evidence_sql: [512]u8 = undefined;
        const evidence = try std.fmt.bufPrint(
            &evidence_sql,
            "INSERT INTO console_incident_evidence(incident_id,version,selected_status," ++
                "query_bytes,body_bytes,declared_body_bytes,truncated) " ++
                "VALUES({d},{d},403,{d},{d},0,{d})",
            .{ row[0], row[2], row[3], row[4], row[5] },
        );
        _ = try db.exec(fx.owner.db, t.allocator, evidence, &.{});
    }
    const live = try fx.run(.{ .policy_replay = .{
        .auth = auth,
        .rule = try p.Bytes(128).init("replay-deny"),
        .hours = 1,
    } });
    try t.expect(live == .replay_summary);
    try t.expectEqual(@as(u32, 4), live.replay_summary.total);
    try t.expectEqual(@as(u32, 3), live.replay_summary.matched);
    try t.expectEqual(@as(u32, 2), live.replay_summary.inconclusive);
    try t.expect(!live.replay_summary.preview);
    const draft = try fx.run(.{ .policy_replay = .{
        .auth = auth,
        .committed = revision,
        .draft = try p.Bytes(4096).init("{\"id\":\"replay-deny\",\"name\":\"replay-deny\"," ++
            "\"action\":\"deny\",\"path\":\"/elsewhere\"}"),
        .rule = try p.Bytes(128).init("replay-deny"),
        .hours = 1,
    } });
    try t.expect(draft == .replay_summary and draft.replay_summary.preview);
    try t.expectEqual(@as(u32, 1), draft.replay_summary.matched);
    const stale = try fx.run(.{ .policy_replay = .{
        .auth = auth,
        .committed = revision + 5,
        .draft = try p.Bytes(4096).init("{\"id\":\"x\",\"name\":\"x\",\"action\":\"deny\"}"),
        .hours = 1,
    } });
    try t.expect(stale == .failed and stale.failed == .conflict);
}

test "country prefixes stage in chunks, preflight in a candidate and apply pinned" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("country", &path, &tmp);
    defer fx.close();
    const digest: [32]u8 = @splat(7);
    var chunk: w.CountryChunk = .{ .digest = digest, .ordinal = 0 };
    for ([_][]const u8{ "192.0.2.0/24", "198.51.100.0/25", "198.51.100.128/25" }) |prefix| {
        chunk.prefixes[chunk.count] = try p.Bytes(w.max_prefix).init(prefix);
        chunk.count += 1;
    }
    try t.expect((try fx.run(.{ .country_chunk = chunk })) == .command_recorded);
    const short = try fx.run(.{ .country_preflight = .{
        .auth = auth,
        .expected_revision = fx.owner.version,
        .digest = digest,
        .count = 4,
        .country = "ZZ".*,
    } });
    try t.expect(short == .failed and short.failed == .invalid_input);
    const preview = try fx.run(.{ .country_preflight = .{
        .auth = auth,
        .expected_revision = fx.owner.version,
        .digest = digest,
        .count = 3,
        .country = "ZZ".*,
    } });
    try t.expect(preview == .country_summary);
    try t.expectEqual(@as(u16, 3), preview.country_summary.prefixes);
    try t.expect(preview.country_summary.nodes_after > preview.country_summary.nodes_before);
    try t.expectEqual(@as(u16, 0), preview.country_summary.overlaps);
    const applied = try fx.run(.{ .country_apply = .{
        .auth = auth,
        .expected_revision = fx.owner.version,
        .digest = digest,
        .count = 3,
        .country = "ZZ".*,
        .action = .deny,
        .geo_generation = try p.Bytes(64).init(&repeat("ab", 32)),
    } });
    try t.expect(applied == .revision);
    var rows = try db.query(fx.owner.db, t.allocator, "SELECT COUNT(*),MIN(source)," ++
        "MIN(geo_generation) FROM ip_reputation WHERE source='console:country:ZZ'", &.{});
    defer rows.deinit();
    try t.expectEqualStrings("3", rows.rows[0][0].?);
    try t.expectEqualStrings(&repeat("ab", 32), rows.rows[0][2].?);
    var stage = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT COUNT(*) FROM console_country_stage",
        &.{},
    );
    defer stage.deinit();
    try t.expectEqualStrings("0", stage.rows[0][0].?);
}

test "set import replaces every managed rule atomically or not at all" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("import", &path, &tmp);
    defer fx.close();
    const revision = try rule(fx, "old", 10, "/old");
    const digest: [32]u8 = @splat(9);
    const documents = [_][]const u8{
        "{\"id\":\"new-a\",\"name\":\"New A\",\"action\":\"deny\",\"path\":\"/new-a\"}",
        "{\"id\":\"new-b\",\"name\":\"New B\",\"action\":\"allow\",\"path\":\"/new-b\"," ++
            "\"priority\":5}",
    };
    for (documents, 0..) |document, ordinal| try t.expect((try fx.run(.{ .import_chunk = .{
        .digest = digest,
        .ordinal = @intCast(ordinal),
        .document = try p.Bytes(4096).init(document),
    } })) == .command_recorded);
    const invalid = try fx.run(.{ .import_chunk = .{
        .digest = digest,
        .ordinal = 2,
        .document = try p.Bytes(4096).init("{\"id\":\"broken\"}"),
    } });
    try t.expect(invalid == .failed and invalid.failed == .invalid_input);
    const wrong_count = try fx.run(.{ .import_commit = .{
        .auth = auth,
        .expected_revision = revision,
        .digest = digest,
        .count = 3,
    } });
    try t.expect(wrong_count == .failed and wrong_count.failed == .invalid_input);
    const committed = try fx.run(.{ .import_commit = .{
        .auth = auth,
        .expected_revision = revision,
        .digest = digest,
        .count = 2,
    } });
    try t.expect(committed == .revision and committed.revision.committed == revision + 1);
    var ids = try db.query(fx.owner.db, t.allocator, "SELECT group_concat(id,' ') FROM " ++
        "(SELECT id FROM policies ORDER BY priority,name,id)", &.{});
    defer ids.deinit();
    try t.expectEqualStrings("new-b new-a", ids.rows[0][0].?);
    var audit = try db.query(fx.owner.db, t.allocator, "SELECT COUNT(*) FROM console_audit " ++
        "WHERE action='policy.import'", &.{});
    defer audit.deinit();
    try t.expectEqualStrings("1", audit.rows[0][0].?);
    // A duplicate id inside the set fails candidate validation and leaves the rules alone.
    const again: [32]u8 = @splat(10);
    for ([_][]const u8{ documents[0], documents[0] }, 0..) |document, ordinal|
        _ = try fx.run(.{ .import_chunk = .{
            .digest = again,
            .ordinal = @intCast(ordinal),
            .document = try p.Bytes(4096).init(document),
        } });
    const rejected = try fx.run(.{ .import_commit = .{
        .auth = auth,
        .expected_revision = revision + 1,
        .digest = again,
        .count = 2,
    } });
    try t.expect(rejected == .failed and rejected.failed == .invalid_input);
    var still = try db.query(fx.owner.db, t.allocator, "SELECT COUNT(*) FROM policies", &.{});
    defer still.deinit();
    try t.expectEqualStrings("2", still.rows[0][0].?);
}

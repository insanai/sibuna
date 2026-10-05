//! Store-level conservation and failure atomicity, independent of finding metadata.
const std = @import("std");
const t = std.testing;
const scores = @import("score_journal.zig");
const tx = @import("transaction_vars.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const keys = [_][]const u8{
    "inbound_anomaly_score_pl1",  "inbound_anomaly_score_pl2",
    "inbound_anomaly_score_pl3",  "inbound_anomaly_score_pl4",
    "outbound_anomaly_score_pl1", "outbound_anomaly_score_pl2",
    "outbound_anomaly_score_pl3", "outbound_anomaly_score_pl4",
};

test "committed numeric transitions conserve every paranoia bucket across roots" {
    var entries: [8]variables.Entry = undefined;
    const bytes = try t.allocator.alloc(u8, 64 * 1024);
    defer t.allocator.free(bytes);
    var store = tx.Store.init(&entries, bytes);
    var rows: [16]scores.Row = undefined;
    var journal: scores.Journal = .{ .rows = &rows };
    journal.reset();
    store.journal = &journal;
    var budget: work.Budget = .{ .remaining = 10_000_000 };
    // Initialization outside rule execution establishes the initial value, not a finding.
    for (keys) |key| try store.put(key, "3", &budget);
    for (0..1000) |index| {
        const root = (index * 7) % rows.len;
        const bucket = index % keys.len;
        journal.bind(root, @intCast(root + 1), .request_body);
        defer journal.unbind();
        const key = keys[bucket];
        switch (index % 5) {
            0 => try store.update(key, .assign, "-9", &budget),
            1 => try store.update(key, .add, "5suffix", &budget),
            2 => try store.update(key, .subtract, "-2", &budget),
            3 => {
                _ = try store.remove(key, &budget);
            },
            4 => try store.update(key, .add, "invalid-zero", &budget),
            else => unreachable,
        }
    }
    for (keys, 0..) |key, bucket| {
        const value = try store.get(key, &budget);
        const final = if (value) |number| try std.fmt.parseInt(i64, number, 10) else 0;
        var sum: i64 = 0;
        for (&rows) |*row| if (row.writes[bucket] != 0) {
            sum += row.value(bucket).?;
        };
        try t.expectEqual(final - 3, sum);
    }
    try t.expect(journal.owner == null);
    journal.reset();
    for (rows) |row| try t.expect(!row.observed());
}

test "unknown numeric transitions remain unknown instead of becoming false zero" {
    var rows: [3]scores.Row = undefined;
    var journal: scores.Journal = .{ .rows = &rows };
    journal.reset();
    journal.bind(0, 1, .request_body);
    journal.committed(keys[0], null, "5");
    journal.committed(keys[0], "5", "secret-payload");
    journal.committed(keys[0], "secret-payload", "0");
    try t.expectEqual(@as(u32, 3), rows[0].writes[0]);
    try t.expectEqual(@as(?i64, null), rows[0].value(0));
    try t.expectEqual(@as(?i64, null), rows[0].value(1));
    journal.unbind();
    journal.bind(1, 2, .response_body);
    journal.committed(keys[4], "-9223372036854775808", "9223372036854775807");
    try t.expectEqual(@as(?i64, null), rows[1].value(4));
    journal.unbind();
    journal.bind(2, 3, .request_headers);
    journal.committed(keys[2], null, "9223372036854775807");
    journal.committed(keys[2], null, "1");
    try t.expectEqual(@as(?i64, null), rows[2].value(2));
    journal.committed(keys[3], "1_000", "0");
    try t.expectEqual(@as(?i64, null), rows[2].value(3));
    journal.unbind();
}

test "failed store writes never publish a score observation" {
    for (0..80) |allowance| {
        var entries: [1]variables.Entry = undefined;
        var bytes: [64]u8 = undefined;
        var store = tx.Store.init(&entries, &bytes);
        var rows: [1]scores.Row = undefined;
        var journal: scores.Journal = .{ .rows = &rows };
        journal.reset();
        var budget: work.Budget = .{ .remaining = 10_000 };
        try store.put(keys[0], "2", &budget);
        store.journal = &journal;
        journal.bind(0, 1, .request_body);
        defer journal.unbind();
        budget.remaining = allowance;
        if (store.put(keys[0], "3", &budget)) |_| {
            try t.expectEqual(@as(?i64, 1), rows[0].value(0));
        } else |err| {
            try t.expectEqual(error.WorkLimit, err);
            try t.expect(!rows[0].observed());
            try t.expectEqualStrings("2", store.entries[0].value);
        }
    }
}

test "classification follows TX case matching and excludes rollups category scores and aliases" {
    for (keys, 0..) |key, bucket| try t.expectEqual(@as(?usize, bucket), scores.classify(key));
    try t.expectEqual(@as(?usize, 7), scores.classify("OUTBOUND_ANOMALY_SCORE_PL4"));
    const excluded = [_][]const u8{
        "inbound_anomaly_score",           "blocking_inbound_anomaly_score",
        "detection_inbound_anomaly_score", "sql_injection_score",
        "inbound_anomaly_score_pl0",       "inbound_anomaly_score_pl5",
        "inbound_anomaly_score_pl1\x00",   "",
    };
    for (excluded) |key| try t.expect(scores.classify(key) == null);
}

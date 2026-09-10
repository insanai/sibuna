const std = @import("std");
const t = std.testing;
const p = @import("console_protocol").rule_hits;
const Counters = @import("store").rule_hits.Counters(p.max_rules);
const Journal = @import("rule_hit_journal.zig").Journal;

fn generation(number: u64, utc: u64, len: usize) p.Generation {
    var result: p.Generation = .{
        .node = 1,
        .boot = @splat(1),
        .number = number,
        .revision = number + 10,
        .born = .{ .utc = utc, .ms = utc * 1000 },
        .len = len,
    };
    for (result.rules[0..len]) |*identity| identity.* = .{
        .key = p.Key.init("m:rule") catch unreachable,
        .name = p.Name.init("Original name") catch unreachable,
    };
    return result;
}

fn observe(journal: *Journal, counters: *Counters, utc: u64) void {
    var snapshot: Counters.Snapshot = undefined;
    counters.read(&snapshot);
    journal.observe(&snapshot, .{ .utc = utc, .ms = utc * 1000 });
}

test "whole ending-minute cohorts conserve exact counts and immutable identities" {
    const journal = try t.allocator.create(Journal);
    defer t.allocator.destroy(journal);
    journal.* = .{};
    var source = generation(1, 60, 9);
    journal.begin(&source);
    source.rules[0].name = try p.Name.init("Recycled name");
    var counters: Counters = .{ .generation = 1 };
    var matches = Counters.Matches.initEmpty();
    matches.set(0);
    for (61..181) |utc| {
        counters.record(&matches);
        observe(journal, &counters, utc);
    }
    const first = journal.pending().?;
    try first.span.validate();
    try t.expectEqual(@as(u64, 59), first.entries[0].hits);
    try t.expect(!first.span.complete);
    try t.expectEqualStrings("Original name", first.entries[0].identity.name.slice());
    journal.acknowledge();
    try t.expectEqual(@as(usize, 1), journal.pending().?.entries.len);
    journal.acknowledge();
    const full = journal.pending().?;
    try full.span.validate();
    try t.expect(full.span.complete);
    try t.expectEqual(@as(u64, 60), full.entries[0].hits);
    try t.expectEqual(@as(u64, 1), journal.status.confirmed);
}

test "publication, failed writes and a full queue preserve ownership and expose loss" {
    const journal = try t.allocator.create(Journal);
    defer t.allocator.destroy(journal);
    journal.* = .{};
    for (1..7) |number| {
        const source = generation(number, number * 60, 1);
        journal.begin(&source);
        var counters: Counters = .{ .generation = number };
        counters.values[0].store(number, .monotonic);
        var snapshot: Counters.Snapshot = undefined;
        counters.read(&snapshot);
        journal.finish(&snapshot, .{ .utc = number * 60 + 1, .ms = number * 60000 + 1000 });
        counters.reset(number + 1);
    }
    try t.expectEqual(@as(usize, 4), journal.count);
    try t.expectEqual(@as(u64, 2), journal.status.unconfirmed);
    const retry = journal.pending().?;
    try t.expectEqual(@as(u64, 1), retry.span.generation);
    try t.expectEqual(@as(u64, 1), retry.entries[0].hits);
    try t.expect(!retry.span.complete);
    journal.discard();
    try t.expectEqual(@as(u64, 3), journal.status.unconfirmed);
    try t.expectEqual(@as(u64, 2), journal.pending().?.span.generation);
}

test "clock reset and saturated counters never become apparently complete zeroes" {
    const journal = try t.allocator.create(Journal);
    defer t.allocator.destroy(journal);
    journal.* = .{};
    const source = generation(1, 120, 1);
    journal.begin(&source);
    var counters: Counters = .{ .generation = 1 };
    observe(journal, &counters, 119);
    try t.expectEqual(@as(u64, 1), journal.status.clock_resets);
    counters.overflow.store(true, .monotonic);
    observe(journal, &counters, 121);
    observe(journal, &counters, 180);
    try t.expectEqual(@as(?u64, null), journal.pending().?.entries[0].hits);
    try t.expect(!journal.pending().?.span.complete);
    try t.expect(journal.status.overflow);
}

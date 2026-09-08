const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const Journal = @import("minute_journal.zig").Journal;
const Mailbox = @import("mailbox.zig").Mailbox;

fn interval(index: u64) p.timeline.Bucket {
    return .{
        .sequence = index / 4,
        .utc_start = 100 + (index - 1) / 4,
        .utc_end = 100 + index / 4,
        .start_ms = (index - 1) * 250,
        .end_ms = index * 250,
        .observed_ms = 250,
        .observations = 1,
        .counts = .{ .admitted = 1 },
    };
}

test "minute aggregation distinguishes startup, complete intervals, gaps and observation resets" {
    var journal: Journal = .{ .node = 1, .boot = @splat(1) };
    for (1..321) |i| journal.observe(1, interval(i));
    try t.expectEqual(@as(usize, 2), journal.count);
    const startup = journal.jobs[0].record;
    const full = journal.jobs[1].record;
    try t.expect(startup.sealed and !startup.complete);
    try t.expectEqual(@as(u64, 79), startup.counts.admitted);
    try t.expect(full.sealed and full.complete and !full.gap);
    try t.expectEqual(@as(u64, 240), full.counts.admitted);
    try t.expectEqual(@as(u64, 60000), full.observed_ms);
    try t.expect(!journal.current.?.sealed and !journal.current.?.complete);
    journal.observe(2, null);
    try t.expect(journal.current == null and !journal.complete_candidate);
    try t.expectEqual(@as(u64, 1), journal.status().unconfirmed_snapshots);
    var gap = interval(321);
    gap.observed_ms = 10000;
    gap.end_ms = gap.start_ms + gap.observed_ms;
    gap.utc_end = gap.utc_start + 10;
    gap.gap = true;
    journal.observe(2, gap);
    try t.expect(journal.current.?.gap);
    try t.expectEqual(@as(u64, 10000), journal.current.?.observed_ms);
}

test "pending partial snapshots coalesce without changing the in-flight acknowledgement" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{ .boot = @splat(1), .prune_at = std.math.maxInt(u64) };
    defer journal.stop(t.io, mailbox);
    journal.observe(1, interval(1));
    journal.tick(t.io, mailbox, 101, 5000);
    const first = mailbox.take(t.io).?;
    try t.expectEqual(@as(u64, 1), first.request.minutes_write.record.counts.admitted);
    journal.observe(1, interval(2));
    journal.tick(t.io, mailbox, 101, 10000);
    try t.expectEqual(@as(u32, 2), journal.status().pending);
    journal.observe(1, interval(3));
    journal.offer(journal.current.?);
    try mailbox.complete(t.io, first.ticket, .command_recorded);
    journal.tick(t.io, mailbox, 101, 10250);
    try t.expectEqual(@as(u64, 250), journal.status().last_saved_end_ms);
    journal.tick(t.io, mailbox, 101, 10500);
    const next = mailbox.take(t.io).?;
    try t.expectEqual(@as(u64, 3), next.request.minutes_write.record.counts.admitted);
    try mailbox.complete(t.io, next.ticket, .command_recorded);
    journal.tick(t.io, mailbox, 101, 10750);
    try t.expectEqual(@as(u64, 2), journal.status().saved_snapshots);
    try t.expectEqual(@as(u32, 0), journal.status().pending);
}

test "timed out SQL retains ownership and newer samples do not reset the bounded retry budget" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{
        .boot = @splat(1),
        .prune_at = std.math.maxInt(u64),
        .offered_ms = std.math.maxInt(u64),
    };
    defer journal.stop(t.io, mailbox);
    journal.observe(1, interval(1));
    journal.offer(journal.current.?);
    journal.tick(t.io, mailbox, 101, 0);
    const abandoned = mailbox.take(t.io).?;
    journal.tick(t.io, mailbox, 111, 10000);
    try t.expect(journal.ticket == null);
    try mailbox.complete(t.io, abandoned.ticket, .command_recorded);
    for (0..7) |attempt| {
        journal.observe(1, interval(attempt + 2));
        journal.offer(journal.current.?);
        const ms = 100000 * (attempt + 1);
        journal.tick(t.io, mailbox, 112, ms);
        const work = mailbox.take(t.io).?;
        try mailbox.complete(t.io, work.ticket, .{ .failed = .unavailable });
        journal.tick(t.io, mailbox, 112, ms + 250);
    }
    try t.expectEqual(@as(u64, 0), journal.status().saved_snapshots);
    try t.expectEqual(@as(u64, 1), journal.status().unconfirmed_snapshots);
    try t.expectEqual(@as(u32, 0), journal.status().pending);
}

test "slow retention cannot starve minute writes and shutdown releases queued work" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{ .boot = @splat(1), .offered_ms = std.math.maxInt(u64) };
    journal.observe(1, interval(1));
    journal.offer(journal.current.?);
    journal.tick(t.io, mailbox, 101, 0);
    const pruning = mailbox.take(t.io).?;
    try t.expect(pruning.request == .minutes_prune);
    try mailbox.complete(t.io, pruning.ticket, .command_recorded);
    journal.tick(t.io, mailbox, 111, 10000);
    journal.tick(t.io, mailbox, 111, 10250);
    const write = mailbox.take(t.io).?;
    try t.expect(write.request == .minutes_write);
    journal.stop(t.io, mailbox);
    try mailbox.complete(t.io, write.ticket, .command_recorded);
    try t.expect(mailbox.take(t.io) == null);
    try t.expectEqual(@as(u32, 0), journal.status().pending);
}

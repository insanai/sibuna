const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const Mailbox = @import("mailbox.zig").Mailbox;
const Journal = @import("rankings_journal.zig").Journal;
const Minute = @import("rankings.zig").Minute;

fn minute() !Minute {
    var result: Minute = .{ .minute = 1, .first_second = 100, .last_second = 100 };
    try result.paths.add("/observed");
    return result;
}

test "journal never waits for storage and publishes only after the finish acknowledgement" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{ .boot = @splat(1), .prune_at = std.math.maxInt(u64) };
    defer journal.stop(t.io, mailbox);
    const source = try minute();
    journal.offer(&source, 3);
    journal.offer(&source, 3);
    journal.offer(&source, 3);
    try t.expectEqual(@as(u32, 2), journal.status(t.io).pending);
    try t.expectEqual(@as(u64, 1), journal.status(t.io).unconfirmed_since_boot);
    const expected = [_]std.meta.Tag(p.StorageRequest){
        .rankings_begin, .rankings_chunk, .rankings_finish,
    };
    for (expected, 0..) |tag, step| {
        const ms = step * 500;
        journal.tick(t.io, mailbox, 180, ms);
        try t.expectEqual(@as(u64, 0), journal.status(t.io).saved_since_boot);
        const work = mailbox.take(t.io).?;
        try t.expectEqual(tag, std.meta.activeTag(work.request));
        try mailbox.complete(t.io, work.ticket, .command_recorded);
        journal.tick(t.io, mailbox, 180, ms + 250);
    }
    try t.expectEqual(@as(u64, 1), journal.status(t.io).saved_since_boot);
    try t.expectEqual(@as(?u64, 1), journal.status(t.io).last_saved_minute);
    try t.expectEqual(@as(u32, 1), journal.status(t.io).pending);
}

test "timed out executing writes retain mailbox ownership and retries stop at their bound" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{ .boot = @splat(1), .prune_at = std.math.maxInt(u64) };
    defer journal.stop(t.io, mailbox);
    const source = try minute();
    journal.offer(&source, 0);
    journal.tick(t.io, mailbox, 180, 0);
    const old = mailbox.take(t.io).?;
    journal.tick(t.io, mailbox, 190, 10000);
    try t.expect(journal.ticket == null);
    journal.tick(t.io, mailbox, 191, 11000);
    const retry = mailbox.take(t.io).?;
    try t.expect(retry.ticket.id != old.ticket.id);
    try t.expect(retry.request == .rankings_begin);
    try t.expectEqualDeep(old.request.rankings_begin.digest, retry.request.rankings_begin.digest);
    try t.expectEqual(
        old.request.rankings_begin.total_bytes,
        retry.request.rankings_begin.total_bytes,
    );
    try mailbox.complete(t.io, old.ticket, .command_recorded);
    try mailbox.complete(t.io, retry.ticket, .{ .failed = .unavailable });
    journal.tick(t.io, mailbox, 191, 11250);
    var ms: u64 = 80000;
    for (0..6) |_| {
        journal.tick(t.io, mailbox, 200, ms);
        const work = mailbox.take(t.io).?;
        try mailbox.complete(t.io, work.ticket, .{ .failed = .unavailable });
        journal.tick(t.io, mailbox, 200, ms + 250);
        ms += 80000;
    }
    try t.expectEqual(@as(u32, 0), journal.status(t.io).pending);
    try t.expectEqual(@as(u64, 1), journal.status(t.io).unconfirmed_since_boot);
    try t.expectEqual(@as(u64, 0), journal.status(t.io).saved_since_boot);
}

test "maintenance errors are visible and shutdown releases pending tickets" {
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var journal: Journal = .{};
    journal.tick(t.io, mailbox, 180, 0);
    const work = mailbox.take(t.io).?;
    try t.expect(work.request == .rankings_prune);
    try mailbox.complete(t.io, work.ticket, .{ .failed = .unavailable });
    journal.tick(t.io, mailbox, 180, 250);
    try t.expectEqual(@as(u64, 1), journal.status(t.io).maintenance_failures_since_boot);
    journal.tick(t.io, mailbox, 185, 5000);
    journal.stop(t.io, mailbox);
    try t.expect(mailbox.take(t.io) == null);
}

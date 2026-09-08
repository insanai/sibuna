//! Periodic cleanup must not wait on the storage owner and stall the 4 Hz collector.
const std = @import("std");
const Mailbox = @import("mailbox.zig").Mailbox;
pub const Maintenance = struct {
    ticket: ?Mailbox.Ticket = null,
    started_ms: u64 = 0,
    next_ms: u64 = 0,

    /// Returns true for an unconfirmed/failed attempt, never as proof SQL was cancelled.
    pub fn tick(
        self: *Maintenance,
        io: std.Io,
        mailbox: *Mailbox,
        now: u64,
        ms: u64,
        eligible: bool,
    ) bool {
        if (self.ticket) |ticket| {
            const result = mailbox.poll(io, ticket) catch @panic("GeoIP cleanup ticket ownership");
            if (result) |done| {
                self.ticket = null;
                self.next_ms = ms +| 5000;
                return done != .command_recorded;
            }
            if (ms -| self.started_ms < 10000) return false;
            self.stop(io, mailbox);
            self.next_ms = ms +| 5000;
            return true;
        }
        if (!eligible or ms < self.next_ms) return false;
        self.next_ms = ms +| 5000;
        self.ticket = mailbox.submit(io, .{ .geo_prune = now }, .background) catch return true;
        self.started_ms = ms;
        return false;
    }

    /// Join the collector before abandoning its owned request; storage can still finish SQL.
    pub fn stop(self: *Maintenance, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("GeoIP cleanup cancellation ownership");
        self.ticket = null;
    }
};

test "cleanup is nonblocking, paced and retains executing request ownership after timeout" {
    const t = std.testing;
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var job: Maintenance = .{};
    try t.expect(!job.tick(t.io, mailbox, 100, 0, false));
    try t.expect(mailbox.take(t.io) == null);
    try t.expect(!job.tick(t.io, mailbox, 100, 0, true));
    const work = mailbox.take(t.io).?;
    try t.expectEqual(@as(u64, 100), work.request.geo_prune);
    for (1..40) |i| try t.expect(!job.tick(t.io, mailbox, 100, i * 250, true));
    try t.expect(job.tick(t.io, mailbox, 110, 10000, true));
    try t.expect(job.ticket == null);
    // Completion of abandoned SQL frees its own slot, without reaching a future caller.
    try mailbox.complete(t.io, work.ticket, .command_recorded);
    try t.expect(!job.tick(t.io, mailbox, 114, 14999, true));
    try t.expect(mailbox.take(t.io) == null);
    try t.expect(!job.tick(t.io, mailbox, 115, 15000, true));
    const next = mailbox.take(t.io).?;
    try t.expect(next.ticket.id != work.ticket.id);
    try mailbox.complete(t.io, next.ticket, .{ .failed = .unavailable });
    try t.expect(job.tick(t.io, mailbox, 115, 15250, true));
    try t.expect(!job.tick(t.io, mailbox, 121, 21000, true));
    job.stop(t.io, mailbox);
    try t.expect(mailbox.take(t.io) == null);
}

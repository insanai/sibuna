//! One nonblocking background ticket; database fences, not caller timeouts, protect writes.
const std = @import("std");
const p = @import("console_protocol");
const Mailbox = @import("mailbox.zig").Mailbox;
pub const Job = struct {
    holder: p.retention.Holder = .{ .node = 0, .boot = @splat(0) },
    lease: ?p.retention.Lease = null,
    ticket: ?Mailbox.Ticket = null,
    kind: p.retention.Kind = .incidents,
    acquiring: bool = false,
    started_ms: u64 = 0,
    next_ms: u64 = 0,
    renew_ms: u64 = 0,

    /// True means a failed/unconfirmed attempt. A competing lease is normal standby.
    pub fn tick(self: *Job, io: std.Io, mailbox: *Mailbox, ms: u64) bool {
        if (self.ticket) |ticket| {
            const result = mailbox.poll(io, ticket) catch @panic("retention ticket ownership");
            if (result) |done| {
                self.ticket = null;
                return self.complete(done, ms);
            }
            if (ms -| self.started_ms < 10000) return false;
            if (!self.acquiring) self.advance();
            self.stop(io, mailbox);
            self.next_ms = ms +| 5000;
            return true;
        }
        if (ms < self.next_ms) return false;
        self.acquiring = self.lease == null or ms >= self.renew_ms;
        const request: p.StorageRequest = if (self.acquiring)
            .{ .retention_acquire = self.holder }
        else
            .{ .retention_prune = .{ .lease = self.lease.?, .kind = self.kind } };
        self.ticket = mailbox.submit(io, request, .background) catch {
            self.next_ms = ms +| 5000;
            return true;
        };
        self.started_ms = ms;
        return false;
    }

    fn complete(self: *Job, result: p.StorageResult, ms: u64) bool {
        self.next_ms = ms +| 5000;
        if (result == .failed) {
            if (!self.acquiring) self.advance();
            self.lease = null;
            return result.failed != .conflict;
        }
        if (self.acquiring) {
            std.debug.assert(result == .retention_lease);
            std.debug.assert(std.meta.eql(result.retention_lease.holder, self.holder));
            self.lease = result.retention_lease;
            self.renew_ms = ms +| 10000;
            self.next_ms = ms;
        } else {
            std.debug.assert(result == .command_recorded);
            self.advance();
        }
        return false;
    }

    // A failed forensic index must not indefinitely prevent audit/session cleanup.
    fn advance(self: *Job) void {
        self.kind = switch (self.kind) {
            .incidents => .audit,
            .audit => .sessions,
            .sessions => .kiosk_grants,
            .kiosk_grants => .stages,
            .stages => .import_stages,
            .import_stages => .incidents,
        };
    }

    /// The daemon joins the collector before abandoning work. Queued inputs are owned;
    /// an executing transaction may still finish and is fenced by its stored lease token.
    pub fn stop(self: *Job, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("retention cancellation ownership");
        self.ticket = null;
        self.lease = null;
    }
};

test "retention standby, renewal, scheduling and cancellation do not block collection" {
    const t = std.testing;
    const mailbox = try t.allocator.create(Mailbox);
    defer t.allocator.destroy(mailbox);
    mailbox.* = .{};
    var job: Job = .{ .holder = .{ .node = 1, .boot = @splat(1) } };
    try t.expect(!job.tick(t.io, mailbox, 0));
    const standby = mailbox.take(t.io).?;
    try mailbox.complete(t.io, standby.ticket, .{ .failed = .conflict });
    try t.expect(!job.tick(t.io, mailbox, 250));
    try t.expect(!job.tick(t.io, mailbox, 5000));
    try t.expect(mailbox.take(t.io) == null);
    try t.expect(!job.tick(t.io, mailbox, 5250));
    const acquisition = mailbox.take(t.io).?;
    const lease: p.retention.Lease = .{ .holder = job.holder, .fence = 1, .expires = 100 };
    try mailbox.complete(t.io, acquisition.ticket, .{ .retention_lease = lease });
    try t.expect(!job.tick(t.io, mailbox, 15000));
    // Even slow acquisition leaves an immediate deletion opportunity before renewal.
    try t.expect(!job.tick(t.io, mailbox, 15250));
    const prune = mailbox.take(t.io).?;
    try t.expectEqual(p.retention.Kind.incidents, prune.request.retention_prune.kind);
    try mailbox.complete(t.io, prune.ticket, .command_recorded);
    try t.expect(!job.tick(t.io, mailbox, 15500));
    try t.expect(!job.tick(t.io, mailbox, 20500));
    const audit = mailbox.take(t.io).?;
    try t.expectEqual(p.retention.Kind.audit, audit.request.retention_prune.kind);
    try t.expect(!job.tick(t.io, mailbox, 30250));
    try t.expect(job.tick(t.io, mailbox, 30500));
    try t.expect(job.lease == null and job.ticket == null);
    try t.expectEqual(p.retention.Kind.sessions, job.kind);
    try mailbox.complete(t.io, audit.ticket, .command_recorded);
    try t.expect(!job.tick(t.io, mailbox, 35500));
    job.stop(t.io, mailbox);
    try t.expect(mailbox.take(t.io) == null);
}

//! Drains the data plane's bounded per-address challenge queue into owned batches and
//! records adaptive-difficulty transitions once per second. One batch and one transition
//! are in flight at a time; a lost acknowledgement is counted, never retried into duplicates,
//! and a change observed while a transition is still pending is counted as missed.
const std = @import("std");
const protocol = @import("console_protocol");
const wire = protocol.challenge_records;
const store = @import("store");
const Mailbox = @import("mailbox.zig").Mailbox;

pub const Journal = struct {
    node: u32 = 0,
    boot: [16]u8 = @splat(0),
    ticket: ?Mailbox.Ticket = null,
    submitted_ms: u64 = 0,
    transition: ?wire.Transition = null,
    transition_ticket: ?Mailbox.Ticket = null,
    transition_ms: u64 = 0,
    last_bits: ?u8 = null,
    observed_second: u64 = 0,
    saved: std.atomic.Value(u64) = .init(0),
    /// Record batches without a recorded acknowledgement (the rows may be absent).
    unconfirmed: std.atomic.Value(u64) = .init(0),
    /// Transitions observed but not recorded: skipped while one was pending, or unconfirmed.
    missed_transitions: std.atomic.Value(u64) = .init(0),

    pub fn tick(
        self: *Journal,
        io: std.Io,
        mailbox: *Mailbox,
        telemetry: *store.ConsoleTelemetry,
        now: u64,
        ms: u64,
    ) void {
        self.observe(telemetry, now);
        self.poll(io, mailbox, ms);
        if (self.ticket == null) self.drain(io, mailbox, telemetry, now, ms);
        if (self.transition_ticket == null) if (self.transition) |value| {
            self.transition_ticket = mailbox.submit(io, .{
                .challenge_transition = value,
            }, .background) catch null;
            if (self.transition_ticket != null) {
                self.transition = null;
                self.transition_ms = ms;
            }
        };
    }

    /// The effective adaptive bump is a level; a change since the last observed second
    /// becomes one transition row carrying the smoothed rate at that moment.
    fn observe(self: *Journal, telemetry: *const store.ConsoleTelemetry, now: u64) void {
        if (now == self.observed_second) return;
        self.observed_second = now;
        const bits: u8 = @intCast(@min(telemetry.adaptive_bits.load(.monotonic), 255));
        defer self.last_bits = bits;
        const previous = self.last_bits orelse return;
        if (previous == bits) return;
        if (self.transition != null) {
            _ = self.missed_transitions.fetchAdd(1, .monotonic);
            return;
        }
        self.transition = .{
            .node = self.node,
            .boot = self.boot,
            .second = now,
            .previous_bits = previous,
            .bits = bits,
            .rate_256 = telemetry.adaptive_rate_256.load(.monotonic),
        };
    }

    fn poll(self: *Journal, io: std.Io, mailbox: *Mailbox, ms: u64) void {
        if (self.ticket) |ticket| {
            const result = mailbox.poll(io, ticket) catch @panic("challenge record ownership");
            if (result) |done| {
                self.ticket = null;
                if (done == .command_recorded) {
                    _ = self.saved.fetchAdd(1, .monotonic);
                } else _ = self.unconfirmed.fetchAdd(1, .monotonic);
            } else if (ms -| self.submitted_ms >= 10000) {
                mailbox.abandon(io, ticket) catch @panic("challenge record cancellation");
                self.ticket = null;
                _ = self.unconfirmed.fetchAdd(1, .monotonic);
            }
        }
        if (self.transition_ticket) |ticket| {
            if (mailbox.poll(io, ticket) catch @panic("challenge transition ownership")) |done| {
                self.transition_ticket = null;
                if (done != .command_recorded)
                    _ = self.missed_transitions.fetchAdd(1, .monotonic);
            } else if (ms -| self.transition_ms >= 10000) {
                mailbox.abandon(io, ticket) catch @panic("challenge transition cancellation");
                self.transition_ticket = null;
                _ = self.missed_transitions.fetchAdd(1, .monotonic);
            }
        }
    }

    fn drain(
        self: *Journal,
        io: std.Io,
        mailbox: *Mailbox,
        telemetry: *store.ConsoleTelemetry,
        now: u64,
        ms: u64,
    ) void {
        var batch: wire.Batch = .{ .node = self.node, .boot = self.boot, .now = now };
        while (batch.count < wire.max_batch) {
            const record = telemetry.challenge_queue.pop() orelse break;
            batch.records[batch.count] = convert(record, now);
            batch.count += 1;
        }
        if (batch.count == 0) return;
        batch.dropped = telemetry.challenge_dropped.load(.monotonic);
        const request: protocol.StorageRequest = .{ .challenge_records_write = batch };
        self.ticket = mailbox.submit(io, request, .background) catch {
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            return;
        };
        self.submitted_ms = ms;
    }

    fn convert(record: store.telemetry.ChallengeRecord, now: u64) wire.Record {
        return .{
            .second = @min(record.second, now),
            .ip = protocol.Bytes(48).init(record.ip[0..record.ip_len]) catch .{},
            .outcome = if (record.outcome <= 2) @enumFromInt(record.outcome) else .rejected,
            .cause = record.cause,
            .algorithm = record.algorithm,
            .parameter = record.parameter,
            .openings = record.openings,
            .duration_ms = if (record.duration_ms == std.math.maxInt(u32))
                null
            else
                record.duration_ms,
        };
    }

    pub fn stop(self: *Journal, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket| mailbox.abandon(io, ticket) catch @panic("record shutdown");
        if (self.transition_ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("transition shutdown");
        self.ticket = null;
        self.transition_ticket = null;
    }
};

test "difficulty transitions are observed once per second and records drain in batches" {
    const t = std.testing;
    const telemetry = try t.allocator.create(store.ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.* = store.ConsoleTelemetry.init();
    var journal: Journal = .{ .node = 1, .boot = @splat(1) };
    journal.observe(telemetry, 100);
    try t.expect(journal.transition == null);
    telemetry.adaptive_bits.store(2, .monotonic);
    telemetry.adaptive_rate_256.store(300 * 256, .monotonic);
    journal.observe(telemetry, 100);
    try t.expect(journal.transition == null);
    journal.observe(telemetry, 101);
    const change = journal.transition.?;
    try t.expectEqual(@as(u8, 0), change.previous_bits);
    try t.expectEqual(@as(u8, 2), change.bits);
    try t.expectEqual(@as(u64, 300 * 256), change.rate_256);
    // A further change while the first is still pending is counted, never silently dropped.
    telemetry.adaptive_bits.store(3, .monotonic);
    journal.observe(telemetry, 102);
    try t.expectEqual(@as(u8, 2), journal.transition.?.bits);
    try t.expectEqual(@as(u64, 1), journal.missed_transitions.load(.monotonic));
    var record = std.mem.zeroes(store.telemetry.ChallengeRecord);
    record.second = 100;
    record.ip_len = 7;
    @memcpy(record.ip[0..7], "8.8.8.8");
    record.duration_ms = std.math.maxInt(u32);
    try t.expect(telemetry.challenge_queue.push(record));
    const converted = Journal.convert(record, 101);
    try t.expectEqualStrings("8.8.8.8", converted.ip.slice());
    try t.expect(converted.duration_ms == null);
}

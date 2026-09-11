//! Per-minute deltas of the boot-local challenge counters, queued to storage the way traffic
//! minutes are: two pending snapshots, bounded retries, the in-progress minute offered every
//! five seconds, and pruning on the retention cadence. The collector owns the baseline copy;
//! storage receives value copies only.
const std = @import("std");
const protocol = @import("console_protocol");
const p = protocol.challenge_minutes;
const cm = @import("store").challenge_metrics;
const Mailbox = @import("mailbox.zig").Mailbox;

const Bin = struct {
    issued: u64 = 0,
    accepted: u64 = 0,
    buckets: [16]u64 = @splat(0),
    missing: u64 = 0,
    invalid: u64 = 0,
    wasm: u64 = 0,
    javascript: u64 = 0,
    unknown_solver: u64 = 0,
};
const bin_fields = .{
    "issued", "accepted", "missing", "invalid", "wasm", "javascript", "unknown_solver",
};

/// A plain copy of every counter; loads are individually atomic, never a transaction.
pub const Totals = struct {
    submitted: u64 = 0,
    causes: [cm.cause_count]u64 = @splat(0),
    bins: [cm.bin_count]Bin = @splat(.{}),

    /// Loads in place: the table is 47 KiB, too large to pass through a collector stack.
    pub fn load(result: *Totals, metrics: *const cm.Metrics) void {
        result.submitted = metrics.submitted.load(.monotonic);
        for (&metrics.causes, &result.causes) |*counter, *count|
            count.* = counter.load(.monotonic);
        for (&metrics.bins, &result.bins) |*source, *bin| {
            inline for (bin_fields) |name|
                @field(bin, name) = @field(source, name).load(.monotonic);
            for (&source.buckets, &bin.buckets) |*counter, *count|
                count.* = counter.load(.monotonic);
        }
    }
};

pub const Journal = struct {
    const Job = struct { record: p.Record, retries: u8 = 0, retry_at: u64 = 0 };
    node: u32 = 0,
    boot: [16]u8 = @splat(0),
    /// Two owned counter tables: the baseline and the observation being taken. Neither is
    /// copied; the journal lives inside the heap-allocated console application.
    last: Totals = .{},
    scratch: Totals = .{},
    baselined: bool = false,
    last_ms: u64 = 0,
    current: ?p.Record = null,
    jobs: [2]Job = undefined,
    head: usize = 0,
    count: usize = 0,
    ticket: ?Mailbox.Ticket = null,
    submitted_ms: u64 = 0,
    offered_ms: u64 = 0,
    prune_at: u64 = 0,
    pruning: bool = false,
    pending: std.atomic.Value(u32) = .init(0),
    saved: std.atomic.Value(u64) = .init(0),
    unconfirmed: std.atomic.Value(u64) = .init(0),
    maintenance_failures: std.atomic.Value(u64) = .init(0),
    last_saved_end_ms: std.atomic.Value(u64) = .init(0),

    /// One observation per collector tick. The first call only sets the baseline; later
    /// calls attribute the interval since the previous tick to the minute it ends in.
    pub fn observe(self: *Journal, metrics: *const cm.Metrics, now: u64, ms: u64) void {
        self.scratch.load(metrics);
        defer {
            self.last = self.scratch;
            self.baselined = true;
            self.last_ms = ms;
        }
        if (!self.baselined or ms <= self.last_ms) return;
        const previous = &self.last;
        const totals = &self.scratch;
        const minute = now / 60;
        if (self.current) |*current| if (current.minute != minute) {
            current.sealed = true;
            current.complete = !current.gap and current.observed_ms >= 59000 and
                current.observed_ms <= 61000;
            self.offer(current.*);
            self.current = null;
        };
        if (self.current == null) self.current = .{
            .node = self.node,
            .boot = self.boot,
            .epoch = 1,
            .minute = minute,
            .start_ms = self.last_ms,
            .end_ms = self.last_ms,
            .observed_ms = 0,
            .observations = 0,
        };
        const current = &self.current.?;
        // A delayed collector cannot attribute its interval to seconds; the minute stays.
        if (ms - self.last_ms > 2000) current.gap = true;
        current.end_ms = ms;
        current.observed_ms = ms - current.start_ms;
        current.observations += 1;
        current.submitted +|= delta(totals.submitted, previous.submitted);
        for (&current.causes, totals.causes, previous.causes) |*count, after, before|
            count.* +|= delta(after, before);
        for (&totals.bins, &previous.bins, 0..) |after, before, index| {
            if (std.meta.eql(after, before)) continue;
            const entry = current.partition(@intCast(index)) orelse {
                current.bins_dropped +|= 1;
                continue;
            };
            inline for (bin_fields) |name|
                @field(entry, name) +|= delta(@field(after, name), @field(before, name));
            for (&entry.buckets, after.buckets, before.buckets) |*count, next, last|
                count.* +|= delta(next, last);
        }
    }

    fn delta(after: u64, before: u64) u32 {
        return @intCast(@min(after -| before, std.math.maxInt(u32)));
    }

    pub fn offer(self: *Journal, record: p.Record) void {
        for (0..self.count) |probe| {
            const offset = self.count - 1 - probe;
            if (offset == 0 and self.ticket != null and !self.pruning) continue;
            const job = &self.jobs[(self.head + offset) % self.jobs.len];
            if (std.meta.eql(job.record.cursor(), record.cursor())) {
                std.debug.assert(record.end_ms >= job.record.end_ms and !job.record.sealed);
                job.record = record;
                return;
            }
        }
        if (self.count == self.jobs.len) {
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            return;
        }
        self.jobs[(self.head + self.count) % self.jobs.len] = .{ .record = record };
        self.count += 1;
        self.pending.store(@intCast(self.count), .monotonic);
    }

    pub fn tick(self: *Journal, io: std.Io, mailbox: *Mailbox, now: u64, ms: u64) void {
        if (ms -| self.offered_ms >= 5000) {
            if (self.current) |current| self.offer(current);
            self.offered_ms = ms;
        }
        if (self.ticket) |ticket| {
            const result = mailbox.poll(io, ticket) catch @panic("challenge ticket ownership");
            if (result) |done| {
                self.ticket = null;
                if (self.pruning) {
                    self.prune_at = ms +| 5000;
                    if (done != .command_recorded)
                        _ = self.maintenance_failures.fetchAdd(1, .monotonic);
                } else if (done == .command_recorded) {
                    self.last_saved_end_ms.store(self.jobs[self.head].record.end_ms, .monotonic);
                    _ = self.saved.fetchAdd(1, .release);
                    self.remove();
                } else self.retry(ms);
            } else if (ms -| self.submitted_ms >= 10000) {
                mailbox.abandon(io, ticket) catch @panic("challenge cancellation ownership");
                self.ticket = null;
                if (self.pruning) {
                    self.prune_at = ms +| 5000;
                    _ = self.maintenance_failures.fetchAdd(1, .monotonic);
                } else self.retry(ms);
            }
            return;
        }
        self.pruning = ms >= self.prune_at;
        const request: protocol.StorageRequest = if (self.pruning)
            .{ .challenge_minutes_prune = now }
        else blk: {
            if (self.count == 0 or ms < self.jobs[self.head].retry_at) return;
            break :blk .{ .challenge_minutes_write = .{
                .record = self.jobs[self.head].record,
                .now = now,
            } };
        };
        self.ticket = mailbox.submit(io, request, .background) catch {
            if (self.pruning) {
                self.prune_at = ms +| 5000;
                _ = self.maintenance_failures.fetchAdd(1, .monotonic);
            } else self.retry(ms);
            return;
        };
        self.submitted_ms = ms;
    }

    fn retry(self: *Journal, ms: u64) void {
        const job = &self.jobs[self.head];
        job.retries += 1;
        if (job.retries == 8) {
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            self.remove();
        } else job.retry_at = ms +| (@as(u64, 1000) << @intCast(job.retries - 1));
    }

    fn remove(self: *Journal) void {
        std.debug.assert(self.count != 0);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.jobs[self.head]));
        self.head = (self.head + 1) % self.jobs.len;
        self.count -= 1;
        self.pending.store(@intCast(self.count), .monotonic);
    }

    /// Join the collector first. Abandonment does not imply rollback of executing SQL.
    pub fn stop(self: *Journal, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("challenge shutdown ownership");
        self.ticket = null;
        while (self.count != 0) self.remove();
        self.current = null;
    }

    pub fn status(self: *const Journal) protocol.minutes.Status {
        return .{
            .available = true,
            .pending = self.pending.load(.monotonic),
            .saved_snapshots = self.saved.load(.acquire),
            .unconfirmed_snapshots = self.unconfirmed.load(.monotonic),
            .retention_failures = self.maintenance_failures.load(.monotonic),
            .last_saved_end_ms = self.last_saved_end_ms.load(.monotonic),
        };
    }
};

test "challenge journal attributes deltas to the ending minute and seals on the roll" {
    const t = std.testing;
    var metrics: cm.Metrics = .{};
    var journal: Journal = .{ .node = 1, .boot = @splat(1) };
    journal.observe(&metrics, 119, 1000);
    try t.expect(journal.current == null);
    metrics.issue(.posw, 13, 16);
    _ = metrics.submitted.fetchAdd(1, .monotonic);
    metrics.reject(.replay);
    journal.observe(&metrics, 120, 1250);
    const current = journal.current.?;
    try t.expectEqual(@as(u64, 2), current.minute);
    try t.expectEqual(@as(u32, 1), current.submitted);
    try t.expectEqual(@as(u32, 1), current.causes[@intFromEnum(cm.Cause.replay)]);
    try t.expectEqual(@as(u8, 1), current.count);
    try t.expectEqual(@as(u8, 133), current.bins[0].bin);
    try t.expectEqual(@as(u32, 1), current.bins[0].issued);
    metrics.accept(.posw, 13, 16, .{ .milliseconds = 8 }, .wasm);
    // The collector ticks four times a second; the minute rolls at the first tick past it.
    var ms: u64 = 1500;
    while (ms < 60500) : (ms += 250) journal.observe(&metrics, 119 + ms / 1000, ms);
    try t.expectEqual(@as(u32, 1), journal.current.?.bins[0].accepted);
    try t.expect(journal.current.?.bins[0].consistent());
    journal.observe(&metrics, 180, 60500);
    try t.expectEqual(@as(usize, 1), journal.count);
    const sealed = journal.jobs[journal.head].record;
    try t.expect(sealed.sealed and sealed.complete and !sealed.gap);
    try t.expectEqual(@as(u64, 2), sealed.minute);
    try t.expectEqual(@as(u64, 3), journal.current.?.minute);
    try t.expectEqual(@as(u8, 0), journal.current.?.count);
    journal.observe(&metrics, 185, 66000);
    try t.expect(journal.current.?.gap);
}

//! The collector owns aggregation and two pending snapshots; storage receives only value copies.
const std = @import("std");
const protocol = @import("console_protocol");
const p = protocol.minutes;
const Interval = protocol.timeline.Bucket;
const Mailbox = @import("mailbox.zig").Mailbox;

pub const Journal = struct {
    const Job = struct { record: p.Record, retries: u8 = 0, retry_at: u64 = 0 };
    node: u32 = 0,
    boot: [16]u8 = @splat(0),
    current: ?p.Record = null,
    last_cpu_ms: ?u64 = null,
    complete_candidate: bool = false,
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

    pub fn observe(self: *Journal, epoch: u32, interval: ?Interval) void {
        var contiguous = false;
        if (self.current) |*current| {
            if (current.epoch != epoch or (interval != null and
                interval.?.utc_end / 60 != current.minute))
            {
                if (interval) |next| contiguous = current.epoch == epoch and
                    next.utc_end / 60 == current.minute + 1 and !next.gap and
                    current.end_ms == next.start_ms;
                current.sealed = true;
                current.complete = self.complete_candidate and !current.gap and contiguous and
                    current.observed_ms >= 59000 and current.observed_ms <= 61000;
                self.offer(current.*);
                self.current = null;
                self.complete_candidate = contiguous;
            }
        }
        const next = interval orelse return;
        std.debug.assert(next.observed_ms == next.end_ms - next.start_ms);
        std.debug.assert(next.observed_ms != 0 and next.observations == 1);
        if (self.current == null) {
            self.current = .{
                .node = self.node,
                .boot = self.boot,
                .epoch = epoch,
                .minute = next.utc_end / 60,
                .utc_start = next.utc_start,
                .utc_end = next.utc_end,
                .start_ms = next.start_ms,
                .end_ms = next.end_ms,
                .observed_ms = next.observed_ms,
                .observations = 1,
                .gap = next.gap,
                .counts = next.counts,
            };
            return;
        }
        const current = &self.current.?;
        std.debug.assert(current.end_ms == next.start_ms and current.utc_end <= next.utc_end);
        current.utc_end = next.utc_end;
        current.end_ms = next.end_ms;
        current.observed_ms += next.observed_ms;
        current.observations += 1;
        current.gap = current.gap or next.gap or current.observed_ms > 61000;
        // Monotonic source counters bound each sum; a wrap resets the observation epoch.
        inline for (p.counter_fields) |name| @field(current.counts, name) +=
            @field(next.counts, name);
    }

    /// Resident memory is a level (last and peak); CPU time is attributed as the delta since
    /// the previous sample. Samples taken while no minute is open only move the baseline.
    pub fn gauges(self: *Journal, sample: @import("resources.zig").Sample) void {
        defer self.last_cpu_ms = sample.cpu_ms;
        const current = &(self.current orelse return);
        current.rss_last_kib = sample.rss_kib;
        var peak = current.rss_max_kib;
        inline for (.{ sample.rss_max_kib, sample.rss_kib, current.rss_last_kib }) |value| {
            if (value) |seen| peak = @max(peak orelse 0, seen);
        }
        current.rss_max_kib = peak;
        const previous = self.last_cpu_ms orelse return;
        current.cpu_ms = (current.cpu_ms orelse 0) +| (sample.cpu_ms -| previous);
    }

    pub fn offer(self: *Journal, record: p.Record) void {
        // Coalesce only queued snapshots. An in-flight head owns its original acknowledgement.
        for (0..self.count) |probe| {
            const offset = self.count - 1 - probe;
            if (offset == 0 and self.ticket != null and !self.pruning) continue;
            const job = &self.jobs[(self.head + offset) % self.jobs.len];
            if (std.meta.eql(job.record.cursor(), record.cursor())) {
                std.debug.assert(record.end_ms >= job.record.end_ms and !job.record.sealed);
                // New samples must not reset the minute's bounded retry count or backoff.
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
            const result = mailbox.poll(io, ticket) catch @panic("minute ticket ownership");
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
                mailbox.abandon(io, ticket) catch @panic("minute cancellation ownership");
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
            .{ .minutes_prune = now }
        else blk: {
            if (self.count == 0 or ms < self.jobs[self.head].retry_at) return;
            break :blk .{ .minutes_write = .{
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

    /// Join the collector first. Abandonment does not imply rollback of already executing SQL.
    pub fn stop(self: *Journal, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("minute shutdown ownership");
        self.ticket = null;
        while (self.count != 0) self.remove();
        self.current = null;
    }

    pub fn status(self: *const Journal) p.Status {
        const saved = self.saved.load(.acquire);
        return .{
            .available = true,
            .pending = self.pending.load(.monotonic),
            .saved_snapshots = saved,
            .unconfirmed_snapshots = self.unconfirmed.load(.monotonic),
            .retention_failures = self.maintenance_failures.load(.monotonic),
            .last_saved_end_ms = self.last_saved_end_ms.load(.monotonic),
        };
    }
};

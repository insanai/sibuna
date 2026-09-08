//! One collector drives this journal without waiting for storage. Every mailbox input is owned.
const std = @import("std");
const p = @import("console_protocol");
const Mailbox = @import("mailbox.zig").Mailbox;
const codec = @import("rankings_archive.zig");
const Minute = @import("rankings.zig").Minute;

pub const Journal = struct {
    const Phase = enum { begin, chunks, finish };
    const Job = struct {
        bytes: [codec.max_bytes]u8 = undefined,
        len: usize,
        digest: [32]u8,
        minute: u64,
        offset: usize = 0,
        phase: Phase = .begin,
        retries: u8 = 0,
    };
    boot: [16]u8 = @splat(0),
    node: u32 = 0,
    jobs: [2]Job = undefined,
    head: usize = 0,
    count: usize = 0,
    ticket: ?Mailbox.Ticket = null,
    submitted_ms: u64 = 0,
    retry_at: u64 = 0,
    prune_at: u64 = 0,
    pruning: bool = false,
    pending: std.atomic.Value(u32) = .init(0),
    saved: std.atomic.Value(u64) = .init(0),
    unconfirmed: std.atomic.Value(u64) = .init(0),
    maintenance_failures: std.atomic.Value(u64) = .init(0),
    last_saved: std.atomic.Value(u64) = .init(0),
    inventory_mutex: std.Io.Mutex = .init,
    inventory: p.rankings.Inventory = .{},

    pub fn offer(self: *Journal, minute: *const Minute, queue_loss: u64) void {
        if (self.count == self.jobs.len) {
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            return;
        }
        const job = &self.jobs[(self.head + self.count) % self.jobs.len];
        job.* = .{ .len = 0, .digest = undefined, .minute = minute.minute.? };
        const archive: codec.Archive = .{
            .identity = .{ .node = self.node, .boot = self.boot, .queue_loss_end = queue_loss },
            .minute = minute.*,
        };
        const bytes = codec.encode(&archive, &job.bytes) catch {
            std.crypto.secureZero(u8, &job.bytes);
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            return;
        };
        job.len = bytes.len;
        std.crypto.hash.sha2.Sha256.hash(bytes, &job.digest, .{});
        self.count += 1;
        self.pending.store(@intCast(self.count), .monotonic);
    }

    pub fn tick(self: *Journal, io: std.Io, mailbox: *Mailbox, now: u64, ms: u64) void {
        if (self.ticket) |ticket| {
            const result = mailbox.poll(io, ticket) catch @panic("ranking ticket ownership");
            if (result) |done| {
                self.ticket = null;
                if (self.pruning) {
                    self.prune_at = ms +| 5000;
                    if (done == .ranking_inventory) {
                        self.inventory_mutex.lockUncancelable(io);
                        self.inventory = done.ranking_inventory;
                        self.inventory_mutex.unlock(io);
                    } else {
                        _ = self.maintenance_failures.fetchAdd(1, .monotonic);
                    }
                    return;
                }
                if (done == .command_recorded) self.advance() else self.retry(ms);
            } else if (ms -| self.submitted_ms >= 10000) {
                mailbox.abandon(io, ticket) catch @panic("ranking cancellation ownership");
                self.ticket = null;
                if (!self.pruning) {
                    self.retry(ms);
                } else {
                    self.prune_at = ms +| 5000;
                    _ = self.maintenance_failures.fetchAdd(1, .monotonic);
                }
            }
            return;
        }
        if (ms < self.retry_at) return;
        self.pruning = ms >= self.prune_at;
        if (self.pruning) self.prune_at = ms +| 5000;
        const request: p.StorageRequest = if (self.pruning) .{ .rankings_prune = now } else blk: {
            if (self.count == 0) return;
            break :blk self.operation(now);
        };
        self.ticket = mailbox.submit(io, request, .background) catch {
            if (!self.pruning and self.count != 0) self.retry(ms) else if (self.pruning)
                _ = self.maintenance_failures.fetchAdd(1, .monotonic);
            return;
        };
        self.submitted_ms = ms;
    }

    fn operation(self: *Journal, now: u64) p.StorageRequest {
        const job = &self.jobs[self.head];
        return switch (job.phase) {
            .begin => .{ .rankings_begin = .{
                .digest = job.digest,
                .total_bytes = @intCast(job.len),
                .now = now,
            } },
            .chunks => .{ .rankings_chunk = .{
                .digest = job.digest,
                .ordinal = @intCast(job.offset / p.ranking_storage.chunk_bytes),
                .bytes = p.Bytes(2048).init(job.bytes[job.offset..][0..@min(
                    p.ranking_storage.chunk_bytes,
                    job.len - job.offset,
                )]) catch unreachable,
            } },
            .finish => .{ .rankings_finish = .{ .digest = job.digest, .now = now } },
        };
    }

    fn advance(self: *Journal) void {
        std.debug.assert(self.count != 0);
        const job = &self.jobs[self.head];
        switch (job.phase) {
            .begin => job.phase = .chunks,
            .chunks => {
                job.offset += @min(p.ranking_storage.chunk_bytes, job.len - job.offset);
                if (job.offset == job.len) job.phase = .finish;
            },
            .finish => {
                self.last_saved.store(job.minute, .monotonic);
                _ = self.saved.fetchAdd(1, .release);
                self.remove();
            },
        }
    }

    fn retry(self: *Journal, ms: u64) void {
        const job = &self.jobs[self.head];
        job.retries += 1;
        if (job.retries == 8) {
            _ = self.unconfirmed.fetchAdd(1, .monotonic);
            self.remove();
        } else {
            // A timeout cannot prove SQL failed. Begin/chunk/finish retries are idempotent.
            // Restart staging in case bounded cleanup expired an earlier attempt.
            job.phase = .begin;
            job.offset = 0;
            self.retry_at = ms +| (@as(u64, 1000) << @intCast(job.retries - 1));
        }
    }

    fn remove(self: *Journal) void {
        const job = &self.jobs[self.head];
        std.crypto.secureZero(u8, job.bytes[0..job.len]);
        self.head = (self.head + 1) % self.jobs.len;
        self.count -= 1;
        self.pending.store(@intCast(self.count), .monotonic);
    }

    /// Called after joining the collector, before releasing the storage owner.
    pub fn stop(self: *Journal, io: std.Io, mailbox: *Mailbox) void {
        if (self.ticket) |ticket|
            mailbox.abandon(io, ticket) catch @panic("ranking shutdown ownership");
        self.ticket = null;
        while (self.count != 0) self.remove();
    }

    pub fn status(self: *Journal, io: std.Io) p.rankings.ArchiveStatus {
        const saved = self.saved.load(.acquire);
        self.inventory_mutex.lockUncancelable(io);
        defer self.inventory_mutex.unlock(io);
        return .{
            .stored = self.inventory,
            .pending = self.pending.load(.monotonic),
            .saved_since_boot = saved,
            .unconfirmed_since_boot = self.unconfirmed.load(.monotonic),
            .maintenance_failures_since_boot = self.maintenance_failures.load(.monotonic),
            .last_saved_minute = if (saved == 0) null else self.last_saved.load(.monotonic),
        };
    }
};

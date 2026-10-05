//! Two stable pin cells publish heap-owned generations. The cells are never moved
//! or reset while workers exist. A single bounded writer reservation serializes
//! publication; no allocator, mutex wait or teardown occurs in reader operations.
const std = @import("std");
const generations = @import("generation.zig");
const pools = @import("transaction_pool.zig");
const config = @import("config.zig");
const versions = @import("release_version.zig");
const http = @import("http_acquisition.zig");
const transactions = @import("http_transaction.zig");
pub const Error = pools.Error || error{
    PublicationBusy,
    PublicationClosed,
    StaleGenerationRevision,
    NoGeneration,
    DisabledGeneration,
};
const absent: u8 = 2;
const maximum_pins = 4096;
const Cell = struct {
    generation: ?*generations.Generation = null,
    readers: std.atomic.Value(u32) = .init(0),
};
pub const Snapshot = struct {
    revision: u64,
    activation: config.Activation,
    thresholds: config.Thresholds,
    version: ?versions.Version,
    digest: ?[32]u8,
    operator_digest: ?[32]u8,
    compiled_peak: usize,
    reservation: usize,
    slots: usize,
    request_bytes: usize,
    response_bytes: usize,
    work_budget: u64,
};
pub const Lease = struct {
    owner: *Publisher,
    index: u8,
    work: pools.Lease,

    pub fn generation(self: *const Lease) *const generations.Generation {
        return self.owner.cells[self.index].generation.?;
    }

    pub fn begin(self: *Lease, input: http.Request) transactions.Error!transactions.Transaction {
        const options = self.generation().options;
        return transactions.Transaction.beginConfigured(self.work.slot(), .{
            .activation = options.activation,
            .thresholds = options.thresholds,
        }, input);
    }

    /// Finish and release slot borrows before dropping the generation pin.
    pub fn release(self: *Lease) void {
        self.work.release();
        self.owner.unpin(self.index);
        self.* = undefined;
    }
};
pub const Publisher = struct {
    cells: [2]Cell = .{ .{}, .{} },
    active: std.atomic.Value(u8) = .init(absent),
    closed: std.atomic.Value(bool) = .init(false),
    writer: std.atomic.Value(bool) = .init(false),
    /// A disabled fast path borrows no cell. Publication stores this after the
    /// active index; a reader that observes true still obtains a normal lease.
    enabled: std.atomic.Value(bool) = .init(false),

    /// Success transfers candidate ownership. Every failure leaves it owned by
    /// the caller and keeps the active generation intact. Expected-revision CAS
    /// and durable intent/completion belong to the management storage owner.
    pub fn publish(self: *Publisher, candidate: *generations.Generation) Error!void {
        if (self.writer.cmpxchgStrong(false, true, .acquire, .monotonic) != null)
            return error.PublicationBusy;
        defer self.writer.store(false, .release);
        if (self.closed.load(.acquire)) return error.PublicationClosed;
        const current = self.active.load(.seq_cst);
        if (current != absent) {
            if (candidate.options.revision <= self.cells[current].generation.?.options.revision)
                return error.StaleGenerationRevision;
        }
        const next: u8 = if (current == 0) 1 else 0;
        const target = &self.cells[next];
        if (target.readers.load(.seq_cst) != 0) return error.PublicationBusy;
        if (target.generation) |previous| {
            if (!previous.drained()) return error.PublicationBusy;
            previous.deinit();
        }
        target.generation = candidate;
        self.active.store(next, .seq_cst);
        self.enabled.store(candidate.options.activation.mode != .off, .release);
        if (current != absent) self.cells[current].generation.?.retire();
    }

    pub fn lease(self: *Publisher) Error!Lease {
        const index = try self.pin();
        errdefer self.unpin(index);
        const generation = self.cells[index].generation.?;
        if (generation.options.activation.mode == .off) return error.DisabledGeneration;
        return .{ .owner = self, .index = index, .work = try generation.pool.lease() };
    }

    /// Small copied metadata needs no body slot and borrows no mutable generation.
    pub fn snapshot(self: *Publisher) Error!Snapshot {
        const index = try self.pin();
        defer self.unpin(index);
        const generation = self.cells[index].generation.?;
        return .{
            .revision = generation.options.revision,
            .activation = generation.options.activation,
            .thresholds = generation.options.thresholds,
            .version = if (generation.package) |package| package.version else null,
            .digest = if (generation.package) |package| package.receipt.digest else null,
            .operator_digest = if (generation.package) |package| package.operator_digest else null,
            .compiled_peak = if (generation.package) |package| package.bounded.peak else 0,
            .reservation = if (generation.pool_live) generation.pool.reserved_bytes else 0,
            .slots = if (generation.pool_live) generation.options.slots else 0,
            .request_bytes = generation.options.limits.request,
            .response_bytes = generation.options.limits.response,
            .work_budget = generation.options.limits.work,
        };
    }

    /// Stop publication and new pins before the owner cancels/joins all workers.
    pub fn close(self: *Publisher) Error!void {
        if (self.writer.cmpxchgStrong(false, true, .acquire, .monotonic) != null)
            return error.PublicationBusy;
        defer self.writer.store(false, .release);
        self.closed.store(true, .release);
        self.enabled.store(false, .release);
        self.active.store(absent, .seq_cst);
        for (&self.cells) |*cell| if (cell.generation) |generation| generation.retire();
    }

    /// The owner must join every potential reader, including one stalled before
    /// pinning. Zero counters alone cannot prove that no future call exists.
    pub fn deinit(self: *Publisher) void {
        std.debug.assert(self.closed.load(.acquire));
        std.debug.assert(!self.writer.load(.acquire));
        for (&self.cells) |*cell| {
            std.debug.assert(cell.readers.load(.seq_cst) == 0);
            if (cell.generation) |generation| generation.deinit();
        }
        self.* = undefined;
    }

    fn pin(self: *Publisher) Error!u8 {
        // Sequential consistency couples index changes to reader increments.
        // Acquire/release on two independent atomics alone is not a pin proof.
        for (0..3) |_| {
            if (self.closed.load(.acquire)) return error.PublicationClosed;
            const index = self.active.load(.seq_cst);
            if (index == absent) return error.NoGeneration;
            const cell = &self.cells[index];
            const count = cell.readers.load(.seq_cst);
            if (count >= maximum_pins) return error.PublicationBusy;
            if (cell.readers.cmpxchgStrong(count, count + 1, .seq_cst, .seq_cst) != null) continue;
            if (self.active.load(.seq_cst) == index) return index;
            self.unpin(index);
        }
        return error.PublicationBusy;
    }

    fn unpin(self: *Publisher, index: u8) void {
        const previous = self.cells[index].readers.fetchSub(1, .seq_cst);
        std.debug.assert(previous > 0 and previous <= maximum_pins);
    }
};

test {
    _ = @import("publication_test.zig");
}

//! Stable, generation-owned workspaces in two tiers. A lease is exclusive until release;
//! shutdown closes admission before waiting for leases and reclaiming the pool.
//!
//! Large slots hold the configured request entity. Most requests are far smaller, and a
//! large slot reserves tens of MiB, so the reservation left after the configured large
//! slots is filled with small slots that differ only in their request entity bound.
//! Response, metadata and work limits are identical, so a small slot gives the same
//! coverage to every request it accepts.
const std = @import("std");
const Io = std.Io;
const slots = @import("transaction_slot.zig");
const rules = @import("rule_program.zig");
pub const Error = slots.Error || error{ InvalidPoolLimits, PoolClosed, PoolBusy };

/// Request entity bound of a small slot.
pub const small_request_bytes = 64 * 1024;
/// Large slots keep their configured, persisted ceiling.
pub const max_large_slots = 31;
/// Both tiers together; 32-bit words keep occupancy atomic on every supported target.
pub const max_slots = 1024;

pub const Tier = enum(u1) { small, large };

/// The declared request entity size selects the smallest tier that can hold it. Chunked
/// framing has no declared size and needs a large slot: acquisition cannot move later.
pub const Demand = struct {
    request_bytes: ?usize,
};

const Set = struct {
    storage: []slots.Slot = &.{},
    len: usize = 0,
    words: []std.atomic.Value(u32) = &.{},

    fn live(self: *const Set, word: usize) u32 {
        const remaining = self.len - word * 32;
        if (remaining >= 32) return std.math.maxInt(u32);
        return (@as(u32, 1) << @intCast(remaining)) - 1;
    }

    fn empty(self: *const Set) bool {
        for (self.words) |*word| if (word.load(.acquire) != 0) return false;
        return true;
    }

    fn deinit(self: *Set, allocator: std.mem.Allocator) void {
        for (self.storage[0..self.len]) |*slot| slot.deinit();
        allocator.free(self.storage);
        allocator.free(self.words);
        self.* = .{};
    }
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    sets: [2]Set = .{ .{}, .{} },
    closed: std.atomic.Value(bool) = .init(false),
    /// Advanced by every release; waiters park on it rather than spin.
    epoch: std.atomic.Value(u32) = .init(0),
    waiters: std.atomic.Value(u32) = .init(0),
    reserved_bytes: usize = 0,

    /// Both the pool and its borrowed generation must outlive every lease. Slot objects
    /// are allocated once and never moved, even when the generation retires.
    pub fn init(
        self: *Pool,
        allocator: std.mem.Allocator,
        program: *const rules.Program,
        limits: slots.Limits,
        count: usize,
        maximum_bytes: usize,
    ) Error!void {
        if (count == 0 or count > max_large_slots or maximum_bytes == 0)
            return error.InvalidPoolLimits;
        self.* = .{ .allocator = allocator };
        errdefer for (&self.sets) |*set| set.deinit(allocator);
        var bytes: usize = 0;
        try self.reserve(.large, program, limits, count, maximum_bytes, &bytes);
        if (limits.request > small_request_bytes) {
            var small = limits;
            small.request = small_request_bytes;
            const unit = try probe(allocator, program, small);
            const room = (maximum_bytes - bytes) / unit;
            const wanted = @min(room, max_slots - count);
            if (wanted != 0)
                try self.reserve(.small, program, small, wanted, maximum_bytes, &bytes);
        }
        self.reserved_bytes = bytes;
    }

    /// Measures one initialized slot, including arena overhead, before sizing a tier.
    fn probe(
        allocator: std.mem.Allocator,
        program: *const rules.Program,
        limits: slots.Limits,
    ) Error!usize {
        const slot = try allocator.create(slots.Slot);
        defer allocator.destroy(slot);
        try slot.init(allocator, program, limits);
        defer slot.deinit();
        return @sizeOf(slots.Slot) + slot.owner.queryCapacity();
    }

    fn reserve(
        self: *Pool,
        tier: Tier,
        program: *const rules.Program,
        limits: slots.Limits,
        count: usize,
        maximum_bytes: usize,
        bytes: *usize,
    ) Error!void {
        const set = &self.sets[@backingInt(tier)];
        set.storage = try self.allocator.alloc(slots.Slot, count);
        set.words = try self.allocator.alloc(std.atomic.Value(u32), (count + 31) / 32);
        @memset(set.words, .init(0));
        for (set.storage) |*slot| {
            try slot.init(self.allocator, program, limits);
            // Saturation turns an overflowing reservation into an ordinary limit refusal.
            const total = bytes.* +| @sizeOf(slots.Slot) +| slot.owner.queryCapacity();
            if (total > maximum_bytes) {
                slot.deinit();
                // Small slots only fill spare reservation; the configured tier must fit.
                if (tier == .small) return;
                return error.ReservationLimit;
            }
            set.len += 1;
            bytes.* = total;
        }
    }

    pub fn slotCount(self: *const Pool, tier: Tier) usize {
        return self.sets[@backingInt(tier)].len;
    }

    /// Never waits. A request that fits a small slot spills to a large one when every
    /// small slot is busy; a large request never displaces work into a smaller bound.
    pub fn lease(self: *Pool, demand: Demand) Error!Lease {
        if (self.closed.load(.acquire)) return error.PoolClosed;
        if (demand.request_bytes) |size| {
            if (size <= small_request_bytes) {
                if (try self.claim(.small)) |claimed| return claimed;
            }
        }
        return (try self.claim(.large)) orelse error.PoolBusy;
    }

    /// Parks on the release epoch until a slot frees or `wait` elapses. The epoch is read
    /// before each attempt, so a release between a failed attempt and the park changes the
    /// expected value and the futex returns at once: no wakeup can be lost.
    pub fn leaseWithin(
        self: *Pool,
        io: Io,
        demand: Demand,
        wait: Io.Clock.Duration,
    ) Error!Lease {
        return self.lease(demand) catch |err| {
            if (err != error.PoolBusy) return err;
            const deadline: Io.Clock.Timestamp = .fromNow(io, wait);
            _ = self.waiters.fetchAdd(1, .seq_cst);
            defer _ = self.waiters.fetchSub(1, .seq_cst);
            while (true) {
                const seen = self.epoch.load(.seq_cst);
                if (self.lease(demand)) |claimed| return claimed else |retry| {
                    if (retry != error.PoolBusy) return retry;
                }
                if (Io.Clock.Timestamp.now(io, wait.clock).compare(.gte, deadline))
                    return error.PoolBusy;
                // Cancellation refuses this request like an expired wait; it holds nothing.
                io.futexWaitTimeout(u32, &self.epoch.raw, seen, .{ .deadline = deadline }) catch
                    return error.PoolBusy;
            }
        };
    }

    fn claim(self: *Pool, tier: Tier) Error!?Lease {
        const set = &self.sets[@backingInt(tier)];
        for (set.words, 0..) |*word, position| {
            const live = set.live(position);
            var observed = word.load(.acquire);
            // Each failed exchange proves another admission or release made progress, so
            // a word is retried at most once per slot it can hold.
            for (0..32) |_| {
                const available = live & ~observed;
                if (available == 0) break;
                const bit: u5 = @intCast(@ctz(available));
                const mask = @as(u32, 1) << bit;
                if (word.cmpxchgWeak(observed, observed | mask, .seq_cst, .acquire)) |current| {
                    observed = current;
                    continue;
                }
                var claimed: Lease = .{ .pool = self, .tier = tier, .index = position * 32 + bit };
                // Close may have linearized after the scan began; back out so `drained`
                // cannot be observed while this slot is still claimed.
                if (self.closed.load(.seq_cst)) {
                    claimed.clear();
                    return error.PoolClosed;
                }
                return claimed;
            }
        }
        return null;
    }

    /// Stops new leases. Parked waiters observe the closed pool at their next wake or
    /// deadline; the owner joins workers before reclaiming the pool.
    pub fn close(self: *Pool) void {
        self.closed.store(true, .seq_cst);
    }

    pub fn drained(self: *const Pool) bool {
        if (!self.closed.load(.seq_cst)) return false;
        for (&self.sets) |*set| if (!set.empty()) return false;
        return true;
    }

    /// The owner joins workers before this call; closing is not cancellation of an
    /// executing transaction and cannot invalidate its immutable generation.
    pub fn deinit(self: *Pool) void {
        std.debug.assert(self.drained());
        for (&self.sets) |*set| set.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Lease = struct {
    pool: *Pool,
    tier: Tier,
    index: usize,

    pub fn slot(self: *const Lease) *slots.Slot {
        return &self.pool.sets[@backingInt(self.tier)].storage[self.index];
    }

    fn clear(self: *const Lease) void {
        const set = &self.pool.sets[@backingInt(self.tier)];
        const mask = @as(u32, 1) << @intCast(self.index % 32);
        const previous = set.words[self.index / 32].fetchAnd(~mask, .seq_cst);
        std.debug.assert(previous & mask != 0);
    }

    /// End all Executor and View borrows first. Do not copy or reuse a released lease.
    /// Release ordering publishes the completed reset to the next owner before the epoch
    /// advances, and a futex wake is paid only when a request is parked.
    pub fn release(self: *Lease, io: Io) void {
        const reserved = self.slot();
        if (reserved.active) reserved.finish();
        self.clear();
        _ = self.pool.epoch.fetchAdd(1, .seq_cst);
        if (self.pool.waiters.load(.seq_cst) != 0) io.futexWake(u32, &self.pool.epoch.raw, 1);
        self.* = undefined;
    }
};

test {
    _ = @import("transaction_pool_test.zig");
}

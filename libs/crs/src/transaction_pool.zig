//! Stable, generation-owned workspaces. A lease is exclusive until release;
//! shutdown closes admission before waiting for leases and reclaiming the pool.
const std = @import("std");
const slots = @import("transaction_slot.zig");
const rules = @import("rule_program.zig");
pub const Error = slots.Error || error{ InvalidPoolLimits, PoolClosed, PoolBusy };
const closed: u32 = @as(u32, 1) << 31;
pub const Pool = struct {
    allocator: std.mem.Allocator,
    slots: []slots.Slot,
    occupancy: std.atomic.Value(u32) = .init(0),
    reserved_bytes: usize,

    /// Both the pool and its borrowed generation must outlive every lease. Slot
    /// objects are allocated once and never moved, even when the generation retires.
    pub fn init(
        self: *Pool,
        allocator: std.mem.Allocator,
        program: *const rules.Program,
        limits: slots.Limits,
        count: usize,
        maximum_bytes: usize,
    ) Error!void {
        if (count == 0 or count > 31 or maximum_bytes == 0) return error.InvalidPoolLimits;
        const reserved = try allocator.alloc(slots.Slot, count);
        errdefer allocator.free(reserved);
        var initialized: usize = 0;
        errdefer for (reserved[0..initialized]) |*slot| slot.deinit();
        var bytes = count * @sizeOf(slots.Slot);
        if (bytes > maximum_bytes) return error.ReservationLimit;
        for (reserved) |*slot| {
            try slot.init(allocator, program, limits);
            initialized += 1;
            bytes = std.math.add(usize, bytes, slot.owner.queryCapacity()) catch
                return error.ReservationLimit;
            if (bytes > maximum_bytes) return error.ReservationLimit;
        }
        self.* = .{ .allocator = allocator, .slots = reserved, .reserved_bytes = bytes };
    }

    /// Strong CAS failures mean another admission changed occupancy. Attempts are
    /// bounded by capacity; contention may refuse admission even with a free slot.
    pub fn lease(self: *Pool) Error!Lease {
        const mask = (@as(u32, 1) << @intCast(self.slots.len)) - 1;
        var observed = self.occupancy.load(.acquire);
        for (0..self.slots.len) |_| {
            if (observed & closed != 0) return error.PoolClosed;
            const available = mask & ~observed;
            if (available == 0) return error.PoolBusy;
            const index: usize = @intCast(@ctz(available));
            const bit = @as(u32, 1) << @intCast(index);
            if (self.occupancy.cmpxchgStrong(
                observed,
                observed | bit,
                .acquire,
                .monotonic,
            )) |current| {
                observed = current;
                continue;
            }
            return .{ .pool = self, .index = index };
        }
        return error.PoolBusy;
    }

    pub fn close(self: *Pool) void {
        _ = self.occupancy.fetchOr(closed, .acq_rel);
    }

    pub fn drained(self: *const Pool) bool {
        return self.occupancy.load(.acquire) == closed;
    }

    /// The owner joins workers before this call; closing is not cancellation of
    /// an executing transaction and cannot invalidate its immutable generation.
    pub fn deinit(self: *Pool) void {
        std.debug.assert(self.drained());
        for (self.slots) |*slot| slot.deinit();
        self.allocator.free(self.slots);
        self.* = undefined;
    }
};

pub const Lease = struct {
    pool: *Pool,
    index: usize,

    pub fn slot(self: *const Lease) *slots.Slot {
        return &self.pool.slots[self.index];
    }

    /// End all Executor and View borrows first. Do not copy or reuse a released
    /// lease. Release ordering publishes the completed reset to the next owner.
    pub fn release(self: *Lease) void {
        const reserved = self.slot();
        if (reserved.active) reserved.finish();
        const bit = @as(u32, 1) << @intCast(self.index);
        const previous = self.pool.occupancy.fetchAnd(~bit, .release);
        std.debug.assert(previous & bit != 0);
        self.* = undefined;
    }
};

test {
    _ = @import("transaction_pool_test.zig");
}

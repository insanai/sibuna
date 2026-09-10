//! The hub owns topic stores and subscriber queues. Its producer never performs network
//! I/O; handlers transfer only owned commands and copied frames across the hub mutex.
const std = @import("std");
const p = @import("console_protocol");
const s = p.subscriptions;
const topics = @import("topic_store.zig");
const subscriber = @import("subscriber.zig");
const Subscriber = subscriber.Subscriber;
const queue = @import("subscription_queue.zig");
const Frame = @import("dashboard_stats.zig").Frame;
pub const Handle = struct { index: usize, generation: u64 };
const Slot = struct { generation: u64 = 0, value: ?*Subscriber = null };
pub const Hub = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    boot: [32]u8,
    stores: [s.topic_count]*topics.Store,
    dashboard: *Frame,
    dashboard_store: *topics.Store,
    slots: [80]Slot = @splat(.{}),
    mutex: std.Io.Mutex = .init,
    next_id: u64 = 1,
    next_epoch: u64 = 1,
    count: std.atomic.Value(u8) = .init(0),
    arena_bytes: []u8,
    scratch: []u8,
    stopping: bool = false,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, boot: [16]u8) !*Hub {
        const self = try gpa.create(Hub);
        errdefer gpa.destroy(self);
        const arena = try gpa.alloc(u8, 512 * 1024);
        errdefer gpa.free(arena);
        const scratch = try gpa.alloc(u8, s.snapshot_bytes);
        errdefer gpa.free(scratch);
        const dashboard = try gpa.create(Frame);
        errdefer gpa.destroy(dashboard);
        dashboard.* = .{};
        const dashboard_store = try gpa.create(topics.Store);
        errdefer gpa.destroy(dashboard_store);
        dashboard_store.* = .{};
        self.* = .{
            .gpa = gpa,
            .io = io,
            .boot = std.fmt.bytesToHex(boot, .lower),
            .stores = undefined,
            .dashboard = dashboard,
            .dashboard_store = dashboard_store,
            .arena_bytes = arena,
            .scratch = scratch,
        };
        var created: usize = 0;
        errdefer for (self.stores[0..created]) |store| gpa.destroy(store);
        for (&self.stores) |*store| {
            store.* = try gpa.create(topics.Store);
            store.*.* = .{};
            created += 1;
        }
        return self;
    }

    /// The composing application joins the feeder and all handlers before destroying us.
    pub fn deinit(self: *Hub) void {
        std.debug.assert(self.count.load(.acquire) == 0);
        for (self.stores) |store| self.gpa.destroy(store);
        self.gpa.destroy(self.dashboard);
        self.gpa.destroy(self.dashboard_store);
        self.gpa.free(self.arena_bytes);
        self.gpa.free(self.scratch);
        self.gpa.destroy(self);
    }

    pub fn attach(self: *Hub) !Handle {
        return self.attachRange(0, 64);
    }

    pub fn attachPeer(self: *Hub) !Handle {
        return self.attachRange(64, self.slots.len);
    }

    fn attachRange(self: *Hub, start: usize, end: usize) !Handle {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.Stopping;
        if (self.next_id == std.math.maxInt(u64)) return error.IdExhausted;
        for (self.slots[start..end], start..) |*slot, index| {
            if (slot.value != null) continue;
            const value = try self.gpa.create(Subscriber);
            value.* = .{};
            slot.* = .{ .generation = self.next_id, .value = value };
            self.next_id += 1;
            _ = self.count.fetchAdd(1, .release);
            return .{ .index = index, .generation = slot.generation };
        }
        return error.Full;
    }

    pub fn detach(self: *Hub, handle: Handle) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const value = self.lookup(handle) orelse @panic("subscription lifetime");
        self.gpa.destroy(value);
        self.slots[handle.index].value = null;
        _ = self.count.fetchSub(1, .release);
    }

    pub fn command(self: *Hub, handle: Handle, input: s.Command) !void {
        try s.validate(input);
        // Management links carry an unfiltered local source, never a browser selection.
        if (handle.index >= 64 and (input.topic != .stats or input.args.node != null))
            return error.InvalidCommand;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.Stopping;
        const value = self.lookup(handle) orelse return error.StaleHandle;
        if (self.next_epoch == std.math.maxInt(u64)) return error.IdExhausted;
        value.command(input, self.next_epoch);
        self.next_epoch += 1;
    }

    pub fn take(self: *Hub, handle: Handle) ?queue.Item {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const value = self.lookup(handle) orelse @panic("subscription lifetime");
        return value.outbox.pop();
    }

    /// Called once per second by the sole feeder. Contended fan-out is skipped, so commands
    /// cannot delay telemetry publication; the next tick catches up or reports a ring gap.
    pub fn fanout(self: *Hub) void {
        if (!self.mutex.tryLock()) return;
        defer self.mutex.unlock(self.io);
        for (self.slots, 0..) |slot, slot_index| {
            const value = slot.value orelse continue;
            const dashboard = if (slot_index < 64 and self.dashboard.initialized)
                self.dashboard
            else
                null;
            var stores = self.stores;
            if (dashboard != null) stores[@intFromEnum(p.Topic.stats)] = self.dashboard_store;
            var fixed = std.heap.FixedBufferAllocator.init(self.arena_bytes);
            value.pump(.{
                .io = self.io,
                .boot = self.boot,
                .stores = &stores,
                .dashboard = dashboard,
                .arena = fixed.allocator(),
                .scratch = self.scratch,
            }) catch |err| {
                // Capacity/serialization failures invalidate every active view. Keep the
                // last good browser state, and do not call incomplete bytes a snapshot.
                std.log.warn("console subscription serialization failed: {t}", .{err});
                for (&value.states, 0..) |*state, index| {
                    if (state.phase == .off or state.phase == .paused) continue;
                    value.outbox.invalidate(@enumFromInt(index), state.epoch, 1);
                    state.phase = .paused;
                }
                value.pending = null;
            };
        }
    }

    pub fn wanted(self: *Hub) [s.topic_count]bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var result: [s.topic_count]bool = @splat(false);
        for (self.slots) |slot| {
            const value = slot.value orelse continue;
            for (value.states, 0..) |state, index|
                result[index] = result[index] or (state.phase != .off and state.phase != .paused);
        }
        return result;
    }

    pub fn stop(self: *Hub) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.stopping = true;
    }

    fn lookup(self: *Hub, handle: Handle) ?*Subscriber {
        if (handle.index >= self.slots.len) return null;
        const slot = &self.slots[handle.index];
        return if (slot.generation == handle.generation) slot.value else null;
    }
};

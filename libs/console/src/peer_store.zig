//! Ephemeral observations from explicitly configured peers. One outbound worker per node;
//! generations fence old connections and copied snapshots never retain parser memory.
const std = @import("std");
const p = @import("console_protocol");
const config = @import("peer_config.zig");
const auth = @import("peer_auth.zig");
pub const Error = auth.Error || error{
    UnknownPeer,
    DuplicateConnection,
    Stopping,
    GenerationExhausted,
    InvalidObservation,
};
pub const Status = p.nodes.PeerStatus;
pub const Handle = struct { index: u8, generation: u64, boot: [16]u8 };
pub const Update = struct {
    /// Borrowed only during publish; Store copies the complete accepted snapshot.
    value: *const p.StatsSnapshot,
    watermark: u64,
    sequence: u64,
    received_at: u64,
};
pub const Observation = struct {
    status: Status = .unobserved,
    received_at: u64 = 0,
    watermark: u64 = 0,
    sequence: u64 = 0,
    resets: u64 = 0,
    has_value: bool = false,
    value: p.StatsSnapshot = undefined,
};
const Slot = struct {
    incoming: bool = false,
    generation: u64 = 0,
    published_generation: u64 = 0,
    boot: [16]u8 = @splat(0),
    observation: Observation = .{},
};
pub const Report = p.nodes.Peer;
pub const Store = struct {
    io: std.Io,
    config: config.Config,
    self_node: u32,
    key: ?[32]u8,
    mutex: std.Io.Mutex = .init,
    replay: auth.ReplayCache = .{},
    slots: [config.max_peers]Slot = @splat(.{}),
    stopping: bool = false,

    /// Caller supplies a separately provisioned master and erases its copy after init.
    pub fn init(io: std.Io, options: config.Config, node: u32, master: ?[32]u8) Store {
        return .{
            .io = io,
            .config = options,
            .self_node = node,
            .key = if (master) |key| auth.derive(key) else null,
        };
    }

    /// All inbound handlers and outbound workers must be joined before deinit.
    pub fn deinit(self: *Store) void {
        for (self.slots) |slot| std.debug.assert(!slot.incoming);
        if (self.key) |*key| std.crypto.secureZero(u8, key);
        self.key = null;
    }

    pub fn stop(self: *Store) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.stopping = true;
    }

    pub fn admit(self: *Store, request: auth.Request, proof: [32]u8, now: u64) Error!u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.Stopping;
        const key = self.key orelse return error.UnknownPeer;
        if (request.to != self.self_node) return error.InvalidIdentity;
        const index = self.find(request.from) orelse return error.UnknownPeer;
        if (self.slots[index].incoming) return error.DuplicateConnection;
        try self.replay.accept(key, request, proof, now);
        self.slots[index].incoming = true;
        return index;
    }

    pub fn release(self: *Store, index: u8) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.debug.assert(self.slots[index].incoming);
        self.slots[index].incoming = false;
    }

    pub fn activate(self: *Store, index: u8, boot: [16]u8) Error!Handle {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.Stopping;
        std.debug.assert(index < self.config.count);
        if (std.mem.allEqual(u8, &boot, 0)) return error.InvalidObservation;
        const slot = &self.slots[index];
        if (slot.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
        slot.generation += 1;
        slot.boot = boot;
        slot.observation.status = .connecting;
        return .{ .index = index, .generation = slot.generation, .boot = boot };
    }

    pub fn publish(self: *Store, handle: Handle, update: Update) Error!bool {
        const value = update.value.*;
        const watermark = update.watermark;
        const sequence = update.sequence;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.debug.assert(handle.index < self.config.count);
        const slot = &self.slots[handle.index];
        if (self.stopping or slot.generation != handle.generation) return false;
        if (value.node != self.config.targets[handle.index].node or value.outcomes_version != 1 or
            !std.mem.eql(u8, &value.boot, &handle.boot) or
            !std.mem.eql(u8, value.sample_probability, "1/64")) return error.InvalidObservation;
        if (value.server_location) |location| {
            if (!location.valid()) return error.InvalidObservation;
        }
        for (value.countries) |country| if (country.code >= 676) return error.InvalidObservation;
        const previous = &slot.observation;
        if (previous.has_value) {
            if (std.mem.eql(u8, &previous.value.boot, &value.boot)) {
                if ((slot.published_generation == handle.generation and
                    sequence <= previous.sequence) or watermark <= previous.watermark or
                    value.uptime_ms <= previous.value.uptime_ms)
                    return false;
            } else previous.resets +|= 1;
        }
        previous.value = value;
        previous.value.sample_probability = "1/64";
        previous.watermark = watermark;
        previous.sequence = sequence;
        slot.published_generation = handle.generation;
        previous.received_at = update.received_at;
        previous.has_value = true;
        previous.status = .current;
        return true;
    }

    pub fn failed(self: *Store, index: u8, rejected: bool) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.slots[index].observation.status = if (rejected) .rejected else .stale;
    }

    pub fn snapshot(self: *Store, output: *[config.max_peers]Observation) u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (output[0..self.config.count], self.slots[0..self.config.count]) |*to, from|
            to.* = from.observation;
        return self.config.count;
    }

    /// A missing sample stays null. Wall-clock skew is displayed separately from receipt age.
    pub fn reports(self: *Store, now: u64, output: *[config.max_peers]Report) u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (output[0..self.config.count], 0..) |*report, index| {
            const sample = &self.slots[index].observation;
            report.* = .{ .node = self.config.targets[index].node, .status = sample.status };
            if (!sample.has_value) continue;
            const age = now -| sample.received_at;
            if (age >= 10 and report.status == .current) report.status = .stale;
            report.boot = p.Bytes(32).init(&std.fmt.bytesToHex(sample.value.boot, .lower)) catch
                unreachable;
            report.age_seconds = age;
            report.clock_skew_seconds = @max(
                sample.value.timestamp -| sample.received_at,
                sample.received_at -| sample.value.timestamp,
            );
            report.sequence = sample.sequence;
            report.watermark = sample.watermark;
            report.resets = sample.resets;
            report.requests = sample.value.requests;
            report.sample_loss = sample.value.sample_loss;
            report.geoip_available = sample.value.geoip_available;
        }
        return self.config.count;
    }

    fn find(self: *const Store, node: u32) ?u8 {
        for (self.config.targets[0..self.config.count], 0..) |target, i|
            if (target.node == node) return @intCast(i);
        return null;
    }
};

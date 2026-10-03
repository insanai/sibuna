//! A reconfigurable command log layered on the core protocol.
//!
//! Commands and configuration stop signs share one bounded, ordered log. A
//! decided stop sign seals the epoch: no later command can commit in it, so
//! the host can transfer application state and start the next configuration
//! at a slot boundary both sides agree on. Checkpoints reuse the same sealing
//! mechanism to bound journal growth across snapshot epochs. The durability
//! contract is inherited unchanged from the core: persist every `Effects`
//! write and call `confirmWritesDurable` before publishing durable claims.
//! A host may pipeline only `Effects.preDurableMessages` while its barrier runs.

const std = @import("std");
const protocol = @import("protocol.zig");

/// Compile-time bounds and protocol policy for a sealed, reconfigurable log.
pub const Options = struct {
    max_members: usize = 7,
    /// Power-of-two consensus window forwarded to the core (ZDS 0011).
    window_slots: usize = 256,
    /// Recovery chunk forwarded to the core; null derives min(64, window).
    recovery_chunk_slots: ?usize = null,
    max_batch: usize = 64,
    max_metadata_bytes: usize = 256,
    read_quorum_size: ?u16 = null,
    write_quorum_size: ?u16 = null,
    election_timeout_ticks: u32 = 10,
    heartbeat_interval_ticks: u32 = 3,
    resend_interval_ticks: u32 = 10,
    /// Forwarded to the core: refuse proposals until the slots a new leader
    /// inherited from earlier ballots are delivered.
    gate_proposals_on_inherited_prefix: bool = false,
};

/// A bounded replicated log built on the explicit Paxos effect machine.
///
/// Commands and configuration stop signs share one ordered log. A decided stop
/// sign seals the current configuration. The host transfers application state
/// and starts the next configuration, just as it would cross a snapshot epoch.
pub fn ReplicatedLog(comptime Value: type, comptime options: Options) type {
    comptime {
        if (options.max_batch == 0) {
            @compileError("paxos ReplicatedLog option max_batch must be greater than zero");
        }
        if (options.max_batch > options.window_slots) {
            @compileError("paxos ReplicatedLog option max_batch must not exceed window_slots");
        }
        const chunk = options.recovery_chunk_slots orelse @min(64, options.window_slots);
        if (options.max_batch > chunk) {
            @compileError("paxos ReplicatedLog option max_batch " ++
                "must not exceed recovery_chunk_slots");
        }
        if (options.max_metadata_bytes > std.math.maxInt(u16)) {
            @compileError("paxos ReplicatedLog option max_metadata_bytes must be at most 65535");
        }
    }

    const StopSignType = struct {
        configuration_id: u64,
        members: [options.max_members]protocol.NodeId,
        member_count: u16,
        metadata: [options.max_metadata_bytes]u8,
        metadata_count: u16,

        /// Validates a next-configuration member list: nonempty, within the
        /// compile-time bound, and free of zero or duplicate IDs. Hosts that
        /// decode stop signs from their own wire formats reuse this check.
        pub fn validateMembers(members: []const protocol.NodeId) !void {
            if (members.len == 0) return error.EmptyMembership;
            if (members.len > options.max_members) return error.TooManyMembers;
            for (members, 0..) |member, index| {
                if (member == 0) return error.InvalidNodeId;
                for (members[0..index]) |previous| {
                    if (previous == member) return error.DuplicateNodeId;
                }
            }
        }

        /// Builds a validated stop sign for the named next configuration.
        pub fn create(
            configuration_id: u64,
            members: []const protocol.NodeId,
            metadata: []const u8,
        ) !@This() {
            if (configuration_id == 0) return error.InvalidConfigurationId;
            if (metadata.len > options.max_metadata_bytes) return error.MetadataTooLarge;
            try validateMembers(members);

            var result = @This(){
                .configuration_id = configuration_id,
                .members = @as([options.max_members]protocol.NodeId, @splat(0)),
                .member_count = @intCast(members.len),
                .metadata = @as([options.max_metadata_bytes]u8, @splat(0)),
                .metadata_count = @intCast(metadata.len),
            };
            @memcpy(result.members[0..members.len], members);
            @memcpy(result.metadata[0..metadata.len], metadata);
            return result;
        }

        /// Returns the next configuration's voting members. The slice borrows
        /// this stop sign's fixed storage and copies nothing.
        pub fn membersSlice(self: *const @This()) []const protocol.NodeId {
            return self.members[0..self.member_count];
        }

        /// Returns the opaque host handover payload (for example, a snapshot
        /// identifier). The slice borrows this stop sign's fixed storage.
        pub fn metadataSlice(self: *const @This()) []const u8 {
            return self.metadata[0..self.metadata_count];
        }
    };

    const EntryType = union(enum) {
        command: Value,
        stop: StopSignType,
    };

    const Core = protocol.Protocol(EntryType, .{
        .max_members = options.max_members,
        .window_slots = options.window_slots,
        .recovery_chunk_slots = options.recovery_chunk_slots,
        .read_quorum_size = options.read_quorum_size,
        .write_quorum_size = options.write_quorum_size,
        .election_timeout_ticks = options.election_timeout_ticks,
        .heartbeat_interval_ticks = options.heartbeat_interval_ticks,
        .resend_interval_ticks = options.resend_interval_ticks,
        .gate_proposals_on_inherited_prefix = options.gate_proposals_on_inherited_prefix,
    });

    return struct {
        /// A decided configuration change: next members plus opaque handover metadata.
        pub const StopSign = StopSignType;
        /// One log entry: an application command or a sealing stop sign.
        pub const Entry = EntryType;
        /// Fixed voting membership with validated, intersecting quorums.
        pub const Membership = Core.Membership;
        /// Caller-owned buffers; sync writes before durable-claim messages.
        pub const Effects = Core.Effects;
        /// One addressed protocol message from the fixed membership.
        pub const Envelope = Core.Envelope;
        /// Wire vocabulary of the core protocol, carrying `Entry` payloads.
        pub const Message = Core.Message;
        /// One durable record; apply in order before publishing durable claims.
        pub const Write = Core.Write;
        /// Durable acceptor and learner state reconstructed by journal replay.
        pub const DurableState = Core.DurableState;
        /// One decided entry, released only as a contiguous slot-ordered prefix.
        pub const Committed = Core.Committed;
        /// Proposer status of the underlying core node.
        pub const Role = Core.Role;
        /// The chosen-trim anchor exchanged with the host (ZDS 0011).
        pub const TrimAnchor = Core.TrimAnchor;

        pub const Node = struct {
            core: Core.Node,
            configuration_id: u64,
            stop_sign: ?StopSign = null,
            stop_slot: protocol.Slot = 0,
            stop_pending: bool = false,
            batch_entries: [options.max_batch]Entry = undefined,

            /// Initializes an empty configuration with priority zero.
            pub fn init(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
            ) !void {
                try self.initWithPriority(id, configuration_id, membership, 0);
            }

            /// Initializes an empty configuration with an election priority.
            pub fn initWithPriority(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                leader_priority: u32,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.initWithPriority(id, membership, leader_priority);
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
            }

            /// Initializes a non-voting learner for this configuration.
            pub fn initLearner(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.initLearner(id, membership);
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
            }

            /// Restores one configuration from replayed durable state.
            ///
            /// `decidedThrough()` reports 0 after restore until this node next
            /// observes a commit or wins an election. The host must rebuild
            /// application state from its own snapshot, not by re-reading
            /// decided entries from this node.
            pub fn restore(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                durable: *const DurableState,
            ) !void {
                try self.restoreWithPriority(id, configuration_id, membership, durable, 0);
            }

            /// Restores one configuration with an election priority.
            ///
            /// `decidedThrough()` reports 0 after restore until this node next
            /// observes a commit or wins an election. The host must rebuild
            /// application state from its own snapshot, not by re-reading
            /// decided entries from this node.
            pub fn restoreWithPriority(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                durable: *const DurableState,
                leader_priority: u32,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.restoreWithPriority(id, membership, durable, leader_priority);
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
                self.observeDurable();
            }

            /// Restores one configuration at the host's consumed floor;
            /// see the core's `restoreAt`.
            pub fn restoreAt(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                durable: *const DurableState,
                floor: protocol.Slot,
                leader_priority: u32,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.restoreAt(id, membership, durable, floor, leader_priority);
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
                self.observeDurable();
            }

            /// Restores a non-voting learner from its commit-only journal.
            pub fn restoreLearner(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                durable: *const DurableState,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.restoreLearner(id, membership, durable);
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
                self.observeDurable();
            }

            /// Starts the configuration named by a decided stop sign,
            /// continuing the same global slot line at `stop_slot` with
            /// the inherited trim anchor (ZDS 0011).
            pub fn initFromStop(
                self: *Node,
                id: protocol.NodeId,
                stop: *const StopSign,
                stop_slot: protocol.Slot,
                anchor: TrimAnchor,
                membership: *Membership,
                leader_priority: u32,
            ) !void {
                try membership.init(stop.membersSlice());
                try self.continueAt(
                    id,
                    stop.configuration_id,
                    membership,
                    anchor,
                    stop_slot,
                    leader_priority,
                );
            }

            /// Starts an empty node at `floor` on the same global slot
            /// line under an explicit configuration and membership.
            pub fn continueAt(
                self: *Node,
                id: protocol.NodeId,
                configuration_id: u64,
                membership: *const Membership,
                anchor: TrimAnchor,
                floor: protocol.Slot,
                leader_priority: u32,
            ) !void {
                if (configuration_id == 0) return error.InvalidConfigurationId;
                try self.core.continueAt(
                    id,
                    membership,
                    anchor,
                    floor,
                    leader_priority,
                );
                self.configuration_id = configuration_id;
                self.stop_sign = null;
                self.stop_slot = 0;
                self.stop_pending = false;
            }

            /// Campaigns using an application command that acts as a no-op.
            pub fn campaign(self: *Node, noop: Value, effects: *Effects) !void {
                try self.core.campaign(.{ .command = noop }, effects);
                self.observeEffects(effects);
            }

            /// Appends one command unless a stop sign is pending or decided.
            pub fn append(self: *Node, value: Value, effects: *Effects) !protocol.Slot {
                if (self.stop_pending or self.stop_sign != null) return error.LogSealed;
                const slot = try self.core.propose(.{ .command = value }, effects);
                self.observeEffects(effects);
                return slot;
            }

            /// Appends a bounded command batch into one caller-consumed effect batch.
            pub fn appendBatch(
                self: *Node,
                values: []const Value,
                slots: []protocol.Slot,
                effects: *Effects,
            ) ![]const protocol.Slot {
                if (self.stop_pending or self.stop_sign != null) return error.LogSealed;
                if (values.len > options.max_batch) return error.BatchTooLarge;
                for (values, self.batch_entries[0..values.len]) |value, *entry| {
                    entry.* = .{ .command = value };
                }
                const proposed = try self.core.proposeBatch(
                    self.batch_entries[0..values.len],
                    slots,
                    effects,
                );
                self.observeEffects(effects);
                return proposed;
            }

            /// Proposes a stop sign for a strictly newer configuration.
            pub fn reconfigure(
                self: *Node,
                configuration_id: u64,
                members: []const protocol.NodeId,
                metadata: []const u8,
                effects: *Effects,
            ) !protocol.Slot {
                if (self.stop_pending or self.stop_sign != null) return error.LogSealed;
                if (configuration_id <= self.configuration_id) {
                    return error.ConfigurationIdRegression;
                }
                const stop = try StopSign.create(configuration_id, members, metadata);
                const slot = try self.core.propose(.{ .stop = stop }, effects);
                self.stop_pending = true;
                self.observeEffects(effects);
                return slot;
            }

            /// Advances logical clocks and observes any stop sign decision.
            pub fn tick(self: *Node, noop: Value, effects: *Effects) !void {
                try self.core.tick(.{ .command = noop }, effects);
                self.observeEffects(effects);
            }

            /// Processes one protocol message and observes committed stop signs.
            pub fn step(self: *Node, envelope: Envelope, effects: *Effects) !void {
                try self.core.step(envelope, effects);
                self.observeEffects(effects);
            }

            /// Records one host-certified chosen entry on a non-voting learner.
            pub fn learnChosen(
                self: *Node,
                from: protocol.NodeId,
                slot: protocol.Slot,
                entry: Entry,
                effects: *Effects,
            ) !void {
                try self.core.learnChosen(from, slot, entry, effects);
                self.observeEffects(effects);
            }

            /// Repairs communication to a peer after transport reconnection.
            pub fn reconnected(
                self: *Node,
                peer: protocol.NodeId,
                effects: *Effects,
            ) !void {
                try self.core.reconnected(peer, effects);
            }

            /// Requests decided entries beginning with `from_slot`.
            pub fn requestCatchUp(
                self: *Node,
                peer: protocol.NodeId,
                from_slot: protocol.Slot,
                effects: *Effects,
            ) !void {
                try self.core.requestCatchUp(peer, from_slot, effects);
            }

            /// Reads one decided command or stop sign from this configuration.
            pub fn read(self: *const Node, slot: protocol.Slot) ?Entry {
                return self.core.committedAt(slot);
            }

            /// Returns the contiguous decided prefix in this configuration.
            pub fn decidedThrough(self: *const Node) protocol.Slot {
                return self.core.decidedThrough();
            }

            /// Returns the first slot the current leadership may fill with a
            /// new value; see the core's `leaderBase`.
            pub fn leaderBase(self: *const Node) protocol.Slot {
                return self.core.leaderBase();
            }

            /// Returns the slot the next append would take.
            pub fn proposalFrontier(self: *const Node) protocol.Slot {
                return self.core.proposalFrontier();
            }

            /// Records that the host durably consumed every released entry
            /// through `through`, licensing consensus-cell reuse below it.
            pub fn advanceMemoryFloor(self: *Node, through: protocol.Slot) !void {
                try self.core.advanceMemoryFloor(through);
            }

            /// Returns the memory floor the host has released.
            pub fn memoryFloor(self: *const Node) protocol.Slot {
                return self.core.memoryFloor();
            }

            /// Adopts a chosen trim record; see the core's
            /// `installChosenTrim` for the contract.
            pub fn installChosenTrim(
                self: *Node,
                anchor: Core.TrimAnchor,
                effects: *Effects,
            ) !void {
                try self.core.installChosenTrim(anchor, effects);
            }

            /// Returns the adopted chosen-trim anchor.
            pub fn trimAnchor(self: *const Node) Core.TrimAnchor {
                return self.core.trimAnchor();
            }

            /// Resets onto an installed state image at `anchor`; the host
            /// replays the retained suffix afterward.
            pub fn beginRecovery(self: *Node, anchor: Core.TrimAnchor) !void {
                try self.core.beginRecovery(anchor);
                self.stop_sign = null;
                self.stop_slot = 0;
                self.recalculateStopPending();
            }

            /// Returns the latest observed leader.
            pub fn currentLeader(self: *const Node) ?protocol.NodeId {
                return self.core.currentLeader();
            }

            /// Returns the durable configuration identity supplied at initialization.
            pub fn configurationId(self: *const Node) u64 {
                return self.configuration_id;
            }

            /// Returns the decided stop sign, if this configuration is sealed.
            pub fn isReconfigured(self: *const Node) ?StopSign {
                return self.stop_sign;
            }

            /// Returns the decided stop sign without copying it. The pointer
            /// borrows this node and is invalidated by the next transition.
            pub fn stopSign(self: *const Node) ?*const StopSign {
                if (self.stop_sign) |*stop| return stop;
                return null;
            }

            /// Returns the slot the decided stop sign occupies, if any. This
            /// is the sealed configuration's final slot; the checkpoint the
            /// host binds to the handover covers every slot before it.
            pub fn stopSlot(self: *const Node) ?protocol.Slot {
                if (self.stop_sign == null) return null;
                return self.stop_slot;
            }

            /// Returns the undecided stop value retained in durable accepted
            /// state or volatile leader proposals. Used by a host to repair
            /// its own durable operation phase after a crash.
            pub fn pendingStopSign(self: *const Node) ?StopSign {
                if (self.stop_sign) |stop| return stop;
                for (&self.core.durable.cells) |*cell| {
                    if (cell.slot == 0 or cell.committed != null) continue;
                    const entry = cell.accepted orelse continue;
                    switch (entry.value) {
                        .command => {},
                        // A stop naming a configuration this node already
                        // runs is completed history, not a pending seal.
                        .stop => |stop| if (stop.configuration_id >
                            self.configuration_id)
                        {
                            return stop;
                        },
                    }
                }
                for (&self.core.lead) |*cell| {
                    if (cell.slot == 0) continue;
                    if (self.core.durable.committedAt(cell.slot) != null) continue;
                    const entry = cell.proposal orelse continue;
                    switch (entry) {
                        .command => {},
                        .stop => |stop| if (stop.configuration_id >
                            self.configuration_id)
                        {
                            return stop;
                        },
                    }
                }
                return null;
            }

            fn recalculateStopPending(self: *Node) void {
                if (self.stop_sign != null) {
                    self.stop_pending = true;
                    return;
                }
                self.stop_pending = self.pendingStopSign() != null;
            }

            fn observeEffects(self: *Node, effects: *const Effects) void {
                for (effects.committedSlice()) |committed| {
                    switch (committed.value) {
                        .command => {},
                        .stop => |stop| if (stop.configuration_id >
                            self.configuration_id)
                        {
                            self.stop_sign = stop;
                            self.stop_slot = committed.slot;
                        },
                    }
                }
                self.recalculateStopPending();
            }

            fn observeDurable(self: *Node) void {
                for (&self.core.durable.cells) |*cell| {
                    const entry = cell.committed orelse continue;
                    switch (entry) {
                        .command => {},
                        // A replayed stop at or below the restored
                        // configuration was already completed.
                        .stop => |stop| if (stop.configuration_id >
                            self.configuration_id)
                        {
                            self.stop_sign = stop;
                            self.stop_slot = cell.slot;
                        },
                    }
                }
                self.recalculateStopPending();
            }
        };
    };
}

test "a decided stop sign seals a configuration" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 2,
        .max_metadata_bytes = 16,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var node: Log.Node = undefined;
    try node.init(1, 7, &membership);
    node.core.role = .leader;
    node.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    _ = try node.append(41, &effects);
    effects.confirmWritesDurable();
    _ = try node.reconfigure(8, &.{ 1, 2, 3 }, "snapshot:19", &effects);
    effects.confirmWritesDurable();
    const stop = node.isReconfigured().?;
    try std.testing.expectEqual(@as(u64, 8), stop.configuration_id);
    try std.testing.expectEqualStrings("snapshot:19", stop.metadataSlice());
    try std.testing.expectError(error.LogSealed, node.append(42, &effects));
}

test "a decided stop sign starts a changed-member configuration" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 2,
        .max_metadata_bytes = 16,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var node: Log.Node = undefined;
    try node.init(1, 7, &membership);
    node.core.role = .leader;
    node.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    _ = try node.append(41, &effects);
    effects.confirmWritesDurable();
    const seal_slot = try node.reconfigure(8, &.{ 2, 3, 4 }, "handover:8", &effects);
    effects.confirmWritesDurable();

    const stop = node.stopSign().?;
    try std.testing.expectEqual(@as(u64, 8), stop.configuration_id);
    try std.testing.expectEqualSlices(
        protocol.NodeId,
        &.{ 2, 3, 4 },
        stop.membersSlice(),
    );
    try std.testing.expectEqual(seal_slot, node.stopSlot().?);

    // A surviving or fresh member starts the next configuration.
    var next_membership: Log.Membership = undefined;
    var next: Log.Node = undefined;
    try next.initFromStop(4, stop, seal_slot, .{}, &next_membership, 0);
    try std.testing.expectEqual(@as(u64, 8), next.configurationId());
    try std.testing.expectEqual(@as(?protocol.Slot, null), next.stopSlot());
    // The next configuration continues the same global slot line.
    try std.testing.expectEqual(seal_slot, next.decidedThrough());

    // The departed member cannot join the configuration that removed it.
    var removed_membership: Log.Membership = undefined;
    var removed: Log.Node = undefined;
    try std.testing.expectError(
        error.NotMember,
        removed.initFromStop(1, stop, seal_slot, .{}, &removed_membership, 0),
    );
}

test "restore recovers the decided stop slot" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 2,
        .max_metadata_bytes = 16,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var node: Log.Node = undefined;
    try node.init(1, 7, &membership);
    node.core.role = .leader;
    node.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    var durable = Log.DurableState{};
    _ = try node.append(41, &effects);
    for (effects.writesSlice()) |write| try durable.apply(write);
    effects.confirmWritesDurable();
    const seal_slot = try node.reconfigure(8, &.{ 1, 2, 4 }, "handover", &effects);
    for (effects.writesSlice()) |write| try durable.apply(write);
    effects.confirmWritesDurable();

    var restored: Log.Node = undefined;
    try restored.restore(1, 7, &membership, &durable);
    try std.testing.expectEqual(seal_slot, restored.stopSlot().?);
    try std.testing.expectEqual(@as(u64, 8), restored.stopSign().?.configuration_id);
}

test "stop sign member validation is reusable by host decoders" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 2,
    });
    try Log.StopSign.validateMembers(&.{ 1, 2, 3 });
    try std.testing.expectError(
        error.EmptyMembership,
        Log.StopSign.validateMembers(&.{}),
    );
    try std.testing.expectError(
        error.TooManyMembers,
        Log.StopSign.validateMembers(&.{ 1, 2, 3, 4 }),
    );
    try std.testing.expectError(
        error.InvalidNodeId,
        Log.StopSign.validateMembers(&.{ 1, 0, 3 }),
    );
    try std.testing.expectError(
        error.DuplicateNodeId,
        Log.StopSign.validateMembers(&.{ 1, 2, 1 }),
    );
}

test "replicated log batches commands without allocation" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 1,
        .window_slots = 4,
        .max_batch = 3,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var node: Log.Node = undefined;
    try node.init(1, 1, &membership);
    node.core.role = .leader;
    node.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};
    var slots: [3]protocol.Slot = undefined;

    const result = try node.appendBatch(&.{ 3, 5, 8 }, &slots, &effects);
    try std.testing.expectEqualSlices(protocol.Slot, &.{ 1, 2, 3 }, result);
    try std.testing.expectEqual(@as(protocol.Slot, 3), node.decidedThrough());
}

test "the replicated log forwards the term base and proposal frontier" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 1,
        .window_slots = 4,
        .max_batch = 2,
        .gate_proposals_on_inherited_prefix = true,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var node: Log.Node = undefined;
    try node.init(1, 1, &membership);
    var effects = Log.Effects{};
    try node.campaign(0, &effects);
    // Deliver the self-addressed phase-one traffic the host would route.
    var pending: [8]Log.Envelope = undefined;
    while (true) {
        effects.confirmWritesDurable();
        var count: usize = 0;
        for (effects.messagesSlice()) |envelope| {
            if (envelope.to == 1) {
                pending[count] = envelope;
                count += 1;
            }
        }
        if (count == 0) break;
        for (pending[0..count]) |envelope| try node.step(envelope, &effects);
    }
    try std.testing.expect(node.core.role == .leader);
    try std.testing.expectEqual(@as(protocol.Slot, 1), node.leaderBase());
    try std.testing.expectEqual(@as(protocol.Slot, 1), node.proposalFrontier());
    // A single member delivers everything it inherited during phase one,
    // so the gate is open and the frontier advances with the append.
    try std.testing.expectEqual(@as(protocol.Slot, 1), try node.append(9, &effects));
    try std.testing.expectEqual(@as(protocol.Slot, 2), node.proposalFrontier());
}

test "reconfigure seals an epoch and initializes the next one" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 1,
        .window_slots = 4,
        .max_batch = 4,
        .max_metadata_bytes = 16,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{1});
    var first: Log.Node = undefined;
    try first.init(1, 11, &membership);
    first.core.role = .leader;
    first.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    const seal_slot = try first.reconfigure(12, &.{1}, "state:3", &effects);
    const stop = first.isReconfigured().?;
    var next_membership: Log.Membership = undefined;
    var next: Log.Node = undefined;
    try next.initFromStop(1, &stop, seal_slot, .{}, &next_membership, 9);
    try std.testing.expectEqual(@as(u64, 12), next.configurationId());
    try std.testing.expectEqual(@as(u32, 9), next.core.leader_priority);
}

test "replicated log learner observes a chosen stop sign" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 2,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var learner: Log.Node = undefined;
    try learner.initLearner(10, 4, &membership);
    var effects = Log.Effects{};
    effects.init();
    const stop = try Log.StopSign.create(5, &.{ 2, 3, 4 }, "snapshot");

    try learner.learnChosen(1, 1, .{ .stop = stop }, &effects);
    try std.testing.expect(learner.isReconfigured() != null);
    try std.testing.expectEqual(
        @as(u64, 5),
        learner.isReconfigured().?.configuration_id,
    );
}

test "restore remains sealed after accepting a stop sign" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 4,
        .max_metadata_bytes = 8,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: Log.Node = undefined;
    try leader.init(1, 4, &membership);
    leader.core.role = .leader;
    leader.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    _ = try leader.reconfigure(5, &.{ 1, 2, 3 }, "next", &effects);
    var durable = Log.DurableState{};
    for (effects.writesSlice()) |write| try durable.apply(write);
    effects.confirmWritesDurable();

    var restored: Log.Node = undefined;
    try restored.restore(1, 4, &membership, &durable);
    try std.testing.expectError(error.LogSealed, restored.append(9, &effects));
}

test "restore does not remain sealed if proposed stop sign was overwritten" {
    const Log = ReplicatedLog(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .max_batch = 4,
        .max_metadata_bytes = 8,
    });
    var membership: Log.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: Log.Node = undefined;
    try leader.init(1, 4, &membership);
    leader.core.role = .leader;
    leader.core.ballot = .{ .round = 1, .node = 1 };
    var effects = Log.Effects{};

    // 1. Propose stop sign in slot 1 (reconfigure)
    _ = try leader.reconfigure(5, &.{ 1, 2, 3 }, "next", &effects);
    var durable = Log.DurableState{};
    for (effects.writesSlice()) |write| try durable.apply(write);
    effects.confirmWritesDurable();

    // 2. Overwrite slot 1 with an accept of a normal command at a higher ballot
    const overwrite_accept = Log.Write{
        .accept = .{
            .ballot = .{ .round = 2, .node = 1 },
            .slot = 1,
            .value = .{ .command = 42 },
        },
    };
    try durable.apply(overwrite_accept);

    // 3. Commit the normal command
    const commit_write = Log.Write{
        .commit = .{
            .slot = 1,
            .value = .{ .command = 42 },
        },
    };
    try durable.apply(commit_write);

    // 4. Restore and verify that append is NOT sealed since the stop sign was overwritten
    var restored: Log.Node = undefined;
    try restored.restore(1, 4, &membership, &durable);
    try std.testing.expect(restored.stop_pending == false);

    // We should be able to append now!
    restored.core.role = .leader;
    restored.core.ballot = .{ .round = 3, .node = 1 };
    effects.reset();
    _ = try restored.append(99, &effects);
}

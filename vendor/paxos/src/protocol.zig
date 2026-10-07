//! A pure, bounded Multi-Paxos state machine with explicit effects.
//!
//! The core owns no sockets, threads, clocks, or heap. The host feeds one
//! `Envelope`, tick, or proposal into a `Node` and receives `Effects`: durable
//! writes, outbound messages, and newly decided entries. Safety rests on the
//! host honoring one ordering rule: persist and sync every record in
//! `writesSlice`, call `confirmWritesDurable`, and only then transmit
//! `messagesSlice`. A reply sent before its write is durable can retract a
//! promise or vote after a crash and break agreement.

const std = @import("std");
const BitSet = @import("bit_set.zig").BitSet;

/// Stable identity of one voting member. Zero is reserved.
pub const NodeId = u32;
/// One-based position in the global protocol log. Zero means no slot.
/// A 64-bit slot never resets over a database lifetime (ZDS 0011).
pub const Slot = u64;

/// Compile-time capacities, quorum policy, and logical clock intervals.
pub const Options = struct {
    /// Maximum members represented by fixed arrays.
    max_members: usize = 7,
    /// Power-of-two count of physical consensus cells. The window bounds
    /// concurrent unresolved and locally cached instances, not lifetime
    /// history: a cell is retagged for a later slot once its occupant is
    /// chosen and released below the memory floor (ZDS 0011).
    window_slots: usize = 256,
    /// Slots resolved per phase-one or catch-up exchange. Bounds every
    /// recovery message and buffer by the chunk, never by history. Null
    /// derives the chunk from the window: min(64, window_slots).
    recovery_chunk_slots: ?usize = null,
    /// Phase one quorum, or a majority when null.
    read_quorum_size: ?u16 = null,
    /// Phase two quorum, or a majority when null.
    write_quorum_size: ?u16 = null,
    /// Follower ticks without leader contact before campaigning.
    election_timeout_ticks: u32 = 10,
    /// Leader ticks between heartbeat broadcasts.
    heartbeat_interval_ticks: u32 = 3,
    /// Leader ticks between bounded retransmission scans.
    resend_interval_ticks: u32 = 10,
    /// Refuse `propose` and `proposeBatch` with `LeaderCatchingUp` until
    /// every slot this leadership inherited from earlier ballots is
    /// delivered. Hosts whose values derive from applied state (hash
    /// chains, compare-and-set, sequence numbers) need it; hosts with
    /// independent values keep pipelining across the takeover.
    gate_proposals_on_inherited_prefix: bool = false,
};

/// Whether the generated type enforces the persist-then-send ordering
/// contract at runtime. `Protocol` always selects `.enforced`; the
/// `host_managed` namespace is the only path to `.host_managed`.
pub const DurabilityGate = enum { enforced, host_managed };

/// Reports a host ordering violation and stops the process in every build
/// mode. Continuing is not safe: a message claiming durability for a write
/// that was never confirmed can retract a promise or vote after a crash.
noinline fn hostOrderViolation(comptime what: []const u8) noreturn {
    @branchHint(.cold);
    std.debug.print("paxos: " ++ what ++ "\n", .{});
    std.process.abort();
}

/// A totally ordered, globally unique proposal attempt.
pub const Ballot = struct {
    round: u64,
    priority: u32 = 0,
    node: NodeId,

    /// Orders below every real ballot. Marks "no promise yet" and tags votes
    /// synthesized for decrees learned without voting (see `Promise`).
    pub const zero: Ballot = .{ .round = 0, .node = 0 };

    /// Compares round, configured priority, and node ID in that order.
    pub fn order(a: Ballot, b: Ballot) std.math.Order {
        if (a.round < b.round) return .lt;
        if (a.round > b.round) return .gt;
        if (a.priority < b.priority) return .lt;
        if (a.priority > b.priority) return .gt;
        if (a.node < b.node) return .lt;
        if (a.node > b.node) return .gt;
        return .eq;
    }

    /// Returns true when `a` is ordered before `b`.
    pub fn lessThan(a: Ballot, b: Ballot) bool {
        return a.order(b) == .lt;
    }

    /// Returns true when every ballot component is equal.
    pub fn eql(a: Ballot, b: Ballot) bool {
        return a.order(b) == .eq;
    }
};

/// Returns a bounded Paxos implementation for a copyable application value.
///
/// Slots are one-based. Slot zero is reserved as the "nothing committed" marker.
/// Values should be self-contained (for example, an ID or fixed-size command),
/// since message serialization and ownership remain the application's concern.
pub fn Protocol(comptime Value: type, comptime options: Options) type {
    return ProtocolGated(Value, options, .enforced);
}

/// Shared implementation behind `Protocol` and `host_managed.Protocol`.
/// Reached from `host_managed.zig` only; root.zig does not re-export it.
pub fn ProtocolGated(
    comptime Value: type,
    comptime options: Options,
    comptime gate: DurabilityGate,
) type {
    comptime {
        if (options.max_members == 0) {
            @compileError("paxos Protocol option max_members must be greater than zero");
        }
        if (options.window_slots == 0) {
            @compileError("paxos Protocol option window_slots must be greater than zero");
        }
        if (!std.math.isPowerOfTwo(options.window_slots)) {
            @compileError("paxos Protocol option window_slots must be a power of two");
        }
        if (options.recovery_chunk_slots) |chunk| {
            if (chunk == 0) {
                @compileError("paxos Protocol option recovery_chunk_slots " ++
                    "must be greater than zero");
            }
            if (chunk > options.window_slots) {
                @compileError("paxos Protocol option recovery_chunk_slots " ++
                    "must not exceed window_slots");
            }
        }
        if (options.max_members > std.math.maxInt(u16)) {
            @compileError("paxos Protocol option max_members must be at most 65535");
        }
        if (options.election_timeout_ticks == 0) {
            @compileError("paxos Protocol option election_timeout_ticks must be greater than zero");
        }
        if (options.heartbeat_interval_ticks == 0) {
            @compileError("paxos Protocol option heartbeat_interval_ticks " ++
                "must be greater than zero");
        }
        if (options.resend_interval_ticks == 0) {
            @compileError("paxos Protocol option resend_interval_ticks must be greater than zero");
        }
        const bound_chunk: usize = options.recovery_chunk_slots orelse
            @min(64, options.window_slots);
        const wide_messages = @as(u128, options.max_members) * bound_chunk +
            2 * options.max_members + 1;
        if (wide_messages > std.math.maxInt(usize)) {
            @compileError("paxos Protocol options max_members and window_slots overflow " ++
                "the derived message capacity");
        }
        const wide_writes = @as(u128, bound_chunk) * 2 + 1;
        if (wide_writes > std.math.maxInt(usize)) {
            @compileError("paxos Protocol option window_slots overflows " ++
                "the derived write capacity");
        }
        if (hasPointers(Value)) {
            @compileError(
                "Value type '" ++ @typeName(Value) ++
                    "' must not contain pointers, slices, or references.",
            );
        }
    }

    const chunk_slots: usize = options.recovery_chunk_slots orelse
        @min(64, options.window_slots);
    // The largest transitions are chunk-bounded: resolving one recovery
    // chunk broadcasts at most one accept per slot per peer plus a prepare
    // continuation and a catch-up request; a resend tick emits at most one
    // chunk per peer plus heartbeats.
    const max_messages = options.max_members * chunk_slots +
        2 * options.max_members + 1;
    // A one-node quorum can accept and commit every slot of one chunk in
    // one step, plus the promise record.
    const max_writes = chunk_slots * 2 + 1;
    const MemberSet = BitSet(options.max_members);
    const SlotSet = BitSet(options.window_slots);
    const window_mask: Slot = options.window_slots - 1;

    return struct {
        const Self = @This();

        /// One acceptor vote: the ballot it was cast in and the value voted
        /// for. Phase one keeps the highest-ballot vote per slot, which is
        /// exactly the evidence condition B3 requires a new leader to honor.
        pub const Accepted = struct {
            ballot: Ballot,
            value: Value,
        };

        /// One tagged phase-one recovery cell: the highest-ballot vote seen
        /// for its slot across the promise quorum.
        const RecoveredCell = struct {
            slot: Slot = 0,
            accepted: ?Accepted = null,
        };

        /// Per-member phase-one progress for the candidate's active chunk.
        const ElectionPeer = struct {
            anchor: TrimAnchor = .{},
            chosen_through: Slot = 0,
            /// The chunk this member is currently reporting; zero until its
            /// `PromiseRange` for the active base arrives.
            range_first: Slot = 0,
            range_last: Slot = 0,
            expected_in_range: u32 = 0,
            received_in_range: u32 = 0,
            range_described: bool = false,
            /// Whether the member knows state above its answered chunk.
            more: bool = false,
        };

        /// One tagged leader bookkeeping cell: the value this leader drives
        /// for its slot and the durable acknowledgements collected for it.
        const LeadCell = struct {
            slot: Slot = 0,
            proposal: ?Value = null,
            acknowledgements: MemberSet = .{},
        };

        /// Fixed voting membership and validated quorum sizes.
        pub const Membership = struct {
            ids: [options.max_members]NodeId = @as([options.max_members]NodeId, @splat(0)),
            count: u16 = 0,
            read_quorum_size: u16 = 0,
            write_quorum_size: u16 = 0,

            /// Replaces `self` with a validated membership.
            pub fn init(self: *Membership, node_ids: []const NodeId) !void {
                if (node_ids.len == 0) return error.EmptyMembership;
                if (node_ids.len > options.max_members) return error.TooManyMembers;

                self.* = .{};
                for (node_ids, 0..) |id, index| {
                    if (id == 0) return error.InvalidNodeId;
                    if (self.indexOf(id) != null) return error.DuplicateNodeId;
                    self.ids[index] = id;
                    self.count += 1;
                }
                const majority: u16 = self.count / 2 + 1;
                self.read_quorum_size = options.read_quorum_size orelse majority;
                self.write_quorum_size = options.write_quorum_size orelse majority;
                if (self.read_quorum_size == 0 or self.read_quorum_size > self.count) {
                    return error.InvalidReadQuorum;
                }
                if (self.write_quorum_size == 0 or self.write_quorum_size > self.count) {
                    return error.InvalidWriteQuorum;
                }
                const quorum_sum = @as(u32, self.read_quorum_size) + self.write_quorum_size;
                if (quorum_sum <= self.count) return error.NonIntersectingQuorums;
                std.debug.assert(self.count == node_ids.len);
                std.debug.assert(self.readQuorum() <= self.count);
                std.debug.assert(self.writeQuorum() <= self.count);
            }

            /// Returns the stable array index for a member ID.
            pub fn indexOf(self: *const Membership, id: NodeId) ?usize {
                for (self.ids[0..self.count], 0..) |member, index| {
                    if (member == id) return index;
                }
                return null;
            }

            /// Returns whether `id` is a member.
            pub fn contains(self: *const Membership, id: NodeId) bool {
                return self.indexOf(id) != null;
            }

            /// Compatibility alias for the phase two quorum.
            pub fn quorum(self: *const Membership) usize {
                return self.writeQuorum();
            }

            /// Number of complete promises required to finish phase one.
            pub fn readQuorum(self: *const Membership) usize {
                return self.read_quorum_size;
            }

            /// Number of durable acceptances required to choose a value.
            pub fn writeQuorum(self: *const Membership) usize {
                return self.write_quorum_size;
            }
        };

        /// The chosen-trim anchor an acceptor answers Phase 1 with for its
        /// released prefix: every slot at or below `chosen_trim_slot` is
        /// chosen under `history_hash`, so its absence from the window can
        /// never be read as an open instance (ZDS 0011). The core treats
        /// the hash as opaque host evidence.
        pub const TrimAnchor = struct {
            trim_id: u64 = 0,
            chosen_trim_slot: Slot = 0,
            history_hash: [32]u8 = @as([32]u8, @splat(0)),
        };

        /// Phase one request (Lamport's NextBallot). `first` is the start
        /// of the chunk the candidate wants resolved; acceptors answer one
        /// bounded range and the candidate re-prepares with a higher
        /// `first` to continue (equal ballots are re-promised without a
        /// second durable write).
        pub const Prepare = struct { ballot: Ballot, first: Slot };
        /// Phase one reply carrying one slot's LastVote evidence. An
        /// acceptor sends one promise per known slot inside the requested
        /// chunk and describes the chunk with `PromiseRange`. A decree this
        /// node learned without ever voting travels as a zero-ballot vote:
        /// it loses to every real vote, so it can never override the
        /// choosing quorum's value, yet it lets a candidate that is behind
        /// on the log recover already-committed decrees.
        pub const Promise = struct {
            ballot: Ballot,
            slot: Slot,
            accepted: Accepted,
        };
        /// Phase one chunk descriptor. The acceptor answered `[first, last]`
        /// with `accepted_count` promises; `chosen_through` summarizes its
        /// contiguous chosen prefix (whose values travel by catch-up, not
        /// by vote), `anchor` its released trim prefix, and `more` whether
        /// it knows state above `last`. Counting per chunk keeps the
        /// exchange correct under reordering and duplication.
        pub const PromiseRange = struct {
            ballot: Ballot,
            anchor: TrimAnchor,
            chosen_through: Slot,
            first: Slot,
            last: Slot,
            accepted_count: u32,
            more: bool,
        };
        /// Phase two request (Lamport's BeginBallot): vote for `value` in
        /// `slot` unless a higher ballot has already been promised.
        pub const Accept = struct {
            ballot: Ballot,
            slot: Slot,
            value: Value,
        };
        /// Phase two vote acknowledgement. Sent only after the vote is
        /// durable, so a leader counting these toward the write quorum is
        /// counting synced disks, not volatile memory. `decided_through`
        /// refreshes the leader's retransmission view of this acceptor.
        pub const AcceptedMessage = struct {
            ballot: Ballot,
            slot: Slot,
            decided_through: Slot,
        };
        /// Announcement that `value` was chosen for `slot`. Commits carry no
        /// ballot: a chosen value can never change, so any commit for a slot
        /// is authoritative regardless of which leader sends it.
        pub const Commit = struct {
            slot: Slot,
            value: Value,
        };
        /// Catch-up request: send known commits in the bounded range
        /// `[from_slot, from_slot + count - 1]`. `count` never exceeds the
        /// recovery chunk; the requester asks again as its prefix advances.
        pub const Learn = struct { from_slot: Slot, count: u32 };
        /// Rejection of `rejected` by an acceptor already promised to
        /// `promised`. Nacks are a liveness aid only: they steer the loser
        /// back to follower and seed its next ballot round. Safety never
        /// depends on a nack arriving.
        pub const Nack = struct {
            rejected: Ballot,
            promised: Ballot,
            decided_through: Slot,
        };
        /// Leader liveness beacon. `decided_through` advertises the leader's
        /// decided prefix so a restarted or lagging follower can request
        /// catch-up without any explicit recovery handshake.
        pub const Heartbeat = struct { ballot: Ballot, decided_through: Slot };

        /// The complete wire vocabulary. Serialization is the host's concern;
        /// every payload is self-contained and free of pointers.
        pub const Message = union(enum) {
            prepare: Prepare,
            promise: Promise,
            promise_range: PromiseRange,
            accept: Accept,
            accepted: AcceptedMessage,
            commit: Commit,
            learn: Learn,
            nack: Nack,
            heartbeat: Heartbeat,
        };

        /// One addressed message. `step` rejects envelopes not addressed to
        /// the local node and senders outside the fixed membership, but it
        /// trusts `from`; the host transport must authenticate the sender.
        pub const Envelope = struct {
            from: NodeId,
            to: NodeId,
            message: Message,
        };

        /// A durable-state delta. Apply in order before publishing any message
        /// that claims durable state. Hosts may pipeline only the narrow
        /// request class returned by `Effects.preDurableMessages`.
        pub const Write = union(enum) {
            promise: Ballot,
            accept: struct {
                ballot: Ballot,
                slot: Slot,
                value: Value,
            },
            commit: struct {
                slot: Slot,
                value: Value,
            },
            /// A chosen trim anchor adopted by this node; replay restores
            /// it so a trimmed acceptor answers Phase 1 correctly after a
            /// restart (ZDS 0011).
            trim_anchor: TrimAnchor,
        };

        /// One decided entry released to the application. Entries are always
        /// released in slot order as a contiguous prefix, never with gaps.
        pub const Committed = struct {
            slot: Slot,
            value: Value,
        };

        /// A request the core cannot answer from its window and hands to
        /// the host: serve journal history below the memory floor to a
        /// peer as ordinary commit envelopes.
        pub const HostRequest = union(enum) {
            serve_range: struct {
                peer: NodeId,
                first: Slot,
                count: u32,
            },
        };

        /// Caller-owned output buffers for one atomic protocol transition.
        pub const Effects = struct {
            writes: [max_writes]Write = undefined,
            writes_count: usize = 0,
            messages: [max_messages]Envelope = undefined,
            messages_count: usize = 0,
            // A commit for the next delivery slot may pass through without
            // claiming its colliding cell, then release every one of the W
            // resident successors. One transition therefore emits at most
            // W + 1 application entries, not merely W.
            committed: [options.window_slots + 1]Committed = undefined,
            committed_count: usize = 0,
            requests: [options.max_members]HostRequest = undefined,
            requests_count: usize = 0,
            writes_confirmed: bool = true,

            /// Initializes only active counts, leaving large backing arrays untouched.
            pub fn init(self: *Effects) void {
                self.writes_count = 0;
                self.messages_count = 0;
                self.committed_count = 0;
                self.requests_count = 0;
                self.writes_confirmed = true;
            }

            /// Clears counts without touching fixed backing storage.
            pub fn reset(self: *Effects) void {
                std.debug.assert(self.writes_count <= self.writes.len);
                std.debug.assert(self.messages_count <= self.messages.len);
                std.debug.assert(self.committed_count <= self.committed.len);
                if (comptime gate == .enforced) {
                    // A nonempty write batch was discarded without the host
                    // confirming durability; replies for it may already be
                    // out. `writes_confirmed` is false only while such a
                    // batch is pending, so one load decides.
                    if (!self.writes_confirmed) {
                        hostOrderViolation("reset discarded unconfirmed writes");
                    }
                }
                self.writes_count = 0;
                self.messages_count = 0;
                self.committed_count = 0;
                self.requests_count = 0;
                self.writes_confirmed = true;
            }

            /// Durable records in required application order.
            pub fn writesSlice(self: *const Effects) []const Write {
                return self.writes[0..self.writes_count];
            }

            /// Whether this batch contains a promise or vote whose loss after
            /// it is published could violate Paxos safety. Those records need
            /// the host's strongest power-loss barrier. A commit-only batch is
            /// different: the value was already chosen from durable quorum
            /// evidence, so its local commit marker is reconstructible during
            /// phase one. Hosts may omit that derived marker, or append it
            /// without paying a second device-cache barrier.
            pub fn requiresPowerLossBarrier(self: *const Effects) bool {
                for (self.writesSlice()) |write| switch (write) {
                    .promise, .accept => return true,
                    .commit, .trim_anchor => {},
                };
                return false;
            }

            /// Returns an iterator over the narrow class of outbound messages
            /// that a host may release while this transition's writes are
            /// being synced.  Today that class contains only phase-two
            /// `accept` requests: they ask remote acceptors to make a vote
            /// durable but make no claim that the sender's own vote is
            /// durable.  Promise streams and `accepted` replies remain behind
            /// `confirmWritesDurable` because they do carry durable claims.
            ///
            /// A pipelining host must still serialize this node: it may not
            /// feed a reply or start another transition until it has persisted
            /// `writesSlice` and called `confirmWritesDurable`.  This lets a
            /// leader overlap its local barrier with follower barriers without
            /// counting volatile state toward a quorum.
            pub fn preDurableMessages(self: *const Effects) PreDurableMessageIterator {
                return .{ .messages = self.messages[0..self.messages_count] };
            }

            /// Records that the host satisfied the persistence contract for
            /// every pending write. If `requiresPowerLossBarrier` is true this
            /// means the strongest durable barrier; a commit-only batch may be
            /// omitted or weakly persisted because it is derived from already
            /// durable quorum evidence. Call before `messagesSlice`.
            pub fn confirmWritesDurable(self: *Effects) void {
                self.writes_confirmed = true;
            }

            /// Messages that may be sent only after all writes are synced.
            /// Every build mode checks that `confirmWritesDurable` ran for
            /// this batch and stops the process on a violation.
            pub fn messagesSlice(self: *const Effects) []const Envelope {
                if (comptime gate == .enforced) {
                    // False only while an unconfirmed write batch is pending.
                    if (!self.writes_confirmed) {
                        hostOrderViolation("messagesSlice before confirmWritesDurable");
                    }
                }
                return self.messages[0..self.messages_count];
            }

            pub const PreDurableMessageIterator = struct {
                messages: []const Envelope,
                index: usize = 0,

                pub fn next(self: *PreDurableMessageIterator) ?Envelope {
                    while (self.index < self.messages.len) {
                        const envelope = self.messages[self.index];
                        self.index += 1;
                        switch (envelope.message) {
                            .accept => return envelope,
                            else => {},
                        }
                    }
                    return null;
                }
            };

            /// Newly available contiguous application entries.
            pub fn committedSlice(self: *const Effects) []const Committed {
                return self.committed[0..self.committed_count];
            }

            /// History the host must serve from its journal: the window no
            /// longer holds these slots.
            pub fn requestsSlice(self: *const Effects) []const HostRequest {
                return self.requests[0..self.requests_count];
            }

            fn addRequest(self: *Effects, request: HostRequest) void {
                std.debug.assert(self.requests_count < self.requests.len);
                self.requests[self.requests_count] = request;
                self.requests_count += 1;
            }

            fn addWrite(self: *Effects, write: Write) void {
                std.debug.assert(self.writes_count < self.writes.len);
                self.writes[self.writes_count] = write;
                self.writes_count += 1;
                self.writes_confirmed = false;
                std.debug.assert(self.writes_count <= self.writes.len);
            }

            fn addMessage(self: *Effects, envelope: Envelope) void {
                std.debug.assert(self.messages_count < self.messages.len);
                self.messages[self.messages_count] = envelope;
                self.messages_count += 1;
                std.debug.assert(self.messages_count <= self.messages.len);
            }

            fn addCommitted(self: *Effects, committed: Committed) void {
                std.debug.assert(self.committed_count < self.committed.len);
                self.committed[self.committed_count] = committed;
                self.committed_count += 1;
                std.debug.assert(self.committed_count <= self.committed.len);
            }
        };

        /// One physical consensus cell. Valid only for the slot stored in its
        /// tag: a lookup for slot `s` succeeds only when `slot == s`, so a
        /// reused cell can never answer for its former occupant (ZDS 0011,
        /// tagged-cell non-aliasing). A zero tag marks an empty cell.
        pub const DurableCell = struct {
            slot: Slot = 0,
            accepted: ?Accepted = null,
            committed: ?Value = null,
        };

        /// Durable acceptor and learner state reconstructed by journal replay.
        pub const DurableState = struct {
            promised: Ballot = Ballot.zero,
            anchor: TrimAnchor = .{},
            cells: [options.window_slots]DurableCell =
                @as([options.window_slots]DurableCell, @splat(.{})),

            /// Returns the durable vote for `slot`, if its cell still holds it.
            pub fn acceptedAt(self: *const DurableState, slot: Slot) ?Accepted {
                if (slot == 0) return null;
                const cell = &self.cells[cellIndex(slot)];
                return if (cell.slot == slot) cell.accepted else null;
            }

            /// Returns the committed value for `slot`, if its cell still holds it.
            pub fn committedAt(self: *const DurableState, slot: Slot) ?Value {
                if (slot == 0) return null;
                const cell = &self.cells[cellIndex(slot)];
                return if (cell.slot == slot) cell.committed else null;
            }

            /// Claims the physical cell for `slot` during journal replay: an
            /// empty cell is tagged, the slot's own cell is returned
            /// unchanged, and a committed older occupant is retagged. The
            /// journal wrote the later record only after live eviction was
            /// legal, so replay may retag without knowing the old floor; an
            /// accepted-only occupant still fails, because eviction never
            /// erases an open vote. Live paths go through `Node.claimLive`,
            /// which additionally requires the occupant below the floor.
            fn claim(self: *DurableState, slot: Slot) ?*DurableCell {
                const cell = &self.cells[cellIndex(slot)];
                if (cell.slot == slot) return cell;
                if (cell.slot == 0 or
                    (cell.slot < slot and cell.committed != null))
                {
                    cell.* = .{ .slot = slot };
                    return cell;
                }
                return null;
            }

            /// Folds one record of a lifetime journal, oldest first.
            /// Unlike `apply`, the fold spans configuration changes and
            /// window reuse (ZDS 0008 over ZDS 0011): a promise or accept
            /// below an earlier ballot line is history, not a regression —
            /// the maximum promise is kept so the acceptor can never
            /// promise backwards — and an accept whose cell was reused by
            /// a newer slot is stale (its own slot was already chosen, or
            /// the newer claim could not have happened) and is skipped.
            pub fn replayFold(self: *DurableState, write: Write) !void {
                self.assertValid();
                switch (write) {
                    .promise => |ballot| {
                        if (self.promised.lessThan(ballot)) self.promised = ballot;
                    },
                    .accept => |accepted| {
                        if (accepted.slot == 0) return error.InvalidSlot;
                        const cell = self.claim(accepted.slot) orelse {
                            const held = &self.cells[cellIndex(accepted.slot)];
                            if (held.slot > accepted.slot) return;
                            return error.WindowOverrun;
                        };
                        if (cell.accepted) |stored| {
                            if (stored.ballot.eql(accepted.ballot) and
                                !std.meta.eql(stored.value, accepted.value))
                            {
                                return error.ConflictingValue;
                            }
                        }
                        if (self.promised.lessThan(accepted.ballot)) {
                            self.promised = accepted.ballot;
                        }
                        cell.accepted = .{
                            .ballot = accepted.ballot,
                            .value = accepted.value,
                        };
                    },
                    .commit, .trim_anchor => try self.apply(write),
                }
                self.assertValid();
            }

            /// Replays one journal record in original write order. Regressed
            /// promises and conflicting values are reported as errors, not
            /// repaired: a journal that violates durable monotonicity is
            /// corrupt, and the node must stop rather than vote from it. A
            /// record whose physical cell is still occupied by another slot
            /// means the journal ran past the window without an anchor, which
            /// is equally corrupt.
            pub fn apply(self: *DurableState, write: Write) !void {
                self.assertValid();
                switch (write) {
                    .promise => |ballot| {
                        if (ballot.lessThan(self.promised)) return error.PromiseRegression;
                        self.promised = ballot;
                    },
                    .accept => |accepted| {
                        if (accepted.slot == 0) return error.InvalidSlot;
                        if (accepted.ballot.lessThan(self.promised)) {
                            return error.PromiseRegression;
                        }
                        const cell = self.claim(accepted.slot) orelse
                            return error.WindowOverrun;
                        if (cell.accepted) |stored| {
                            if (stored.ballot.eql(accepted.ballot) and
                                !std.meta.eql(stored.value, accepted.value))
                            {
                                return error.ConflictingValue;
                            }
                        }
                        self.promised = accepted.ballot;
                        cell.accepted = .{
                            .ballot = accepted.ballot,
                            .value = accepted.value,
                        };
                    },
                    .trim_anchor => |anchor| {
                        if (anchor.trim_id < self.anchor.trim_id or
                            anchor.chosen_trim_slot < self.anchor.chosen_trim_slot)
                        {
                            return error.TrimRegression;
                        }
                        // A trim id names one chosen record; a replayed
                        // twin with different content is corruption, the
                        // same rule `trim.classify` applies on adoption.
                        if (anchor.trim_id == self.anchor.trim_id and
                            self.anchor.trim_id != 0 and
                            !std.meta.eql(anchor, self.anchor))
                        {
                            return error.TrimRegression;
                        }
                        self.anchor = anchor;
                    },
                    .commit => |committed| {
                        if (committed.slot == 0) return error.InvalidSlot;
                        // A commit whose cell is owned by a later slot was
                        // passed through to the host at delivery time; the
                        // window never held it and replay skips it.
                        const cell = self.claim(committed.slot) orelse return;
                        if (cell.committed) |value| {
                            if (!std.meta.eql(value, committed.value)) {
                                return error.ConflictingCommit;
                            }
                        }
                        // A vote for another value may coexist with the
                        // commit; see `recordCommit` for why that is legal.
                        cell.committed = committed.value;
                    },
                }
                self.assertValid();
            }

            fn assertValid(self: *const DurableState) void {
                if (!std.debug.runtime_safety) return;
                for (self.cells, 0..) |cell, index| {
                    if (cell.slot != 0) {
                        std.debug.assert(cellIndex(cell.slot) == index);
                    }
                    if (cell.accepted) |value| {
                        std.debug.assert(!self.promised.lessThan(value.ballot));
                    }
                }
            }
        };

        /// Proposer status. A `follower` acts only as acceptor and learner,
        /// `preparing` is running phase one, and a `leader` has completed
        /// phase one and may propose new values.
        pub const Role = enum { follower, preparing, leader };

        /// One protocol participant containing proposer, acceptor, and learner roles.
        pub const Node = struct {
            id: NodeId,
            membership: Membership,
            durable: DurableState,
            role: Role = .follower,
            ballot: Ballot = Ballot.zero,
            highest_observed_round: u64 = 0,
            // Nacks need the full ordering: priorities and node IDs also
            // distinguish promises within one election round.
            highest_observed_ballot: Ballot = .zero,
            leader_hint: ?NodeId = null,
            next_slot: Slot = 1,
            /// First slot this leadership may fill with a new value. Every
            /// lower slot was decided, re-proposed, or learned during phase
            /// one; the host reads it through `leaderBase`.
            leader_base: Slot = 1,
            delivered_through: Slot = 0,
            leader_priority: u32 = 0,
            voting_member: bool = true,
            /// Acceptor-only participants keep voting but never start phase one.
            /// This is a liveness policy; it does not change Paxos safety.
            campaign_enabled: bool = true,
            election_ticks: u32 = 0,
            heartbeat_ticks: u32 = 0,
            resend_ticks: u32 = 0,
            peer_decided_through: [options.max_members]Slot =
                @as([options.max_members]Slot, @splat(0)),

            noop: Value = undefined,
            noop_set: bool = false,
            election: [options.max_members]ElectionPeer =
                @as([options.max_members]ElectionPeer, @splat(.{})),
            promise_seen: [options.max_members]SlotSet =
                @as([options.max_members]SlotSet, @splat(.{})),
            /// First slot of the chunk the candidate is currently resolving.
            recover_base: Slot = 0,
            /// Per-peer resume position for chunk-bounded retransmission.
            resend_cursor: [options.max_members]usize =
                @as([options.max_members]usize, @splat(0)),
            recovered: [options.window_slots]RecoveredCell =
                @as([options.window_slots]RecoveredCell, @splat(.{})),
            lead: [options.window_slots]LeadCell =
                @as([options.window_slots]LeadCell, @splat(.{})),

            /// The greatest slot whose cell the host has released for reuse:
            /// everything at or below it is journal-durable and consumed by
            /// the host, which is what licenses eviction (ZDS 0011).
            memory_floor: Slot = 0,

            /// Initializes a member with priority zero.
            pub fn init(self: *Node, id: NodeId, membership: *const Membership) !void {
                try self.initWithPriority(id, membership, 0);
            }

            /// Initializes a member with an election priority.
            pub fn initWithPriority(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                leader_priority: u32,
            ) !void {
                if (!membership.contains(id)) return error.NotMember;
                self.* = .{
                    .id = id,
                    .membership = membership.*,
                    .durable = .{},
                    .leader_priority = leader_priority,
                };
                self.assertValid();
            }

            /// Initializes a non-voting learner for host-certified decisions.
            /// The learner ID must be outside the acceptor membership.
            pub fn initLearner(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
            ) !void {
                if (id == 0) return error.InvalidNodeId;
                if (membership.contains(id)) return error.LearnerIsVoter;
                self.* = .{
                    .id = id,
                    .membership = membership.*,
                    .durable = .{},
                    .voting_member = false,
                    .campaign_enabled = false,
                };
                self.assertValid();
            }

            /// Restores a priority-zero member from replayed durable state.
            ///
            /// `decidedThrough()` reports 0 after restore until this node next
            /// observes a commit or wins an election, so `readDecided` cannot
            /// replay history yet. The host must rebuild application state
            /// from its own snapshot, not from this node.
            pub fn restore(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                durable: *const DurableState,
            ) !void {
                try self.restoreWithPriority(id, membership, durable, 0);
            }

            /// Restores a prioritized member from replayed durable state.
            ///
            /// `decidedThrough()` reports 0 after restore until this node next
            /// observes a commit or wins an election, so `readDecided` cannot
            /// replay history yet. The host must rebuild application state
            /// from its own snapshot, not from this node.
            pub fn restoreWithPriority(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                durable: *const DurableState,
                leader_priority: u32,
            ) !void {
                try self.restoreAt(id, membership, durable, 0, leader_priority);
            }

            /// Restores a member whose host has already consumed the prefix
            /// through `floor`: the memory floor and delivered prefix resume
            /// there, so a replayed window whose early cells were reused
            /// stays deliverable. `decidedThrough()` reports `floor` until
            /// commits above it re-release the suffix.
            /// Starts an empty node whose window resumes at `floor` on
            /// the same global slot line, carrying an inherited trim
            /// anchor. Used to continue across a decided configuration
            /// change without journal replay (ZDS 0011, ZDS 0008).
            pub fn continueAt(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                anchor: TrimAnchor,
                floor: Slot,
                leader_priority: u32,
            ) !void {
                if (anchor.chosen_trim_slot > floor) return error.TrimRegression;
                try self.initWithPriority(id, membership, leader_priority);
                self.durable.anchor = anchor;
                self.memory_floor = floor;
                self.delivered_through = floor;
                self.next_slot = floor + 1;
                self.assertValid();
            }

            pub fn restoreAt(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                durable: *const DurableState,
                floor: Slot,
                leader_priority: u32,
            ) !void {
                try self.initWithPriority(id, membership, leader_priority);
                self.durable = durable.*;
                // A replayed trim anchor implies the prefix through it is
                // chosen and released; the floor never sits below it.
                const base = @max(floor, self.durable.anchor.chosen_trim_slot);
                // A vote at or below the base is discharged history: the
                // slot sits inside the consumed or anchored chosen prefix
                // that this node's `chosen_through` fences, so the open
                // obligation the vote carried no longer protects anything.
                // An accepted-only occupant left behind would wedge its
                // cell forever, because accepted-only cells are never
                // evicted; a committed occupant stays and retags on
                // demand.
                for (&self.durable.cells) |*cell| {
                    if (cell.slot == 0 or cell.slot > base) continue;
                    if (cell.committed == null) cell.* = .{};
                }
                self.memory_floor = base;
                self.delivered_through = base;
                self.next_slot = @max(self.highestUsedSlot(), base) + 1;
                self.assertValid();
            }

            /// Records that the host has durably consumed every released
            /// entry through `through`, licensing cell reuse below it. The
            /// claim is a host obligation in the same class as
            /// `confirmWritesDurable`: the core can check only monotonicity
            /// and that the slots were delivered.
            pub fn advanceMemoryFloor(self: *Node, through: Slot) !void {
                self.assertValid();
                if (through > self.delivered_through) return error.InvalidSlot;
                if (through > self.memory_floor) self.memory_floor = through;
                self.assertValid();
            }

            /// Returns the memory floor: the greatest slot whose cell the
            /// host has released for reuse.
            pub fn memoryFloor(self: *const Node) Slot {
                return self.memory_floor;
            }

            /// Adopts a chosen trim record: every slot at or below its
            /// anchor is chosen under the bound history hash, and Phase 1
            /// answers the prefix from the anchor instead of the window.
            /// The host calls this when a trim entry commits; the emitted
            /// write makes the adoption durable. Trimming never evicts by
            /// itself; the memory floor still governs cell reuse.
            pub fn installChosenTrim(
                self: *Node,
                anchor: TrimAnchor,
                effects: *Effects,
            ) !void {
                self.assertValid();
                if (anchor.chosen_trim_slot > self.delivered_through) {
                    return error.InvalidSlot;
                }
                const current = &self.durable.anchor;
                if (anchor.trim_id <= current.trim_id) return;
                if (anchor.chosen_trim_slot < current.chosen_trim_slot) {
                    return error.TrimRegression;
                }
                self.durable.anchor = anchor;
                effects.addWrite(.{ .trim_anchor = anchor });
                self.assertValid();
            }

            /// Returns the adopted chosen-trim anchor.
            pub fn trimAnchor(self: *const Node) TrimAnchor {
                return self.durable.anchor;
            }

            /// Resets this node onto an installed state image: the window
            /// empties, and every frontier resumes at the anchor. The host
            /// calls this after verifying a transferred image whose history
            /// prefix ends exactly at the anchor, then replays the retained
            /// suffix through ordinary steps.
            pub fn beginRecovery(self: *Node, anchor: TrimAnchor) !void {
                self.assertValid();
                if (anchor.chosen_trim_slot < self.durable.anchor.chosen_trim_slot) {
                    return error.TrimRegression;
                }
                self.durable.anchor = anchor;
                self.durable.cells =
                    @as([options.window_slots]DurableCell, @splat(.{}));
                self.memory_floor = anchor.chosen_trim_slot;
                self.delivered_through = anchor.chosen_trim_slot;
                self.next_slot = anchor.chosen_trim_slot + 1;
                self.role = .follower;
                self.clearElection();
                self.assertValid();
            }

            /// Restores a non-voting learner from its commit-only journal.
            pub fn restoreLearner(
                self: *Node,
                id: NodeId,
                membership: *const Membership,
                durable: *const DurableState,
            ) !void {
                try self.initLearner(id, membership);
                self.durable = durable.*;
                self.next_slot = self.highestUsedSlot() + 1;
                self.assertValid();
            }

            /// Starts phase one with a locally unique, monotonically increasing ballot.
            pub fn campaign(self: *Node, noop: Value, effects: *Effects) !void {
                self.assertValid();
                effects.reset();
                if (!self.voting_member) return error.NotVoter;
                if (!self.campaign_enabled) return error.CampaignDisabled;
                try self.startCampaign(noop, effects);
                self.assertValid();
            }

            /// Enables or disables automatic and explicit phase-one campaigns.
            /// A disabled node remains a full acceptor and learner.
            pub fn setCampaignEnabled(self: *Node, enabled: bool) void {
                self.assertValid();
                self.campaign_enabled = enabled;
                if (!enabled and self.role == .preparing) self.role = .follower;
                self.assertValid();
            }

            /// Proposes a value after phase one has established this node as leader.
            pub fn propose(self: *Node, value: Value, effects: *Effects) !Slot {
                self.assertValid();
                effects.reset();
                if (!self.voting_member) return error.NotVoter;
                if (self.role != .leader) return error.NotLeader;
                if (!self.inheritedPrefixDelivered()) return error.LeaderCatchingUp;
                if (self.next_slot == std.math.maxInt(Slot)) return error.GlobalSlotExhausted;
                if (self.next_slot - self.memory_floor > options.window_slots) {
                    return error.WindowFull;
                }

                const slot = self.next_slot;
                self.next_slot = slot + 1;
                try self.sendAccept(slot, value, effects);
                self.assertValid();
                return slot;
            }

            /// Proposes several values while returning one combined effect batch.
            pub fn proposeBatch(
                self: *Node,
                values: []const Value,
                slots: []Slot,
                effects: *Effects,
            ) ![]const Slot {
                self.assertValid();
                effects.reset();
                if (!self.voting_member) return error.NotVoter;
                if (self.role != .leader) return error.NotLeader;
                if (!self.inheritedPrefixDelivered()) return error.LeaderCatchingUp;
                if (values.len == 0) return error.EmptyBatch;
                if (values.len > chunk_slots) return error.BatchTooLarge;
                if (slots.len < values.len) return error.SlotBufferTooSmall;
                if (values.len > std.math.maxInt(Slot) - self.next_slot) {
                    return error.GlobalSlotExhausted;
                }

                const occupied: Slot = self.next_slot - 1 - self.memory_floor;
                if (occupied >= options.window_slots) return error.WindowFull;
                const free: Slot = @as(Slot, options.window_slots) - occupied;
                if (values.len > free) return error.WindowFull;

                for (values, slots[0..values.len]) |value, *slot| {
                    slot.* = self.next_slot;
                    self.next_slot += 1;
                    try self.sendAccept(slot.*, value, effects);
                }
                self.assertValid();
                return slots[0..values.len];
            }

            /// Advances failure detection, heartbeats, and bounded retransmission.
            /// Call at a stable application-defined interval.
            pub fn tick(self: *Node, noop: Value, effects: *Effects) !void {
                self.assertValid();
                effects.reset();
                if (!self.voting_member) return;
                self.election_ticks +|= 1;
                self.heartbeat_ticks +|= 1;
                self.resend_ticks +|= 1;

                if (self.role == .leader) {
                    self.sendHeartbeatIfDue(effects);
                    self.resendIfDue(effects);
                } else if (self.role == .preparing and
                    self.election_ticks < options.election_timeout_ticks)
                {
                    // Retry a chunk stalled on window backpressure; the
                    // floor may have advanced since the last attempt.
                    try self.maybeResolveChunk(effects);
                } else if (self.campaign_enabled and
                    self.election_ticks >= options.election_timeout_ticks)
                {
                    try self.startCampaign(noop, effects);
                }
                self.assertValid();
            }

            /// Repairs protocol traffic after the transport reconnects to one peer.
            pub fn reconnected(self: *Node, peer: NodeId, effects: *Effects) !void {
                self.assertValid();
                effects.reset();
                if (!self.membership.contains(peer)) return error.NotMember;
                if (peer == self.id) return error.InvalidPeer;

                if (self.role == .leader) {
                    self.resendTo(peer, effects);
                } else if (self.leader_hint == peer) {
                    self.sendTo(peer, effects, .{ .learn = .{
                        .from_slot = self.delivered_through + 1,
                        .count = @intCast(chunk_slots),
                    } });
                }
                self.assertValid();
            }

            /// Requests committed entries from a peer, starting at `from_slot`.
            pub fn requestCatchUp(
                self: *Node,
                peer: NodeId,
                from_slot: Slot,
                effects: *Effects,
            ) !void {
                self.assertValid();
                effects.reset();
                if (!self.membership.contains(peer)) return error.NotMember;
                if (from_slot == 0) return error.InvalidSlot;
                effects.addMessage(.{
                    .from = self.id,
                    .to = peer,
                    .message = .{ .learn = .{
                        .from_slot = from_slot,
                        .count = @intCast(chunk_slots),
                    } },
                });
                self.assertValid();
            }

            /// Processes one authenticated message from the fixed membership.
            pub fn step(self: *Node, envelope: Envelope, effects: *Effects) !void {
                self.assertValid();
                effects.reset();
                if (envelope.to != self.id) return error.WrongRecipient;
                const member = self.membership.indexOf(envelope.from) orelse return error.NotMember;

                if (extractDecidedThrough(envelope.message)) |dt| {
                    self.peer_decided_through[member] = @max(self.peer_decided_through[member], dt);
                }

                if (!self.voting_member) {
                    return switch (envelope.message) {
                        .commit => |message| self.onCommit(
                            envelope.from,
                            message,
                            effects,
                        ),
                        else => error.LearnerMessageForbidden,
                    };
                }

                switch (envelope.message) {
                    .prepare => |message| try self.onPrepare(
                        envelope.from,
                        message.ballot,
                        message.first,
                        effects,
                    ),
                    .promise => |message| try self.onPromise(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .promise_range => |message| try self.onPromiseRange(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .accept => |message| try self.onAccept(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .accepted => |message| try self.onAccepted(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .commit => |message| try self.onCommit(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .learn => |message| try self.onLearn(
                        envelope.from,
                        message,
                        effects,
                    ),
                    .nack => |message| self.onNack(envelope.from, message),
                    .heartbeat => |message| self.onHeartbeat(
                        envelope.from,
                        message,
                        effects,
                    ),
                }
                self.assertValid();
            }

            /// Installs one value that the host has certified as chosen by the
            /// current acceptor configuration. Intended for non-voting learners.
            pub fn learnChosen(
                self: *Node,
                from: NodeId,
                slot: Slot,
                value: Value,
                effects: *Effects,
            ) !void {
                self.assertValid();
                effects.reset();
                if (self.voting_member) return error.NotLearner;
                if (!self.membership.contains(from)) return error.NotMember;
                try self.onCommit(from, .{ .slot = slot, .value = value }, effects);
                self.assertValid();
            }

            /// Returns a learned value, or null for an undecided or invalid
            /// slot. A slot whose cell was reused below the memory floor
            /// returns null; the host recovers released history from its own
            /// journal or materialized state.
            pub fn committedAt(self: *const Node, slot: Slot) ?Value {
                self.assertValid();
                return self.durable.committedAt(slot);
            }

            /// Returns the last observed leader, if any.
            pub fn currentLeader(self: *const Node) ?NodeId {
                self.assertValid();
                return self.leader_hint;
            }

            /// Returns the highest contiguous slot released to the application.
            pub fn decidedThrough(self: *const Node) Slot {
                self.assertValid();
                return self.delivered_through;
            }

            /// Returns the first slot the current leadership may fill with a
            /// new value. Every lower slot was decided, re-proposed under this
            /// ballot, or requested from a peer during phase one, so a host
            /// whose values depend on applied state must deliver through
            /// `leaderBase() - 1` before it derives a proposal. Meaningful
            /// only while `role == .leader`.
            pub fn leaderBase(self: *const Node) Slot {
                self.assertValid();
                return self.leader_base;
            }

            /// Returns the slot the next proposal would take. Every lower
            /// slot is decided or in flight.
            pub fn proposalFrontier(self: *const Node) Slot {
                self.assertValid();
                return self.next_slot;
            }

            /// Whether the gate option permits a proposal now: either the
            /// option is off or the inherited prefix is delivered.
            fn inheritedPrefixDelivered(self: *const Node) bool {
                if (!options.gate_proposals_on_inherited_prefix) return true;
                return self.delivered_through + 1 >= self.leader_base;
            }

            /// Copies a decided contiguous suffix into caller-owned storage.
            pub fn readDecided(
                self: *const Node,
                from_slot: Slot,
                output: []Committed,
            ) ![]const Committed {
                self.assertValid();
                if (from_slot == 0) return error.InvalidSlot;
                // History at or below the floor may occupy reused cells; the
                // host recovers it from its own journal or materialized
                // state, never from the window.
                if (from_slot <= self.memory_floor) return error.Trimmed;
                if (from_slot > self.delivered_through) return output[0..0];

                const available = self.delivered_through - from_slot + 1;
                if (output.len < available) return error.ReadBufferTooSmall;
                for (0..available) |offset| {
                    const slot = from_slot + @as(Slot, @intCast(offset));
                    output[offset] = .{ .slot = slot, .value = self.committedAt(slot).? };
                }
                return output[0..available];
            }

            fn assertValid(self: *const Node) void {
                if (!std.debug.runtime_safety) return;
                std.debug.assert(self.id != 0);
                if (self.voting_member) {
                    std.debug.assert(self.membership.contains(self.id));
                } else {
                    std.debug.assert(!self.membership.contains(self.id));
                    std.debug.assert(!self.campaign_enabled);
                }
                std.debug.assert(self.membership.count > 0);
                std.debug.assert(self.membership.count <= options.max_members);
                std.debug.assert(self.next_slot >= 1);

                self.durable.assertValid();
            }

            /// Lamport step 1: choose a ballot above every ballot seen,
            /// owned by this node, and broadcast NextBallot (prepare).
            fn startCampaign(self: *Node, noop: Value, effects: *Effects) !void {
                const greatest_round = @max(
                    @max(self.ballot.round, self.durable.promised.round),
                    self.highest_observed_round,
                );
                if (greatest_round == std.math.maxInt(u64)) return error.BallotExhausted;

                self.ballot = .{
                    .round = greatest_round + 1,
                    .priority = self.leader_priority,
                    .node = self.id,
                };
                self.role = .preparing;
                self.leader_hint = null;
                self.noop = noop;
                self.noop_set = true;
                self.election_ticks = 0;
                self.clearElection();
                self.recover_base = self.delivered_through + 1;
                self.broadcast(effects, .{ .prepare = .{
                    .ballot = self.ballot,
                    .first = self.recover_base,
                } });
            }

            fn observeLeader(self: *Node, from: NodeId, ballot: Ballot) void {
                self.leader_hint = from;
                self.noteObservedBallot(ballot);
                self.election_ticks = 0;
                if (!self.ballot.eql(ballot)) self.role = .follower;
            }

            /// Lamport step 2: promise a ballot not below the current one
            /// and reply with LastVote information for the requested chunk,
            /// including decrees learned without voting (paper section 3.1)
            /// as zero-ballot votes. Slots at or below this acceptor's trim
            /// anchor are answered by the anchor itself: their absence from
            /// the window means chosen, never open (ZDS 0011).
            fn onPrepare(
                self: *Node,
                from: NodeId,
                ballot: Ballot,
                first: Slot,
                effects: *Effects,
            ) !void {
                if (ballot.lessThan(self.durable.promised)) {
                    self.sendNack(from, ballot, effects);
                    return;
                }
                if (first == 0) return error.InvalidSlot;

                if (!ballot.eql(self.durable.promised)) {
                    self.durable.promised = ballot;
                    effects.addWrite(.{ .promise = ballot });
                }
                self.observeLeader(from, ballot);
                if (self.ballot.lessThan(ballot)) self.role = .follower;

                const limit = first +| (chunk_slots - 1);
                var accepted_count: u32 = 0;
                var more = false;
                for (&self.durable.cells) |*cell| {
                    if (cell.slot < first or cell.slot == 0) continue;
                    if (cell.slot <= self.durable.anchor.chosen_trim_slot) continue;
                    if (cell.slot > limit) {
                        more = true;
                        continue;
                    }
                    // A decree that was learned without voting still travels
                    // as a zero-ballot vote: the paper's parliamentary
                    // protocol has legislators return already-passed decrees
                    // with their LastVote reply so a president behind on the
                    // log recovers them. A zero ballot loses to every real
                    // vote, so it can never override the choosing quorum's
                    // value.
                    var known = cell.accepted;
                    if (known == null) {
                        if (cell.committed) |value| {
                            known = .{ .ballot = Ballot.zero, .value = value };
                        }
                    }
                    if (known) |value| {
                        accepted_count += 1;
                        effects.addMessage(.{
                            .from = self.id,
                            .to = from,
                            .message = .{ .promise = .{
                                .ballot = ballot,
                                .slot = cell.slot,
                                .accepted = value,
                            } },
                        });
                    }
                }
                effects.addMessage(.{
                    .from = self.id,
                    .to = from,
                    .message = .{ .promise_range = .{
                        .ballot = ballot,
                        .anchor = self.durable.anchor,
                        .chosen_through = self.delivered_through,
                        .first = first,
                        .last = limit,
                        .accepted_count = accepted_count,
                        .more = more,
                    } },
                });
            }

            /// Lamport step 3 (collection): keep the highest-ballot vote
            /// per slot across the promise quorum, as condition B3 needs.
            /// Only votes for the active chunk are counted; anything else
            /// is a stale duplicate from an already-resolved chunk, and
            /// dropping it keeps every counted slot in a distinct cell.
            fn onPromise(
                self: *Node,
                from: NodeId,
                message: Promise,
                effects: *Effects,
            ) !void {
                if (self.role != .preparing) return;
                if (!message.ballot.eql(self.ballot)) return;
                if (message.slot < self.recover_base) return;
                if (message.slot > self.chunkLimit()) return;

                const member = self.membership.indexOf(from) orelse return;
                const index = cellIndex(message.slot);
                if (self.promise_seen[member].insert(index)) {
                    self.election[member].received_in_range += 1;
                }

                const cell = &self.recovered[index];
                if (cell.slot != message.slot) {
                    // The old occupant belongs to a resolved chunk.
                    std.debug.assert(cell.slot < self.recover_base);
                    cell.* = .{ .slot = message.slot };
                }
                if (cell.accepted) |recovered| {
                    if (recovered.ballot.lessThan(message.accepted.ballot)) {
                        cell.accepted = message.accepted;
                    }
                } else {
                    cell.accepted = message.accepted;
                }
                try self.maybeResolveChunk(effects);
            }

            fn onPromiseRange(
                self: *Node,
                from: NodeId,
                message: PromiseRange,
                effects: *Effects,
            ) !void {
                if (self.role != .preparing) return;
                if (!message.ballot.eql(self.ballot)) return;
                if (message.accepted_count > chunk_slots) {
                    return error.InvalidPromise;
                }
                if (message.last < message.first) return error.InvalidPromise;

                const member = self.membership.indexOf(from) orelse return;
                const peer = &self.election[member];
                // Anchors and chosen prefixes are true facts whenever they
                // arrive; the fences only grow.
                if (message.anchor.chosen_trim_slot > peer.anchor.chosen_trim_slot) {
                    peer.anchor = message.anchor;
                }
                peer.chosen_through = @max(peer.chosen_through, message.chosen_through);
                if (message.first != self.recover_base) return;

                peer.range_first = message.first;
                peer.range_last = message.last;
                peer.expected_in_range = message.accepted_count;
                peer.range_described = true;
                peer.more = message.more;
                try self.maybeResolveChunk(effects);
            }

            /// Lamport step 3 (proposal), one chunk at a time: once a read
            /// quorum has fully described the active chunk, drive it and
            /// either continue with the next chunk or take leadership.
            fn maybeResolveChunk(self: *Node, effects: *Effects) !void {
                var complete: usize = 0;
                var any_more = false;
                for (0..self.membership.count) |member| {
                    const peer = &self.election[member];
                    if (!peer.range_described) continue;
                    if (peer.received_in_range >= peer.expected_in_range) {
                        complete += 1;
                        if (peer.more) any_more = true;
                    }
                }
                if (complete < self.membership.readQuorum()) return;
                if (!self.noop_set) return error.MissingNoop;

                const resolved = try self.resolveChunk(any_more, effects);
                // A chunk clamped by the memory floor is window
                // backpressure during the election: stay preparing and let
                // the tick retry once the host releases cells.
                if (!resolved) return;
                if (any_more) {
                    self.beginNextChunk(effects);
                    return;
                }
                self.becomeLeader(effects);
            }

            /// Drives every slot of the resolved chunk above the quorum
            /// fences. F (the greatest trim anchor) and K (the greatest
            /// chosen prefix) are both permanently chosen territory: a
            /// slot at or below them is never filled or re-proposed,
            /// because a vote's absence there means released, not open. A
            /// zero-ballot vote is a learned decree and re-broadcasts as a
            /// commit; values chosen elsewhere but absent here arrive by
            /// catch-up before new proposals, which start above both
            /// fences.
            fn resolveChunk(self: *Node, any_more: bool, effects: *Effects) !bool {
                const fences = self.quorumFences();
                const fence = @max(fences.trim, fences.chosen);
                var slot = @max(self.recover_base, fence + 1);
                // A hole is filled with the no-op only below known state:
                // slots past everything the quorum knows are unallocated,
                // not gaps. When a member reports more beyond this chunk,
                // the whole chunk is below known state.
                const known_high = @max(
                    @max(self.highestUsedSlot(), self.highestRecoveredSlot()),
                    fence,
                );
                const limit = if (any_more)
                    self.chunkLimit()
                else
                    @min(self.chunkLimit(), known_high);
                // Driving a slot needs its physical cell; occupants above
                // the memory floor are not evictable yet, so the drive
                // range is clamped and the caller stays preparing.
                const drive_limit =
                    @min(limit, self.memory_floor +| options.window_slots);
                while (slot <= drive_limit) : (slot += 1) {
                    if (self.durable.committedAt(slot)) |value| {
                        self.broadcastPeers(effects, .{ .commit = .{
                            .slot = slot,
                            .value = value,
                        } });
                        continue;
                    }
                    if (self.recoveredAt(slot)) |vote| {
                        if (vote.ballot.round == 0) {
                            try self.recordCommit(slot, vote.value, effects);
                            self.broadcastPeers(effects, .{ .commit = .{
                                .slot = slot,
                                .value = vote.value,
                            } });
                        } else {
                            try self.sendAccept(slot, vote.value, effects);
                        }
                    } else {
                        try self.sendAccept(slot, self.noop, effects);
                    }
                }
                if (fences.chosen > self.delivered_through) {
                    if (fences.chosen_peer) |peer| {
                        self.sendTo(peer, effects, .{ .learn = .{
                            .from_slot = self.delivered_through + 1,
                            .count = @intCast(chunk_slots),
                        } });
                    }
                }
                return drive_limit >= limit;
            }

            fn beginNextChunk(self: *Node, effects: *Effects) void {
                self.recover_base = self.chunkLimit() + 1;
                for (0..self.membership.count) |member| {
                    const peer = &self.election[member];
                    peer.range_first = 0;
                    peer.range_last = 0;
                    peer.expected_in_range = 0;
                    peer.received_in_range = 0;
                    peer.range_described = false;
                    peer.more = false;
                }
                self.promise_seen = @as([options.max_members]SlotSet, @splat(.{}));
                self.broadcast(effects, .{ .prepare = .{
                    .ballot = self.ballot,
                    .first = self.recover_base,
                } });
            }

            fn becomeLeader(self: *Node, effects: *Effects) void {
                self.role = .leader;
                self.leader_hint = self.id;
                const fences = self.quorumFences();
                const highest = @max(
                    self.highestUsedSlot(),
                    @max(fences.trim, fences.chosen),
                );
                self.next_slot = @max(self.next_slot, highest + 1);
                self.leader_base = self.next_slot;
                // A leader restored from its journal re-releases its own
                // contiguous committed prefix; peers hear re-broadcast
                // commits during resolution, but nobody sends commits to
                // the leader.
                self.emitContiguous(effects);
            }

            const Fences = struct {
                trim: Slot,
                chosen: Slot,
                chosen_peer: ?NodeId,
            };

            fn quorumFences(self: *const Node) Fences {
                var fences = Fences{
                    .trim = self.durable.anchor.chosen_trim_slot,
                    .chosen = self.delivered_through,
                    .chosen_peer = null,
                };
                for (0..self.membership.count) |member| {
                    const peer = &self.election[member];
                    fences.trim = @max(fences.trim, peer.anchor.chosen_trim_slot);
                    if (peer.chosen_through > fences.chosen) {
                        fences.chosen = peer.chosen_through;
                        fences.chosen_peer = self.membership.ids[member];
                    }
                }
                return fences;
            }

            fn chunkLimit(self: *const Node) Slot {
                return self.recover_base +| (chunk_slots - 1);
            }

            /// Lamport step 4: vote unless the ballot is below the promise;
            /// the vote is durable before the reply may be sent.
            fn onAccept(
                self: *Node,
                from: NodeId,
                message: Accept,
                effects: *Effects,
            ) !void {
                if (message.slot == 0) return error.InvalidSlot;
                // The anchored prefix is closed (GlobalTrim.tla `Vote`
                // guards `slot > anchor`): every slot at or below the
                // certified trim anchor is already chosen, so a late
                // accept there is history. Voting would re-tag a released
                // cell with an accepted-only occupant that eviction can
                // never clear.
                if (message.slot <= self.durable.anchor.chosen_trim_slot) {
                    return;
                }
                if (message.ballot.lessThan(self.durable.promised)) {
                    self.sendNack(from, message.ballot, effects);
                    return;
                }

                // A slot whose physical cell still holds another live slot
                // cannot vote yet; the request is dropped and the leader's
                // resend recovers it after this node's window advances.
                const cell = self.claimLive(message.slot) orelse return;

                if (cell.accepted) |accepted| {
                    if (accepted.ballot.eql(message.ballot)) {
                        if (!std.meta.eql(accepted.value, message.value)) {
                            return error.ConflictingValue;
                        }
                        effects.addMessage(.{
                            .from = self.id,
                            .to = from,
                            .message = .{ .accepted = .{
                                .ballot = message.ballot,
                                .slot = message.slot,
                                .decided_through = self.delivered_through,
                            } },
                        });
                        return;
                    }
                }

                self.durable.promised = message.ballot;
                cell.accepted = .{
                    .ballot = message.ballot,
                    .value = message.value,
                };
                self.observeLeader(from, message.ballot);
                effects.addWrite(.{ .accept = .{
                    .ballot = message.ballot,
                    .slot = message.slot,
                    .value = message.value,
                } });
                effects.addMessage(.{
                    .from = self.id,
                    .to = from,
                    .message = .{ .accepted = .{
                        .ballot = message.ballot,
                        .slot = message.slot,
                        .decided_through = self.delivered_through,
                    } },
                });
            }

            /// Lamport step 5: a write quorum of votes for this ballot
            /// passes the decree.
            fn onAccepted(
                self: *Node,
                from: NodeId,
                message: AcceptedMessage,
                effects: *Effects,
            ) !void {
                if (self.role != .leader) return;
                if (!message.ballot.eql(self.ballot)) return;
                if (message.slot == 0) return error.InvalidSlot;

                const cell = &self.lead[cellIndex(message.slot)];
                if (cell.slot != message.slot) return;
                const member = self.membership.indexOf(from) orelse return;
                _ = cell.acknowledgements.insert(member);
                if (cell.acknowledgements.count() < self.membership.writeQuorum()) {
                    return;
                }
                if (self.durable.committedAt(message.slot) != null) return;

                const value = cell.proposal orelse return error.MissingProposedValue;

                try self.recordCommit(message.slot, value, effects);
                self.broadcastPeers(effects, .{ .commit = .{
                    .slot = message.slot,
                    .value = value,
                } });
            }

            /// Lamport step 6: write the passed decree in the ledger.
            fn onCommit(
                self: *Node,
                from: NodeId,
                message: Commit,
                effects: *Effects,
            ) !void {
                // A commit proves a chosen value, not current leadership. Any
                // member may serve catch-up history, including delayed commits
                // from an earlier ballot; only ballot-bearing contact may reset
                // election time or replace the observed leader.
                _ = from;
                try self.recordCommit(message.slot, message.value, effects);
            }

            fn onHeartbeat(
                self: *Node,
                from: NodeId,
                message: Heartbeat,
                effects: *Effects,
            ) void {
                if (message.ballot.lessThan(self.durable.promised)) {
                    self.sendNack(from, message.ballot, effects);
                    return;
                }
                if (!message.ballot.eql(self.durable.promised)) return;
                self.observeLeader(from, message.ballot);
                // A restarted follower re-learns silently: the heartbeat
                // advertises the leader's decided prefix, and the learn reply
                // also corrects the leader's stale view of this follower.
                if (message.decided_through > self.delivered_through) {
                    self.sendTo(from, effects, .{ .learn = .{
                        .from_slot = self.delivered_through + 1,
                        .count = @intCast(chunk_slots),
                    } });
                }
            }

            fn recordCommit(self: *Node, slot: Slot, value: Value, effects: *Effects) !void {
                if (slot == 0) return error.InvalidSlot;
                // A commit at or below the memory floor is a duplicate for a
                // slot whose cell was already released: it was chosen and
                // delivered, so there is nothing left to record. The same
                // holds at or below the certified trim anchor, which can
                // run ahead of the floor until the host consumes
                // (GlobalTrim.tla `Learn` guards `slot > anchor`).
                if (slot <= self.memory_floor) return;
                if (slot <= self.durable.anchor.chosen_trim_slot) return;
                // A commit whose physical cell is owned by another live
                // slot does not need window residency: at exactly the next
                // delivery position it passes straight through to the host,
                // and anywhere else it is dropped and re-served later.
                const cell = self.claimLive(slot) orelse {
                    if (slot == self.delivered_through + 1) {
                        effects.addWrite(.{ .commit = .{
                            .slot = slot,
                            .value = value,
                        } });
                        effects.addCommitted(.{ .slot = slot, .value = value });
                        self.delivered_through = slot;
                        self.emitContiguous(effects);
                    }
                    return;
                };
                if (cell.committed) |committed| {
                    if (!std.meta.eql(committed, value)) return error.ConflictingCommit;
                    // A duplicate commit still releases the contiguous
                    // prefix: after a restart the replayed log is committed
                    // but undelivered, and this is where delivery resumes.
                    self.emitContiguous(effects);
                    return;
                }
                // A differing accepted entry is legal: this node may hold a
                // stale vote from a ballot that never won while a quorum it
                // was not part of chose another value. The commit is
                // authoritative; the stale vote stays and stays harmless
                // because every read quorum intersects the choosing write
                // quorum, whose higher-ballot votes carry the chosen value.
                cell.committed = value;
                effects.addWrite(.{ .commit = .{
                    .slot = slot,
                    .value = value,
                } });
                self.emitContiguous(effects);
            }

            fn emitContiguous(self: *Node, effects: *Effects) void {
                while (true) {
                    const next = self.delivered_through + 1;
                    const value = self.durable.committedAt(next) orelse break;
                    effects.addCommitted(.{ .slot = next, .value = value });
                    self.delivered_through = next;
                }
            }

            fn onLearn(
                self: *Node,
                from: NodeId,
                message: Learn,
                effects: *Effects,
            ) !void {
                if (message.from_slot == 0) return error.InvalidSlot;
                if (message.count == 0 or
                    message.count > chunk_slots)
                {
                    return error.InvalidSlot;
                }
                const limit = message.from_slot +| (message.count - 1);
                if (message.from_slot <= self.memory_floor) {
                    // The requested prefix left the window; the host owns
                    // that history and serves it as commit envelopes.
                    const served_through = @min(limit, self.memory_floor);
                    effects.addRequest(.{ .serve_range = .{
                        .peer = from,
                        .first = message.from_slot,
                        .count = @intCast(served_through - message.from_slot + 1),
                    } });
                }
                for (&self.durable.cells) |*cell| {
                    if (cell.slot < message.from_slot or cell.slot == 0) continue;
                    if (cell.slot > limit) continue;
                    if (cell.committed) |value| {
                        effects.addMessage(.{
                            .from = self.id,
                            .to = from,
                            .message = .{ .commit = .{
                                .slot = cell.slot,
                                .value = value,
                            } },
                        });
                    }
                }
            }

            fn onNack(self: *Node, from: NodeId, message: Nack) void {
                _ = from;
                if (!message.rejected.eql(self.ballot)) return;
                if (!self.ballot.lessThan(message.promised)) return;
                // A delayed rejection concerns our old campaign; it cannot
                // replace a newer durable promise or observed routing hint.
                if (message.promised.lessThan(self.durable.promised) or
                    message.promised.lessThan(self.highest_observed_ballot)) return;
                self.noteObservedBallot(message.promised);
                self.role = .follower;
                self.leader_hint = message.promised.node;
            }

            fn noteObservedBallot(self: *Node, ballot: Ballot) void {
                if (self.highest_observed_ballot.lessThan(ballot))
                    self.highest_observed_ballot = ballot;
                self.highest_observed_round = @max(self.highest_observed_round, ballot.round);
            }

            fn sendAccept(
                self: *Node,
                slot: Slot,
                value: Value,
                effects: *Effects,
            ) !void {
                std.debug.assert(slot != 0);
                const lead = &self.lead[cellIndex(slot)];
                if (lead.slot == slot) {
                    if (lead.proposal) |proposed| {
                        if (!std.meta.eql(proposed, value)) return error.ConflictingValue;
                    }
                } else {
                    lead.* = .{ .slot = slot };
                }
                lead.proposal = value;
                lead.acknowledgements = .{};

                std.debug.assert(!self.ballot.lessThan(self.durable.promised));
                self.durable.promised = self.ballot;
                // The occupancy check in `propose` and the recovery bound in
                // `maybeBecomeLeader` keep every driven slot inside the
                // window, so the leader's own claim cannot fail.
                const cell = self.claimLive(slot) orelse return error.WindowOverrun;
                cell.accepted = .{
                    .ballot = self.ballot,
                    .value = value,
                };
                effects.addWrite(.{ .accept = .{
                    .ballot = self.ballot,
                    .slot = slot,
                    .value = value,
                } });

                const local_member = self.membership.indexOf(self.id).?;
                _ = lead.acknowledgements.insert(local_member);
                if (self.membership.quorum() == 1) {
                    try self.recordCommit(slot, value, effects);
                }
                self.broadcastPeers(effects, .{ .accept = .{
                    .ballot = self.ballot,
                    .slot = slot,
                    .value = value,
                } });
            }

            fn sendNack(
                self: *Node,
                to: NodeId,
                rejected: Ballot,
                effects: *Effects,
            ) void {
                effects.addMessage(.{
                    .from = self.id,
                    .to = to,
                    .message = .{ .nack = .{
                        .rejected = rejected,
                        .promised = self.durable.promised,
                        .decided_through = self.delivered_through,
                    } },
                });
            }

            fn sendHeartbeatIfDue(self: *Node, effects: *Effects) void {
                if (self.heartbeat_ticks < options.heartbeat_interval_ticks) return;
                self.heartbeat_ticks = 0;
                self.broadcastPeers(effects, .{ .heartbeat = .{
                    .ballot = self.ballot,
                    .decided_through = self.delivered_through,
                } });
            }

            fn resendIfDue(self: *Node, effects: *Effects) void {
                if (self.resend_ticks < options.resend_interval_ticks) return;
                self.resend_ticks = 0;
                for (self.membership.ids[0..self.membership.count]) |peer| {
                    if (peer == self.id) continue;
                    self.resendTo(peer, effects);
                }
            }

            fn resendTo(self: *Node, peer: NodeId, effects: *Effects) void {
                const peer_idx = self.membership.indexOf(peer) orelse return;
                const peer_decided = self.peer_decided_through[peer_idx];

                // At most one chunk per peer per resend tick keeps every
                // transition inside the chunk-derived message capacity; the
                // cursor resumes where the last tick stopped.
                var scanned: usize = 0;
                var sent: usize = 0;
                var index = self.resend_cursor[peer_idx] % options.window_slots;
                while (scanned < options.window_slots and sent < chunk_slots) {
                    const cell = &self.durable.cells[index];
                    index = (index + 1) % options.window_slots;
                    scanned += 1;
                    if (cell.slot == 0 or cell.slot <= peer_decided) continue;
                    if (cell.committed) |value| {
                        self.sendTo(peer, effects, .{ .commit = .{
                            .slot = cell.slot,
                            .value = value,
                        } });
                        sent += 1;
                    } else if (self.leadProposalAt(cell.slot)) |value| {
                        self.sendTo(peer, effects, .{ .accept = .{
                            .ballot = self.ballot,
                            .slot = cell.slot,
                            .value = value,
                        } });
                        sent += 1;
                    }
                }
                self.resend_cursor[peer_idx] = index;
            }

            fn leadProposalAt(self: *const Node, slot: Slot) ?Value {
                const cell = &self.lead[cellIndex(slot)];
                return if (cell.slot == slot) cell.proposal else null;
            }

            fn recoveredAt(self: *const Node, slot: Slot) ?Accepted {
                const cell = &self.recovered[cellIndex(slot)];
                return if (cell.slot == slot) cell.accepted else null;
            }

            /// Claims the physical cell for `slot` on the live path. On top
            /// of the replay rule, the occupant must sit at or below the
            /// memory floor: the host has consumed it, so reuse cannot lose
            /// anything the window still owes anyone (ZDS 0011 eviction).
            fn claimLive(self: *Node, slot: Slot) ?*DurableCell {
                const cell = &self.durable.cells[cellIndex(slot)];
                if (cell.slot != slot and cell.slot != 0 and
                    cell.slot > self.memory_floor)
                {
                    return null;
                }
                return self.durable.claim(slot);
            }

            fn sendTo(
                self: *Node,
                peer: NodeId,
                effects: *Effects,
                message: Message,
            ) void {
                effects.addMessage(.{
                    .from = self.id,
                    .to = peer,
                    .message = message,
                });
            }

            fn broadcast(self: *Node, effects: *Effects, message: Message) void {
                for (self.membership.ids[0..self.membership.count]) |member| {
                    self.sendTo(member, effects, message);
                }
            }

            fn broadcastPeers(self: *Node, effects: *Effects, message: Message) void {
                for (self.membership.ids[0..self.membership.count]) |member| {
                    if (member == self.id) continue;
                    self.sendTo(member, effects, message);
                }
            }

            fn clearElection(self: *Node) void {
                self.election = @as([options.max_members]ElectionPeer, @splat(.{}));
                self.promise_seen = @as([options.max_members]SlotSet, @splat(.{}));
                self.recover_base = 0;
                self.recovered = @as([options.window_slots]RecoveredCell, @splat(.{}));
                self.lead = @as([options.window_slots]LeadCell, @splat(.{}));
            }

            fn highestRecoveredSlot(self: *const Node) Slot {
                var result: Slot = 0;
                for (&self.recovered) |*cell| {
                    if (cell.accepted != null) result = @max(result, cell.slot);
                }
                for (&self.durable.cells) |*cell| {
                    if (cell.committed != null) result = @max(result, cell.slot);
                }
                return result;
            }

            fn highestUsedSlot(self: *const Node) Slot {
                var result: Slot = 0;
                for (&self.durable.cells) |*cell| {
                    if (cell.accepted != null or cell.committed != null) {
                        result = @max(result, cell.slot);
                    }
                }
                return result;
            }
        };

        /// Physical cell index for a slot: `slot & (W - 1)`. The power-of-two
        /// window makes this a mask, never a division.
        fn cellIndex(slot: Slot) usize {
            return @intCast(slot & window_mask);
        }

        fn extractDecidedThrough(message: Message) ?Slot {
            switch (message) {
                .prepare => |m| return if (m.first > 0) m.first - 1 else 0,
                .promise_range => |m| return m.chosen_through,
                .accepted => |m| return m.decided_through,
                .nack => |m| return m.decided_through,
                .heartbeat => |m| return m.decided_through,
                .learn => |m| return if (m.from_slot > 1) m.from_slot - 1 else 0,
                else => return null,
            }
        }
    };
}

test "ballots are ordered lexicographically" {
    try std.testing.expect(Ballot.lessThan(
        .{ .round = 1, .node = 9 },
        .{ .round = 2, .node = 1 },
    ));
    try std.testing.expect(Ballot.lessThan(
        .{ .round = 2, .node = 1 },
        .{ .round = 2, .node = 2 },
    ));
    try std.testing.expect(Ballot.lessThan(
        .{ .round = 2, .priority = 3, .node = 9 },
        .{ .round = 2, .priority = 4, .node = 1 },
    ));
}

test "membership rejects invalid configurations" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 8 });
    var membership: P.Membership = undefined;
    try std.testing.expectError(error.EmptyMembership, membership.init(&.{}));
    try std.testing.expectError(error.InvalidNodeId, membership.init(&.{ 1, 0 }));
    try std.testing.expectError(error.DuplicateNodeId, membership.init(&.{ 1, 1 }));
}

test "acceptor-only member never campaigns but still promises" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: P.Node = undefined;
    try node.init(2, &membership);
    node.setCampaignEnabled(false);
    var effects = P.Effects{};
    effects.init();

    try std.testing.expectError(error.CampaignDisabled, node.campaign(0, &effects));
    for (0..20) |_| try node.tick(0, &effects);
    try std.testing.expectEqual(P.Role.follower, node.role);

    try node.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .prepare = .{
            .ballot = .{ .round = 1, .node = 1 },
            .first = 1,
        } },
    }, &effects);
    try std.testing.expect(effects.writesSlice().len > 0);
    effects.confirmWritesDurable();
    try std.testing.expect(effects.messagesSlice().len > 0);
}

test "non-voting learner records only host-certified chosen values" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var learner: P.Node = undefined;
    try learner.initLearner(10, &membership);
    var effects = P.Effects{};
    effects.init();

    try std.testing.expectError(error.NotVoter, learner.campaign(0, &effects));
    try learner.learnChosen(1, 2, 22, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.writesSlice().len);
    try std.testing.expectEqual(@as(usize, 0), effects.committedSlice().len);
    effects.confirmWritesDurable();
    try learner.learnChosen(2, 1, 11, &effects);
    try std.testing.expectEqual(@as(usize, 2), effects.committedSlice().len);
    try std.testing.expectEqual(@as(u64, 11), effects.committedSlice()[0].value);
    try std.testing.expectEqual(@as(u64, 22), effects.committedSlice()[1].value);
    effects.confirmWritesDurable();
    try std.testing.expectError(
        error.NotMember,
        learner.learnChosen(99, 3, 33, &effects),
    );
}

test "flexible read and write quorums must intersect" {
    const Valid = Protocol(u64, .{
        .max_members = 5,
        .window_slots = 8,
        .read_quorum_size = 4,
        .write_quorum_size = 2,
    });
    var valid: Valid.Membership = undefined;
    try valid.init(&.{ 1, 2, 3, 4, 5 });
    try std.testing.expectEqual(@as(usize, 4), valid.readQuorum());
    try std.testing.expectEqual(@as(usize, 2), valid.writeQuorum());

    const Invalid = Protocol(u64, .{
        .max_members = 5,
        .window_slots = 8,
        .read_quorum_size = 2,
        .write_quorum_size = 3,
    });
    var invalid: Invalid.Membership = undefined;
    try std.testing.expectError(
        error.NonIntersectingQuorums,
        invalid.init(&.{ 1, 2, 3, 4, 5 }),
    );
}

const TestProtocol = Protocol(u64, .{ .max_members = 3, .window_slots = 16 });
const TestEnvelope = TestProtocol.Envelope;

fn appendMessages(
    queue: *[512]TestEnvelope,
    queue_count: *usize,
    effects: *const TestProtocol.Effects,
) void {
    for (effects.messagesSlice()) |message| {
        std.debug.assert(queue_count.* < queue.len);
        queue[queue_count.*] = message;
        queue_count.* += 1;
    }
}

fn drainQueue(
    nodes: *[3]TestProtocol.Node,
    durable: *[3]TestProtocol.DurableState,
    queue: *[512]TestEnvelope,
    queue_count: *usize,
) !void {
    var effects = TestProtocol.Effects{};
    while (queue_count.* > 0) {
        const envelope = queue[0];
        std.mem.copyForwards(
            TestEnvelope,
            queue[0 .. queue_count.* - 1],
            queue[1..queue_count.*],
        );
        queue_count.* -= 1;

        const node_index = switch (envelope.to) {
            1 => @as(usize, 0),
            2 => @as(usize, 1),
            3 => @as(usize, 2),
            else => return error.UnknownNode,
        };
        try nodes[node_index].step(envelope, &effects);
        for (effects.writesSlice()) |write| try durable[node_index].apply(write);
        effects.confirmWritesDurable();
        appendMessages(queue, queue_count, &effects);
    }
}

test "multi-paxos elects a leader and commits consecutive values" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var nodes: [3]TestProtocol.Node = undefined;
    try nodes[0].init(1, &membership);
    try nodes[1].init(2, &membership);
    try nodes[2].init(3, &membership);
    var durable = @as([3]TestProtocol.DurableState, @splat(.{}));
    var queue: [512]TestEnvelope = undefined;
    var queue_count: usize = 0;
    var effects = TestProtocol.Effects{};

    try nodes[0].campaign(0, &effects);
    appendMessages(&queue, &queue_count, &effects);
    try drainQueue(&nodes, &durable, &queue, &queue_count);
    try std.testing.expectEqual(TestProtocol.Role.leader, nodes[0].role);

    const first = try nodes[0].propose(41, &effects);
    try std.testing.expectEqual(@as(Slot, 1), first);
    for (effects.writesSlice()) |write| try durable[0].apply(write);
    effects.confirmWritesDurable();
    appendMessages(&queue, &queue_count, &effects);
    try drainQueue(&nodes, &durable, &queue, &queue_count);

    const second = try nodes[0].propose(42, &effects);
    try std.testing.expectEqual(@as(Slot, 2), second);
    for (effects.writesSlice()) |write| try durable[0].apply(write);
    effects.confirmWritesDurable();
    appendMessages(&queue, &queue_count, &effects);
    try drainQueue(&nodes, &durable, &queue, &queue_count);

    for (&nodes, &durable) |*node, *stored| {
        try std.testing.expectEqual(@as(?u64, 41), node.committedAt(1));
        try std.testing.expectEqual(@as(?u64, 42), node.committedAt(2));
        try std.testing.expectEqualDeep(stored.*, node.durable);
    }
}

test "duplicate messages are idempotent" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(2, &membership);
    var effects = TestProtocol.Effects{};
    const prepare = TestEnvelope{
        .from = 1,
        .to = 2,
        .message = .{ .prepare = .{
            .ballot = .{ .round = 1, .node = 1 },
            .first = 1,
        } },
    };
    try node.step(prepare, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.writes_count);
    effects.confirmWritesDurable();
    try node.step(prepare, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.writes_count);

    const accept = TestEnvelope{
        .from = 1,
        .to = 2,
        .message = .{ .accept = .{
            .ballot = .{ .round = 1, .node = 1 },
            .slot = 1,
            .value = 99,
        } },
    };
    try node.step(accept, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.writes_count);
    effects.confirmWritesDurable();
    try node.step(accept, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.writes_count);
    try std.testing.expectEqual(@as(usize, 1), effects.messages_count);
}

test "phase one tolerates reordering and recovers the highest accepted value" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    const lower = Ballot{ .round = 1, .node = 1 };
    const higher = Ballot{ .round = 1, .node = 2 };

    var first_disk = TestProtocol.DurableState{ .promised = lower };
    first_disk.cells[1] = .{ .slot = 1, .accepted = .{ .ballot = lower, .value = 77 } };
    var second_disk = TestProtocol.DurableState{ .promised = higher };
    second_disk.cells[1] = .{ .slot = 1, .accepted = .{ .ballot = higher, .value = 88 } };

    var nodes: [3]TestProtocol.Node = undefined;
    try nodes[0].restore(1, &membership, &first_disk);
    try nodes[1].restore(2, &membership, &second_disk);
    try nodes[2].init(3, &membership);
    var effects = TestProtocol.Effects{};
    try nodes[2].campaign(0, &effects);
    const prepares = effects.messages;
    const prepares_count = effects.messages_count;
    try std.testing.expectEqual(@as(usize, 3), prepares_count);

    var replies: [6]TestEnvelope = undefined;
    var reply_count: usize = 0;
    for (prepares[0..prepares_count]) |prepare| {
        const index = switch (prepare.to) {
            1 => @as(usize, 0),
            2 => @as(usize, 1),
            3 => @as(usize, 2),
            else => unreachable,
        };
        try nodes[index].step(prepare, &effects);
        effects.confirmWritesDurable();

        // Deliver each completion marker before its entry to exercise a network
        // that does not preserve sender ordering.
        for (effects.messagesSlice()) |reply| {
            if (reply.message == .promise_range) {
                replies[reply_count] = reply;
                reply_count += 1;
            }
        }
        for (effects.messagesSlice()) |reply| {
            if (reply.message == .promise) {
                replies[reply_count] = reply;
                reply_count += 1;
            }
        }
    }

    var saw_recovered_accept = false;
    for (replies[0..reply_count]) |reply| {
        try nodes[2].step(reply, &effects);
        effects.confirmWritesDurable();
        for (effects.messagesSlice()) |outbound| {
            switch (outbound.message) {
                .accept => |accept| {
                    if (accept.slot == 1 and accept.value == 88) {
                        saw_recovered_accept = true;
                    }
                },
                else => {},
            }
        }
    }
    try std.testing.expectEqual(TestProtocol.Role.leader, nodes[2].role);
    try std.testing.expect(saw_recovered_accept);
}

/// Drives a takeover in which node 3 recovers an accept for slot 1 from
/// node 2 and becomes leader while that slot is still undecided. Returns
/// the leader so the caller can inspect the term base and propose.
fn takeoverWithInheritedSlot(comptime P: type, nodes: *[3]P.Node) !void {
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    const lower = Ballot{ .round = 1, .node = 1 };
    const higher = Ballot{ .round = 1, .node = 2 };

    var first_disk = P.DurableState{ .promised = lower };
    first_disk.cells[1] = .{ .slot = 1, .accepted = .{ .ballot = lower, .value = 77 } };
    var second_disk = P.DurableState{ .promised = higher };
    second_disk.cells[1] = .{ .slot = 1, .accepted = .{ .ballot = higher, .value = 88 } };

    try nodes[0].restore(1, &membership, &first_disk);
    try nodes[1].restore(2, &membership, &second_disk);
    try nodes[2].init(3, &membership);
    var effects = P.Effects{};
    try nodes[2].campaign(0, &effects);
    var replies: [6]P.Envelope = undefined;
    var reply_count: usize = 0;
    for (effects.messagesSlice()) |prepare| {
        const index: usize = prepare.to - 1;
        var inner = P.Effects{};
        try nodes[index].step(prepare, &inner);
        inner.confirmWritesDurable();
        for (inner.messagesSlice()) |reply| {
            replies[reply_count] = reply;
            reply_count += 1;
        }
    }
    for (replies[0..reply_count]) |reply| {
        try nodes[2].step(reply, &effects);
        effects.confirmWritesDurable();
    }
    try std.testing.expectEqual(P.Role.leader, nodes[2].role);
}

test "a new leader reports the first slot above everything it inherited" {
    var nodes: [3]TestProtocol.Node = undefined;
    try takeoverWithInheritedSlot(TestProtocol, &nodes);
    const leader = &nodes[2];
    // Slot 1 is re-proposed under the new ballot and still undecided.
    try std.testing.expectEqual(@as(Slot, 0), leader.decidedThrough());
    try std.testing.expectEqual(@as(Slot, 2), leader.leaderBase());
    try std.testing.expectEqual(@as(Slot, 2), leader.proposalFrontier());
    // Without the gate, proposals pipeline above the inherited slot.
    var effects = TestProtocol.Effects{};
    try std.testing.expectEqual(@as(Slot, 2), try leader.propose(5, &effects));
    try std.testing.expectEqual(@as(Slot, 3), leader.proposalFrontier());
}

test "the inherited-prefix gate refuses proposals until the takeover delivers" {
    const Gated = Protocol(u64, .{
        .max_members = 3,
        .window_slots = 16,
        .gate_proposals_on_inherited_prefix = true,
    });
    var nodes: [3]Gated.Node = undefined;
    try takeoverWithInheritedSlot(Gated, &nodes);
    const leader = &nodes[2];
    var effects = Gated.Effects{};
    try std.testing.expectError(error.LeaderCatchingUp, leader.propose(5, &effects));
    var batch = [_]u64{ 5, 6 };
    var slots: [2]Slot = undefined;
    try std.testing.expectError(
        error.LeaderCatchingUp,
        leader.proposeBatch(&batch, &slots, &effects),
    );

    // Node 2 votes for the re-proposed slot 1 under the new ballot; with
    // the leader's own durable vote that decides it, and the gate opens.
    var accept: ?Gated.Envelope = null;
    try leader.reconnected(2, &effects);
    for (effects.messagesSlice()) |outbound| {
        if (outbound.message == .accept and outbound.to == 2) accept = outbound;
    }
    try std.testing.expect(accept != null);
    var inner = Gated.Effects{};
    try nodes[1].step(accept.?, &inner);
    inner.confirmWritesDurable();
    for (inner.messagesSlice()) |reply| {
        if (reply.message == .accepted) {
            try leader.step(reply, &effects);
            effects.confirmWritesDurable();
        }
    }
    try std.testing.expectEqual(@as(Slot, 1), leader.decidedThrough());
    try std.testing.expectEqual(@as(Slot, 2), leader.leaderBase());
    try std.testing.expectEqual(@as(Slot, 2), try leader.propose(5, &effects));
}

test "the window continues past its size once the floor advances" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{1});
    var node: P.Node = undefined;
    try node.init(1, &membership);
    node.role = .leader;
    node.ballot = .{ .round = 1, .node = 1 };
    var effects = P.Effects{};

    // Three full windows of slots commit through the same four cells.
    var slot: Slot = 1;
    while (slot <= 12) : (slot += 1) {
        try std.testing.expectEqual(slot, try node.propose(slot * 100, &effects));
        effects.confirmWritesDurable();
        try std.testing.expectEqual(slot, node.decidedThrough());
        try node.advanceMemoryFloor(slot);
    }
    try std.testing.expectEqual(@as(Slot, 12), node.decidedThrough());

    // Released history answers from the host, not the window.
    try std.testing.expectEqual(@as(?u64, null), node.committedAt(3));
    var output: [4]P.Committed = undefined;
    try std.testing.expectError(error.Trimmed, node.readDecided(2, &output));

    // A stalled floor turns into transient backpressure once the window
    // fills, then clears when the host releases cells.
    while (slot <= 16) : (slot += 1) {
        try std.testing.expectEqual(slot, try node.propose(slot * 100, &effects));
        effects.confirmWritesDurable();
    }
    try std.testing.expectError(error.WindowFull, node.propose(1700, &effects));
    try node.advanceMemoryFloor(16);
    try std.testing.expectEqual(@as(Slot, 17), try node.propose(1700, &effects));
    effects.confirmWritesDurable();
}

test "an election spanning several chunks recovers the whole history" {
    const P = Protocol(u64, .{
        .max_members = 3,
        .window_slots = 16,
        .recovery_chunk_slots = 4,
    });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });

    // One survivor holds ten committed slots; a fresh peer campaigns and
    // must fetch that history four slots at a time before leading.
    var survivor: P.Node = undefined;
    try survivor.init(2, &membership);
    var fresh: P.Node = undefined;
    try fresh.init(1, &membership);
    var effects = P.Effects{};

    var slot: Slot = 1;
    while (slot <= 10) : (slot += 1) {
        try survivor.step(.{ .from = 3, .to = 2, .message = .{ .commit = .{
            .slot = slot,
            .value = slot * 10,
        } } }, &effects);
        effects.confirmWritesDurable();
    }
    try std.testing.expectEqual(@as(Slot, 10), survivor.decidedThrough());

    var queue: [256]P.Envelope = undefined;
    var queue_count: usize = 0;
    try fresh.campaign(0, &effects);
    effects.confirmWritesDurable();
    for (effects.messagesSlice()) |message| {
        queue[queue_count] = message;
        queue_count += 1;
    }

    var guard: usize = 0;
    while (queue_count > 0) : (guard += 1) {
        try std.testing.expect(guard < 1024);
        const envelope = queue[0];
        std.mem.copyForwards(
            P.Envelope,
            queue[0 .. queue_count - 1],
            queue[1..queue_count],
        );
        queue_count -= 1;
        // The third member stays silent; the two-node quorum suffices.
        if (envelope.to == 3) continue;
        const target: *P.Node = if (envelope.to == 1) &fresh else &survivor;
        try target.step(envelope, &effects);
        effects.confirmWritesDurable();
        for (effects.messagesSlice()) |message| {
            queue[queue_count] = message;
            queue_count += 1;
        }
    }

    try std.testing.expectEqual(P.Role.leader, fresh.role);
    try std.testing.expectEqual(@as(Slot, 10), fresh.decidedThrough());
    try std.testing.expectEqual(@as(Slot, 11), fresh.next_slot);
    try std.testing.expectEqual(@as(?u64, 50), fresh.committedAt(5));
}

test "a trimmed quorum closes its prefix to a new leader" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });

    // Two acceptors chose and trimmed slots 1..6: their windows no longer
    // hold that history, only the durable anchor.
    var effects = P.Effects{};
    var nodes: [2]P.Node = undefined;
    for (&nodes, 0..) |*node, index| {
        try node.init(@intCast(index + 2), &membership);
        var slot: Slot = 1;
        while (slot <= 6) : (slot += 1) {
            try node.step(.{ .from = 1, .to = @intCast(index + 2), .message = .{
                .commit = .{ .slot = slot, .value = slot * 10 },
            } }, &effects);
            effects.confirmWritesDurable();
        }
        try node.advanceMemoryFloor(6);
        try node.installChosenTrim(.{
            .trim_id = 1,
            .chosen_trim_slot = 6,
            .history_hash = @as([32]u8, @splat(7)),
        }, &effects);
        effects.confirmWritesDurable();
    }

    // A fresh candidate campaigns against the trimmed pair.
    var fresh: P.Node = undefined;
    try fresh.init(1, &membership);
    try fresh.campaign(0, &effects);
    effects.confirmWritesDurable();
    var prepare_message: ?P.Envelope = null;
    for (effects.messagesSlice()) |envelope| {
        if (envelope.to != 1 and envelope.message == .prepare) {
            prepare_message = envelope;
        }
    }

    var scratch = P.Effects{};
    for (&nodes, 0..) |*node, index| {
        var prepare = prepare_message.?;
        prepare.to = @intCast(index + 2);
        try node.step(prepare, &scratch);
        scratch.confirmWritesDurable();
        for (scratch.messagesSlice()) |reply| {
            try fresh.step(reply, &effects);
            effects.confirmWritesDurable();
        }
    }

    // Leadership is reached with the prefix closed: nothing was proposed
    // at or below the anchor, and the first fresh proposal lands above it.
    try std.testing.expectEqual(P.Role.leader, fresh.role);
    for (effects.messagesSlice()) |envelope| {
        if (envelope.message == .accept) {
            try std.testing.expect(envelope.message.accept.slot > 6);
        }
    }
    try std.testing.expectEqual(@as(Slot, 7), fresh.next_slot);
}

test "a trimmed quorum closes its prefix to a new leader after replay" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });

    // The anchor survives a journal replay and restore.
    var effects = P.Effects{};
    var disk = P.DurableState{};
    try disk.apply(.{ .trim_anchor = .{
        .trim_id = 1,
        .chosen_trim_slot = 6,
        .history_hash = @as([32]u8, @splat(7)),
    } });
    var restored: P.Node = undefined;
    try restored.restoreAt(2, &membership, &disk, 0, 0);
    try std.testing.expectEqual(@as(Slot, 6), restored.trimAnchor().chosen_trim_slot);
    try std.testing.expectEqual(@as(Slot, 6), restored.decidedThrough());

    // Its Phase-1 answer carries the anchor rather than votes.
    try restored.step(.{ .from = 1, .to = 2, .message = .{ .prepare = .{
        .ballot = .{ .round = 1, .node = 1 },
        .first = 1,
    } } }, &effects);
    effects.confirmWritesDurable();
    var described = false;
    for (effects.messagesSlice()) |envelope| {
        switch (envelope.message) {
            .promise => unreachable,
            .promise_range => |range| {
                try std.testing.expectEqual(@as(Slot, 6), range.anchor.chosen_trim_slot);
                described = true;
            },
            else => {},
        }
    }
    try std.testing.expect(described);
}

test "the anchored prefix refuses accepts and commits even above the floor" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 8 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: P.Node = undefined;
    try node.init(2, &membership);
    var effects = P.Effects{};

    // Deliver six slots, but consume only two: the installed anchor runs
    // ahead of the memory floor, exactly the gap the guards must cover.
    var slot: Slot = 1;
    while (slot <= 6) : (slot += 1) {
        try node.step(.{ .from = 1, .to = 2, .message = .{
            .commit = .{ .slot = slot, .value = slot * 10 },
        } }, &effects);
        effects.confirmWritesDurable();
    }
    try node.advanceMemoryFloor(2);
    try node.installChosenTrim(.{
        .trim_id = 1,
        .chosen_trim_slot = 6,
        .history_hash = @as([32]u8, @splat(7)),
    }, &effects);
    effects.confirmWritesDurable();

    // An accept inside the anchored prefix is history: no vote, no write,
    // no reply, whatever its ballot.
    try node.step(.{ .from = 1, .to = 2, .message = .{ .accept = .{
        .ballot = .{ .round = 9, .node = 1 },
        .slot = 4,
        .value = 999,
    } } }, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.writesSlice().len);
    try std.testing.expectEqual(@as(usize, 0), effects.messagesSlice().len);
    try std.testing.expectEqual(@as(u64, 40), node.durable.committedAt(4).?);

    // A duplicate commit there is equally inert.
    try node.step(.{ .from = 1, .to = 2, .message = .{
        .commit = .{ .slot = 3, .value = 999 },
    } }, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.writesSlice().len);
    try std.testing.expectEqual(@as(u64, 30), node.durable.committedAt(3).?);

    // The first slot above the anchor still votes normally.
    try node.step(.{ .from = 1, .to = 2, .message = .{ .accept = .{
        .ballot = .{ .round = 9, .node = 1 },
        .slot = 7,
        .value = 70,
    } } }, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.writesSlice().len);
    effects.confirmWritesDurable();
    try std.testing.expectEqual(@as(u64, 70), node.durable.acceptedAt(7).?.value);
}

test "restore preserves the promise and votes above the floor, not below" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 8 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });

    // A durable state carrying a promise, a discharged vote below the
    // restore floor, and an open vote above it — the shape a state
    // transfer leaves behind.
    var disk = P.DurableState{};
    const promised = Ballot{ .round = 5, .node = 3 };
    try disk.replayFold(.{ .accept = .{
        .ballot = .{ .round = 2, .node = 1 },
        .slot = 3,
        .value = 30,
    } });
    try disk.replayFold(.{ .promise = promised });
    try disk.replayFold(.{ .accept = .{
        .ballot = .{ .round = 5, .node = 3 },
        .slot = 7,
        .value = 70,
    } });

    var node: P.Node = undefined;
    try node.restoreAt(2, &membership, &disk, 5, 0);

    // The promise and the open vote above the floor survive; the vote
    // below the floor is history the image already covers, and its cell
    // is free again rather than wedged accepted-only forever.
    try std.testing.expect(!node.durable.promised.lessThan(promised));
    try std.testing.expectEqual(@as(u64, 70), node.durable.acceptedAt(7).?.value);
    try std.testing.expectEqual(@as(?P.Accepted, null), node.durable.acceptedAt(3));
    try std.testing.expectEqual(@as(Slot, 8), node.next_slot);
}

test "replaying twin trim anchors under one id fails closed" {
    var disk = TestProtocol.DurableState{};
    try disk.replayFold(.{ .trim_anchor = .{
        .trim_id = 3,
        .chosen_trim_slot = 6,
        .history_hash = @as([32]u8, @splat(7)),
    } });
    // The identical record replays idempotently.
    try disk.replayFold(.{ .trim_anchor = .{
        .trim_id = 3,
        .chosen_trim_slot = 6,
        .history_hash = @as([32]u8, @splat(7)),
    } });
    // A twin with the same id and different content is corruption.
    try std.testing.expectError(error.TrimRegression, disk.replayFold(.{ .trim_anchor = .{
        .trim_id = 3,
        .chosen_trim_slot = 6,
        .history_hash = @as([32]u8, @splat(9)),
    } }));
}

test "a full window reports transient backpressure without reusing a cell" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 1 });
    var membership: P.Membership = undefined;
    try membership.init(&.{1});
    var node: P.Node = undefined;
    try node.init(1, &membership);
    node.role = .leader;
    node.ballot = .{ .round = 1, .node = 1 };
    var effects = P.Effects{};

    try std.testing.expectEqual(@as(Slot, 1), try node.propose(1, &effects));
    effects.confirmWritesDurable();
    try std.testing.expectError(error.WindowFull, node.propose(2, &effects));
}

test "one-node quorum commits without a remote acknowledgement" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 2 });
    var membership: P.Membership = undefined;
    try membership.init(&.{1});
    var node: P.Node = undefined;
    try node.init(1, &membership);
    node.role = .leader;
    node.ballot = .{ .round = 1, .node = 1 };
    var effects = P.Effects{};

    try std.testing.expectEqual(@as(Slot, 1), try node.propose(71, &effects));
    try std.testing.expectEqual(@as(usize, 2), effects.writes_count);
    try std.testing.expectEqual(@as(usize, 1), effects.committed_count);
    try std.testing.expectEqual(@as(?u64, 71), node.committedAt(1));
}

test "batch proposal returns consecutive slots and one effect batch" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{1});
    var node: P.Node = undefined;
    try node.init(1, &membership);
    node.role = .leader;
    node.ballot = .{ .round = 1, .node = 1 };
    var effects = P.Effects{};
    var slots: [3]Slot = undefined;

    const proposed = try node.proposeBatch(&.{ 11, 22, 33 }, &slots, &effects);
    try std.testing.expectEqualSlices(Slot, &.{ 1, 2, 3 }, proposed);
    try std.testing.expectEqual(@as(usize, 6), effects.writes_count);
    try std.testing.expectEqual(@as(usize, 3), effects.committed_count);
}

test "tick starts an election and emits leader heartbeats" {
    const P = Protocol(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .election_timeout_ticks = 2,
        .heartbeat_interval_ticks = 2,
    });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: P.Node = undefined;
    try node.init(1, &membership);
    var effects = P.Effects{};

    try node.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.messages_count);
    try node.tick(0, &effects);
    try std.testing.expectEqual(P.Role.preparing, node.role);
    try std.testing.expectEqual(@as(usize, 3), effects.messages_count);

    node.role = .leader;
    node.leader_hint = 1;
    node.durable.promised = node.ballot;
    node.heartbeat_ticks = 0;
    try node.tick(0, &effects);
    try node.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 2), effects.messages_count);
    for (effects.messagesSlice()) |message| {
        try std.testing.expect(message.message == .heartbeat);
    }
}

test "durable replay rejects conflicting values" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 1 });
    var durable = P.DurableState{};
    const ballot = Ballot{ .round = 1, .node = 1 };
    try durable.apply(.{ .accept = .{ .ballot = ballot, .slot = 1, .value = 7 } });

    // Two different values in one ballot and slot is corruption.
    try std.testing.expectError(
        error.ConflictingValue,
        durable.apply(.{ .accept = .{ .ballot = ballot, .slot = 1, .value = 8 } }),
    );
    // A commit that differs from a stale local vote is legal Paxos: the
    // choosing quorum may not have included this node.
    try durable.apply(.{ .commit = .{ .slot = 1, .value = 8 } });
    // Two different committed values for one slot is corruption.
    try std.testing.expectError(
        error.ConflictingCommit,
        durable.apply(.{ .commit = .{ .slot = 1, .value = 7 } }),
    );
    // A later-ballot vote may land after the commit; replay accepts it.
    try durable.apply(.{
        .accept = .{
            .ballot = .{ .round = 2, .node = 1 },
            .slot = 1,
            .value = 8,
        },
    });
    // A promise below the recorded vote is regression.
    try std.testing.expectError(
        error.PromiseRegression,
        durable.apply(.{ .accept = .{ .ballot = ballot, .slot = 1, .value = 7 } }),
    );
}

test "leader persists its local acceptance before remote acknowledgements" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: TestProtocol.Node = undefined;
    try leader.init(1, &membership);
    leader.role = .leader;
    leader.ballot = .{ .round = 1, .node = 1 };
    var effects = TestProtocol.Effects{};
    _ = try leader.propose(123, &effects);
    effects.confirmWritesDurable();

    for ([_]NodeId{ 2, 3 }) |from| {
        effects.confirmWritesDurable();
        try leader.step(.{
            .from = from,
            .to = 1,
            .message = .{ .accepted = .{
                .ballot = leader.ballot,
                .slot = 1,
                .decided_through = 0,
            } },
        }, &effects);
    }

    try std.testing.expectEqual(@as(?u64, 123), leader.committedAt(1));
    try std.testing.expectEqual(@as(?u64, 123), leader.durable.acceptedAt(1).?.value);
}

test "learners release commits only as a contiguous prefix" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(2, &membership);
    var effects = TestProtocol.Effects{};
    try node.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .commit = .{ .slot = 2, .value = 22 } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.committed_count);
    effects.confirmWritesDurable();

    try node.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .commit = .{ .slot = 1, .value = 11 } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 2), effects.committed_count);
    try std.testing.expectEqual(@as(Slot, 1), effects.committed[0].slot);
    try std.testing.expectEqual(@as(Slot, 2), effects.committed[1].slot);
}

test "a pass-through commit can release one more than the window" {
    const P = Protocol(u64, .{ .max_members = 1, .window_slots = 4 });
    var membership: P.Membership = undefined;
    try membership.init(&.{1});
    var node: P.Node = undefined;
    try node.init(1, &membership);
    var effects = P.Effects{};

    // Slots 2 through 5 occupy all four cells. Slot 5 owns slot 1's
    // physical cell, so the later commit for slot 1 takes recordCommit's
    // pass-through path and then releases the four resident successors.
    var slot: Slot = 2;
    while (slot <= 5) : (slot += 1) {
        try node.step(.{
            .from = 1,
            .to = 1,
            .message = .{ .commit = .{ .slot = slot, .value = slot * 10 } },
        }, &effects);
        try std.testing.expectEqual(@as(usize, 0), effects.committed_count);
        effects.confirmWritesDurable();
    }

    try node.step(.{
        .from = 1,
        .to = 1,
        .message = .{ .commit = .{ .slot = 1, .value = 10 } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 5), effects.committed_count);
    for (effects.committedSlice(), 1..) |committed, expected_slot| {
        try std.testing.expectEqual(@as(Slot, expected_slot), committed.slot);
        try std.testing.expectEqual(@as(u64, expected_slot * 10), committed.value);
    }
}

test "effects track durability confirmation for each write batch" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(2, &membership);
    var effects = TestProtocol.Effects{};

    try std.testing.expect(effects.writes_confirmed);
    try node.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .prepare = .{
            .ballot = .{ .round = 1, .node = 1 },
            .first = 1,
        } },
    }, &effects);
    try std.testing.expect(effects.writes_count > 0);
    try std.testing.expect(!effects.writes_confirmed);
    effects.confirmWritesDurable();
    try std.testing.expect(effects.writes_confirmed);
    try std.testing.expect(effects.messagesSlice().len > 0);

    // A confirmed batch may be reset and reused for the next transition.
    effects.reset();
    try std.testing.expect(effects.writes_confirmed);
    try std.testing.expectEqual(@as(usize, 0), effects.writes_count);
}

test "only accept requests are available before durability confirmation" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });

    var leader: TestProtocol.Node = undefined;
    try leader.init(1, &membership);
    leader.role = .leader;
    leader.ballot = .{ .round = 1, .node = 1 };
    leader.durable.promised = leader.ballot;

    var effects = TestProtocol.Effects{};
    _ = try leader.propose(42, &effects);
    try std.testing.expect(!effects.writes_confirmed);
    try std.testing.expect(effects.requiresPowerLossBarrier());
    var early = effects.preDurableMessages();
    var accept_count: usize = 0;
    while (early.next()) |envelope| {
        try std.testing.expect(envelope.message == .accept);
        accept_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), accept_count);

    // A promise is evidence about an acceptor's durable state and must not
    // be exposed through the pre-barrier class.
    var follower: TestProtocol.Node = undefined;
    try follower.init(2, &membership);
    effects.confirmWritesDurable();
    try follower.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .prepare = .{
            .ballot = .{ .round = 2, .node = 1 },
            .first = 1,
        } },
    }, &effects);
    var promises = effects.preDurableMessages();
    try std.testing.expect(promises.next() == null);
    try std.testing.expect(effects.requiresPowerLossBarrier());
}

test "commit-only effects are reconstructible derived state" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var follower: TestProtocol.Node = undefined;
    try follower.init(2, &membership);
    var effects = TestProtocol.Effects{};

    try follower.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .commit = .{ .slot = 1, .value = 99 } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.writesSlice().len);
    try std.testing.expect(!effects.requiresPowerLossBarrier());
    try std.testing.expectEqual(@as(usize, 1), effects.committedSlice().len);
}

test "catch-up returns known commits from the requested slot" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(1, &membership);
    node.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    node.durable.cells[2] = .{ .slot = 2, .committed = 20 };
    node.durable.cells[3] = .{ .slot = 3, .committed = 30 };
    var effects = TestProtocol.Effects{};

    try node.step(.{
        .from = 2,
        .to = 1,
        .message = .{ .learn = .{ .from_slot = 2, .count = 16 } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 2), effects.messages_count);
    for (effects.messagesSlice()) |message| {
        try std.testing.expectEqual(@as(NodeId, 2), message.to);
    }
}

test "reconnected leader retransmits missing commits and open accepts" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: TestProtocol.Node = undefined;
    try leader.init(1, &membership);
    leader.role = .leader;
    leader.ballot = .{ .round = 1, .node = 1 };
    leader.durable.promised = leader.ballot;
    leader.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    leader.durable.cells[2] = .{ .slot = 2, .accepted = .{
        .ballot = leader.ballot,
        .value = 20,
    } };
    leader.lead[2] = .{ .slot = 2, .proposal = 20 };
    var effects = TestProtocol.Effects{};

    // The peer reported no progress, so it receives the decided slot as a
    // commit and the still-open slot as a fresh accept, in slot order.
    try leader.reconnected(2, &effects);
    try std.testing.expectEqual(@as(usize, 2), effects.messages_count);
    const commit = effects.messagesSlice()[0];
    try std.testing.expectEqual(@as(NodeId, 2), commit.to);
    try std.testing.expect(commit.message == .commit);
    try std.testing.expectEqual(@as(Slot, 1), commit.message.commit.slot);
    try std.testing.expectEqual(@as(u64, 10), commit.message.commit.value);
    const accept = effects.messagesSlice()[1];
    try std.testing.expectEqual(@as(NodeId, 2), accept.to);
    try std.testing.expect(accept.message == .accept);
    try std.testing.expectEqual(@as(Slot, 2), accept.message.accept.slot);
    try std.testing.expectEqual(@as(u64, 20), accept.message.accept.value);

    try std.testing.expectError(error.InvalidPeer, leader.reconnected(1, &effects));
    try std.testing.expectError(error.NotMember, leader.reconnected(9, &effects));
}

test "reconnected follower asks its leader for undelivered decisions" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var follower: TestProtocol.Node = undefined;
    try follower.init(2, &membership);
    follower.leader_hint = 1;
    follower.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    follower.delivered_through = 1;
    var effects = TestProtocol.Effects{};

    // Reconnecting to the presumed leader requests everything undelivered.
    try follower.reconnected(1, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.messages_count);
    const request = effects.messagesSlice()[0];
    try std.testing.expectEqual(@as(NodeId, 1), request.to);
    try std.testing.expect(request.message == .learn);
    try std.testing.expectEqual(@as(Slot, 2), request.message.learn.from_slot);

    // Reconnecting to a peer that is not the leader hint repairs nothing.
    try follower.reconnected(3, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.messages_count);
}

test "requestCatchUp round trip returns decided entries from the slot" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var provider: TestProtocol.Node = undefined;
    try provider.init(1, &membership);
    provider.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    provider.durable.cells[2] = .{ .slot = 2, .committed = 20 };
    provider.durable.cells[3] = .{ .slot = 3, .committed = 30 };
    var lagging: TestProtocol.Node = undefined;
    try lagging.init(2, &membership);
    lagging.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    lagging.delivered_through = 1;
    var effects = TestProtocol.Effects{};

    try std.testing.expectError(
        error.InvalidSlot,
        lagging.requestCatchUp(1, 0, &effects),
    );
    try std.testing.expectError(
        error.NotMember,
        lagging.requestCatchUp(9, 2, &effects),
    );

    try lagging.requestCatchUp(1, 2, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.messages_count);
    const request = effects.messagesSlice()[0];
    try std.testing.expectEqual(@as(NodeId, 1), request.to);
    try std.testing.expect(request.message == .learn);
    try std.testing.expectEqual(@as(Slot, 2), request.message.learn.from_slot);

    // The provider answers with every known commit at or above the slot,
    // and delivering those commits advances the lagging decided prefix.
    var provider_effects = TestProtocol.Effects{};
    try provider.step(request, &provider_effects);
    try std.testing.expectEqual(@as(usize, 2), provider_effects.messages_count);
    for (provider_effects.messagesSlice()) |envelope| {
        try std.testing.expectEqual(@as(NodeId, 2), envelope.to);
        try std.testing.expect(envelope.message == .commit);
        try lagging.step(envelope, &effects);
        effects.confirmWritesDurable();
    }
    try std.testing.expectEqual(@as(Slot, 3), lagging.decidedThrough());
    try std.testing.expectEqual(@as(?u64, 20), lagging.committedAt(2));
    try std.testing.expectEqual(@as(?u64, 30), lagging.committedAt(3));
}

test "resendIfDue retransmits to lagging peers after the resend interval" {
    const P = Protocol(u64, .{
        .max_members = 3,
        .window_slots = 4,
        .election_timeout_ticks = 20,
        .heartbeat_interval_ticks = 16,
        .resend_interval_ticks = 2,
    });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: P.Node = undefined;
    try leader.init(1, &membership);
    leader.role = .leader;
    leader.ballot = .{ .round = 1, .node = 1 };
    leader.durable.promised = leader.ballot;
    leader.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    leader.durable.cells[2] = .{ .slot = 2, .accepted = .{
        .ballot = leader.ballot,
        .value = 20,
    } };
    leader.lead[2] = .{ .slot = 2, .proposal = 20 };
    var effects = P.Effects{};

    // Nothing is retransmitted before the interval of silence elapses.
    try leader.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.messages_count);
    // At the interval, both lagging peers receive the decided slot as a
    // commit and the open slot as an accept.
    try leader.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 4), effects.messages_count);
    for (effects.messagesSlice()) |envelope| {
        try std.testing.expect(
            envelope.message == .commit or envelope.message == .accept,
        );
    }
    // The interval counter resets, so the next tick is silent again.
    try leader.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.messages_count);

    // A peer that reported progress is only sent what it still misses.
    leader.peer_decided_through[1] = 1;
    try leader.tick(0, &effects);
    try std.testing.expectEqual(@as(usize, 3), effects.messages_count);
    for (effects.messagesSlice()) |envelope| {
        if (envelope.to == 2) try std.testing.expect(envelope.message == .accept);
    }
}

test "heartbeat ahead of the follower triggers a catch-up request" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var follower: TestProtocol.Node = undefined;
    try follower.init(2, &membership);
    const leader_ballot = Ballot{ .round = 1, .node = 1 };
    follower.durable.promised = leader_ballot;
    var effects = TestProtocol.Effects{};

    // The leader advertises a longer decided prefix; the follower learns.
    try follower.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .heartbeat = .{
            .ballot = leader_ballot,
            .decided_through = 3,
        } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.messages_count);
    const request = effects.messagesSlice()[0];
    try std.testing.expectEqual(@as(NodeId, 1), request.to);
    try std.testing.expect(request.message == .learn);
    try std.testing.expectEqual(@as(Slot, 1), request.message.learn.from_slot);
    try std.testing.expectEqual(@as(?NodeId, 1), follower.currentLeader());

    // A heartbeat that is not ahead of this follower requests nothing.
    try follower.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .heartbeat = .{
            .ballot = leader_ballot,
            .decided_through = 0,
        } },
    }, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.messages_count);
}

test "nack for a higher promise steps the leader down" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var leader: TestProtocol.Node = undefined;
    try leader.init(1, &membership);
    leader.role = .leader;
    leader.ballot = .{ .round = 1, .node = 1 };
    leader.durable.promised = leader.ballot;
    var effects = TestProtocol.Effects{};

    // A nack for a ballot this node never issued is ignored.
    try leader.step(.{
        .from = 2,
        .to = 1,
        .message = .{ .nack = .{
            .rejected = .{ .round = 9, .node = 1 },
            .promised = .{ .round = 10, .node = 2 },
            .decided_through = 0,
        } },
    }, &effects);
    try std.testing.expectEqual(TestProtocol.Role.leader, leader.role);

    // A nack that names no higher promise is ignored.
    try leader.step(.{
        .from = 2,
        .to = 1,
        .message = .{ .nack = .{
            .rejected = leader.ballot,
            .promised = leader.ballot,
            .decided_through = 0,
        } },
    }, &effects);
    try std.testing.expectEqual(TestProtocol.Role.leader, leader.role);

    // A higher promise abandons leadership and adopts the winner as hint.
    try leader.step(.{
        .from = 2,
        .to = 1,
        .message = .{ .nack = .{
            .rejected = leader.ballot,
            .promised = .{ .round = 2, .node = 2 },
            .decided_through = 0,
        } },
    }, &effects);
    try std.testing.expectEqual(TestProtocol.Role.follower, leader.role);
    try std.testing.expectEqual(@as(?NodeId, 2), leader.currentLeader());
    try std.testing.expectEqual(@as(u64, 2), leader.highest_observed_round);

    // The next campaign picks a round above the observed higher promise.
    try leader.campaign(0, &effects);
    try std.testing.expectEqual(@as(u64, 3), leader.ballot.round);
}

test "chosen history preserves the follower's ballot-bearing leader and election timer" {
    for ([_]bool{ false, true }) |duplicate| {
        var membership: TestProtocol.Membership = undefined;
        try membership.init(&.{ 1, 2, 3 });
        var node: TestProtocol.Node = undefined;
        try node.init(3, &membership);
        node.durable.promised = .{ .round = 2, .node = 1 };
        node.leader_hint = 1;
        node.election_ticks = 9;
        if (duplicate) {
            node.durable.cells[1] = .{ .slot = 1, .committed = 10 };
            node.delivered_through = 1;
        }
        var effects = TestProtocol.Effects{};
        try node.step(.{
            .from = 2,
            .to = 3,
            .message = .{ .commit = .{ .slot = 1, .value = 10 } },
        }, &effects);
        try std.testing.expectEqual(@as(?NodeId, 1), node.currentLeader());
        try std.testing.expectEqual(@as(u32, 9), node.election_ticks);
        try std.testing.expectEqual(@as(Slot, 1), node.decidedThrough());
        try std.testing.expectEqual(@as(?u64, 10), node.committedAt(1));
        try std.testing.expectEqual(@as(usize, if (duplicate) 0 else 1), effects.writes_count);
    }
}

test "catch-up from a follower cannot replace an elected leader's own identity" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(1, &membership);
    node.role = .leader;
    node.ballot = .{ .round = 2, .node = 1 };
    node.durable.promised = node.ballot;
    node.leader_hint = 1;
    node.election_ticks = 9;
    node.durable.cells[1] = .{ .slot = 1, .committed = 10 };
    node.delivered_through = 1;
    var effects = TestProtocol.Effects{};
    try node.step(.{
        .from = 3,
        .to = 1,
        .message = .{ .commit = .{ .slot = 1, .value = 10 } },
    }, &effects);
    try std.testing.expectEqual(TestProtocol.Role.leader, node.role);
    try std.testing.expectEqual(@as(?NodeId, 1), node.currentLeader());
    try std.testing.expectEqual(@as(u32, 9), node.election_ticks);
}

test "valid ballot-bearing contact refreshes a follower during ordinary operation" {
    const ballot: Ballot = .{ .round = 2, .node = 1 };
    const messages = [_]TestProtocol.Message{
        .{ .prepare = .{ .ballot = ballot, .first = 1 } },
        .{ .accept = .{ .ballot = ballot, .slot = 1, .value = 10 } },
        .{ .heartbeat = .{ .ballot = ballot, .decided_through = 0 } },
    };
    for (messages) |message| {
        var membership: TestProtocol.Membership = undefined;
        try membership.init(&.{ 1, 2, 3 });
        var node: TestProtocol.Node = undefined;
        try node.init(3, &membership);
        node.durable.promised = ballot;
        node.leader_hint = 2;
        node.election_ticks = 9;
        var effects = TestProtocol.Effects{};
        try node.step(.{ .from = 1, .to = 3, .message = message }, &effects);
        try std.testing.expectEqual(@as(?NodeId, 1), node.currentLeader());
        try std.testing.expectEqual(@as(u32, 0), node.election_ticks);
        try std.testing.expectEqual(TestProtocol.Role.follower, node.role);
    }
}

fn hasPointers(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .@"struct" => |info| {
            inline for (info.field_types) |Field| {
                if (hasPointers(Field)) return true;
            }
            return false;
        },
        .@"union" => |info| {
            inline for (info.field_types) |Field| {
                if (hasPointers(Field)) return true;
            }
            return false;
        },
        .array => |info| hasPointers(info.child),
        .optional => |info| hasPointers(info.child),
        .error_union => |info| hasPointers(info.payload) or hasPointers(info.error_set),
        else => false,
    };
}

test "a delayed nack preserves the newer durable leader observation" {
    var membership: TestProtocol.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: TestProtocol.Node = undefined;
    try node.init(1, &membership);
    node.role = .preparing;
    node.ballot = .{ .round = 1, .node = 1 };
    node.durable.promised = node.ballot;
    var effects = TestProtocol.Effects{};
    const newer = Ballot{ .round = 3, .node = 3 };
    try node.step(.{ .from = 3, .to = 1, .message = .{ .prepare = .{
        .ballot = newer,
        .first = 1,
    } } }, &effects);
    effects.confirmWritesDurable();
    node.election_ticks = 7;
    try node.step(.{ .from = 2, .to = 1, .message = .{ .nack = .{
        .rejected = node.ballot,
        .promised = .{ .round = 2, .node = 2 },
        .decided_through = 0,
    } } }, &effects);
    try std.testing.expectEqual(@as(?NodeId, 3), node.currentLeader());
    try std.testing.expectEqual(TestProtocol.Role.follower, node.role);
    try std.testing.expect(node.durable.promised.eql(newer));
    try std.testing.expectEqual(@as(u32, 7), node.election_ticks);
}

test "nack routing evidence never moves backward in full ballot order" {
    const Case = struct { newer: Ballot, older: Ballot };
    const cases = [_]Case{
        .{ .newer = .{ .round = 3, .node = 3 }, .older = .{ .round = 2, .node = 2 } },
        .{
            .newer = .{ .round = 3, .priority = 9, .node = 2 },
            .older = .{ .round = 3, .priority = 8, .node = 3 },
        },
        .{
            .newer = .{ .round = 3, .priority = 9, .node = 3 },
            .older = .{ .round = 3, .priority = 9, .node = 2 },
        },
    };
    for (cases) |case| {
        var membership: TestProtocol.Membership = undefined;
        try membership.init(&.{ 1, 2, 3 });
        var node: TestProtocol.Node = undefined;
        try node.init(1, &membership);
        node.role = .leader;
        node.ballot = .{ .round = 1, .node = 1 };
        node.durable.promised = node.ballot;
        var effects = TestProtocol.Effects{};
        for ([_]Ballot{ case.newer, case.older }) |promise| {
            try node.step(.{ .from = 2, .to = 1, .message = .{ .nack = .{
                .rejected = node.ballot,
                .promised = promise,
                .decided_through = 0,
            } } }, &effects);
        }
        try std.testing.expectEqual(@as(?NodeId, case.newer.node), node.currentLeader());
        try std.testing.expect(node.highest_observed_ballot.eql(case.newer));
        try std.testing.expect(node.durable.promised.eql(node.ballot));
        try std.testing.expectEqual(@as(u64, case.newer.round), node.highest_observed_round);
    }
}

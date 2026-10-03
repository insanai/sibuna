//! Human-friendly explanations for protocol and replicated-log errors.

/// Returns a concise operator-oriented explanation and recovery hint.
pub fn explainError(err: anyerror) []const u8 {
    return switch (err) {
        error.EmptyMembership,
        error.TooManyMembers,
        error.InvalidNodeId,
        error.DuplicateNodeId,
        error.InvalidReadQuorum,
        error.InvalidWriteQuorum,
        error.NonIntersectingQuorums,
        => explainMembershipError(err),

        error.NotMember,
        error.WrongRecipient,
        error.InvalidPeer,
        error.InvalidSlot,
        error.ReadBufferTooSmall,
        error.UnknownNode,
        => explainInputError(err),

        error.NotVoter,
        error.NotLearner,
        error.LearnerIsVoter,
        error.LearnerMessageForbidden,
        error.ConfigurationMismatch,
        => explainRoleError(err),

        error.NotLeader,
        error.LeaderCatchingUp,
        error.WindowFull,
        error.GlobalSlotExhausted,
        error.EmptyBatch,
        error.SlotBufferTooSmall,
        error.BallotExhausted,
        error.InvalidPromise,
        error.MissingNoop,
        error.MissingProposedValue,
        error.CampaignDisabled,
        => explainProgressError(err),

        error.PromiseRegression,
        error.ConflictingValue,
        error.ConflictingCommit,
        error.ConflictingChosenValue,
        error.TrimRegression,
        => explainSafetyError(err),

        error.InvalidConfigurationId,
        error.MetadataTooLarge,
        error.LogSealed,
        error.BatchTooLarge,
        error.ConfigurationIdRegression,
        error.ConfigurationIdExhausted,
        error.WindowOverrun,
        => explainLogError(err),

        else =>
        \\-- UNEXPECTED ERROR -------------------------------------------------------------
        \\
        \\The error is not one of the library's documented protocol errors.
        \\
        \\Hint: Preserve the original host I/O or transport context in logs.
        ,
    };
}

fn explainMembershipError(err: anyerror) []const u8 {
    return switch (err) {
        error.EmptyMembership =>
        \\-- EMPTY MEMBERSHIP ------------------------------------------------------------
        \\
        \\A consensus configuration needs at least one voting member.
        \\Hint: Pass a slice with at least one non-zero ID to Membership.init().
        ,
        error.TooManyMembers =>
        \\-- TOO MANY MEMBERS ------------------------------------------------------------
        \\
        \\The membership is larger than the compile-time max_members bound.
        \\Hint: Reduce the member slice or deliberately raise max_members.
        ,
        error.InvalidNodeId =>
        \\-- INVALID NODE ID -------------------------------------------------------------
        \\
        \\Node ID zero is reserved as a sentinel.
        \\Hint: Assign every logical member a stable, non-zero ID.
        ,
        error.DuplicateNodeId =>
        \\-- DUPLICATE NODE ID -----------------------------------------------------------
        \\
        \\The membership contains one voting identity more than once.
        \\Hint: Validate uniqueness before calling Membership.init().
        ,
        error.InvalidReadQuorum =>
        \\-- INVALID READ QUORUM ----------------------------------------------------------
        \\
        \\The phase-one size is zero or exceeds the actual member count.
        \\Hint: Choose 1 <= read_quorum_size <= member_count.
        ,
        error.InvalidWriteQuorum =>
        \\-- INVALID WRITE QUORUM ---------------------------------------------------------
        \\
        \\The phase-two size is zero or exceeds the actual member count.
        \\Hint: Choose 1 <= write_quorum_size <= member_count.
        ,
        error.NonIntersectingQuorums =>
        \\-- NON-INTERSECTING QUORUMS ----------------------------------------------------
        \\
        \\A phase-one quorum might miss a prior phase-two quorum.
        \\Hint: Require read_quorum_size + write_quorum_size > member_count.
        ,
        else => unreachable,
    };
}

fn explainInputError(err: anyerror) []const u8 {
    return switch (err) {
        error.NotMember =>
        \\-- NOT A MEMBER ----------------------------------------------------------------
        \\
        \\The source, target, or local ID is outside the active membership.
        \\Hint: Check the configuration ID and authenticated peer identity.
        ,
        error.WrongRecipient =>
        \\-- WRONG RECIPIENT --------------------------------------------------------------
        \\
        \\The envelope target is not the node processing it.
        \\Hint: Repair transport routing before retrying the envelope.
        ,
        error.InvalidPeer =>
        \\-- INVALID PEER -----------------------------------------------------------------
        \\
        \\A peer-only operation targeted the local node itself.
        \\Hint: Pass a different member ID to the peer operation.
        ,
        error.InvalidSlot =>
        \\-- INVALID SLOT -----------------------------------------------------------------
        \\
        \\Slot zero is reserved and cannot address a log entry.
        \\Hint: Use a one-based slot.
        ,
        error.ReadBufferTooSmall =>
        \\-- READ BUFFER TOO SMALL --------------------------------------------------------
        \\
        \\The caller buffer cannot hold the available decided suffix.
        \\Hint: Size output for decided_through - from_slot + 1 entries.
        ,
        error.UnknownNode =>
        \\-- UNKNOWN NODE -----------------------------------------------------------------
        \\
        \\The example or host router does not recognize this node ID.
        \\Hint: Reconcile routing state with the active membership.
        ,
        else => unreachable,
    };
}

fn explainRoleError(err: anyerror) []const u8 {
    return switch (err) {
        error.NotVoter =>
        \\-- NOT A VOTER ------------------------------------------------------------------
        \\
        \\A voter-only operation ran on a node outside the voting membership.
        \\Hint: Route proposals and campaigns to a configured voting member.
        ,
        error.NotLearner =>
        \\-- NOT A LEARNER ----------------------------------------------------------------
        \\
        \\A learner-only operation ran on a voting member.
        \\Hint: Use the voter step path; learnChosen is for non-voting nodes.
        ,
        error.LearnerIsVoter =>
        \\-- LEARNER IS A VOTER -----------------------------------------------------------
        \\
        \\A learner was initialized with an ID inside the voting membership.
        \\Hint: Give learners IDs outside the configured voter set.
        ,
        error.LearnerMessageForbidden =>
        \\-- LEARNER MESSAGE FORBIDDEN ----------------------------------------------------
        \\
        \\A learner received a message kind only voters may process.
        \\Hint: Send learners commits and heartbeats only.
        ,
        error.ConfigurationMismatch =>
        \\-- CONFIGURATION MISMATCH -------------------------------------------------------
        \\
        \\The message's configuration ID differs from the local one.
        \\Hint: Finish the configuration handover before mixing traffic.
        ,
        else => unreachable,
    };
}

fn explainProgressError(err: anyerror) []const u8 {
    return switch (err) {
        error.NotLeader =>
        \\-- NOT LEADER ------------------------------------------------------------------
        \\
        \\This node has not completed phase one for its current ballot.
        \\Hint: Route to currentLeader() or wait for a successful campaign.
        ,
        error.LeaderCatchingUp =>
        \\-- LEADER CATCHING UP -----------------------------------------------------------
        \\
        \\Hint: Slots inherited in phase one are undelivered; deliver through leaderBase() - 1.
        ,
        error.WindowFull =>
        \\-- WINDOW FULL ------------------------------------------------------------------
        \\
        \\Every consensus cell holds a live slot; this is transient flow control.
        \\Hint: Retry after the memory floor advances past delivered slots.
        ,
        error.GlobalSlotExhausted =>
        \\-- GLOBAL SLOT EXHAUSTED --------------------------------------------------------
        \\
        \\The 64-bit global slot space is exhausted and never wraps to zero.
        \\Hint: This database has reached the end of its logical history.
        ,
        error.EmptyBatch =>
        \\-- EMPTY BATCH -----------------------------------------------------------------
        \\
        \\A batch proposal contained no values.
        \\Hint: Skip the call or submit at least one value.
        ,
        error.SlotBufferTooSmall =>
        \\-- SLOT BUFFER TOO SMALL ---------------------------------------------------------
        \\
        \\The output slot slice is shorter than the value batch.
        \\Hint: Provide at least values.len slot elements.
        ,
        error.BallotExhausted =>
        \\-- BALLOT EXHAUSTED -------------------------------------------------------------
        \\
        \\The node cannot create a round greater than maxInt(u64).
        \\Hint: Stop this epoch and investigate the runaway campaign source.
        ,
        error.InvalidPromise =>
        \\-- INVALID PROMISE --------------------------------------------------------------
        \\
        \\A completion marker claims more accepted entries than window_slots.
        \\Hint: Reject the peer and verify codec and protocol bounds.
        ,
        error.MissingNoop =>
        \\-- MISSING NO-OP ----------------------------------------------------------------
        \\
        \\Leader recovery needs the host's no-op value to fill a hole.
        \\Hint: Supply a deterministic no-op to campaign() or tick().
        ,
        error.MissingProposedValue =>
        \\-- MISSING PROPOSED VALUE --------------------------------------------------------
        \\
        \\An acknowledgement names a slot with no local leader proposal.
        \\Hint: Preserve proposal state until the slot commits.
        ,
        error.CampaignDisabled =>
        \\-- CAMPAIGN DISABLED ------------------------------------------------------------
        \\
        \\This voter is configured to never start elections.
        \\Hint: Campaign from a member whose priority permits leadership.
        ,
        else => unreachable,
    };
}

fn explainSafetyError(err: anyerror) []const u8 {
    return switch (err) {
        error.PromiseRegression =>
        \\-- PROMISE REGRESSION -----------------------------------------------------------
        \\
        \\Replay attempted to move the durable promise to a lower ballot.
        \\Hint: Stop the node and inspect journal ordering or corruption.
        ,
        error.ConflictingValue =>
        \\-- CONFLICTING VALUE -----------------------------------------------------------
        \\
        \\One ballot and slot contain two different values.
        \\Hint: Stop the node and preserve the full message and journal trace.
        ,
        error.ConflictingCommit =>
        \\-- CONFLICTING COMMIT ----------------------------------------------------------
        \\
        \\One slot observed two different committed values.
        \\Hint: Treat this as a safety incident; stop and retain all evidence.
        ,
        error.ConflictingChosenValue =>
        \\-- CONFLICTING CHOSEN VALUE -----------------------------------------------------
        \\
        \\A learner saw two different chosen values for one slot.
        \\Hint: Treat this as a safety incident; stop and retain all evidence.
        ,
        error.TrimRegression =>
        \\-- TRIM REGRESSION --------------------------------------------------------------
        \\
        \\A trim anchor moved backward or conflicts with the adopted one.
        \\Hint: Stop the node and inspect trim records and journal ordering.
        ,
        else => unreachable,
    };
}

fn explainLogError(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidConfigurationId =>
        \\-- INVALID CONFIGURATION ID -----------------------------------------------------
        \\
        \\Configuration ID zero is reserved.
        \\Hint: Persist and use a positive epoch identity.
        ,
        error.MetadataTooLarge =>
        \\-- METADATA TOO LARGE -----------------------------------------------------------
        \\
        \\Stop-sign metadata exceeds max_metadata_bytes.
        \\Hint: Store a smaller durable snapshot identifier or raise the bound.
        ,
        error.LogSealed =>
        \\-- LOG SEALED -------------------------------------------------------------------
        \\
        \\A stop sign is pending or decided in this configuration.
        \\Hint: Finish handover to the decided next configuration.
        ,
        error.BatchTooLarge =>
        \\-- BATCH TOO LARGE --------------------------------------------------------------
        \\
        \\The command batch exceeds max_batch.
        \\Hint: Split the batch or deliberately raise the compile-time bound.
        ,
        error.ConfigurationIdRegression =>
        \\-- CONFIGURATION ID REGRESSION --------------------------------------------------
        \\
        \\The proposed configuration ID is not newer than the current ID.
        \\Hint: Allocate a strictly increasing durable configuration ID.
        ,
        error.ConfigurationIdExhausted =>
        \\-- CONFIGURATION ID EXHAUSTED ---------------------------------------------------
        \\
        \\No configuration ID exists after maxInt(u64).
        \\Hint: Stop and investigate configuration churn before recovery.
        ,
        error.WindowOverrun =>
        \\-- WINDOW OVERRUN ---------------------------------------------------------------
        \\
        \\A journal record addresses a cell still occupied by an earlier slot.
        \\Hint: Stop the node; the journal ran past the window without an anchor.
        ,
        else => unreachable,
    };
}

test "explainError - human friendly messages" {
    const std = @import("std");
    const empty = explainError(error.EmptyMembership);
    try std.testing.expect(std.mem.indexOf(u8, empty, "-- EMPTY MEMBERSHIP") != null);
    try std.testing.expect(std.mem.indexOf(u8, empty, "Hint: Pass a slice") != null);

    const not_leader = explainError(error.NotLeader);
    try std.testing.expect(std.mem.indexOf(u8, not_leader, "-- NOT LEADER") != null);

    const unexpected = explainError(error.UnknownErrorStringOrSentinel);
    try std.testing.expect(std.mem.indexOf(u8, unexpected, "-- UNEXPECTED ERROR") != null);
}

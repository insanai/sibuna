//! Maps a rejected voter replacement to the client-facing error code and
//! message. Kept apart from the server so the table can grow without the
//! request loop.

/// A client-facing rejection.
pub const Response = struct { code: []const u8, message: []const u8 };

const Entry = struct { err: anyerror, code: []const u8, message: []const u8 };

const table = [_]Entry{
    .{
        .err = error.StaleConfiguration,
        .code = "stale_configuration",
        .message = "The expected configuration is no longer active.",
    },
    .{
        .err = error.UnknownVoter,
        .code = "unknown_voter",
        .message = "The node being replaced is not a current data voter.",
    },
    .{
        .err = error.NodeIdNotFresh,
        .code = "node_id_not_fresh",
        .message = "The replacement node ID has already been allocated.",
    },
    .{
        .err = error.NodeIdExhausted,
        .code = "node_id_exhausted",
        .message = "The node ID allocation fence cannot advance.",
    },
    .{
        .err = error.OperationIdExhausted,
        .code = "operation_id_exhausted",
        .message = "The replacement operation ID space cannot advance.",
    },
    .{
        .err = error.ConfigurationIdExhausted,
        .code = "configuration_id_exhausted",
        .message = "The configuration ID space cannot advance.",
    },
    .{
        .err = error.InvalidEndpoint,
        .code = "invalid_endpoint",
        .message = "The replacement endpoint is empty, malformed, or too long.",
    },
    .{
        .err = error.EndpointInUse,
        .code = "endpoint_in_use",
        .message = "Another current node already uses the replacement endpoint.",
    },
    .{
        .err = error.TooFewVoters,
        .code = "too_few_voters",
        .message = "Replacing a voter would leave an unsupported voter set.",
    },
    .{
        .err = error.OperationConflict,
        .code = "operation_conflict",
        .message = "This operation ID is bound to different replacement arguments.",
    },
    .{
        .err = error.OperationPending,
        .code = "operation_pending",
        .message = "Another voter replacement is still pending.",
    },
    .{
        .err = error.OperationHistoryExpired,
        .code = "operation_history_expired",
        .message = "This operation ID is older than the retained result history.",
    },
    .{
        .err = error.CorruptPendingOperation,
        .code = "corrupt_pending_operation",
        .message = "The durable pending replacement record is unreadable.",
    },
    .{
        .err = error.TransactionOpen,
        .code = "replacement_busy",
        .message = "A database write is still in progress.",
    },
    .{
        .err = error.WriteInFlight,
        .code = "replacement_busy",
        .message = "A database write is still in progress.",
    },
    .{
        .err = error.LeaderCatchingUp,
        .code = "replacement_busy",
        .message = "The leader is still applying slots it inherited; retry.",
    },
    .{
        .err = error.LeaderNotReady,
        .code = "replacement_busy",
        .message = "The leader is still applying slots it inherited; retry.",
    },
    .{
        .err = error.StorageFailed,
        .code = "storage_failed",
        .message = "Durable storage failed, so this node cannot replace a voter.",
    },
    .{
        .err = error.NoDecidedRegistry,
        .code = "no_registry",
        .message = "This node does not have decided registry membership.",
    },
    .{
        .err = error.RoleCannotWrite,
        .code = "role_cannot_write",
        .message = "This node role cannot coordinate a voter replacement.",
    },
};

/// Classifies one replacement failure; unknown errors keep their name.
pub fn classify(err: anyerror) Response {
    for (table) |entry| {
        if (entry.err == err) return .{ .code = entry.code, .message = entry.message };
    }
    return .{ .code = "replace_rejected", .message = @errorName(err) };
}

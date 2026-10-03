//! The embedded zaxonlite node host.
//!
//! One node owns one data directory: a segmented lifetime journal, a
//! content-addressed payload store, durable state anchors, and a
//! materialized SQLite image. The journal plus payloads are authoritative;
//! the SQLite file is reconstructed from the durable anchor plus the
//! retained journal suffix on every open.
//!
//! Ordering contract per write:
//!   execute -> capture frames -> persist payload -> Paxos append ->
//!   journal + required sync -> confirmWritesDurable -> committed -> acknowledge.
//! The payload install flushes to the drive; the journal fsync is the one
//! storage barrier per write and makes both power-loss durable together
//! (see durability.zig on group fsync).
//! Promise and accept records require that barrier. A later commit-only
//! marker is reconstructible from the durable accepting quorum, so Zaxonlite
//! does not duplicate it in the authoritative journal. This matches classic
//! Paxos: a restart re-learns the chosen value from the accepting quorum.
//!
//! Cluster shape: the same node type serves one-member and multi-member
//! configurations. Only the current leader keeps a live SQLite writer
//! connection (the capture connection); every other member applies
//! committed payloads offline, page by page, to the materialized image.
//! Protocol messages addressed to peers accumulate in `outbox`; the
//! transport host (`server.zig`) drains it after every protocol call.  The
//! sole pipelined exception is a phase-two `accept` request: it may leave
//! after the journal append while the leader's barrier is in progress,
//! because it asks a follower to persist a vote and asserts no durable fact
//! about the leader.  Promise evidence, vote acknowledgements, commits, and
//! client replies still remain behind the local barrier.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const paxos = @import("paxos");

const command = @import("command.zig");
const segment_mod = @import("segment.zig");
const types = @import("types.zig");
const applied_anchor = @import("applied_anchor.zig");
const history = @import("history.zig");
const journal_mod = @import("journal.zig");
const trim = @import("trim.zig");
const payload_store_mod = @import("payload_store.zig");
const sqlite = @import("sqlite.zig");
const search_api = @import("search_api.zig");
const zaxon_search = @import("zaxon_search");
const guard_mod = @import("guard.zig");
const wal = @import("wal.zig");
const failpoint = @import("failpoint.zig");
const wire = @import("wire.zig");
const durability = @import("durability.zig");
const prepared = @import("prepared.zig");
const registry = @import("registry.zig");
const roles = @import("roles.zig");

const Journal = journal_mod.Journal;
const PayloadStore = payload_store_mod.PayloadStore;
const Log = types.Log;

const db_file_name = "current.db";
const wal_file_name = "current.db-wal";
const shm_file_name = "current.db-shm";
const identity_file_name = "identity";
const current_file_name = "CURRENT";
const lock_file_name = "LOCK";
/// Sender-side pinned transfer image, private to `consensus/`.
const transfer_pin_name = "transfer-pin.db";
/// Receiver-side staged transfer image, replaced onto `current.db`.
pub const transfer_install_name = ".transfer-install.db";
const pending_operation_file_name = "PENDING-OP";
const deleted_file_tombstone = ".ZX-DELETED";
const join_file_name = "JOIN";
const install_tmp_dir = "snapshots/tmp-install";

pub const OpenOptions = struct {
    /// Node data directory; created when missing.
    directory: []const u8,
    node_id: paxos.NodeId = 1,
    /// Full voting membership including this node. Empty means a
    /// single-member configuration of just `node_id`. Order does not
    /// matter; membership is canonicalized to ascending node IDs.
    members: []const paxos.NodeId = &.{},
    /// Election priority carried in this node's ballots.
    leader_priority: u32 = 0,
    /// Database identity for a freshly created directory. Cluster members
    /// must agree on it; `null` draws a random one (single-node default).
    database_id: ?u128 = null,
    /// Product role. Only data voters and witnesses appear in `members`.
    role: roles.Role = .data_voter,
    /// Full product registry (IDs, roles, endpoints) for a network-hosted
    /// cluster. Non-null bootstraps and then enforces the durable decided
    /// registry; null (embedded and local hosts) keeps membership fixed by
    /// flags and writes no registry file.
    registry_nodes: ?[]const registry.NodeRecord = null,
    /// Test-only delay injected immediately before each journal sync.
    test_storage_delay_ms: u64 = 0,
    /// SQLite-managed mapped-I/O limit for every connection this node
    /// opens. Zero (the default) disables mmap; a nonzero value is an
    /// explicit operator opt-in bounded at 1 GiB (ZDS 0009).
    mmap_size: u64 = 0,
    /// Retention horizon in slots: physical reclamation never deletes
    /// the most recent `retention_slots` of applied history, even below
    /// the chosen trim, so lagging replicas can range-recover without a
    /// transfer. Zero keeps only what the trim requires (ZDS 0011).
    retention_slots: u64 = 0,
    /// Hard local storage ceiling over journal plus retained payload
    /// bytes: at or above it, new writes are refused with
    /// `RecoveryRetentionExceeded` instead of deleting unproven history.
    /// Ships at the ZDS 0011 Q2 hard ceiling; zero disables it.
    journal_cap_bytes: u64 = 64 * 1024 * 1024 * 1024,
};

pub const SessionError = error{
    UnknownSession,
    SequenceGap,
    ResultExpired,
};

pub const ExecResult = struct {
    changes: i64,
    slot: paxos.Slot,
    replayed: bool = false,
    /// Set when the caller's statements observably updated SQLite's last
    /// insert rowid; absent for updates, deletes, DDL, and replays.
    last_insert_rowid: ?i64 = null,
};

pub const RecentBatch = struct {
    slot: paxos.Slot = 0,
    batch_id: u128 = 0,
};

const HistoryMark = struct {
    slot: paxos.Slot = 0,
    hash: [32]u8 = @as([32]u8, @splat(0)),
};
pub const Status = struct {
    node_id: paxos.NodeId,
    database_id: u128,
    configuration_id: u64,
    role: []const u8,
    node_type: []const u8,
    leader: ?paxos.NodeId,
    ballot: paxos.Ballot,
    /// Global frontiers (ZDS 0011): decided C, executed E, durable A,
    /// the core memory floor, and the retention window.
    decided_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    durable_state_slot: paxos.Slot,
    memory_floor: paxos.Slot,
    trim_decision_slot: paxos.Slot,
    chosen_trim_slot: paxos.Slot,
    trim_ignored: u64,
    retained_first_slot: paxos.Slot,
    journal_records: u64,
    journal_segment_count: u64,
    journal_bytes: u64,
    payload_retained_bytes: u64,
    chain: command.HashBytes,
    history: command.HashBytes,
    page_size: u32,
    /// Search capability manifest (ZDS 0009).
    fts5_enabled: bool,
    sqlite_vec_version: []const u8,
    search_feature_version: i64,
    simd_backend: []const u8,
    /// The mapped-I/O limit SQLite accepted on the most recent
    /// connection; zero when mmap is disabled or unsupported.
    mmap_size: i64,
    candidate_hard_limit: u32,
};

/// Hard ceiling for vector KNN candidate counts (ZDS 0009). The typed
/// search API enforces it; raw SQL treats it as a documented contract
/// backed by the query row, byte, and VM-step budgets.
pub const candidate_hard_limit: u32 = search_api.candidate_hard_limit;

pub const IntegrityReport = struct {
    sqlite_ok: bool,
    chain_ok: bool,
    payloads_ok: bool,

    pub fn ok(self: IntegrityReport) bool {
        return self.sqlite_ok and self.chain_ok and self.payloads_ok;
    }
};

const Identity = struct {
    node_id: paxos.NodeId,
    database_id: u128,
    configuration_id: u64,
    role: roles.Role,
};

pub const QueryResult = struct {
    arena: std.heap.ArenaAllocator,
    columns: []const []const u8,
    rows: []const []const ?[]const u8,

    pub fn deinit(self: *QueryResult) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Typed query result: one tagged SQLite value per cell. This is the
/// source form; the text `QueryResult` and every JSON encoding are
/// presentation adapters derived from it.
pub const TypedResult = struct {
    arena: std.heap.ArenaAllocator,
    columns: []const []const u8,
    rows: []const []const prepared.Value,

    pub fn deinit(self: *TypedResult) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Optional write-result capture: typed `RETURNING` rows and the last
/// insert rowid observed for the caller's statements.
pub const WriteCapture = struct {
    gpa: std.mem.Allocator,
    returning: ?TypedResult = null,
    last_insert_rowid: ?i64 = null,
};

/// Prepared-statement facts a host needs before executing: parameter
/// count, result shape, read-only classification, and whether the input
/// holds a trailing second statement.
pub const StatementInfo = struct {
    parameter_count: u32,
    column_count: u32,
    read_only: bool,
    has_tail: bool,
};

/// Optional result and SQLite VM budgets. Zero means unlimited, which remains
/// the default for trusted embedded callers. Network hosts pass conservative
/// non-zero limits so one query cannot monopolize memory or CPU indefinitely.
pub const QueryLimits = struct {
    max_rows: usize = 0,
    max_bytes: usize = 0,
    max_vm_steps: u64 = 0,
};

/// Countdown state for one installed VM-step budget. Must outlive the
/// connection's progress handler; callers keep it on their stack for the
/// duration of the read.
pub const QueryProgress = struct {
    callbacks_remaining: u64,
};

fn queryProgress(context: ?*anyopaque) callconv(.c) c_int {
    const progress: *QueryProgress = @ptrCast(@alignCast(context.?));
    if (progress.callbacks_remaining == 0) return 1;
    progress.callbacks_remaining -= 1;
    return 0;
}

/// SQLite VM instructions between progress callbacks; the budget below is
/// rounded up to this granularity.
pub const query_progress_granularity: u64 = 1_000;

/// Installs a VM-instruction budget on `db`. A budget is deterministic
/// and SQLite-native; zero means unlimited and installs nothing, which
/// remains the default for trusted embedded callers.
pub fn installVmBudget(
    db: *sqlite.Db,
    max_vm_steps: u64,
    progress: *QueryProgress,
) void {
    if (max_vm_steps == 0) {
        progress.* = .{ .callbacks_remaining = 0 };
        return;
    }
    progress.* = .{ .callbacks_remaining = @max(
        @as(u64, 1),
        (max_vm_steps +| query_progress_granularity - 1) / query_progress_granularity,
    ) };
    db.setProgressHandler(
        @intCast(query_progress_granularity),
        queryProgress,
        progress,
    );
}

/// Clears a budget installed by `installVmBudget`; a zero budget was
/// never installed, so there is nothing to clear.
pub fn clearVmBudget(db: *sqlite.Db, max_vm_steps: u64) void {
    if (max_vm_steps == 0) return;
    db.setProgressHandler(0, null, null);
}

/// Result budget consumed across every statement of one read call. Rows
/// and bytes count down against `limits` as sets materialize; zero limits
/// stay unlimited. Column names count into the byte budget, as the text
/// read path always did.
pub const ReadBudget = struct {
    limits: QueryLimits,
    rows_used: usize = 0,
    bytes_used: usize = 0,

    fn addRow(self: *ReadBudget) error{QueryRowLimit}!void {
        if (self.limits.max_rows != 0 and self.rows_used >= self.limits.max_rows) {
            return error.QueryRowLimit;
        }
        self.rows_used += 1;
    }

    fn addBytes(self: *ReadBudget, count: usize) error{QueryResultTooLarge}!void {
        self.bytes_used = std.math.add(usize, self.bytes_used, count) catch
            return error.QueryResultTooLarge;
        if (self.limits.max_bytes != 0 and self.bytes_used > self.limits.max_bytes) {
            return error.QueryResultTooLarge;
        }
    }
};

/// One materialized result set: arena-owned column names and typed rows.
pub const MaterializedSet = struct {
    columns: []const []const u8,
    rows: []const []const prepared.Value,
};

/// Prepares and steps one read-only statement on `db`, copying every cell
/// into `alloc` (an arena) and charging `budget`. The caller owns guard
/// scope, the surrounding transaction, and any VM budget on `db`.
pub fn materializeReadStatement(
    db: *sqlite.Db,
    alloc: std.mem.Allocator,
    sql: []const u8,
    values: []const prepared.Value,
    budget: *ReadBudget,
) !MaterializedSet {
    var stmt = try db.prepare(sql);
    defer stmt.finalize();
    if (!stmt.isReadOnly()) return error.WriteInReadQuery;
    try prepared.bind(&stmt, values);

    const column_count = stmt.columnCount();
    const columns = try alloc.alloc([]const u8, column_count);
    for (columns, 0..) |*column, index| {
        const name = stmt.columnName(@intCast(index));
        try budget.addBytes(name.len);
        column.* = try alloc.dupe(u8, name);
    }

    var rows: std.ArrayList([]const prepared.Value) = .empty;
    while (try stmt.step()) {
        try budget.addRow();
        const row = try alloc.alloc(prepared.Value, column_count);
        for (row, 0..) |*cell, index| {
            const column: u32 = @intCast(index);
            // Integers and reals count as their storage width; text and
            // blob count their byte length, as the text path always did.
            const cell_bytes: usize = switch (stmt.columnValueType(column)) {
                .null => 0,
                .integer, .real => 8,
                .text => stmt.columnText(column).len,
                .blob => stmt.columnBlob(column).len,
            };
            try budget.addBytes(cell_bytes);
            cell.* = switch (stmt.columnValueType(column)) {
                .null => .null_value,
                .integer => .{ .integer = stmt.columnInt64(column) },
                .real => .{ .real = stmt.columnDouble(column) },
                .text => .{
                    .text = try alloc.dupe(u8, stmt.columnText(column)),
                },
                .blob => .{
                    .blob = try alloc.dupe(u8, stmt.columnBlob(column)),
                },
            };
        }
        try rows.append(alloc, row);
    }
    return .{ .columns = columns, .rows = try rows.toOwnedSlice(alloc) };
}

/// True for errors that carry a SQLite error message on the connection
/// worth saving for `lastSqliteMessage`.
fn isSqliteFailure(err: anyerror) bool {
    return switch (err) {
        error.SqliteError,
        error.SqliteBusy,
        error.SqliteMisuse,
        error.SqliteInterrupted,
        => true,
        else => false,
    };
}

/// Converts a typed result into the legacy text presentation, rendering
/// integer and real cells exactly as SQLite's own text conversion does.
/// Consumes `typed`: the returned result adopts its arena.
pub fn textFromTyped(typed: *TypedResult) !QueryResult {
    const alloc = typed.arena.allocator();
    const rows = try alloc.alloc([]const ?[]const u8, typed.rows.len);
    for (typed.rows, rows) |typed_row, *text_row| {
        const cells = try alloc.alloc(?[]const u8, typed_row.len);
        for (typed_row, cells) |value, *cell| {
            cell.* = switch (value) {
                .null_value => null,
                .integer => |number| try std.fmt.allocPrint(
                    alloc,
                    "{d}",
                    .{number},
                ),
                .real => |number| blk: {
                    var buffer: [32]u8 = undefined;
                    break :blk try alloc.dupe(
                        u8,
                        sqlite.formatReal(&buffer, number),
                    );
                },
                .text => |bytes| bytes,
                .blob => |bytes| bytes,
            };
        }
        text_row.* = cells;
    }
    return .{ .arena = typed.arena, .columns = typed.columns, .rows = rows };
}

/// Hard cap on statements in one `Node.queryBatch` call.
pub const batch_queries_max: usize = 64;

/// One tagged read statement of a batch; the tag rides into the matching
/// result set so callers can correlate without positional bookkeeping.
pub const BatchQuery = struct {
    tag: u32,
    sql: []const u8,
    values: []const prepared.Value,
};

/// Arena-owned result of `Node.queryBatch`: one tagged set per query, all
/// materialized from a single WAL snapshot.
pub const BatchResult = struct {
    arena: std.heap.ArenaAllocator,
    sets: []const Set,

    pub const Set = struct {
        tag: u32,
        columns: []const []const u8,
        rows: []const []const prepared.Value,
    };

    pub fn deinit(self: *BatchResult) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Byte cap on scalar-expectation text/blob comparisons (see
/// `prepared.scalar_bytes_max`, the defining declaration).
pub const scalar_bytes_max = prepared.scalar_bytes_max;

/// Which statement of a checked transaction failed its expectation, and
/// what the write path actually observed. Valid only when
/// `execCheckedTransaction` returned `error.ExpectationFailed`.
pub const CheckedFailure = struct {
    statement_index: u32,
    observed_changes: i64,
    observed_rows: u64,
};

/// Host callback used to release protocol-core messages explicitly
/// classified as safe before the current journal barrier.  The callback is
/// optional so the embedded storage node remains transport-independent.
pub const PreDurableOutboxHook = struct {
    context: *anyopaque,
    run: *const fn (context: *anyopaque) anyerror!void,
};

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    lock_file: Io.File,
    identity: Identity,
    store: PayloadStore,
    journal: Journal,
    log: *Log.Node,
    effects: *Log.Effects,
    inbox: []Log.Envelope,
    /// Envelopes addressed to peers. Most are appended after the backing
    /// journal writes are durable; phase-two accepts may be appended during
    /// the barrier and released through `pre_durable_outbox_hook`.
    outbox: std.ArrayList(Log.Envelope) = .empty,
    pre_durable_outbox_hook: ?PreDurableOutboxHook = null,
    db: sqlite.Db,
    db_path: [:0]u8,
    /// True while the live SQLite writer (capture) connection is open.
    db_open: bool = false,
    /// Authorizer state for the live connection. Application statements
    /// are screened; zaxonlite's own statements run in internal scope.
    guard: guard_mod.Guard = .{},
    /// True when this node was opened as a one-member configuration.
    single: bool,
    product_role: roles.Role,
    capabilities: roles.Capabilities,
    /// The durable decided registry, present on network-hosted nodes. It
    /// is the single membership authority after bootstrap.
    decided_registry: ?registry.Decided = null,
    /// One-shot enrollment binding retained until the fetched registry is
    /// verified and installed.
    join_descriptor: ?JoinDescriptor = null,
    /// Campaigning withheld while a joining data voter has nothing
    /// applied; leading would starve its own catch-up and transfer.
    join_campaign_hold: bool = false,
    members: [types.log_options.max_members]paxos.NodeId,
    member_count: u16,
    leader_priority: u32,
    committed_frames: u32 = 0,
    captured_frames: u32 = 0,
    page_size: u32 = 4096,
    /// The executed frontier E_i: the greatest contiguous chosen slot
    /// reflected in the open materialized image. Not power-loss safe by
    /// itself; the durable anchor below is.
    applied_slot: paxos.Slot = 0,
    /// The durable-state frontier A_i: the greatest slot covered by a
    /// synchronized image and its APPLIED anchor record (ZDS 0011).
    durable_state_slot: paxos.Slot = 0,
    /// Anchored data frontier; prevents an idle anchor/trim feedback loop.
    durable_data_slot: paxos.Slot = 0,
    /// Generation counter of the alternating APPLIED records.
    anchor_generation: u64 = 0,
    /// Durable local trim state: the adopted cluster anchor plus the
    /// active transfer leases capping deletion (ZDS 0011).
    trim_state: trim.State = .{},
    /// Chosen-trim generation the payload sweep last ran for.
    swept_trim_decision_slot: u64 = 0,
    /// Recent chosen transaction batches, kept so a write waiter can be
    /// resolved even after the core window released the slot's cell.
    recent_batches: [64]RecentBatch = @as([64]RecentBatch, @splat(.{})),
    /// Recent per-slot history hashes, for vouching transfer anchors
    /// (ZDS 0011). Indexed like `recent_batches`; slot 0 means empty.
    recent_history: [64]HistoryMark = @as([64]HistoryMark, @splat(.{})),
    /// The global ordered-history anchor H at `applied_slot`.
    history_hash: command.HashBytes,
    /// The history anchor frozen at `durable_state_slot`; trim candidates
    /// bind exactly this pair.
    history_hash_at_anchor: command.HashBytes = @as([32]u8, @splat(0)),
    last_chain: command.HashBytes,
    last_data_slot: paxos.Slot = 0,
    /// Batch identity at `last_data_slot`, kept because the consensus
    /// window may have released that slot's cell.
    last_batch_id: u128 = 0,
    /// Batch identity of the write currently captured in the live WAL but
    /// not yet decided. Any other decision while this is set means the
    /// live image speculated wrongly and must be resynced.
    capture_batch_id: ?u128 = null,
    /// Set when the live image no longer matches the decided log; the
    /// host must call `resyncImage` before serving.
    needs_resync: bool = false,
    /// Result of the most recent local append (see `lastAppend`).
    last_append: ExecResult = .{ .changes = 0, .slot = 0 },
    /// Set when a decided stop sign awaits the membership handover. Slots
    /// continue on the same global line; only the voter set changes.
    membership_change_pending: bool = false,
    /// Copy of the SQLite error message from a failed write transaction,
    /// captured before the rollback statement clears it.
    saved_error: [512]u8 = undefined,
    saved_error_len: usize = 0,
    /// Extended SQLite result code captured with `saved_error`.
    saved_error_code: i32 = 0,
    /// Gate C (ZDS 0010): true while a caller holds a live SQLite
    /// transaction on the writer connection. Single-member nodes only.
    live_transaction: bool = false,
    /// Total-change baseline recorded at `beginLive`.
    live_changes_base: i64 = 0,
    /// Batch identity reserved at `beginLive` and replicated at commit.
    live_batch_id_bytes: [16]u8 = undefined,
    /// Set after a journal/payload durability failure. A cluster host must
    /// stop voting and serving; continuing after a failed fsync would violate
    /// the effects contract.
    fatal_storage_error: bool = false,
    trim_ignored_count: u64 = 0,
    test_storage_delay_ms: u64 = 0,
    /// Operator-selected mapped-I/O limit applied to every connection.
    mmap_size: u64 = 0,
    /// Retention horizon in slots kept below the chosen trim; zero
    /// keeps only what the trim requires.
    retention_slots: u64 = 0,
    /// Hard journal-byte ceiling refusing writes; zero disables.
    journal_cap_bytes: u64 = 0,
    /// When the last durable state anchor published, for the 30-second
    /// cadence trigger; zero until the first anchor of this process.
    last_anchor_ns: i96 = 0,
    /// The limit SQLite actually accepted on the most recent connection.
    effective_mmap_size: i64 = 0,
    /// Recorded search-feature version of the served image; zero means
    /// the image predates the search feature.
    search_feature_version: i64 = 0,
    /// Cached `vec_version()` of the statically linked sqlite-vec.
    sqlite_vec_version_buffer: [32]u8 = undefined,
    sqlite_vec_version_len: usize = 0,

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    pub fn open(gpa: std.mem.Allocator, io: Io, options: OpenOptions) !*Node {
        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);

        const capabilities = options.role.capabilities();
        if (!capabilities.stores_log) return error.RoleHasNoLocalStore;
        var member_storage: [types.log_options.max_members]paxos.NodeId = undefined;
        var members = try canonicalFlagMembers(&options, capabilities, &member_storage);
        // Iterating opens carry a real descriptor on every platform; a
        // non-iterating open is `O_PATH` on Linux, which `fchmod` and
        // `fsync` reject. This handle is chmodded here and synced on
        // every storage barrier.
        var dir = try Io.Dir.cwd().createDirPathOpen(io, options.directory, .{
            .permissions = @fromBackingInt(@intCast(0o700)),
            .open_options = .{ .iterate = true },
        });
        errdefer dir.close(io);
        // Windows has no POSIX mode bits and Zig 0.16 does not implement
        // `dirSetPermissionsWindows`; the directory keeps its inherited ACL.
        if (builtin.os.tag != .windows) {
            try dir.setPermissions(io, @fromBackingInt(@intCast(0o700)));
        }

        // One process per data directory.
        const lock_file = try dir.createFile(io, lock_file_name, .{
            .read = true,
            .truncate = false,
        });
        errdefer lock_file.close(io);
        if (!try lock_file.tryLock(io, .exclusive)) return error.NodeLocked;

        // Under the lock, so the probe's scratch names cannot race another
        // process, and before any storage exists to be made durable.
        try durability.probePathnameSemantics(io, dir);

        // The durable decided registry is authoritative once it exists.
        // Loading fails closed: a present but unreadable registry stops the
        // open instead of falling back to flags or re-derivation.
        var decided_registry = try registry.load(io, dir, gpa);

        // An enrolled replacement carries a join descriptor: the decided
        // database identity it must adopt instead of deriving one from its
        // flags, and the registry digest it will fetch and verify.
        const join = try readJoinDescriptor(gpa, io, dir);
        if (join != null and options.role != .data_voter) return error.JoinRequiresDataVoter;

        // The database identity derived from bootstrap flags applies only
        // while no registry exists; afterwards the decided registry carries
        // it, so changed flags cannot re-derive a new database.
        const expected_database_id: ?u128 = if (decided_registry) |*decided|
            decided.database_id
        else if (join) |descriptor|
            descriptor.database_id
        else
            options.database_id;

        const identity = try loadOrCreateIdentity(
            gpa,
            io,
            dir,
            options.node_id,
            expected_database_id,
            options.role,
        );

        if (decided_registry) |*decided| {
            if (decided.database_id != identity.database_id) {
                return error.RegistryMismatch;
            }
            if (join) |descriptor| {
                if (descriptor.database_id != decided.database_id or
                    descriptor.configuration_id != decided.configuration_id or
                    !std.mem.eql(u8, &descriptor.registry_digest, &decided.digest()))
                {
                    return error.RegistryMismatch;
                }
            }
            members = decided.voterIds(&member_storage);
        } else if (join != null) {
            // A joining replacement must not invent a registry: it fetches
            // and verifies the decided one during snapshot install.
        } else if (options.registry_nodes) |records| {
            // First boot of a network-hosted node: persist the bootstrap
            // registry. The pointer write commits it; a crash in between
            // simply re-runs this idempotent bootstrap.
            const bootstrapped = try registry.Decided.bootstrapAt(
                identity.database_id,
                identity.configuration_id,
                records,
            );
            try registry.storeBlob(io, dir, &bootstrapped);
            try registry.activatePointer(io, dir, bootstrapped.configuration_id);
            decided_registry = bootstrapped;
            members = bootstrapped.voterIds(&member_storage);
        }

        var found_self = false;
        for (members) |member| {
            if (member == options.node_id) found_self = true;
        }
        if (found_self != capabilities.votes) return error.RoleMembershipMismatch;
        const single = capabilities.votes and members.len == 1;

        var store = try PayloadStore.init(io, dir);
        errdefer store.deinit();

        const log = try gpa.create(Log.Node);
        errdefer gpa.destroy(log);
        const effects = try gpa.create(Log.Effects);
        errdefer gpa.destroy(effects);
        effects.init();
        const inbox = try gpa.alloc(Log.Envelope, effects.messages.len);
        errdefer gpa.free(inbox);

        const db_path = try gpa.printSentinel(
            "{s}/{s}",
            .{ options.directory, db_file_name },
            0,
        );
        errdefer gpa.free(db_path);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .lock_file = lock_file,
            .identity = identity,
            .store = store,
            .journal = undefined,
            .log = log,
            .effects = effects,
            .inbox = inbox,
            .db = undefined,
            .db_path = db_path,
            .single = single,
            .product_role = options.role,
            .capabilities = capabilities,
            .decided_registry = decided_registry,
            .join_descriptor = join,
            .members = @as([types.log_options.max_members]paxos.NodeId, @splat(0)),
            .member_count = @intCast(members.len),
            .leader_priority = options.leader_priority,
            .history_hash = history.genesis(identity.database_id),
            .last_chain = command.genesisChain(identity.database_id),
            .test_storage_delay_ms = options.test_storage_delay_ms,
            .mmap_size = options.mmap_size,
            .retention_slots = options.retention_slots,
            .journal_cap_bytes = options.journal_cap_bytes,
        };
        @memcpy(self.members[0..members.len], members);

        // Any journal v1 artifact fails closed: this format cut has no
        // bridge (ZDS 0011).
        try rejectLegacyArtifacts(io, dir);

        // Restore or initialize the protocol node from the segmented
        // journal, keyed by database identity for the database's lifetime.
        var membership: Log.Membership = undefined;
        try membership.init(members);
        const durable = try gpa.create(Log.DurableState);
        defer gpa.destroy(durable);
        durable.* = .{};

        var replay_info: journal_mod.ReplayInfo = undefined;
        var fresh_journal = false;
        if (Journal.open(
            io,
            gpa,
            dir,
            identity.database_id,
            durable,
            &replay_info,
        )) |opened| {
            self.journal = opened;
        } else |err| switch (err) {
            error.FileNotFound => {
                self.journal = try Journal.create(io, gpa, dir, identity.database_id);
                fresh_journal = true;
            },
            else => return err,
        }
        errdefer self.journal.close();
        if (try trim.load(io, self.journal.dir)) |stored| {
            self.trim_state = stored;
            self.journal.noteTrimAnchor(
                stored.decision_slot,
                stored.through_slot,
                stored.history_hash,
            );
        }
        // The TRIM file and the journal's replayed anchor are written in
        // that order, so a crash between them leaves the file one record
        // ahead; re-installing it keeps the core's anchor at the frontier
        // that already licensed deletion. Twins under one id, or a journal
        // ahead of the file, mean corruption and fail closed.
        const replayed = durable.anchor;
        if (self.trim_state.decision_slot == replayed.trim_id) {
            if (replayed.trim_id != 0 and
                (self.trim_state.through_slot != replayed.chosen_trim_slot or
                    !std.mem.eql(
                        u8,
                        &self.trim_state.history_hash,
                        &replayed.history_hash,
                    )))
            {
                return error.TrimRegression;
            }
        } else if (self.trim_state.decision_slot > replayed.trim_id) {
            try durable.apply(.{ .trim_anchor = .{
                .trim_id = self.trim_state.decision_slot,
                .chosen_trim_slot = self.trim_state.through_slot,
                .history_hash = self.trim_state.history_hash,
            } });
        } else {
            return error.TrimRegression;
        }

        // Materialize the image from the durable anchor plus the retained
        // journal suffix (ZDS 0011 recovery ladder), then restore the core
        // at the consumed floor so its window resumes exactly there.
        if (!fresh_journal) {
            self.materializeFromJournal() catch |err| {
                // Replaying the suffix over a corrupt image fails inside
                // SQLite; rebuild from the genesis-retained journal.
                if (err != error.SqliteError) return err;
                try self.discardImageAndRematerialize();
            };
        }
        if (capabilities.votes) {
            try self.log.restoreAt(
                identity.node_id,
                identity.configuration_id,
                &membership,
                durable,
                self.applied_slot,
                options.leader_priority,
            );
        } else {
            try self.log.restoreLearner(
                identity.node_id,
                identity.configuration_id,
                &membership,
                durable,
            );
        }

        // A materializing voter that joins an existing cluster with no
        // applied state must not lead: catch-up and snapshot escalation
        // run against the leader, so winning the election would starve
        // its own recovery forever. The server also suppresses its Paxos
        // envelopes until transfer installs and clears the durable JOIN.
        const fresh_voter = capabilities.campaigns and capabilities.materializes and
            identity.configuration_id > 1;
        if (fresh_voter and join == null and self.applied_slot == 0)
            return error.JoinDescriptorRequired;
        self.join_campaign_hold = fresh_voter and join != null;
        self.log.core.setCampaignEnabled(capabilities.campaigns and !self.join_campaign_hold);
        if (single and capabilities.campaigns) {
            // Volatile leadership: campaign on every open. A one-member
            // quorum completes phase one immediately.
            try self.log.campaign(.noop, self.effects);
            try self.consumeEffectsRecovery();
        }

        // A decided stop sign from a previous run means a membership
        // handover never completed (ZDS 0008 over global slots).
        if (self.log.isReconfigured() != null) {
            self.membership_change_pending = true;
        }
        try self.reconcilePendingOperation();

        if (single and capabilities.serves_writes) {
            self.openLiveDatabase() catch |err| switch (err) {
                error.SqliteError => {
                    // A corrupt image under a valid-looking anchor. When
                    // the journal still retains from genesis the image is
                    // rebuildable; anything else needs a state transfer.
                    try self.discardImageAndRematerialize();
                    try self.openLiveDatabase();
                },
                else => return err,
            };
            try self.bootstrapSchema();
        }
        try self.validateMaterializedBatch();

        // A mixed binary whose search feature manifest is incompatible
        // fails closed before serving anything (ZDS 0009).
        try self.verifySearchFeatureVersion();

        if (sqlite.vecVersion(&self.sqlite_vec_version_buffer)) |text| {
            self.sqlite_vec_version_len = text.len;
        } else |_| {
            self.sqlite_vec_version_len = 0;
        }

        return self;
    }

    pub fn close(self: *Node) void {
        const gpa = self.gpa;
        if (self.db_open) self.db.close();
        self.journal.close();
        self.store.deinit();
        self.lock_file.unlock(self.io);
        self.lock_file.close(self.io);
        self.dir.close(self.io);
        self.outbox.deinit(gpa);
        gpa.free(self.db_path);
        gpa.free(self.inbox);
        gpa.destroy(self.effects);
        gpa.destroy(self.log);
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------
    // Cluster surface used by the transport host
    // ------------------------------------------------------------------

    pub fn isLeader(self: *const Node) bool {
        return self.log.core.role == .leader;
    }

    pub fn isVoter(self: *const Node) bool {
        return self.capabilities.votes;
    }

    /// True once every slot this leadership inherited from earlier ballots
    /// is decided and accounted locally. Until then the applied state can
    /// miss writes the previous leader acknowledged, so leader-level reads
    /// must wait. Meaningful only while this node leads.
    pub fn inheritedPrefixApplied(self: *const Node) bool {
        return self.applied_slot + 1 >= self.log.leaderBase();
    }

    /// True when nothing below the next proposal slot is undecided: the
    /// inherited prefix is applied and no trim, lease, stop, or batch of
    /// this leadership is still in flight. A batch's chain base is read
    /// from applied state, so a write may only be captured in this state.
    pub fn proposalFrontierSettled(self: *const Node) bool {
        return self.applied_slot + 1 >= self.log.proposalFrontier();
    }

    pub fn role(self: *const Node) roles.Role {
        return self.product_role;
    }

    pub fn currentLeader(self: *const Node) ?paxos.NodeId {
        return self.log.currentLeader();
    }

    /// Processes one protocol message from a peer.
    pub fn stepEnvelope(self: *Node, envelope: Log.Envelope) !void {
        try self.log.step(envelope, self.effects);
        try self.consumeEffects();
    }

    /// Learns a voter-certified chosen entry. The commit is journaled and
    /// synced before it is applied to the SQLite materialization.
    pub fn learnChosen(
        self: *Node,
        from: paxos.NodeId,
        slot: paxos.Slot,
        entry: types.Entry,
    ) !void {
        try self.log.learnChosen(from, slot, entry, self.effects);
        try self.consumeEffects();
    }

    /// Advances protocol timers (election, heartbeat, retransmission).
    pub fn tickProtocol(self: *Node) !void {
        try self.log.tick(.noop, self.effects);
        try self.consumeEffects();
    }

    /// Repairs protocol traffic after the transport reconnects to a peer.
    pub fn peerReconnected(self: *Node, peer: paxos.NodeId) !void {
        try self.log.reconnected(peer, self.effects);
        try self.consumeEffects();
    }

    /// Requests decided entries this node is missing from `peer`.
    pub fn requestCatchUp(self: *Node, peer: paxos.NodeId) !void {
        // A fresh voter joining a later configuration cannot reconstruct
        // old entries' configuration-bound history leaves from entries
        // alone. It must first install a survivor's post-handover anchor;
        // range recovery is safe for the suffix after that base.
        if (self.join_descriptor != null) return;
        try self.log.requestCatchUp(peer, self.applied_slot + 1, self.effects);
        try self.consumeEffects();
    }

    /// Starts phase one immediately (used by hosts that manage elections).
    pub fn campaign(self: *Node) !void {
        try self.log.campaign(.noop, self.effects);
        try self.consumeEffects();
    }

    // ------------------------------------------------------------------
    // Public SQL surface
    // ------------------------------------------------------------------

    /// Executes one write transaction and replicates its WAL frames.
    /// In a one-member configuration the result is committed and applied
    /// on return; in a cluster the host must await `applied_slot`.
    pub fn exec(self: *Node, sql: [:0]const u8) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        return self.writeTransaction(.application, sql, null);
    }

    /// Executes one prepared statement as a replicated SQLite transaction.
    /// Parameter bytes are borrowed only for the duration of this call.
    pub fn execPrepared(
        self: *Node,
        sql: []const u8,
        values: []const prepared.Value,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        return self.writePreparedTransaction(.application, &statements, null);
    }

    /// Executes one prepared statement as a replicated transaction and
    /// captures the structured write result: the change count, the last
    /// insert rowid when the statement set one, and typed `RETURNING` rows
    /// when the statement produces them. The returned rows complete before
    /// the write is acknowledged; the caller owns `out_returning`.
    pub fn execPreparedResult(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        out_returning: *?TypedResult,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        out_returning.* = null;
        var capture = WriteCapture{ .gpa = gpa };
        errdefer if (capture.returning) |*rows| rows.deinit();
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        var result = try self.writeRequest(
            .application,
            .{ .prepared = &statements },
            null,
            &capture,
        );
        result.last_insert_rowid = capture.last_insert_rowid;
        out_returning.* = capture.returning;
        return result;
    }

    /// Executes one prepared statement once per parameter vector in `batch`
    /// as ONE replicated transaction (the typed client RPC's atomic
    /// `executemany`). Every statement shares `sql`; the reported change
    /// count is the whole batch's total, and any per-row failure rolls the
    /// entire transaction back. The caller bounds `batch` (the wire path
    /// enforces `prepared.maximum_statements`).
    pub fn execPreparedBatch(
        self: *Node,
        sql: []const u8,
        batch: []const []const prepared.Value,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (batch.len == 0) return error.EmptyTransaction;
        const statements = try self.gpa.alloc(prepared.Statement, batch.len);
        defer self.gpa.free(statements);
        for (batch, statements) |values, *statement| {
            statement.* = .{ .sql = sql, .values = values };
        }
        return self.writePreparedTransaction(.application, statements, null);
    }

    /// Commits a completed multi-call transaction builder as one replicated
    /// WAL transition. A builder is single-use even when execution fails,
    /// preventing accidental retry without an idempotent session.
    pub fn execTransaction(
        self: *Node,
        transaction: *prepared.Transaction,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        try transaction.markFinished();
        return self.writePreparedTransaction(.application, transaction.slice(), null);
    }

    /// Commits several prepared statements as one replicated transaction,
    /// verifying each statement's expectation as it executes. The first
    /// failed expectation records `out_failure`, rolls the whole SQLite
    /// transaction back BEFORE any WAL frame is captured or appended, and
    /// returns `error.ExpectationFailed` — the journal never sees it.
    pub fn execCheckedTransaction(
        self: *Node,
        statements: []const prepared.CheckedStatement,
        out_failure: *?CheckedFailure,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        out_failure.* = null;
        try prepared.validateCheckedBounds(statements);
        return self.writeRequest(.application, .{ .checked = .{
            .statements = statements,
            .out_failure = out_failure,
        } }, null, null);
    }

    /// Opens a replicated client session for idempotent retry.
    pub fn openSession(self: *Node) !u64 {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        const next_id = 1 + try self.metaInt("session_counter");
        const sql = try self.gpa.printSentinel(
            \\update __zaxon_meta set value = {d} where key = 'session_counter';
            \\update __zaxon_meta set value = cast(value as integer) + 1
            \\  where key = 'write_seq';
            \\insert into __zaxon_sessions(id, next_sequence, last_sequence,
            \\  last_changes, last_activity_slot) values ({d}, 1, null, null,
            \\  (select cast(value as integer) from __zaxon_meta
            \\   where key = 'write_seq'));
        ,
            .{ next_id, next_id },
            0,
        );
        defer self.gpa.free(sql);
        _ = try self.writeTransaction(.internal, sql, null);
        return @intCast(next_id);
    }

    pub const SessionCheck = union(enum) {
        /// The sequence is the permitted next one; execute it.
        execute,
        /// The sequence equals the last executed one; return this result.
        replay: ExecResult,
    };

    /// Validates a session sequence against the replicated session table
    /// without executing anything.
    pub fn checkSession(
        self: *Node,
        session_id: u64,
        sequence: u64,
    ) !SessionCheck {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select next_sequence, last_sequence, last_changes " ++
                "from __zaxon_sessions where id = ?1",
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, @intCast(session_id));
        if (!try stmt.step()) return error.UnknownSession;
        const next_sequence: u64 = @intCast(stmt.columnInt64(0));
        const last_sequence: ?u64 = if (stmt.isColumnNull(1))
            null
        else
            @intCast(stmt.columnInt64(1));
        const last_changes = stmt.columnInt64(2);

        if (last_sequence) |last| {
            if (sequence == last) {
                return .{ .replay = .{
                    .changes = last_changes,
                    .slot = 0,
                    .replayed = true,
                } };
            }
        }
        if (sequence < next_sequence) return error.ResultExpired;
        if (sequence > next_sequence) return error.SequenceGap;
        return .execute;
    }

    /// Executes `sequence` for `session_id` exactly once. Retrying the last
    /// sequence returns the recorded result without executing SQL; older or
    /// out-of-order sequences fail without executing SQL.
    pub fn execIdempotent(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: [:0]const u8,
    ) !ExecResult {
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        return self.writeTransaction(.application, sql, .{
            .session_id = session_id,
            .sequence = sequence,
        });
    }

    /// Prepared-statement variant of `execIdempotent` for the typed client
    /// RPC: same session and sequence semantics, positional bound values.
    /// A fresh execution reports the last insert rowid when the statement
    /// set one; a replay retains only the change count (the session table
    /// does not persist the rowid yet).
    pub fn execIdempotentPrepared(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: []const u8,
        values: []const prepared.Value,
    ) !ExecResult {
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        return self.execIdempotentStatements(&statements, session_id, sequence);
    }

    /// Batch variant of `execIdempotentPrepared` for the typed client
    /// RPC's atomic `executemany`: every parameter vector in `batch` binds
    /// the same `sql`, the whole batch is ONE replicated transaction under
    /// ONE session sequence, and the recorded result is the batch's total
    /// change count.
    pub fn execIdempotentPreparedBatch(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: []const u8,
        batch: []const []const prepared.Value,
    ) !ExecResult {
        if (batch.len == 0) return error.EmptyTransaction;
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        const statements = try self.gpa.alloc(prepared.Statement, batch.len);
        defer self.gpa.free(statements);
        for (batch, statements) |values, *statement| {
            statement.* = .{ .sql = sql, .values = values };
        }
        return self.execIdempotentStatements(statements, session_id, sequence);
    }

    /// Shared session-write tail: one replicated transaction with the
    /// session update, capturing the last insert rowid for fresh
    /// executions. Any captured `RETURNING` rows are discarded; the
    /// session RPC does not retain them for replay.
    fn execIdempotentStatements(
        self: *Node,
        statements: []const prepared.Statement,
        session_id: u64,
        sequence: u64,
    ) !ExecResult {
        var capture = WriteCapture{ .gpa = self.gpa };
        defer if (capture.returning) |*rows| rows.deinit();
        var result = try self.writeRequest(
            .application,
            .{ .prepared = statements },
            .{ .session_id = session_id, .sequence = sequence },
            &capture,
        );
        result.last_insert_rowid = capture.last_insert_rowid;
        return result;
    }

    /// Deletes sessions whose last activity is more than `retain` session
    /// writes behind the newest session write.
    pub fn expireSessions(self: *Node, retain: u64) !ExecResult {
        const sql = try self.gpa.printSentinel(
            \\delete from __zaxon_sessions where last_activity_slot <
            \\  (select cast(value as integer) from __zaxon_meta
            \\   where key = 'write_seq') - {d};
        ,
            .{retain},
            0,
        );
        defer self.gpa.free(sql);
        return self.writeTransaction(.internal, sql, null);
    }

    /// Runs a read-only query. The result owns its memory via an arena.
    /// On a member without the live writer connection this opens a
    /// short-lived connection against the materialized image.
    pub fn query(self: *Node, gpa: std.mem.Allocator, sql: []const u8) !QueryResult {
        return self.queryPrepared(gpa, sql, &.{});
    }

    pub fn queryWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        limits: QueryLimits,
    ) !QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, &.{}, limits);
    }

    /// Runs one read-only prepared query and returns copied result values.
    pub fn queryPrepared(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, values, .{});
    }

    /// Typed hybrid search (ZDS 0009): validates the request — including
    /// the 4096 candidate cap — builds the canonical lexical, vector, or
    /// fused statement, and runs it through the standard read path so
    /// leases, guards, and query budgets apply unchanged.
    pub fn search(
        self: *Node,
        gpa: std.mem.Allocator,
        request: search_api.Request,
        limits: QueryLimits,
    ) !QueryResult {
        const plan = try search_api.plan(gpa, request);
        defer plan.deinit(gpa);
        return self.queryPreparedWithLimits(gpa, plan.sql, plan.values(), limits);
    }

    /// Typed search over the same validated planner as `search`.
    pub fn searchTyped(
        self: *Node,
        gpa: std.mem.Allocator,
        request: search_api.Request,
        limits: QueryLimits,
    ) !TypedResult {
        const plan = try search_api.plan(gpa, request);
        defer plan.deinit(gpa);
        return self.queryPreparedTypedWithLimits(gpa, plan.sql, plan.values(), limits);
    }

    /// Runs one read-only prepared query and returns tagged SQLite values.
    pub fn queryPreparedTyped(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !TypedResult {
        return self.queryPreparedTypedWithLimits(gpa, sql, values, .{});
    }

    /// Legacy text presentation of the typed read path. Integer and real
    /// cells are rendered exactly as SQLite's own text conversion renders
    /// them, so existing JSON consumers keep byte-identical responses.
    pub fn queryPreparedWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: QueryLimits,
    ) !QueryResult {
        var typed = try self.queryPreparedTypedWithLimits(gpa, sql, values, limits);
        errdefer typed.deinit();
        return textFromTyped(&typed);
    }

    pub fn queryPreparedTypedWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: QueryLimits,
    ) !TypedResult {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        // Reads are application statements too: the reserved namespace and
        // checkpoint pragmas must stay unreachable. A short-lived lease
        // connection gets its own guard; the live connection reuses the
        // node's. The guard outlives the statement because the lease is
        // released (and any owned connection closed) before this returns.
        var lease_guard = guard_mod.Guard{};
        const read_guard = self.leaseReadGuard(&lease, &lease_guard);
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        // A VM-instruction budget is deterministic and SQLite-native. It is
        // intentionally optional: embedded callers and approved migrations
        // can retain SQLite's normal unlimited behavior.
        var progress: QueryProgress = undefined;
        installVmBudget(&lease.db, limits.max_vm_steps, &progress);
        defer clearVmBudget(&lease.db, limits.max_vm_steps);

        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        var budget = ReadBudget{ .limits = limits };
        const set = materializeReadStatement(
            &lease.db,
            arena.allocator(),
            sql,
            values,
            &budget,
        ) catch |err| {
            if (isSqliteFailure(err)) self.saveErrorFrom(&lease.db);
            return err;
        };
        return .{ .arena = arena, .columns = set.columns, .rows = set.rows };
    }

    /// Runs several prepared read statements through ONE read lease inside
    /// ONE deferred read transaction, so every set observes the same WAL
    /// snapshot. `limits` is a single budget shared across the whole
    /// batch: rows, bytes, and VM steps count down across statements.
    pub fn queryBatch(
        self: *Node,
        gpa: std.mem.Allocator,
        queries: []const BatchQuery,
        limits: QueryLimits,
    ) !BatchResult {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (queries.len == 0) return error.EmptyTransaction;
        if (queries.len > batch_queries_max) return error.TooManyQueries;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();
        // The live writer connection cannot nest a read transaction under
        // an open Gate C transaction or an in-flight write.
        if (!lease.owned and self.db.inTransaction()) return error.TransactionOpen;

        var lease_guard = guard_mod.Guard{};
        const read_guard = self.leaseReadGuard(&lease, &lease_guard);

        var progress: QueryProgress = undefined;
        installVmBudget(&lease.db, limits.max_vm_steps, &progress);
        defer clearVmBudget(&lease.db, limits.max_vm_steps);

        // The deferred transaction (and its commit below) is zaxonlite's
        // own statement and runs in internal scope; only the caller's
        // statements are screened as application SQL.
        try lease.db.exec("begin");
        var committed = false;
        defer if (!committed) lease.db.exec("rollback") catch {};

        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        const sets = try alloc.alloc(BatchResult.Set, queries.len);
        var budget = ReadBudget{ .limits = limits };
        {
            read_guard.scope = .application;
            defer read_guard.scope = .internal;
            for (queries, sets) |batch_query, *set| {
                const materialized = materializeReadStatement(
                    &lease.db,
                    alloc,
                    batch_query.sql,
                    batch_query.values,
                    &budget,
                ) catch |err| {
                    if (isSqliteFailure(err)) self.saveErrorFrom(&lease.db);
                    return err;
                };
                set.* = .{
                    .tag = batch_query.tag,
                    .columns = materialized.columns,
                    .rows = materialized.rows,
                };
            }
        }
        try lease.db.exec("commit");
        committed = true;
        return .{ .arena = arena, .sets = sets };
    }

    /// The guard screening one read lease: a short-lived lease connection
    /// gets `storage` installed as its own guard; the live connection
    /// reuses the node's. `storage` must outlive the lease.
    fn leaseReadGuard(
        self: *Node,
        lease: *ReadLease,
        storage: *guard_mod.Guard,
    ) *guard_mod.Guard {
        if (lease.owned) {
            storage.install(&lease.db);
            return storage;
        }
        return &self.guard;
    }

    /// Copies the name of one bound parameter (1-based index) into
    /// `buffer` and returns its length; zero for positional parameters.
    /// Resolved by SQLite itself so `:name`, `@name`, and `$name` all work
    /// without the host parsing SQL.
    pub fn statementParameterName(
        self: *Node,
        sql: []const u8,
        index: u32,
        buffer: []u8,
    ) !usize {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        var lease_guard = guard_mod.Guard{};
        const read_guard: *guard_mod.Guard = if (lease.owned) blk: {
            lease_guard.install(&lease.db);
            break :blk &lease_guard;
        } else &self.guard;
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        var stmt = lease.db.prepare(sql) catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer stmt.finalize();
        if (index == 0 or index > stmt.parameterCount()) {
            return error.ParameterCountMismatch;
        }
        const name = stmt.parameterName(index) orelse return 0;
        const len = @min(name.len, buffer.len);
        @memcpy(buffer[0..len], name[0..len]);
        return len;
    }

    /// Prepares (without executing) the first statement of `sql` under the
    /// application guard and reports its shape. Hosts use this to reject
    /// multi-statement `execute()` input and to size parameter binding.
    pub fn statementInfo(self: *Node, sql: []const u8) !StatementInfo {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        var lease_guard = guard_mod.Guard{};
        const read_guard: *guard_mod.Guard = if (lease.owned) blk: {
            lease_guard.install(&lease.db);
            break :blk &lease_guard;
        } else &self.guard;
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        var first = lease.db.prepareWithTail(sql) catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer first.stmt.finalize();
        const tail = std.mem.trim(u8, first.tail, " \t\r\n;");
        return .{
            .parameter_count = first.stmt.parameterCount(),
            .column_count = first.stmt.columnCount(),
            .read_only = first.stmt.isReadOnly(),
            .has_tail = tail.len != 0,
        };
    }

    pub fn lastSqliteMessage(self: *const Node) []const u8 {
        if (self.saved_error_len > 0) return self.saved_error[0..self.saved_error_len];
        if (self.db_open) return self.db.errmsg();
        return "no live database connection";
    }

    // ------------------------------------------------------------------
    // Operations surface
    // ------------------------------------------------------------------

    pub fn status(self: *Node) Status {
        // The gate caches the version at open, which precedes lazy schema
        // bootstrap on hosts and page-applied bootstrap on followers;
        // refresh while it still reads zero.
        if (self.search_feature_version == 0) {
            if (self.schemaReady() catch false) {
                self.search_feature_version =
                    self.metaInt("search_feature_version") catch 0;
            }
        }
        const journal_stats = self.journal.stats();
        return .{
            .node_id = self.identity.node_id,
            .database_id = self.identity.database_id,
            .configuration_id = self.identity.configuration_id,
            .role = @tagName(self.log.core.role),
            .node_type = self.product_role.name(),
            .leader = self.log.currentLeader(),
            .ballot = self.log.core.ballot,
            .decided_slot = self.log.decidedThrough(),
            .applied_slot = self.applied_slot,
            .durable_state_slot = self.durable_state_slot,
            .memory_floor = self.log.memoryFloor(),
            .trim_decision_slot = self.trim_state.decision_slot,
            .chosen_trim_slot = self.log.trimAnchor().chosen_trim_slot,
            .trim_ignored = self.trim_ignored_count,
            .retained_first_slot = self.journal.retainedFirstSlot(),
            .journal_records = self.journal.next_sequence - 1,
            .journal_segment_count = journal_stats.segment_count,
            .journal_bytes = journal_stats.journal_bytes,
            .payload_retained_bytes = self.store.retained_bytes,
            .chain = self.last_chain,
            .history = self.history_hash,
            .page_size = self.page_size,
            .fts5_enabled = sqlite.compileOptionUsed("ENABLE_FTS5"),
            .sqlite_vec_version = self.sqliteVecVersion(),
            .search_feature_version = self.search_feature_version,
            .simd_backend = zaxon_search.vector.backend.name(),
            .mmap_size = self.effective_mmap_size,
            .candidate_hard_limit = candidate_hard_limit,
        };
    }

    fn sqliteVecVersion(self: *const Node) []const u8 {
        return self.sqlite_vec_version_buffer[0..self.sqlite_vec_version_len];
    }

    pub fn memberIds(self: *const Node) []const paxos.NodeId {
        return self.members[0..self.member_count];
    }

    /// The durable decided registry, or null for embedded and local nodes
    /// whose membership stays fixed by flags.
    pub fn decidedRegistry(self: *const Node) ?*const registry.Decided {
        if (self.decided_registry) |*decided| return decided;
        return null;
    }

    /// Installs the transport host's pre-barrier outbox drain. The host must
    /// serialize node transitions until the callback returns and the storage
    /// barrier completes; `server.zig` does so with its node mutex.
    pub fn setPreDurableOutboxHook(
        self: *Node,
        hook: ?PreDurableOutboxHook,
    ) void {
        self.pre_durable_outbox_hook = hook;
    }

    pub const PendingOperationPhase = enum { prepared, proposed };

    /// The durably recorded in-flight replacement request. `prepared`
    /// means membership has not changed and the request may be retried or
    /// cancelled; `proposed` means the stop sign is in Paxos and a timeout
    /// does not mean failure.
    pub const PendingOperation = struct {
        operation_id: u64,
        expected_configuration_id: u64,
        old_node_id: paxos.NodeId,
        new_node_id: paxos.NodeId,
        endpoint: [registry.max_endpoint_bytes]u8,
        endpoint_len: u8,
        phase: PendingOperationPhase,

        pub fn endpointSlice(self: *const PendingOperation) []const u8 {
            return self.endpoint[0..self.endpoint_len];
        }

        pub fn matches(
            self: *const PendingOperation,
            request: *const registry.ReplacementRequest,
        ) bool {
            return self.operation_id == request.operation_id and
                self.expected_configuration_id == request.expected_configuration_id and
                self.old_node_id == request.old_node_id and
                self.new_node_id == request.new_node_id and
                std.mem.eql(u8, self.endpointSlice(), request.new_endpoint);
        }

        fn toRequest(self: *const PendingOperation) registry.ReplacementRequest {
            return .{
                .operation_id = self.operation_id,
                .expected_configuration_id = self.expected_configuration_id,
                .old_node_id = self.old_node_id,
                .new_node_id = self.new_node_id,
                .new_endpoint = self.endpointSlice(),
            };
        }
    };

    /// Slots of execution beyond the durable anchor that trigger a new
    /// anchor (ZDS 0011 Q5).
    /// Proven worst-case growth of one admitted write: the maximum
    /// payload plus its accept and commit journal records, a sealing
    /// trailer, and a fresh segment header, each taken from the
    /// constant it must cover so the bound cannot drift. Held in
    /// reserve below the storage cap so an admitted write can never
    /// land above it.
    pub const admission_reserve_bytes: u64 =
        @as(u64, command.max_payload_bytes) +
        2 * (@as(u64, segment_mod.record_header_size) +
            @as(u64, types.max_write_size)) +
        @as(u64, segment_mod.Writer.trailer_size_max) +
        @as(u64, segment_mod.header_size);

    /// Whether one more write may be admitted under the storage cap:
    /// the current usage plus the proven one-write reserve must stay
    /// below the cap, so a cap at or below the reserve refuses every
    /// write. Pure, so the arithmetic is unit-testable with synthetic
    /// numbers.
    pub fn admissionOverCap(usage: u64, reserve: u64, cap: u64) bool {
        return usage +| reserve >= cap;
    }
    pub const anchor_interval_slots: paxos.Slot = 10_000;
    /// Test-overridable so the cadence trigger is verifiable without a
    /// thirty-second wait; production never changes it.
    pub var anchor_interval_ns: i96 = 30 * std.time.ns_per_s;
    pub const anchor_wal_bytes: u64 = 64 * 1024 * 1024;

    /// Creates a durable state anchor: checkpoints the live WAL into the
    /// image, synchronizes it, and publishes the alternating APPLIED
    /// record binding `(applied_slot, history_hash)`. Periodic work
    /// proportional to dirty pages, never a full-database copy or hash.
    pub fn createStateAnchor(self: *Node) !void {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (!self.capabilities.materializes) return error.RoleCannotWrite;
        if (self.needs_resync) try self.resyncImage();
        if (self.live_transaction) return error.TransactionOpen;
        if (self.capture_batch_id != null) return error.WriteInFlight;
        if (self.applied_slot <= self.durable_state_slot) return;

        if (self.db_open) {
            try self.db.checkpointTruncate();
            self.committed_frames = 0;
            self.captured_frames = 0;
        }
        const file = try self.dir.openFile(self.io, db_file_name, .{
            .mode = .read_write,
        });
        defer file.close(self.io);
        failpoint.hit("before_db_sync");
        try durability.syncFile(self.io, file);
        failpoint.hit("after_db_sync");
        const length = try file.length(self.io);

        self.anchor_generation += 1;
        try applied_anchor.publish(self.io, self.journal.dir, .{
            .generation = self.anchor_generation,
            .database_id = self.identity.database_id,
            .global_slot = self.applied_slot,
            .configuration_id = self.identity.configuration_id,
            .history_hash = self.history_hash,
            .sqlite_page_size = self.page_size,
            .sqlite_page_count = length / self.page_size,
            .last_data_slot = self.last_data_slot,
            .last_batch_id = self.last_batch_id,
            .last_chain = self.last_chain,
        });
        self.durable_state_slot = self.applied_slot;
        self.durable_data_slot = self.last_data_slot;
        self.history_hash_at_anchor = self.history_hash;
        self.last_anchor_ns =
            std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds;

        // A one-member configuration is its own only data replica: the
        // conservative trim degenerates to the fresh anchor, chosen and
        // reclaimed inline (ZDS 0011).
        if (self.single and self.capabilities.votes) {
            if (self.durable_state_slot > self.trim_state.through_slot) {
                try self.proposeTrim(.{
                    .through_slot = self.durable_state_slot,
                    .history_hash = self.history_hash_at_anchor,
                });
                try self.reclaim();
            }
        }
    }

    /// Proposes a chosen trim entry. Leader only; the candidate comes
    /// from the minimum durable-state frontier of every data replica.
    pub fn proposeTrim(self: *Node, candidate: trim.Candidate) !void {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (!self.proposalFrontierSettled()) return;
        if (candidate.through_slot <= self.trim_state.through_slot) return;
        const expected_slot = self.log.proposalFrontier();
        const record = command.TrimRecord{
            .through_slot = candidate.through_slot,
            .history_hash = candidate.history_hash,
            .configuration_id = self.identity.configuration_id,
            .policy = 0,
        };
        const proposal_slot = try self.log.append(.{ .trim = record }, self.effects);
        std.debug.assert(proposal_slot == expected_slot);
        try self.consumeEffects();
    }

    /// Adopts a chosen trim record. Exact replay is idempotent; stale or
    /// duplicate decisions are diagnosed and skipped because they cannot
    /// authorize deletion beyond the durable anchor. A decision-slot twin or
    /// conflicting history at the same frontier is durable-history divergence.
    /// A real advance persists TRIM, installs the core anchor, and leaves
    /// physical reclamation to the next pump.
    fn adoptChosenTrim(
        self: *Node,
        decision_slot: paxos.Slot,
        record: command.TrimRecord,
    ) !void {
        return trim.adoptChosen(self, decision_slot, record);
    }

    /// Records a chosen transfer lease; deletion is capped at its base
    /// until completion, whatever happens to the sender.
    fn trackLease(self: *Node, lease: command.TransferLease) !void {
        return trim.trackLease(self, lease);
    }

    fn releaseLease(self: *Node, lease_id: u64) !void {
        return trim.releaseLease(self, lease_id);
    }

    /// Physically reclaims journal segments and payload objects below the
    /// local delete floor. Called from the host pump, never inline in the
    /// commit path.
    pub fn reclaim(self: *Node) !void {
        if (self.trim_state.through_slot == 0) return;
        // A witness holds no materialized state: its trim anchor alone is
        // its recovery base, so it deletes through the anchor (ZDS 0011).
        // A data replica is additionally capped by its durable anchor.
        const durable_cap = if (self.capabilities.materializes)
            self.durable_state_slot
        else
            self.trim_state.through_slot;
        // The retention horizon keeps a recent suffix below the chosen
        // trim so lagging replicas range-recover instead of transferring.
        const retention_cutoff = if (self.retention_slots == 0)
            std.math.maxInt(u64)
        else
            self.applied_slot -| self.retention_slots;
        const floor = trim.deleteFloor(
            self.trim_state.through_slot,
            durable_cap,
            retention_cutoff,
            self.trim_state.leasesSlice(),
        );
        if (floor == 0) return;
        failpoint.hit("before_segment_unlink");
        const removed = try self.journal.trimThrough(floor);
        failpoint.hit("after_segment_unlink");
        // The payload sweep streams the whole retained journal, so it
        // runs when history was removed or the chosen trim advanced —
        // never on every pump.
        if (removed or self.trim_state.decision_slot > self.swept_trim_decision_slot) {
            try self.sweepPayloads();
            self.swept_trim_decision_slot = self.trim_state.decision_slot;
        }
    }

    /// Deletes payload objects no retained journal record references.
    /// The reachable set is streamed from the retained segments, so a
    /// crash can leak an object but never delete a reachable one.
    fn sweepPayloads(self: *Node) !void {
        var reachable = std.AutoHashMap([32]u8, void).init(self.gpa);
        defer reachable.deinit();
        var it = try self.journal.iterate(1);
        defer it.close();
        while (try it.next()) |write| {
            const entry = switch (write) {
                .accept => |accept| accept.value,
                .commit => |commit| commit.value,
                else => continue,
            };
            switch (entry) {
                .command => |cmd| switch (cmd) {
                    .transaction_batch => |batch| {
                        try reachable.put(batch.payload_hash, {});
                    },
                    else => {},
                },
                .stop => {},
            }
        }
        failpoint.hit("before_payload_gc_publish");
        try self.store.sweepUnreachable(&reachable);
        failpoint.hit("after_payload_gc_publish");
    }

    /// The history hash after applying `slot`, when this node can still
    /// vouch for it: from the recent ring, the durable anchor, or the
    /// chosen trim anchor. Null when the slot left every source.
    pub fn historyHashAt(self: *const Node, slot: paxos.Slot) ?[32]u8 {
        if (slot == 0) return null;
        const mark = self.recent_history[@intCast(slot % self.recent_history.len)];
        if (mark.slot == slot) return mark.hash;
        if (slot == self.durable_state_slot) return self.history_hash_at_anchor;
        if (slot == self.trim_state.through_slot) return self.trim_state.history_hash;
        return null;
    }

    pub const TransferPin = struct {
        node: *Node,
        file: Io.File,
        size: u64,
        sha256: [32]u8,
        anchor: applied_anchor.Anchor,

        pub fn close(self: *TransferPin) void {
            self.file.close(self.node.io);
            self.node.journal.dir.deleteFile(
                self.node.io,
                transfer_pin_name,
            ) catch {};
            self.* = undefined;
        }
    };

    /// Pins the durable anchor for a state transfer: publishes a fresh
    /// anchor, then copies the synchronized image into a private file
    /// the stream reads without blocking later anchors (ZDS 0011). The
    /// copy is O(database) — the cost inherent to a full state transfer.
    pub fn pinTransferImage(self: *Node) !TransferPin {
        try self.createStateAnchor();
        const anchor = applied_anchor.select(
            self.io,
            self.journal.dir,
            self.identity.database_id,
        ) orelse return error.StateUnavailable;

        const source = try self.dir.openFile(self.io, db_file_name, .{});
        defer source.close(self.io);
        self.journal.dir.deleteFile(self.io, transfer_pin_name) catch {};
        const pin = try self.journal.dir.createFile(
            self.io,
            transfer_pin_name,
            .{ .read = true },
        );
        errdefer {
            pin.close(self.io);
            self.journal.dir.deleteFile(self.io, transfer_pin_name) catch {};
        }
        var sha = Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (true) {
            const count = try source.readPositionalAll(self.io, &buffer, offset);
            if (count == 0) break;
            sha.update(buffer[0..count]);
            try pin.writePositionalAll(self.io, buffer[0..count], offset);
            offset += count;
            failpoint.hit("during_transfer_pin");
        }
        failpoint.hit("after_transfer_pin");
        return .{
            .node = self,
            .file = pin,
            .size = offset,
            .sha256 = sha.finalResult(),
            .anchor = anchor,
        };
    }

    /// Installs a verified anchor-pinned image as this node's base state
    /// (ZDS 0011): the image becomes `current.db`, a fresh durable anchor
    /// binds it, and the protocol node resumes at the anchor slot on the
    /// same global slot line. The caller has already confirmed the image
    /// digest and quorum-vouched `(anchor_slot, history_hash)`.
    pub fn installTransferredState(
        self: *Node,
        begin: wire.SnapshotBegin,
    ) !void {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (!self.capabilities.materializes) return error.RoleCannotWrite;
        if (begin.configuration_id != self.identity.configuration_id) {
            return error.ConfigurationMismatch;
        }
        if (begin.anchor_slot <= self.applied_slot) return error.StaleTransfer;
        if (self.live_transaction) return error.TransactionOpen;

        const image_sha = try fileSha256(self.io, self.dir, transfer_install_name);
        if (!std.mem.eql(u8, &image_sha, &begin.image_sha256)) {
            return error.TransferDigestMismatch;
        }
        failpoint.hit("before_transfer_install");

        if (self.db_open) {
            self.db.close();
            self.db_open = false;
        }
        self.capture_batch_id = null;
        self.needs_resync = false;
        self.dir.deleteFile(self.io, wal_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.dir.deleteFile(self.io, shm_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.dir.rename(transfer_install_name, self.dir, db_file_name, self.io);
        try durability.syncPathnameTransition(self.io, self.dir, db_file_name);
        failpoint.hit("after_transfer_install");

        self.history_hash = begin.history_hash;
        self.history_hash_at_anchor = begin.history_hash;
        self.last_chain = begin.last_chain;
        self.last_data_slot = begin.last_data_slot;
        self.last_batch_id = begin.last_batch_id;
        self.page_size = begin.sqlite_page_size;
        self.applied_slot = begin.anchor_slot;
        self.recent_batches = @as([64]RecentBatch, @splat(.{}));
        self.recent_history = @as([64]HistoryMark, @splat(.{}));

        self.anchor_generation += 1;
        try applied_anchor.publish(self.io, self.journal.dir, .{
            .generation = self.anchor_generation,
            .database_id = self.identity.database_id,
            .global_slot = begin.anchor_slot,
            .configuration_id = self.identity.configuration_id,
            .history_hash = begin.history_hash,
            .sqlite_page_size = begin.sqlite_page_size,
            .sqlite_page_count = begin.db_size / begin.sqlite_page_size,
            .last_data_slot = begin.last_data_slot,
            .last_batch_id = begin.last_batch_id,
            .last_chain = begin.last_chain,
        });
        self.durable_state_slot = begin.anchor_slot;
        self.durable_data_slot = begin.last_data_slot;
        if (self.join_descriptor != null) try durableDeleteFile(self.io, self.dir, join_file_name);
        self.join_descriptor = null;
        failpoint.hit("after_transfer_anchor");

        // The protocol node resumes at the anchor; everything below it is
        // covered by the installed image, everything above arrives through
        // ordinary catch-up. The transfer stays inside one configuration,
        // so the promise and votes above the anchor must survive it.
        try self.continueOnConfigurationPreserving(begin.anchor_slot);
        failpoint.hit("after_transfer_resume");
    }

    /// This node's progress report for trim coordination and monitoring.
    pub fn frontier(self: *const Node) trim.Frontier {
        return .{
            .node_id = self.identity.node_id,
            .configuration_id = self.identity.configuration_id,
            .durable_state_slot = if (self.capabilities.materializes)
                self.durable_state_slot
            else
                0,
            .history_hash = self.history_hash_at_anchor,
            .executed_slot = self.applied_slot,
            .persisted_slot = self.journal.persistedThrough(),
            .local_delete_floor = self.journal.trimmed_through,
        };
    }

    /// Creates a state anchor once execution has run far enough past the
    /// durable one. Returns whether an anchor was published.
    /// Re-enables campaigning after a joining voter installs its transfer,
    /// or after an ordinary held voter applies state.
    pub fn releaseCampaignHold(self: *Node) void {
        if (!self.join_campaign_hold) return;
        if (self.join_descriptor != null and self.durable_state_slot == 0) return;
        if (self.join_descriptor != null)
            durableDeleteFile(self.io, self.dir, join_file_name) catch return;
        self.join_descriptor = null;
        if (self.applied_slot == 0) return;
        self.join_campaign_hold = false;
        self.log.core.setCampaignEnabled(self.capabilities.campaigns);
    }

    pub fn maybeCreateStateAnchor(self: *Node) !bool {
        if (!self.anchorDue()) return false;
        try self.createStateAnchor();
        return true;
    }

    /// The ZDS 0011 Q5 cadence: a node with no anchor at all still
    /// recovers from genesis, so the first anchor publishes promptly;
    /// afterwards an anchor is due every 10,000 applied slots, every 30
    /// seconds, or when the uncheckpointed WAL reaches 64 MiB —
    /// whichever arrives first, and only while new transaction state exists
    /// to anchor. Configuration handover publishes its required anchor directly.
    fn anchorDue(self: *Node) bool {
        if (self.join_descriptor != null) return false;
        if (self.last_data_slot <= self.durable_data_slot) return false;
        if (self.durable_state_slot == 0) return self.applied_slot > 0;
        if (self.applied_slot >= self.durable_state_slot +| anchor_interval_slots) {
            return true;
        }
        const now = std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds;
        if (self.last_anchor_ns == 0) {
            // The 30-second clock starts at the first cadence check of
            // this process, so a restarted node whose anchor predates
            // the restart still time-anchors.
            self.last_anchor_ns = now;
        } else if (now - self.last_anchor_ns >= anchor_interval_ns) {
            return true;
        }
        const wal_stat = self.dir.statFile(self.io, wal_file_name, .{}) catch
            return false;
        return wal_stat.size >= anchor_wal_bytes;
    }

    /// The batch identity chosen at `slot`, if it was a transaction batch
    /// and is recent enough to still be tracked. Survives consensus-cell
    /// reuse, which `log.read` does not.
    pub fn batchAtSlot(self: *const Node, slot: paxos.Slot) ?u128 {
        const entry = self.recent_batches[@intCast(slot % self.recent_batches.len)];
        if (entry.slot != slot) return null;
        return entry.batch_id;
    }

    /// Reads the durable pending replacement record, if one exists.
    pub fn pendingOperation(self: *Node) !?PendingOperation {
        const bytes = self.dir.readFileAlloc(
            self.io,
            pending_operation_file_name,
            self.gpa,
            .limited(512),
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer self.gpa.free(bytes);
        const format = manifestValue(bytes, "format") orelse
            return error.CorruptPendingOperation;
        if (!std.mem.eql(u8, format, "1")) return error.CorruptPendingOperation;
        const operation_text = manifestValue(bytes, "operation_id") orelse
            return error.CorruptPendingOperation;
        const expected_text = manifestValue(bytes, "expected_configuration_id") orelse
            return error.CorruptPendingOperation;
        const old_text = manifestValue(bytes, "old_node_id") orelse
            return error.CorruptPendingOperation;
        const new_text = manifestValue(bytes, "new_node_id") orelse
            return error.CorruptPendingOperation;
        const endpoint_text = manifestValue(bytes, "endpoint") orelse
            return error.CorruptPendingOperation;
        const phase_text = manifestValue(bytes, "phase") orelse
            return error.CorruptPendingOperation;
        registry.validateEndpoint(endpoint_text) catch
            return error.CorruptPendingOperation;
        var pending = PendingOperation{
            .operation_id = std.fmt.parseInt(u64, operation_text, 10) catch
                return error.CorruptPendingOperation,
            .expected_configuration_id = std.fmt.parseInt(u64, expected_text, 10) catch
                return error.CorruptPendingOperation,
            .old_node_id = std.fmt.parseInt(paxos.NodeId, old_text, 10) catch
                return error.CorruptPendingOperation,
            .new_node_id = std.fmt.parseInt(paxos.NodeId, new_text, 10) catch
                return error.CorruptPendingOperation,
            .endpoint = @as([registry.max_endpoint_bytes]u8, @splat(0)),
            .endpoint_len = @intCast(endpoint_text.len),
            .phase = std.meta.stringToEnum(PendingOperationPhase, phase_text) orelse
                return error.CorruptPendingOperation,
        };
        @memcpy(pending.endpoint[0..endpoint_text.len], endpoint_text);
        return pending;
    }

    fn persistPendingOperation(
        self: *Node,
        request: *const registry.ReplacementRequest,
        phase: PendingOperationPhase,
    ) !void {
        var buffer: [512]u8 = undefined;
        const contents = std.fmt.bufPrint(
            &buffer,
            "format=1\noperation_id={d}\nexpected_configuration_id={d}\n" ++
                "old_node_id={d}\nnew_node_id={d}\nendpoint={s}\nphase={s}\n",
            .{
                request.operation_id,
                request.expected_configuration_id,
                request.old_node_id,
                request.new_node_id,
                request.new_endpoint,
                @tagName(phase),
            },
        ) catch unreachable;
        try atomicWriteFile(self.io, self.dir, pending_operation_file_name, contents);
    }

    fn clearPendingOperation(self: *Node) !void {
        try durableDeleteFile(self.io, self.dir, pending_operation_file_name);
    }

    /// Repairs the scratch phase after a crash. A durable accepted stop
    /// proves that proposal submission completed even if the phase-file
    /// update did not. Without that evidence, `prepared` remains retryable.
    fn reconcilePendingOperation(self: *Node) !void {
        const pending = (try self.pendingOperation()) orelse return;
        if (pending.phase == .proposed) return;
        const stop = self.log.pendingStopSign() orelse return;
        const parsed = try registry.parseStopMetadata(stop.metadataSlice());
        const seed = parsed.seed orelse {
            try self.clearPendingOperation();
            return;
        };
        if (seed.operation_id != pending.operation_id or
            seed.old_node_id != pending.old_node_id or
            seed.new_node_id != pending.new_node_id or
            !std.mem.eql(u8, seed.endpointSlice(), pending.endpointSlice()))
        {
            try self.clearPendingOperation();
            return;
        }
        const request = pending.toRequest();
        try self.persistPendingOperation(&request, .proposed);
    }

    /// Prepares and proposes a decided one-for-one voter replacement.
    /// Leader only. The stop sign carries the candidate registry digest
    /// and the replacement seed, so every survivor reconstructs the same
    /// next registry without the network.
    pub fn prepareReplacement(
        self: *Node,
        request: *const registry.ReplacementRequest,
    ) !void {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.fatal_storage_error) return error.StorageFailed;
        const decided = self.decidedRegistry() orelse
            return error.NoDecidedRegistry;
        if (try self.pendingOperation()) |pending| {
            if (!pending.matches(request)) return error.OperationConflict;
            if (pending.phase == .proposed) return error.OperationAlreadyProposed;
        }
        switch (try decided.validateRequest(request)) {
            .fresh => {},
            .retry => return error.OperationAlreadyComplete,
        }
        if (self.needs_resync) try self.resyncImage();
        if (self.live_transaction) return error.TransactionOpen;
        if (self.capture_batch_id != null) return error.WriteInFlight;

        // The request is durable before anything is proposed, so an
        // ambiguous crash resolves by operation ID.
        try self.persistPendingOperation(request, .prepared);
        failpoint.hit("after_pending_op");

        // The stop sign binds only the canonical next registry and the
        // seed reconstructing it. State rides the retained journal and
        // the anchor-pinned transfer, never a snapshot generation
        // (ZDS 0011); global slots continue across the transition.
        const next = try decided.successor(request);
        const metadata = registry.renderStopMetadata(next.digest(), request);
        var voter_buffer: [types.log_options.max_members]paxos.NodeId = undefined;
        const next_voters = next.voterIds(&voter_buffer);
        _ = try self.log.reconfigure(
            next.configuration_id,
            next_voters,
            metadata.slice(),
            self.effects,
        );
        try self.consumeEffects();
        failpoint.hit("after_replacement_submission");
        try self.persistPendingOperation(request, .proposed);
        failpoint.hit("after_replacement_proposed");
    }

    /// Completes a decided membership change on a survivor: reconstructs
    /// and durably installs the next registry, advances the identity, and
    /// continues the protocol node on the same global slot line
    /// (ZDS 0008 over ZDS 0011). A voter the stop sign removed stays
    /// permanently sealed on its final configuration.
    pub fn completeMembershipChange(self: *Node) !void {
        const stop = self.log.isReconfigured() orelse return error.NoStopSign;
        const stop_slot = self.log.stopSlot() orelse return error.NoStopSign;
        // Nothing can be chosen beyond a sealed configuration, so the
        // handover waits only for the stop itself to be applied.
        if (self.applied_slot < stop_slot) return error.StopNotApplied;
        std.debug.assert(self.applied_slot == stop_slot);
        const parsed = try registry.parseStopMetadata(stop.metadataSlice());

        if (self.capabilities.votes) {
            var still_member = false;
            for (stop.membersSlice()) |member| {
                if (member == self.identity.node_id) still_member = true;
            }
            if (!still_member) return error.RetiredByReconfiguration;
        }

        const decided = self.decidedRegistry() orelse
            return error.NoDecidedRegistry;
        const next = try reconstructNextRegistry(
            decided,
            &parsed,
            stop.configuration_id,
        );
        try registry.storeBlob(self.io, self.dir, &next);
        failpoint.hit("after_registry_blob");
        try registry.activatePointer(self.io, self.dir, next.configuration_id);
        failpoint.hit("after_registry_pointer");

        self.identity.configuration_id = next.configuration_id;
        try writeIdentity(self.io, self.dir, self.identity);
        self.decided_registry = next;
        try self.adoptDecidedMembers();
        try self.continueOnConfiguration(stop_slot);
        // Publish a base carrying the new configuration identity even when
        // the stop changed no SQLite pages. A later replacement installs
        // this exact history anchor before requesting the retained suffix.
        if (self.join_descriptor == null and !self.join_campaign_hold and
            self.capabilities.materializes and
            self.applied_slot > self.durable_state_slot)
        {
            try self.createStateAnchor();
        }

        if (try self.pendingOperation()) |pending| {
            if (parsed.seed) |seed| {
                if (pending.operation_id == seed.operation_id) {
                    try self.clearPendingOperation();
                }
            }
        }
        self.membership_change_pending = false;
    }

    /// Installs the decided registry a joining replacement fetched from a
    /// peer, verified against the enrollment join descriptor, then joins
    /// the configuration it names at the empty global slot line. The
    /// pointer write commits the install; a crash before it repeats the
    /// fetch on restart.
    pub fn installFetchedRegistry(self: *Node, blob: []const u8) !void {
        const join = self.join_descriptor orelse return error.NoJoinPending;
        // Stored blobs are canonical bytes plus a 32-byte digest trailer;
        // the join descriptor binds the digest of the canonical bytes.
        if (blob.len <= 32) return error.RegistryMismatch;
        const encoded = blob[0 .. blob.len - 32];
        var blob_digest: [32]u8 = undefined;
        Sha256.hash(encoded, &blob_digest, .{});
        if (!std.mem.eql(u8, &blob_digest, blob[blob.len - 32 ..]) or
            !std.mem.eql(u8, &blob_digest, &join.registry_digest))
        {
            return error.RegistryMismatch;
        }
        var fetched = registry.Decided.decode(encoded) catch
            return error.RegistryMismatch;
        fetched.validate() catch return error.RegistryMismatch;
        if (fetched.database_id != self.identity.database_id or
            fetched.configuration_id != join.configuration_id)
        {
            return error.RegistryMismatch;
        }

        try registry.storeBlob(self.io, self.dir, &fetched);
        failpoint.hit("after_registry_blob");
        try registry.activatePointer(self.io, self.dir, fetched.configuration_id);
        failpoint.hit("after_registry_pointer");
        self.identity.configuration_id = fetched.configuration_id;
        try writeIdentity(self.io, self.dir, self.identity);
        self.decided_registry = fetched;
        try self.adoptDecidedMembers();
        try self.continueOnConfiguration(self.applied_slot);
    }

    /// Refreshes the member table from the decided registry.
    fn adoptDecidedMembers(self: *Node) !void {
        var member_storage: [types.log_options.max_members]paxos.NodeId = undefined;
        const members = self.decided_registry.?.voterIds(&member_storage);
        var found_self = false;
        for (members) |member| {
            if (member == self.identity.node_id) found_self = true;
        }
        if (found_self != self.capabilities.votes) {
            return error.RoleMembershipMismatch;
        }
        @memcpy(self.members[0..members.len], members);
        self.member_count = @intCast(members.len);
        self.single = self.capabilities.votes and members.len == 1;
    }

    /// Restarts the protocol node under the current identity and member
    /// table at `floor`, keeping the global slot line and the adopted
    /// trim anchor. Accepted-only state above the floor belongs to the
    /// sealed configuration and is discarded, exactly as a restart is.
    fn continueOnConfiguration(self: *Node, floor: paxos.Slot) !void {
        const durable = try self.gpa.create(Log.DurableState);
        defer self.gpa.destroy(durable);
        durable.* = .{};
        durable.anchor = self.log.trimAnchor();
        try self.restoreCoreOn(durable, floor);
    }

    /// Same-configuration continuation onto an installed state image. The
    /// image discharges every slot at or below `floor`, but the node's
    /// open Paxos obligations survive it: the durable promise and every
    /// vote above the floor are carried into the restored core, so a
    /// transfer can never let an older ballot win a slot this node
    /// already helped choose. Discarding them is safe only across a
    /// configuration change, where the new configuration id fences the
    /// old ballot line.
    fn continueOnConfigurationPreserving(self: *Node, floor: paxos.Slot) !void {
        const durable = try self.gpa.create(Log.DurableState);
        defer self.gpa.destroy(durable);
        durable.* = self.log.core.durable;
        try self.restoreCoreOn(durable, floor);
    }

    fn restoreCoreOn(
        self: *Node,
        durable: *const Log.DurableState,
        floor: paxos.Slot,
    ) !void {
        var membership: Log.Membership = undefined;
        try membership.init(self.members[0..self.member_count]);
        if (self.capabilities.votes) {
            try self.log.restoreAt(
                self.identity.node_id,
                self.identity.configuration_id,
                &membership,
                durable,
                floor,
                self.leader_priority,
            );
        } else {
            try self.log.restoreLearner(
                self.identity.node_id,
                self.identity.configuration_id,
                &membership,
                durable,
            );
        }
        // A stateless continuation of a joined configuration must not
        // lead (a joiner opens at configuration 1 and only learns its
        // real configuration from the fetched registry, so this is
        // where the hold is decided); it lifts after transfer clears JOIN.
        self.join_campaign_hold = self.capabilities.campaigns and
            self.capabilities.materializes and
            self.identity.configuration_id > 1 and
            self.applied_slot == 0;
        self.log.core.setCampaignEnabled(
            self.capabilities.campaigns and !self.join_campaign_hold,
        );
        if (self.single and self.capabilities.campaigns) {
            try self.log.campaign(.noop, self.effects);
            try self.consumeEffects();
        }
    }

    pub fn backup(self: *Node, destination: []const u8) !void {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();
        var stmt = lease.db.prepare("vacuum into ?1") catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer stmt.finalize();
        try stmt.bindText(1, destination);
        _ = stmt.step() catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
    }

    pub const BackupHandle = struct {
        node: *Node,
        file: Io.File,
        size: u64,
        sha256: [32]u8,
        name: [64]u8,
        name_length: usize,

        pub fn close(self: *BackupHandle) void {
            self.file.close(self.node.io);
            self.node.dir.deleteFile(
                self.node.io,
                self.name[0..self.name_length],
            ) catch {};
            self.* = undefined;
        }
    };

    /// Creates an immutable logical backup for bounded streaming. The caller
    /// must close the returned handle, which removes the temporary image.
    pub fn openBackup(self: *Node) !BackupHandle {
        var random_bytes: [8]u8 = undefined;
        self.io.random(&random_bytes);
        const nonce = std.mem.readInt(u64, &random_bytes, .little);
        var name: [64]u8 = undefined;
        const rendered = std.fmt.bufPrint(
            &name,
            ".remote-backup-{x}.db",
            .{nonce},
        ) catch unreachable;
        self.dir.deleteFile(self.io, rendered) catch {};
        const directory = std.fs.path.dirname(self.db_path) orelse ".";
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const destination = try std.fmt.bufPrint(
            &path_buffer,
            "{s}/{s}",
            .{ directory, rendered },
        );
        try self.backup(destination);
        errdefer self.dir.deleteFile(self.io, rendered) catch {};
        const file = try self.dir.openFile(self.io, rendered, .{});
        errdefer file.close(self.io);
        return .{
            .node = self,
            .file = file,
            .size = try file.length(self.io),
            .sha256 = try fileSha256(self.io, self.dir, rendered),
            .name = name,
            .name_length = rendered.len,
        };
    }

    /// A deterministic digest of the logical database content, computed
    /// from a `VACUUM INTO` image. Nodes with identical applied history
    /// produce identical digests.
    pub fn contentHash(self: *Node) ![32]u8 {
        var name_buffer: [64]u8 = undefined;
        const tmp_name = std.fmt.bufPrint(
            &name_buffer,
            ".content-hash-{d}.db",
            .{self.identity.node_id},
        ) catch unreachable;
        self.dir.deleteFile(self.io, tmp_name) catch {};
        const directory = std.fs.path.dirname(self.db_path) orelse ".";
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const destination = try std.fmt.bufPrint(
            &path_buffer,
            "{s}/{s}",
            .{ directory, tmp_name },
        );
        try self.backup(destination);
        defer self.dir.deleteFile(self.io, tmp_name) catch {};
        return fileSha256(self.io, self.dir, tmp_name);
    }

    /// Verifies the SQLite image, the descriptor chain, and payload
    /// availability for the committed suffix.
    pub fn integrityCheck(self: *Node) !IntegrityReport {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var report = IntegrityReport{
            .sqlite_ok = blk: {
                var lease = self.readLease() catch |err| {
                    // A fresh member with no decided writes has no image.
                    break :blk err == error.NoDatabaseImage and
                        self.log.decidedThrough() == 0;
                };
                defer lease.release();
                break :blk lease.db.integrityCheckOk() catch false;
            },
            .chain_ok = true,
            .payloads_ok = true,
        };
        // Walk the retained journal suffix from the durable anchor,
        // revalidating the batch chain and payload store (ZDS 0011: the
        // trimmed prefix is vouched for by the anchor itself).
        var chain = command.genesisChain(self.identity.database_id);
        var data_slot: paxos.Slot = 0;
        var next_slot: paxos.Slot = 1;
        if (applied_anchor.select(
            self.io,
            self.journal.dir,
            self.identity.database_id,
        )) |anchor| {
            chain = anchor.last_chain;
            data_slot = anchor.last_data_slot;
            next_slot = anchor.global_slot + 1;
        }
        var progressed = true;
        while (progressed) {
            progressed = false;
            var it = self.journal.iterate(next_slot) catch {
                report.chain_ok = false;
                return report;
            };
            defer it.close();
            while (it.next() catch {
                report.chain_ok = false;
                break;
            }) |write| {
                const commit = switch (write) {
                    .commit => |commit| commit,
                    else => continue,
                };
                if (commit.slot != next_slot) continue;
                next_slot += 1;
                progressed = true;
                switch (commit.value) {
                    .command => |cmd| switch (cmd) {
                        .transaction_batch => |batch| {
                            if (batch.database_id != self.identity.database_id or
                                batch.base_data_slot != data_slot or
                                !std.mem.eql(u8, &batch.base_chain_hash, &chain) or
                                !command.chainValid(batch))
                            {
                                report.chain_ok = false;
                            }
                            chain = batch.result_chain_hash;
                            data_slot = commit.slot;
                            const payload = self.store.load(
                                self.gpa,
                                batch.payload_hash,
                            ) catch {
                                report.payloads_ok = false;
                                continue;
                            };
                            defer self.gpa.free(payload);
                            _ = self.validateBatchPayload(batch, payload) catch {
                                report.payloads_ok = false;
                            };
                        },
                        else => {},
                    },
                    .stop => {},
                }
            }
        }
        return report;
    }

    // ------------------------------------------------------------------
    // Write path
    // ------------------------------------------------------------------

    const SessionUpdate = struct {
        session_id: u64,
        sequence: u64,
    };

    const CheckedRequest = struct {
        statements: []const prepared.CheckedStatement,
        out_failure: *?CheckedFailure,
    };

    const WriteRequest = union(enum) {
        raw: [:0]const u8,
        prepared: []const prepared.Statement,
        checked: CheckedRequest,
    };

    /// Opens the live writer (capture) connection. The materialized image
    /// must be current; the host calls this when it holds leadership.
    pub fn ensureWriter(self: *Node) !void {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.db_open) return;
        std.debug.assert(!self.needs_resync);
        try self.openLiveDatabase();
    }

    /// Closes the live writer connection and discards its WAL, then
    /// rebuilds the materialized image from the decided log. Used when
    /// leadership is lost with speculative frames in the WAL, or when a
    /// decision contradicted the live image.
    pub fn resyncImage(self: *Node) !void {
        if (self.db_open) {
            self.db.close();
            self.db_open = false;
        }
        self.capture_batch_id = null;
        try self.materializeFromJournal();
        self.needs_resync = false;
    }

    /// True when the replicated bootstrap schema exists in the image.
    pub fn schemaReady(self: *Node) !bool {
        var lease = self.readLease() catch return false;
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select 1 from sqlite_master where name = '__zaxon_meta'",
        );
        defer stmt.finalize();
        return try stmt.step();
    }

    /// The replicated schema-bootstrap statement batch. Callers free it.
    pub fn bootstrapSql(self: *Node, gpa: std.mem.Allocator) ![:0]u8 {
        return gpa.printSentinel(
            \\create table __zaxon_meta(key text primary key, value) without rowid;
            \\create table __zaxon_sessions(
            \\  id integer primary key,
            \\  next_sequence integer not null,
            \\  last_sequence integer,
            \\  last_changes integer,
            \\  last_activity_slot integer not null default 0);
            \\insert into __zaxon_meta(key, value) values
            \\  ('schema_version', '1'),
            \\  ('search_feature_version', '1'),
            \\  ('database_id', '{x:0>32}'),
            \\  ('session_counter', '0'),
            \\  ('write_seq', '0');
        ,
            .{self.identity.database_id},
            0,
        );
    }

    /// Executes one SQL batch inside a captured transaction and appends
    /// the resulting descriptor to the replicated log. Returns once the
    /// descriptor is journaled; in a one-member configuration the slot is
    /// also committed and applied on return.
    fn writeTransaction(
        self: *Node,
        scope: guard_mod.Scope,
        sql: [:0]const u8,
        session: ?SessionUpdate,
    ) !ExecResult {
        return self.writeRequest(scope, .{ .raw = sql }, session, null);
    }

    fn writePreparedTransaction(
        self: *Node,
        scope: guard_mod.Scope,
        statements: []const prepared.Statement,
        session: ?SessionUpdate,
    ) !ExecResult {
        return self.writeRequest(scope, .{ .prepared = statements }, session, null);
    }

    fn writeRequest(
        self: *Node,
        scope: guard_mod.Scope,
        request: WriteRequest,
        session: ?SessionUpdate,
        capture: ?*WriteCapture,
    ) !ExecResult {
        if (self.fatal_storage_error) return error.StorageFailed;
        // The storage-budget hard ceiling (ZDS 0011): past the
        // configured cap, new writes are refused rather than unproven
        // history deleted; a safe trim, a state transfer, or an
        // operator capacity change restores service. Admission holds a
        // one-transaction reserve below the cap, so no leader-admitted
        // write can land above it; followers install what consensus
        // chose regardless and fail loudly on their own write path.
        if (self.journal_cap_bytes != 0) {
            const usage = self.journal.stats().journal_bytes +|
                self.store.retained_bytes;
            if (admissionOverCap(
                usage,
                admission_reserve_bytes,
                self.journal_cap_bytes,
            )) {
                return error.RecoveryRetentionExceeded;
            }
        }
        if (self.needs_resync) try self.resyncImage();
        // Never execute SQL that cannot be appended: a sealed log would
        // otherwise leave a committed SQLite transaction with no slot.
        // Slots continue globally; sealing now means membership change
        // only (ZDS 0011).
        if (self.membership_change_pending or self.log.stop_pending or
            self.log.isReconfigured() != null)
        {
            return error.LogSealed;
        }
        // The base of the captured batch is this node's applied frontier;
        // a slot still undecided below the proposal frontier (inherited
        // from an earlier ballot, or a trim in flight) would make that base
        // stale in the decided log. The host waits before it gets here;
        // this refusal happens before any SQL runs, so nothing to resync.
        if (self.isLeader() and !self.proposalFrontierSettled()) {
            return error.LeaderNotReady;
        }
        try self.ensureWriter();
        if (self.capture_batch_id != null) return error.WriteInFlight;
        if (self.live_transaction) return error.TransactionOpen;

        var batch_id_bytes: [16]u8 = undefined;
        self.io.random(&batch_id_bytes);

        // Execute the transaction. The replicated session and batch marker
        // rows are updated inside the same SQLite transaction, so captured
        // frames carry them atomically with the user's changes.
        try self.db.exec("begin immediate");
        errdefer self.db.exec("rollback") catch {};

        const changes_before = self.totalChanges();
        const rowid_before = self.db.lastInsertRowId();
        self.saved_error_len = 0;
        {
            // Only the caller's SQL runs in its scope; the metadata and
            // commit statements below are always internal.
            self.guard.scope = scope;
            defer self.guard.scope = .internal;
            const execution = switch (request) {
                .raw => |sql| self.db.exec(sql),
                .prepared => |statements| if (capture) |sink|
                    self.executePreparedCapture(statements, sink)
                else
                    prepared.execute(&self.db, statements),
                .checked => |checked| self.executeCheckedStatements(
                    checked.statements,
                    checked.out_failure,
                ),
            };
            execution catch |err| {
                // An expectation failure already saved its own message;
                // the connection's would read "not an error".
                if (err != error.ExpectationFailed) self.saveErrorFrom(&self.db);
                return err;
            };
        }
        // Read the rowid before the session and batch-marker inserts below
        // overwrite it with reserved-table bookkeeping.
        if (capture) |sink| {
            const rowid_after = self.db.lastInsertRowId();
            if (rowid_after != rowid_before) sink.last_insert_rowid = rowid_after;
        }
        if (scope == .application) {
            // The authorizer already denied contract-changing statements;
            // this cheap re-check keeps capture robust to anything the
            // deny list missed before the frames are extracted.
            guard_mod.verifyCaptureContract(
                &self.db,
                self.page_size,
                &self.committed_frames,
            ) catch |err| {
                self.saveErrorText("application SQL broke the capture contract");
                return err;
            };
        }
        const changes: i64 = self.totalChanges() - changes_before;
        return self.sealCapturedTransaction(batch_id_bytes, changes, session);
    }

    /// Commits the open writer transaction, captures its WAL frames, and
    /// replicates them as one transaction batch. Shared by the one-shot
    /// write path and Gate C live-transaction commit. A failure after the
    /// SQLite commit marks the image for resync.
    fn sealCapturedTransaction(
        self: *Node,
        batch_id_bytes: [16]u8,
        changes: i64,
        session: ?SessionUpdate,
    ) !ExecResult {
        const batch_id = std.mem.readInt(u128, &batch_id_bytes, .little);
        var committed_without_log = false;
        errdefer if (committed_without_log) {
            self.capture_batch_id = null;
            self.needs_resync = true;
        };

        if (session) |update| {
            try self.db.exec(
                "update __zaxon_meta set value = cast(value as integer) + 1 " ++
                    "where key = 'write_seq'",
            );
            var stmt = try self.db.prepare(
                "update __zaxon_sessions set next_sequence = ?1, " ++
                    "last_sequence = ?2, last_changes = ?3, " ++
                    "last_activity_slot = (select cast(value as integer) " ++
                    "from __zaxon_meta where key = 'write_seq') where id = ?4",
            );
            defer stmt.finalize();
            try stmt.bindInt64(1, @intCast(update.sequence + 1));
            try stmt.bindInt64(2, @intCast(update.sequence));
            try stmt.bindInt64(3, changes);
            try stmt.bindInt64(4, @intCast(update.session_id));
            _ = try stmt.step();
        }
        {
            const batch_id_hex = std.fmt.bytesToHex(batch_id_bytes, .lower);
            var stmt = try self.db.prepare(
                "insert or replace into __zaxon_meta(key, value) " ++
                    "values ('batch_id', ?1)",
            );
            defer stmt.finalize();
            try stmt.bindText(1, &batch_id_hex);
            _ = try stmt.step();
        }
        try self.db.exec("commit");
        committed_without_log = true;

        // Capture the committed frames and persist them as one payload.
        if (self.committed_frames <= self.captured_frames) {
            return error.CaptureLost;
        }
        var frames = try wal.readCommittedFrames(
            self.io,
            self.gpa,
            self.dir,
            wal_file_name,
            self.page_size,
            self.captured_frames,
            self.committed_frames,
        );
        defer frames.deinit(self.gpa);
        self.captured_frames = self.committed_frames;

        const transactions = [_]wal.Transaction{.{
            .session_id = if (session) |update| update.session_id else 0,
            .sequence = if (session) |update| update.sequence else 0,
            .first_frame = 0,
            .frame_count = @intCast(frames.infos.len),
            .change_count = changes,
        }};
        const payload = try wal.encodePayload(
            self.gpa,
            self.identity.database_id,
            &transactions,
            &frames,
        );
        defer self.gpa.free(payload);
        if (payload.len > command.max_payload_bytes) {
            return error.TransactionTooLarge;
        }
        failpoint.hit("before_payload_sync");
        const payload_hash = self.store.put(payload) catch |err| {
            self.fatal_storage_error = true;
            return err;
        };
        failpoint.hit("after_payload_sync");

        var batch = command.TransactionBatch{
            .database_id = self.identity.database_id,
            .batch_id = batch_id,
            .base_data_slot = self.last_data_slot,
            .base_chain_hash = self.last_chain,
            .result_chain_hash = undefined,
            .payload_hash = payload_hash,
            .payload_bytes = payload.len,
            .transaction_count = 1,
            .frame_count = @intCast(frames.infos.len),
        };
        batch.result_chain_hash = command.chainStep(batch.base_chain_hash, batch);

        // Replicate: journal + fsync happen inside consumeEffects before any
        // dependent message or acknowledgement.
        const slot = self.log.append(
            .{ .transaction_batch = batch },
            self.effects,
        ) catch |err| {
            // The SQLite transaction is committed locally but has no log
            // slot; the image must be resynced from the decided log.
            self.needs_resync = true;
            return err;
        };
        self.capture_batch_id = batch_id;
        try self.consumeEffects();
        committed_without_log = false;
        if (self.single and self.applied_slot < slot) return error.CommitIncomplete;
        const result = ExecResult{ .changes = changes, .slot = slot };
        self.last_append = result;
        return result;
    }

    /// Batch identity of the in-flight captured write, if any. The host
    /// uses it to confirm that the decided value at the awaited slot is
    /// this write and not a competing leader's.
    pub fn pendingBatchId(self: *const Node) ?u128 {
        return self.capture_batch_id;
    }

    // ------------------------------------------------------------------
    // Gate C: live transactions (single-member nodes only)
    // ------------------------------------------------------------------

    pub const LiveStatementResult = struct {
        changes: i64,
        last_insert_rowid: ?i64,
    };

    /// Opens a live SQLite transaction on the writer connection. Later
    /// `liveExec` calls observe earlier uncommitted writes; nothing is
    /// replicated until `commitLive`. Restricted to a single-member node,
    /// which cannot lose leadership while the caller holds the transaction.
    pub fn beginLive(self: *Node) !void {
        if (!self.single) return error.ClusterTransactionUnsupported;
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.live_transaction) return error.TransactionOpen;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        if (self.membership_change_pending or self.log.stop_pending or
            self.log.isReconfigured() != null)
        {
            return error.LogSealed;
        }
        try self.ensureWriter();
        if (self.capture_batch_id != null) return error.WriteInFlight;

        self.io.random(&self.live_batch_id_bytes);
        self.saved_error_len = 0;
        try self.db.exec("begin immediate");
        self.live_changes_base = self.totalChanges();
        self.live_transaction = true;
    }

    /// Executes one statement inside the live transaction under the
    /// application guard. Read statements run on the writer connection and
    /// observe uncommitted writes; DML `RETURNING` rows are captured into
    /// `out_returning`, which the caller owns.
    pub fn liveExec(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        out_returning: *?TypedResult,
    ) !LiveStatementResult {
        if (!self.live_transaction) return error.NoTransaction;
        if (self.fatal_storage_error) return error.StorageFailed;
        out_returning.* = null;
        var capture = WriteCapture{ .gpa = gpa };
        errdefer if (capture.returning) |*rows| rows.deinit();
        const changes_before = self.totalChanges();
        const rowid_before = self.db.lastInsertRowId();
        self.saved_error_len = 0;
        {
            self.guard.scope = .application;
            defer self.guard.scope = .internal;
            const statements = [_]prepared.Statement{.{
                .sql = sql,
                .values = values,
            }};
            self.executePreparedCapture(&statements, &capture) catch |err| {
                self.saveErrorFrom(&self.db);
                // A conflict-rollback or similar abort can end the whole
                // transaction inside SQLite; reflect that state so the
                // host sees the transaction as closed.
                if (!self.db.inTransaction()) self.live_transaction = false;
                return err;
            };
        }
        const rowid_after = self.db.lastInsertRowId();
        out_returning.* = capture.returning;
        return .{
            .changes = self.totalChanges() - changes_before,
            .last_insert_rowid = if (rowid_after != rowid_before)
                rowid_after
            else
                null,
        };
    }

    /// Host-managed savepoint operations. Names are SDK-generated ordinal
    /// identifiers executed under internal scope, so arbitrary application
    /// transaction-control SQL stays denied.
    pub fn liveSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("savepoint zx_sp_{d}", index);
    }

    pub fn liveReleaseSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("release zx_sp_{d}", index);
    }

    pub fn liveRollbackToSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("rollback to zx_sp_{d}", index);
    }

    fn liveSavepointControl(
        self: *Node,
        comptime format: []const u8,
        index: u32,
    ) !void {
        if (!self.live_transaction) return error.NoTransaction;
        if (self.fatal_storage_error) return error.StorageFailed;
        var buffer: [48]u8 = undefined;
        const sql = std.mem.printSentinel(&buffer, format, .{index}, 0) catch
            unreachable;
        self.db.exec(sql) catch |err| {
            self.saveErrorFrom(&self.db);
            return err;
        };
    }

    /// Commits the live transaction: verifies the capture contract, seals
    /// the batch marker, commits SQLite, and acknowledges only when the
    /// captured transition is decided and applied. The returned change
    /// count follows SQLite's total-changes semantics: work undone by a
    /// savepoint rollback still counts; per-statement counts from
    /// `liveExec` are the precise ones.
    pub fn commitLive(self: *Node) !ExecResult {
        if (!self.live_transaction) return error.NoTransaction;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.log.stop_pending or self.log.isReconfigured() != null) {
            return error.LogSealed;
        }
        const changes = self.totalChanges() - self.live_changes_base;
        self.live_transaction = false;
        errdefer self.db.exec("rollback") catch {};
        guard_mod.verifyCaptureContract(
            &self.db,
            self.page_size,
            &self.committed_frames,
        ) catch |err| {
            self.saveErrorText("application SQL broke the capture contract");
            return err;
        };
        return self.sealCapturedTransaction(
            self.live_batch_id_bytes,
            changes,
            null,
        );
    }

    /// Rolls the live transaction back; nothing is replicated. A rollback
    /// failure marks the image for resync so the connection cannot reuse
    /// an unknown writer state.
    pub fn rollbackLive(self: *Node) !void {
        if (!self.live_transaction) return error.NoTransaction;
        self.live_transaction = false;
        self.db.exec("rollback") catch |err| {
            self.saveErrorFrom(&self.db);
            self.needs_resync = true;
            return err;
        };
    }

    /// True while a Gate C live transaction is open on this node.
    pub fn inLiveTransaction(self: *const Node) bool {
        return self.live_transaction;
    }

    /// Executes prepared statements like `prepared.execute`, additionally
    /// collecting typed rows from the last row-producing statement (a DML
    /// `RETURNING` clause in the single-statement caller).
    fn executePreparedCapture(
        self: *Node,
        statements: []const prepared.Statement,
        capture: *WriteCapture,
    ) !void {
        for (statements) |statement| {
            var stmt = try self.db.prepare(statement.sql);
            defer stmt.finalize();
            try prepared.bind(&stmt, statement.values);
            const column_count = stmt.columnCount();
            if (column_count == 0) {
                while (try stmt.step()) {}
                continue;
            }
            if (capture.returning) |*previous| previous.deinit();
            capture.returning = null;
            var arena = std.heap.ArenaAllocator.init(capture.gpa);
            errdefer arena.deinit();
            const alloc = arena.allocator();
            const columns = try alloc.alloc([]const u8, column_count);
            for (columns, 0..) |*column, index| {
                column.* = try alloc.dupe(u8, stmt.columnName(@intCast(index)));
            }
            var rows: std.ArrayList([]const prepared.Value) = .empty;
            while (try stmt.step()) {
                const row = try alloc.alloc(prepared.Value, column_count);
                for (row, 0..) |*cell, index| {
                    const column: u32 = @intCast(index);
                    cell.* = switch (stmt.columnValueType(column)) {
                        .null => .null_value,
                        .integer => .{ .integer = stmt.columnInt64(column) },
                        .real => .{ .real = stmt.columnDouble(column) },
                        .text => .{
                            .text = try alloc.dupe(u8, stmt.columnText(column)),
                        },
                        .blob => .{
                            .blob = try alloc.dupe(u8, stmt.columnBlob(column)),
                        },
                    };
                }
                try rows.append(alloc, row);
            }
            capture.returning = .{
                .arena = arena,
                .columns = columns,
                .rows = try rows.toOwnedSlice(alloc),
            };
        }
    }

    /// What one checked statement actually did: its total-changes delta,
    /// the result rows it produced, and whether a scalar expectation
    /// matched the first row.
    const CheckedObservation = struct {
        changes: i64,
        rows: u64,
        scalar_ok: bool,
    };

    /// Executes checked statements in order inside the open write
    /// transaction, verifying each expectation before the next statement
    /// runs. The caller's `errdefer rollback` fires before any capture or
    /// Paxos work, so a failure replicates nothing.
    fn executeCheckedStatements(
        self: *Node,
        statements: []const prepared.CheckedStatement,
        out_failure: *?CheckedFailure,
    ) !void {
        for (statements, 0..) |statement, index| {
            const observation = try self.runCheckedStatement(statement);
            if (expectationHolds(statement.expectation, observation)) continue;
            out_failure.* = .{
                .statement_index = @intCast(index),
                .observed_changes = observation.changes,
                .observed_rows = observation.rows,
            };
            self.saveErrorText("checked transaction expectation failed");
            return error.ExpectationFailed;
        }
    }

    /// Runs one checked statement, counting rows and the change delta. A
    /// scalar expectation is compared against the first row while its
    /// column bytes are still live on the statement.
    fn runCheckedStatement(
        self: *Node,
        statement: prepared.CheckedStatement,
    ) !CheckedObservation {
        const changes_before = self.totalChanges();
        var stmt = try self.db.prepare(statement.sql);
        defer stmt.finalize();
        try prepared.bind(&stmt, statement.values);
        var observation = CheckedObservation{
            .changes = 0,
            .rows = 0,
            .scalar_ok = false,
        };
        while (try stmt.step()) {
            if (observation.rows == 0) {
                observation.scalar_ok = switch (statement.expectation) {
                    .scalar_equals => |expected| stmt.columnCount() == 1 and
                        scalarMatches(&stmt, expected),
                    else => false,
                };
            }
            observation.rows += 1;
        }
        observation.changes = self.totalChanges() - changes_before;
        return observation;
    }

    /// Typed equality between the first column of the current row and an
    /// expected scalar. Strict on storage class: integer 1 does not equal
    /// real 1.0. Expected text/blob bytes are already bounded by
    /// `prepared.scalar_bytes_max`, so an oversized observed cell simply
    /// fails the length comparison.
    fn scalarMatches(stmt: *sqlite.Stmt, expected: prepared.Value) bool {
        return switch (expected) {
            .null_value => stmt.columnValueType(0) == .null,
            .integer => |number| stmt.columnValueType(0) == .integer and
                stmt.columnInt64(0) == number,
            .real => |number| stmt.columnValueType(0) == .real and
                stmt.columnDouble(0) == number,
            .text => |bytes| stmt.columnValueType(0) == .text and
                std.mem.eql(u8, stmt.columnText(0), bytes),
            .blob => |bytes| stmt.columnValueType(0) == .blob and
                std.mem.eql(u8, stmt.columnBlob(0), bytes),
        };
    }

    fn expectationHolds(
        expectation: prepared.Expectation,
        observation: CheckedObservation,
    ) bool {
        return switch (expectation) {
            .any => true,
            .changes_exactly => |expected| observation.changes >= 0 and
                @as(u64, @intCast(observation.changes)) == expected,
            .rows_exactly => |expected| observation.rows == expected,
            .scalar_equals => observation.rows == 1 and observation.scalar_ok,
        };
    }

    /// The result of the most recent append made through this node. Hosts
    /// use it to await commitment of compound operations (session open)
    /// whose public API does not surface the slot.
    pub fn lastAppend(self: *const Node) ExecResult {
        return self.last_append;
    }

    fn totalChanges(self: *Node) i64 {
        return self.db.totalChanges64();
    }

    /// The newest replicated search-feature version this binary serves
    /// (ZDS 0009). Version 1: FTS5, statically linked sqlite-vec, and the
    /// Zig fusion and distance SQL functions.
    pub const supported_search_feature_version: i64 = 1;

    /// Refuses to serve an image whose recorded search-feature version is
    /// newer than this binary implements. An image without the key
    /// predates the feature and serves normally; a directory without an
    /// image (witness, fresh member) has nothing to gate.
    fn verifySearchFeatureVersion(self: *Node) !void {
        if (!(self.schemaReady() catch false)) return;
        const stored = self.metaInt("search_feature_version") catch |err|
            switch (err) {
                error.MetaMissing => 0,
                else => return err,
            };
        self.search_feature_version = stored;
        if (stored > supported_search_feature_version) {
            self.saveErrorText(
                "image search-feature version is newer than this binary",
            );
            return error.SearchFeatureTooNew;
        }
    }

    /// Records search-feature version 1 in an image that predates it, as
    /// one replicated internal-scope write. Idempotent; an operator runs
    /// this only after every member serves a compatible binary (ZDS 0009
    /// rolling-upgrade rule). New databases record it at bootstrap.
    pub fn enableSearchFeature(self: *Node) !ExecResult {
        const result = try self.writeTransaction(
            .internal,
            "insert into __zaxon_meta(key, value) " ++
                "values ('search_feature_version', '1') " ++
                "on conflict(key) do nothing",
            null,
        );
        self.search_feature_version = supported_search_feature_version;
        return result;
    }

    fn metaInt(self: *Node, key: []const u8) !i64 {
        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select value from __zaxon_meta where key = ?1",
        );
        defer stmt.finalize();
        try stmt.bindText(1, key);
        if (!try stmt.step()) return error.MetaMissing;
        return std.fmt.parseInt(i64, stmt.columnText(0), 10) catch error.MetaMissing;
    }

    fn saveErrorFrom(self: *Node, db: *const sqlite.Db) void {
        self.saveErrorText(db.errmsg());
        self.saved_error_code = db.extendedErrcode();
    }

    fn saveErrorText(self: *Node, message: []const u8) void {
        self.saved_error_len = @min(message.len, self.saved_error.len);
        @memcpy(
            self.saved_error[0..self.saved_error_len],
            message[0..self.saved_error_len],
        );
        self.saved_error_code = 0;
    }

    /// SQLite extended result code of the most recent saved SQL error, or
    /// the live connection's when nothing is saved. Hosts derive stable
    /// error categories from it instead of parsing message text.
    pub fn lastSqliteExtendedCode(self: *const Node) i32 {
        if (self.saved_error_len > 0) return self.saved_error_code;
        if (self.db_open) return self.db.extendedErrcode();
        return 0;
    }

    // ------------------------------------------------------------------
    // Read lease: the live connection, or a short-lived one
    // ------------------------------------------------------------------

    const ReadLease = struct {
        node: *Node,
        db: sqlite.Db,
        owned: bool,

        fn release(self: *ReadLease) void {
            if (self.owned) self.db.close();
            self.* = undefined;
        }
    };

    fn readLease(self: *Node) !ReadLease {
        if (self.db_open) {
            return .{ .node = self, .db = self.db, .owned = false };
        }
        self.dir.access(self.io, db_file_name, .{}) catch {
            return error.NoDatabaseImage;
        };
        const db = try sqlite.Db.openWithOptions(
            self.db_path,
            .{ .mmap_size = self.mmap_size },
        );
        self.effective_mmap_size = db.effective_mmap_size;
        return .{ .node = self, .db = db, .owned = true };
    }

    // ------------------------------------------------------------------
    // Effect handling
    // ------------------------------------------------------------------

    /// Applies one batch of protocol effects: journal writes, fsync,
    /// confirm, deliver self-addressed messages, queue peer messages, and
    /// account committed entries.
    fn consumeEffects(self: *Node) !void {
        while (true) {
            const writes = self.effects.writesSlice();
            if (writes.len > 0) {
                // Every record is appended: the journal is the recovery
                // authority under ZDS 0011, so commit markers must reach
                // it. A commit-only batch is derived from durable quorum
                // evidence and skips only the barrier, riding the next
                // synced batch instead.
                self.journal.appendWrites(writes) catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
                const requires_barrier = self.effects.requiresPowerLossBarrier();
                if (requires_barrier) {
                    failpoint.hit("after_accept_append");

                    // Phase-two requests do not claim the leader's local vote
                    // is durable. Queue and release only those requests now so
                    // follower barriers overlap this node's barrier. The host
                    // mutex prevents a reply from entering the core early.
                    var early = self.effects.preDurableMessages();
                    var queued_early = false;
                    while (early.next()) |envelope| {
                        std.debug.assert(envelope.to != self.identity.node_id);
                        try self.outbox.append(self.gpa, envelope);
                        queued_early = true;
                    }
                    if (queued_early) {
                        if (self.pre_durable_outbox_hook) |hook| {
                            hook.run(hook.context) catch |err| {
                                // The request may already have reached a peer.
                                // Make the local vote durable before returning
                                // the transport failure to the host.
                                self.delayStorage();
                                self.journal.sync() catch |sync_err| {
                                    self.fatal_storage_error = true;
                                    return sync_err;
                                };
                                self.effects.confirmWritesDurable();
                                return err;
                            };
                        }
                    }
                    self.delayStorage();
                    self.journal.sync() catch |err| {
                        self.fatal_storage_error = true;
                        return err;
                    };
                    failpoint.hit("after_accept_sync");
                }
            }
            self.effects.confirmWritesDurable();
            if (self.effects.committedSlice().len > 0) {
                // Legacy failpoint name retained for crash-matrix stability.
                // Commit-only markers are now derived and need no second sync;
                // this boundary means chosen-before-materialized-apply.
                failpoint.hit("after_commit_sync_before_apply");
            }

            var pending: usize = 0;
            for (self.effects.messagesSlice()) |envelope| {
                // Already queued above when this transition had writes.
                if (self.effects.requiresPowerLossBarrier()) switch (envelope.message) {
                    .accept => continue,
                    else => {},
                };
                if (envelope.to == self.identity.node_id) {
                    self.inbox[pending] = envelope;
                    pending += 1;
                } else {
                    try self.outbox.append(self.gpa, envelope);
                }
            }
            const writes_before_accounting = self.effects.writes_count;
            self.accountCommitted(self.effects.committedSlice()) catch |err| {
                self.fatal_storage_error = true;
                return err;
            };
            // Accounting can adopt a chosen trim, which appends its own
            // durable marker; journal the tail before the reset below
            // would discard it. Derived records ride the next barrier.
            if (self.effects.writes_count > writes_before_accounting) {
                const tail = self.effects
                    .writes[writes_before_accounting..self.effects.writes_count];
                self.journal.appendWrites(tail) catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
                // Derived records (trim anchors) ride the next barrier.
                self.effects.confirmWritesDurable();
            }
            // Everything accounted is journal-durable and consumed, so its
            // consensus cells may be reused (ZDS 0011 memory floor).
            self.journal.noteChosen(self.log.decidedThrough());
            const floor = @min(
                self.journal.persistedThrough(),
                self.log.decidedThrough(),
            );
            try self.log.core.advanceMemoryFloor(floor);
            try self.serveJournalRanges();
            self.effects.reset();
            if (pending == 0) return;
            for (self.inbox[0..pending]) |envelope| {
                try self.log.step(envelope, self.effects);
            }
        }
    }

    /// Serves catch-up history the core released below its memory floor:
    /// the journal streams retained commits back as ordinary envelopes.
    fn serveJournalRanges(self: *Node) !void {
        for (self.effects.requestsSlice()) |request| {
            const range = request.serve_range;
            const Sink = struct {
                node: *Node,
                peer: paxos.NodeId,
                fn emit(context: @This(), slot: paxos.Slot, entry: types.Entry) !void {
                    try context.node.outbox.append(context.node.gpa, .{
                        .from = context.node.identity.node_id,
                        .to = context.peer,
                        .message = .{ .commit = .{
                            .slot = slot,
                            .value = entry,
                        } },
                    });
                }
            };
            try self.journal.serveRange(
                range.first,
                range.count,
                Sink{ .node = self, .peer = range.peer },
                Sink.emit,
            );
        }
    }

    /// Effect handling during recovery, before chain state is rebuilt:
    /// committed entries are not accounted (rebuild does that from the log).
    fn consumeEffectsRecovery(self: *Node) !void {
        while (true) {
            const writes = self.effects.writesSlice();
            if (writes.len > 0) {
                self.journal.appendWrites(writes) catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
                self.delayStorage();
                self.journal.sync() catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
            }
            self.effects.confirmWritesDurable();
            var pending: usize = 0;
            for (self.effects.messagesSlice()) |envelope| {
                if (envelope.to == self.identity.node_id) {
                    self.inbox[pending] = envelope;
                    pending += 1;
                } else {
                    try self.outbox.append(self.gpa, envelope);
                }
            }
            self.effects.reset();
            if (pending == 0) return;
            for (self.inbox[0..pending]) |envelope| {
                try self.log.step(envelope, self.effects);
            }
        }
    }

    fn accountCommitted(self: *Node, committed: []const Log.Committed) !void {
        for (committed) |entry| {
            switch (entry.value) {
                .command => |cmd| switch (cmd) {
                    .noop, .read_barrier => {
                        if (self.capture_batch_id != null) {
                            // Our captured write lost its slot; the live
                            // WAL contains frames the log never decided.
                            self.capture_batch_id = null;
                            self.needs_resync = true;
                        }
                    },
                    .trim => |record| {
                        if (self.capture_batch_id != null) {
                            self.capture_batch_id = null;
                            self.needs_resync = true;
                        }
                        try self.adoptChosenTrim(entry.slot, record);
                    },
                    .transfer_lease => |lease| {
                        if (self.capture_batch_id != null) {
                            self.capture_batch_id = null;
                            self.needs_resync = true;
                        }
                        try self.trackLease(lease);
                    },
                    .lease_complete => |complete| {
                        if (self.capture_batch_id != null) {
                            self.capture_batch_id = null;
                            self.needs_resync = true;
                        }
                        try self.releaseLease(complete.lease_id);
                    },
                    .transaction_batch => |batch| {
                        try self.checkChainBase(entry.slot, batch);
                        if (self.capture_batch_id) |pending| {
                            self.capture_batch_id = null;
                            if (pending != batch.batch_id) {
                                self.needs_resync = true;
                            }
                            // A matching batch is already materialized in
                            // the live WAL of the capture connection.
                        } else if (self.db_open) {
                            // A decision this live connection never
                            // captured: the image is stale.
                            self.needs_resync = true;
                        } else {
                            failpoint.hit("before_apply");
                            try self.applyBatchOffline(batch);
                        }
                        self.last_chain = batch.result_chain_hash;
                        self.last_data_slot = entry.slot;
                        self.last_batch_id = batch.batch_id;
                        self.recent_batches[
                            @intCast(entry.slot % self.recent_batches.len)
                        ] = .{ .slot = entry.slot, .batch_id = batch.batch_id };
                    },
                },
                .stop => |stop| {
                    if (self.capture_batch_id != null) {
                        self.capture_batch_id = null;
                        self.needs_resync = true;
                    }
                    // A stop at or below the running configuration is
                    // replayed history, not a pending handover.
                    if (stop.configuration_id > self.identity.configuration_id) {
                        self.membership_change_pending = true;
                    }
                },
            }
            // Every chosen entry advances the global history anchor,
            // including noops, stops, and retention records (ZDS 0011).
            self.history_hash = history.advance(
                self.history_hash,
                self.identity.database_id,
                self.identity.configuration_id,
                entry.slot,
                entry.value,
            );
            self.recent_history[@intCast(entry.slot % self.recent_history.len)] =
                .{ .slot = entry.slot, .hash = self.history_hash };
            self.applied_slot = entry.slot;
        }
    }

    /// Verifies that a decided batch extends the chain this node has
    /// applied. A mismatch is fatal and never repaired silently; the log
    /// line names the failing check so an operator can tell a stale base
    /// (ordering) from a foreign database or a corrupt descriptor.
    fn checkChainBase(
        self: *const Node,
        slot: paxos.Slot,
        batch: command.TransactionBatch,
    ) error{ChainMismatch}!void {
        const database_ok = batch.database_id == self.identity.database_id;
        const chain_ok = std.mem.eql(u8, &batch.base_chain_hash, &self.last_chain);
        const base_slot_ok = batch.base_data_slot == self.last_data_slot;
        const self_ok = command.chainValid(batch);
        if (database_ok and chain_ok and base_slot_ok and self_ok) return;
        std.log.err(
            "chain mismatch at slot {d}: batch {x:0>32} base slot {d} " ++
                "(applied {d}) base chain {x}.. (applied {x}..) " ++
                "database match {} descriptor self-check {}; hint: keep this " ++
                "data directory and line for the report, replace only this " ++
                "member by state transfer if its peers serve, and restore " ++
                "from backup if every member reports the same slot",
            .{
                slot,
                batch.batch_id,
                batch.base_data_slot,
                self.last_data_slot,
                batch.base_chain_hash[0..8],
                self.last_chain[0..8],
                database_ok,
                self_ok,
            },
        );
        return error.ChainMismatch;
    }

    fn delayStorage(self: *Node) void {
        if (self.test_storage_delay_ms == 0) return;
        self.io.sleep(
            .fromMilliseconds(@intCast(self.test_storage_delay_ms)),
            .awake,
        ) catch {};
    }

    /// True when the host must run `resyncImage` before further service.
    pub fn needsResync(self: *const Node) bool {
        return self.needs_resync;
    }

    pub fn storageFailed(self: *const Node) bool {
        return self.fatal_storage_error;
    }

    /// Irreversibly disables the local protocol participant after a host
    /// invariant or durability failure. Recovery requires a fresh Node.
    pub fn markFailed(self: *Node) void {
        self.fatal_storage_error = true;
    }

    /// Applies one committed payload offline to the materialized image.
    fn applyBatchOffline(self: *Node, batch: command.TransactionBatch) !void {
        const payload = self.store.load(self.gpa, batch.payload_hash) catch {
            return error.PayloadMissing;
        };
        defer self.gpa.free(payload);
        const view = try self.validateBatchPayload(batch, payload);
        // Stale working artifacts from a previous read connection.
        self.dir.deleteFile(self.io, wal_file_name) catch {};
        self.dir.deleteFile(self.io, shm_file_name) catch {};
        const file = try self.dir.createFile(self.io, db_file_name, .{
            .read = true,
            .truncate = false,
        });
        defer file.close(self.io);
        try wal.applyPayload(self.io, file, &view);
        // `current.db` is a materialized cache, rebuilt from the durable
        // anchor, accepted journal records, and payload store on every open. The page
        // writes need to finish before local reads, but do not require a
        // second power-loss barrier per chosen transaction.
    }

    /// Cross-checks the fixed Paxos descriptor against the immutable payload.
    /// A valid content hash alone is not enough: descriptor counts, database
    /// identity, and page geometry are part of the replicated transition.
    fn validateBatchPayload(
        self: *Node,
        batch: command.TransactionBatch,
        payload: []const u8,
    ) !wal.PayloadView {
        if (batch.database_id != self.identity.database_id) {
            return error.DatabaseMismatch;
        }
        if (payload.len != batch.payload_bytes) return error.PayloadCorrupt;
        const view = try wal.PayloadView.parse(payload);
        if (view.database_id != batch.database_id) return error.DatabaseMismatch;
        if (view.transaction_count != batch.transaction_count or
            view.frame_count != batch.frame_count or
            view.page_size != self.page_size)
        {
            return error.PayloadDescriptorMismatch;
        }
        return view;
    }

    // ------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------

    /// Refuses to open over any journal v1 artifact: the ZDS 0011 format
    /// cut has no bridge, and guessing would risk both histories.
    fn rejectLegacyArtifacts(io: Io, dir: Io.Dir) !void {
        if (dir.access(io, current_file_name, .{})) |_| {
            return error.UnsupportedLegacyFormat;
        } else |_| {}
        var name_buffer: [26]u8 = undefined;
        const legacy = std.fmt.bufPrint(
            &name_buffer,
            "paxos-{x:0>16}.log",
            .{@as(u64, 1)},
        ) catch unreachable;
        if (dir.access(io, legacy, .{})) |_| {
            return error.UnsupportedLegacyFormat;
        } else |_| {}
    }

    /// Materializes `current.db` from the durable APPLIED anchor plus the
    /// retained journal suffix (ZDS 0011 recovery ladder, steps 1 and 3).
    /// Startup cost follows the anchor cadence, never the log lifetime.
    fn materializeFromJournal(self: *Node) !void {
        std.debug.assert(!self.db_open);
        // SQLite's own WAL is a working artifact, never authoritative.
        self.dir.deleteFile(self.io, wal_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.dir.deleteFile(self.io, shm_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };

        var base: paxos.Slot = 0;
        var anchor_config = self.identity.configuration_id;
        if (applied_anchor.select(
            self.io,
            self.journal.dir,
            self.identity.database_id,
        )) |anchor| {
            if (try self.anchorMatchesImage(anchor)) {
                base = anchor.global_slot;
                self.anchor_generation = anchor.generation;
                anchor_config = anchor.configuration_id;
                self.history_hash = anchor.history_hash;
                self.history_hash_at_anchor = anchor.history_hash;
                self.last_chain = anchor.last_chain;
                self.last_data_slot = anchor.last_data_slot;
                self.durable_data_slot = anchor.last_data_slot;
                self.last_batch_id = anchor.last_batch_id;
                self.durable_state_slot = anchor.global_slot;
                self.page_size = anchor.sqlite_page_size;
            }
        }
        if (base == 0) {
            // No usable anchor: only a journal physically retained from
            // genesis can rebuild the image; anything else needs a state
            // transfer. A chosen trim alone does not destroy records.
            if (self.journal.retainedFirstSlot() > 1) {
                return error.StateUnavailable;
            }
            self.dir.deleteFile(self.io, db_file_name) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
            self.history_hash = history.genesis(self.identity.database_id);
            self.last_chain = command.genesisChain(self.identity.database_id);
            self.last_data_slot = 0;
            self.durable_state_slot = 0;
        }
        self.applied_slot = base;
        if (base > 0 and self.journal.retainedFirstSlot() > base + 1) {
            // The retained journal no longer reaches the anchor: the
            // newest anchor generation was lost and the fallback sits
            // below what reclamation already deleted. Serving the stale
            // image would silently skip the gap.
            return error.StateUnavailable;
        }

        const file = try self.dir.createFile(self.io, db_file_name, .{
            .read = true,
            .truncate = false,
        });
        defer file.close(self.io);

        // Entries fold into the history hash under the configuration
        // they were chosen in; a replayed stop advances the cursor the
        // same way the live handover does. A genesis rebuild starts at
        // the database's first configuration.
        var config_cursor: u64 = if (base == 0) 1 else anchor_config;

        // Commit records sit in arrival order in the journal, but the
        // reorder distance is bounded by the consensus window (the core
        // only journals in-window commits), so one streaming pass with a
        // window-sized park ring applies the whole contiguous suffix.
        const window = types.log_options.window_slots;
        const Parked = struct { slot: paxos.Slot = 0, value: types.Entry = undefined };
        const parked = try self.gpa.alloc(Parked, window);
        defer self.gpa.free(parked);
        @memset(parked, .{});

        var it = try self.journal.iterate(self.applied_slot + 1);
        defer it.close();
        while (try it.next()) |write| {
            const commit = switch (write) {
                .commit => |commit| commit,
                else => continue,
            };
            if (commit.slot <= self.applied_slot) continue;
            if (commit.slot == self.applied_slot + 1) {
                try self.applyReplayCommit(file, commit.slot, commit.value, &config_cursor);
                while (true) {
                    const cell = &parked[@intCast((self.applied_slot + 1) % window)];
                    if (cell.slot != self.applied_slot + 1) break;
                    const value = cell.value;
                    cell.slot = 0;
                    try self.applyReplayCommit(file, self.applied_slot + 1, value, &config_cursor);
                }
            } else if (commit.slot - self.applied_slot <= window) {
                parked[@intCast(commit.slot % window)] =
                    .{ .slot = commit.slot, .value = commit.value };
            }
        }
        try durability.syncFile(self.io, file);
    }

    /// Applies one replayed commit and advances the configuration cursor
    /// across stop entries: the stop itself is hashed under the outgoing
    /// configuration, everything after it under the incoming one, byte
    /// for byte the ordering the live handover produces.
    fn applyReplayCommit(
        self: *Node,
        file: Io.File,
        slot: paxos.Slot,
        value: types.Entry,
        config_cursor: *u64,
    ) !void {
        try self.applyEntryToImage(file, slot, value, config_cursor.*);
        switch (value) {
            .stop => |stop| if (stop.configuration_id > config_cursor.*) {
                config_cursor.* = stop.configuration_id;
            },
            else => {},
        }
        self.applied_slot = slot;
    }

    /// Discards the local image and its anchors, then re-materializes
    /// from the genesis-retained journal. Only legal while nothing has
    /// been trimmed; the durable frontier restarts at zero and re-anchors
    /// on the next cadence.
    fn discardImageAndRematerialize(self: *Node) !void {
        if (self.journal.retainedFirstSlot() > 1) {
            return error.StateUnavailable;
        }
        self.dir.deleteFile(self.io, db_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.journal.dir.deleteFile(self.io, "APPLIED.0") catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.journal.dir.deleteFile(self.io, "APPLIED.1") catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.durable_state_slot = 0;
        self.durable_data_slot = 0;
        try self.materializeFromJournal();
    }

    /// Whether a selected anchor matches the on-disk image geometry; a
    /// mismatch means the image was lost or replaced and the anchor is
    /// not a recovery base.
    fn anchorMatchesImage(self: *Node, anchor: applied_anchor.Anchor) !bool {
        const file = self.dir.openFile(self.io, db_file_name, .{}) catch |err|
            switch (err) {
                error.FileNotFound => return false,
                else => return err,
            };
        defer file.close(self.io);
        // Offline applies legitimately grow the image past the anchor;
        // replaying the suffix over them is idempotent. Only an image
        // smaller than the anchored base is unusable.
        const length = try file.length(self.io);
        return length >=
            @as(u64, anchor.sqlite_page_count) * anchor.sqlite_page_size;
    }

    /// Applies one chosen entry to the materialized image and advances
    /// the chain cursors and the global history anchor.
    fn applyEntryToImage(
        self: *Node,
        file: Io.File,
        slot: paxos.Slot,
        entry: types.Entry,
        configuration_id: u64,
    ) !void {
        switch (entry) {
            .command => |cmd| switch (cmd) {
                // Retention records change no page; membership stops are
                // finished by the pending-handover path after open.
                .noop, .read_barrier, .trim, .transfer_lease, .lease_complete => {},
                .transaction_batch => |batch| {
                    try self.checkChainBase(slot, batch);
                    const payload = self.store.load(self.gpa, batch.payload_hash) catch {
                        // A committed descriptor without payload bytes:
                        // this node must not serve.
                        return error.PayloadMissing;
                    };
                    defer self.gpa.free(payload);
                    const view = try self.validateBatchPayload(batch, payload);
                    try wal.applyPayload(self.io, file, &view);
                    self.last_chain = batch.result_chain_hash;
                    self.last_data_slot = slot;
                    self.last_batch_id = batch.batch_id;
                },
            },
            .stop => |stop| {
                if (stop.configuration_id > self.identity.configuration_id) {
                    self.membership_change_pending = true;
                }
            },
        }
        self.history_hash = history.advance(
            self.history_hash,
            self.identity.database_id,
            configuration_id,
            slot,
            entry,
        );
        self.recent_history[@intCast(slot % self.recent_history.len)] =
            .{ .slot = slot, .hash = self.history_hash };
    }

    fn openLiveDatabase(self: *Node) !void {
        self.db = try sqlite.Db.openWithOptions(
            self.db_path,
            .{ .mmap_size = self.mmap_size },
        );
        self.effective_mmap_size = self.db.effective_mmap_size;
        errdefer self.db.close();
        try self.db.exec("pragma page_size = 4096");
        try self.db.exec("pragma journal_mode = wal");
        try self.db.exec("pragma wal_autocheckpoint = 0");
        try self.db.exec("pragma synchronous = normal");
        try self.db.exec("pragma foreign_keys = on");
        self.committed_frames = 0;
        self.captured_frames = 0;
        self.db.trackCommittedFrames(&self.committed_frames);
        self.page_size = try self.db.pageSize();
        // The guard outlives the connection: it is embedded in this Node,
        // and every application statement below runs through it.
        self.guard.scope = .internal;
        self.guard.install(&self.db);
        self.db_open = true;
    }

    fn bootstrapSchema(self: *Node) !void {
        _ = try self.bootstrapSchemaIfMissing();
    }

    /// Replicates the schema bootstrap batch when it is absent. Runs in
    /// internal scope: bootstrap creates the reserved `__zaxon_*` tables
    /// that the application authorizer denies. An already present schema
    /// returns a replayed result, so a raced bootstrap is harmless.
    pub fn bootstrapSchemaIfMissing(self: *Node) !ExecResult {
        if (try self.schemaReady()) {
            return .{ .changes = 0, .slot = 0, .replayed = true };
        }
        const sql = try self.bootstrapSql(self.gpa);
        defer self.gpa.free(sql);
        return self.writeTransaction(.internal, sql, null);
    }

    /// After rebuild, the materialized image's recorded batch marker must
    /// match the last committed transaction batch in the retained journal.
    fn validateMaterializedBatch(self: *Node) !void {
        if (self.last_data_slot == 0) return;
        var batch_id_bytes: [16]u8 = undefined;
        std.mem.writeInt(u128, &batch_id_bytes, self.last_batch_id, .little);
        const expected = std.fmt.bytesToHex(batch_id_bytes, .lower);

        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select value from __zaxon_meta where key = 'batch_id'",
        );
        defer stmt.finalize();
        if (!try stmt.step()) return error.StateMismatch;
        if (!std.mem.eql(u8, stmt.columnText(0), &expected)) {
            return error.StateMismatch;
        }
    }

    /// Reconstructs and verifies the decided next registry named by stop
    /// metadata. Deterministic: a same-member rollover is the checkpoint
    /// successor, a replacement applies the metadata seed, and a lagging
    /// member first fast-forwards through unchanged-member epochs. The
    /// digest bound into the chosen stop sign is the only acceptance test.
    fn reconstructNextRegistry(
        decided: *const registry.Decided,
        parsed: *const registry.StopMetadata,
        next_configuration: u64,
    ) !registry.Decided {
        const expected_digest = parsed.registry_digest;
        var base = decided.*;
        if (base.configuration_id == next_configuration) {
            // The pointer already advanced in a previous crashed rollover.
            if (!std.mem.eql(u8, &base.digest(), &expected_digest)) {
                return error.RegistryDigestMismatch;
            }
            return base;
        }
        const sealed = next_configuration - 1;
        if (base.configuration_id < sealed) {
            base.predecessor_configuration_id = sealed - 1;
            base.configuration_id = sealed;
        }
        const next = blk: {
            if (parsed.seed) |*seed| {
                const request = registry.ReplacementRequest{
                    .operation_id = seed.operation_id,
                    .expected_configuration_id = base.configuration_id,
                    .old_node_id = seed.old_node_id,
                    .new_node_id = seed.new_node_id,
                    .new_endpoint = seed.endpointSlice(),
                };
                break :blk base.successor(&request) catch
                    return error.RegistryDigestMismatch;
            }
            break :blk base.checkpointSuccessor() catch
                return error.RegistryDigestMismatch;
        };
        if (next.configuration_id != next_configuration) {
            return error.RegistryDigestMismatch;
        }
        if (!std.mem.eql(u8, &next.digest(), &expected_digest)) {
            return error.RegistryDigestMismatch;
        }
        return next;
    }

    /// Reads the persisted registry blob for one configuration from the
    /// data directory, bounded by the registry encoding limit.
    pub fn readRegistryBlob(
        self: *Node,
        gpa: std.mem.Allocator,
        configuration_id: u64,
    ) ![]u8 {
        var path_buffer: [32]u8 = undefined;
        const path = registry.blobPath(&path_buffer, configuration_id);
        return self.dir.readFileAlloc(
            self.io,
            path,
            gpa,
            .limited(registry.max_encoded_bytes + 32),
        );
    }
};

// ----------------------------------------------------------------------
// Identity file
// ----------------------------------------------------------------------

/// The one-shot descriptor `zaxon enroll` writes for a joining
/// replacement: the decided database identity and the registry digest the
/// node fetches and verifies before it can participate.
pub const JoinDescriptor = struct {
    database_id: u128,
    configuration_id: u64,
    registry_digest: [32]u8,
};

fn readJoinDescriptor(
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
) !?JoinDescriptor {
    const bytes = dir.readFileAlloc(io, join_file_name, gpa, .limited(512)) catch |err|
        switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
    defer gpa.free(bytes);
    const format = manifestValue(bytes, "format") orelse
        return error.CorruptJoinDescriptor;
    if (!std.mem.eql(u8, format, "1")) return error.CorruptJoinDescriptor;
    const database_text = manifestValue(bytes, "database_id") orelse
        return error.CorruptJoinDescriptor;
    const configuration_text = manifestValue(bytes, "configuration_id") orelse
        return error.CorruptJoinDescriptor;
    const digest_text = manifestValue(bytes, "registry_digest") orelse
        return error.CorruptJoinDescriptor;
    if (digest_text.len != 64) return error.CorruptJoinDescriptor;
    var descriptor = JoinDescriptor{
        .database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptJoinDescriptor,
        .configuration_id = std.fmt.parseInt(u64, configuration_text, 10) catch
            return error.CorruptJoinDescriptor,
        .registry_digest = undefined,
    };
    _ = std.fmt.hexToBytes(&descriptor.registry_digest, digest_text) catch
        return error.CorruptJoinDescriptor;
    return descriptor;
}

/// Writes the join descriptor into a (possibly not yet created) data
/// directory. Called by `zaxon enroll` before the node's first start.
pub fn writeJoinDescriptor(
    io: Io,
    directory: []const u8,
    descriptor: JoinDescriptor,
) !void {
    var dir = try Io.Dir.cwd().createDirPathOpen(io, directory, .{
        .permissions = @fromBackingInt(@intCast(0o700)),
        .open_options = .{ .iterate = true },
    });
    defer dir.close(io);
    var buffer: [256]u8 = undefined;
    const contents = std.fmt.bufPrint(
        &buffer,
        "format=1\ndatabase_id={x:0>32}\nconfiguration_id={d}\n" ++
            "registry_digest={s}\n",
        .{
            descriptor.database_id,
            descriptor.configuration_id,
            &std.fmt.bytesToHex(descriptor.registry_digest, .lower),
        },
    ) catch unreachable;
    try atomicWriteFile(io, dir, join_file_name, contents);
}

/// Resolves the flag-provided membership for `Node.open`. Proofs and the
/// registry encode voter sets in canonical ascending order, so flag order
/// must not matter.
fn canonicalFlagMembers(
    options: *const OpenOptions,
    capabilities: roles.Capabilities,
    storage: *[types.log_options.max_members]paxos.NodeId,
) ![]const paxos.NodeId {
    if (options.members.len == 0 and capabilities.votes) {
        storage[0] = options.node_id;
        return storage[0..1];
    }
    if (options.members.len == 0) return error.VotersRequired;
    if (options.members.len > types.log_options.max_members) {
        return error.TooManyMembers;
    }
    @memcpy(storage[0..options.members.len], options.members);
    std.mem.sort(
        paxos.NodeId,
        storage[0..options.members.len],
        {},
        std.sort.asc(paxos.NodeId),
    );
    return storage[0..options.members.len];
}

fn loadOrCreateIdentity(
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    node_id: paxos.NodeId,
    fixed_database_id: ?u128,
    requested_role: roles.Role,
) !Identity {
    const bytes = dir.readFileAlloc(io, identity_file_name, gpa, .limited(4096)) catch |err|
        switch (err) {
            error.FileNotFound => {
                const database_id = fixed_database_id orelse blk: {
                    var database_id_bytes: [16]u8 = undefined;
                    io.random(&database_id_bytes);
                    break :blk std.mem.readInt(u128, &database_id_bytes, .little);
                };
                const identity = Identity{
                    .node_id = node_id,
                    .database_id = database_id,
                    .configuration_id = 1,
                    .role = requested_role,
                };
                try writeIdentity(io, dir, identity);
                return identity;
            },
            else => return err,
        };
    defer gpa.free(bytes);

    const format = manifestValue(bytes, "format") orelse return error.CorruptIdentity;
    if (!std.mem.eql(u8, format, "3")) return error.UnsupportedIdentityVersion;
    const node_text = manifestValue(bytes, "node_id") orelse return error.CorruptIdentity;
    const database_text = manifestValue(bytes, "database_id") orelse return error.CorruptIdentity;
    const configuration_text = manifestValue(bytes, "configuration_id") orelse
        return error.CorruptIdentity;
    const role_text = manifestValue(bytes, "role") orelse
        return error.CorruptIdentity;
    const persisted_role = roles.Role.parse(role_text) catch
        return error.CorruptIdentity;

    const identity = Identity{
        .node_id = std.fmt.parseInt(paxos.NodeId, node_text, 10) catch
            return error.CorruptIdentity,
        .database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptIdentity,
        .configuration_id = std.fmt.parseInt(u64, configuration_text, 10) catch
            return error.CorruptIdentity,
        .role = persisted_role,
    };
    if (identity.node_id != node_id) return error.NodeIdMismatch;
    if (identity.role != requested_role) return error.NodeRoleMismatch;
    if (fixed_database_id) |fixed| {
        if (identity.database_id != fixed) return error.DatabaseMismatch;
    }
    return identity;
}

fn writeIdentity(io: Io, dir: Io.Dir, identity: Identity) !void {
    var buffer: [256]u8 = undefined;
    const contents = std.fmt.bufPrint(
        &buffer,
        \\format=3
        \\node_id={d}
        \\database_id={x:0>32}
        \\configuration_id={d}
        \\role={s}
        \\
    ,
        .{
            identity.node_id,
            identity.database_id,
            identity.configuration_id,
            identity.role.name(),
        },
    ) catch unreachable;
    try atomicWriteFile(io, dir, identity_file_name, contents);
}

/// Reads `key=value` lines from a small text file body.
pub fn manifestValue(bytes: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (std.mem.eql(u8, line[0..separator], key)) {
            return std.mem.trim(u8, line[separator + 1 ..], " \r");
        }
    }
    return null;
}

fn atomicWriteFile(io: Io, dir: Io.Dir, name: []const u8, contents: []const u8) !void {
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, contents, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, name);
}

test "identity format 2 is explicitly unsupported" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try atomicWriteFile(
        io,
        tmp.dir,
        identity_file_name,
        "format=2\nnode_id=1\ndatabase_id=00000000000000000000000000000001\n" ++
            "configuration_id=1\nrole=data-voter\n",
    );
    try std.testing.expectError(
        error.UnsupportedIdentityVersion,
        loadOrCreateIdentity(std.testing.allocator, io, tmp.dir, 1, 1, .data_voter),
    );
}

/// Makes removal durable on every supported platform. Renaming to a live
/// tombstone gives Windows a file handle it can flush for the namespace
/// transition. A leftover tombstone is harmless and is removed best-effort.
fn durableDeleteFile(io: Io, dir: Io.Dir, name: []const u8) !void {
    dir.deleteFile(io, deleted_file_tombstone) catch {};
    dir.rename(name, dir, deleted_file_tombstone, io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    try durability.syncPathnameTransition(io, dir, deleted_file_tombstone);
    dir.deleteFile(io, deleted_file_tombstone) catch return;
    try durability.syncDirectory(dir);
}

fn fileSha256(io: Io, dir: Io.Dir, name: []const u8) ![32]u8 {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const read = try file.readPositionalAll(io, &buffer, offset);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        offset += read;
        if (read < buffer.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const node_testing = std.testing;

test "an image with a newer search-feature version refuses to serve" {
    const gpa = node_testing.allocator;
    var tmp = node_testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(node_testing.io, &buffer);
    const dir = try std.fmt.allocPrint(gpa, "{s}/node", .{buffer[0..len]});
    defer gpa.free(dir);

    {
        const node = try Node.open(gpa, node_testing.io, .{ .directory = dir });
        defer node.close();
        // A fresh database records the supported version at bootstrap.
        try node_testing.expectEqual(
            Node.supported_search_feature_version,
            node.status().search_feature_version,
        );
        // Simulate a future binary having activated version 2 through the
        // replicated internal write path.
        _ = try node.writeTransaction(
            .internal,
            "update __zaxon_meta set value = '2' " ++
                "where key = 'search_feature_version'",
            null,
        );
    }
    // This binary must fail closed rather than serve the newer image.
    try node_testing.expectError(
        error.SearchFeatureTooNew,
        Node.open(gpa, node_testing.io, .{ .directory = dir }),
    );
}

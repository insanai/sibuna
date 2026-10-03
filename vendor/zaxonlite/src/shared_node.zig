//! Thread-safe facade over one embedded zaxonlite node.
//!
//! `Node` is deliberately not thread-safe: it shares the live writer
//! connection with its read leases and mutates capture state on every
//! call. `SharedNode` owns a node privately and layers three pieces on
//! top so many threads can use it concurrently:
//!
//!   * one serialized node executor for writes and node-delegated
//!     operations (status, backup, integrity check), admission-bounded by
//!     `write_queue_depth` and deadline-bounded by `write_deadline_ms`;
//!   * a lazily populated pool of READ-ONLY SQLite connections against
//!     the node's materialized image — every read or batch runs on a
//!     pooled connection inside its own deferred read transaction, so it
//!     observes exactly one WAL snapshot while writes commit concurrently;
//!   * a shared/exclusive maintenance gate — state-anchor publication
//!     (`createStateAnchor`), image resync, and `close` first drain and
//!     close every pooled
//!     reader (their descriptors go stale once the image file is
//!     rebuilt), then take the node exclusively; the pool reopens lazily
//!     afterwards.
//!
//! Blocking uses the repo's `std.Io` primitives. Deadline-bounded waits
//! sleep on a state-generation futex (`Io.Condition` has no timed wait):
//! every state transition bumps the generation and wakes all sleepers,
//! which then re-check their predicate and deadline under the mutex.

const std = @import("std");
const Io = std.Io;

const node_mod = @import("node.zig");
const sqlite = @import("sqlite.zig");
const guard_mod = @import("guard.zig");
const prepared = @import("prepared.zig");

const Node = node_mod.Node;

pub const read_connections_default: u32 = 4;
pub const read_connections_max: u32 = 64;
pub const write_queue_depth_default: u32 = 32;
pub const write_queue_depth_max: u32 = 1024;
pub const write_deadline_ms_default: u64 = 5000;
pub const read_deadline_ms_default: u64 = 2000;

/// Facade tuning. Every knob has a named default above; zero values and
/// values above the named maxima are rejected at `open`/`adopt`.
pub const Options = struct {
    read_connections: u32 = read_connections_default,
    write_queue_depth: u32 = write_queue_depth_default,
    write_deadline_ms: u64 = write_deadline_ms_default,
    read_deadline_ms: u64 = read_deadline_ms_default,
};

pub const SharedNode = struct {
    gpa: std.mem.Allocator,
    io: Io,
    inner: *Node,
    options: Options,
    mutex: Io.Mutex = .init,
    /// State-generation futex: bumped and woken on every facade state
    /// change so deadline-bounded waiters can sleep without a timed
    /// condition variable.
    state_gen: std.atomic.Value(u32) = .init(0),
    closed: bool = false,
    /// Threads currently inside any public method; `close` waits for
    /// this to drain before freeing the facade.
    entrants: u32 = 0,
    /// Node-executor admissions in flight (waiting plus executing).
    write_tickets: u32 = 0,
    /// True while one thread holds the serialized node executor.
    node_busy: bool = false,
    /// Pooled reads in flight (each holds one slot).
    readers_active: u32 = 0,
    exclusive_waiting: u32 = 0,
    exclusive_held: bool = false,
    /// Mirror of the node's resync flag, refreshed race-free after every
    /// node turn; reads and writes escalate to the exclusive gate when
    /// it is set, so the image rebuild never races pooled readers.
    resync_pending: bool = false,
    pool: []ReadSlot,

    const ReadSlot = struct {
        db: sqlite.Db = undefined,
        /// Per-connection authorizer; must outlive the connection, so it
        /// lives in the heap-allocated slot, not on a caller stack.
        guard: guard_mod.Guard = .{},
        open: bool = false,
        in_use: bool = false,
    };

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Opens a node and wraps it. Mirrors `Node.open`, then `adopt`.
    pub fn open(
        gpa: std.mem.Allocator,
        io: Io,
        node_options: node_mod.OpenOptions,
        options: Options,
    ) !*SharedNode {
        const inner = try Node.open(gpa, io, node_options);
        errdefer inner.close();
        return adopt(gpa, inner, options);
    }

    /// Wraps an already opened node — the host opens and migrates
    /// single-threaded first, then adopts. On success the facade owns the
    /// node and `close` closes it; on error ownership stays with the
    /// caller.
    pub fn adopt(
        gpa: std.mem.Allocator,
        owned_node: *Node,
        options: Options,
    ) !*SharedNode {
        if (options.read_connections == 0 or
            options.read_connections > read_connections_max)
        {
            return error.InvalidReadConnections;
        }
        if (options.write_queue_depth == 0 or
            options.write_queue_depth > write_queue_depth_max)
        {
            return error.InvalidWriteQueueDepth;
        }
        const self = try gpa.create(SharedNode);
        errdefer gpa.destroy(self);
        const pool = try gpa.alloc(ReadSlot, options.read_connections);
        for (pool) |*slot| slot.* = .{};
        self.* = .{
            .gpa = gpa,
            .io = owned_node.io,
            .inner = owned_node,
            .options = options,
            .pool = pool,
        };
        return self;
    }

    /// Closes the facade exactly once: new callers get
    /// `error.SharedNodeClosed`, in-flight calls finish, pooled readers
    /// close, then the node closes and the facade is freed. Calling any
    /// method after `close` returns is undefined behavior, exactly like
    /// using a closed `Node`.
    pub fn close(self: *SharedNode) void {
        self.mutex.lockUncancelable(self.io);
        if (self.closed) {
            self.mutex.unlock(self.io);
            return;
        }
        self.closed = true;
        self.bumpStateLocked();
        while (self.entrants != 0) self.waitStateChange(null);
        self.closePoolLocked();
        self.mutex.unlock(self.io);
        const gpa = self.gpa;
        self.inner.close();
        gpa.free(self.pool);
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------
    // Reads: pooled read-only connections, one snapshot per call
    // ------------------------------------------------------------------

    /// Runs a read-only query; the result owns its memory via an arena.
    pub fn query(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
    ) !node_mod.QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, &.{}, .{});
    }

    pub fn queryWithLimits(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        limits: node_mod.QueryLimits,
    ) !node_mod.QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, &.{}, limits);
    }

    pub fn queryPrepared(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !node_mod.QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, values, .{});
    }

    pub fn queryPreparedWithLimits(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: node_mod.QueryLimits,
    ) !node_mod.QueryResult {
        var typed = try self.queryPreparedTypedWithLimits(gpa, sql, values, limits);
        errdefer typed.deinit();
        return node_mod.textFromTyped(&typed);
    }

    pub fn queryPreparedTyped(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !node_mod.TypedResult {
        return self.queryPreparedTypedWithLimits(gpa, sql, values, .{});
    }

    pub fn queryPreparedTypedWithLimits(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: node_mod.QueryLimits,
    ) !node_mod.TypedResult {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        const slot = try self.acquireReadSlot();
        defer self.releaseReadSlot(slot);
        try self.ensureSlotOpen(slot);
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const queries = [_]node_mod.BatchQuery{
            .{ .tag = 0, .sql = sql, .values = values },
        };
        var sets: [1]node_mod.BatchResult.Set = undefined;
        try self.readOnSlot(slot, arena.allocator(), &queries, &sets, limits);
        return .{
            .arena = arena,
            .columns = sets[0].columns,
            .rows = sets[0].rows,
        };
    }

    /// Runs several prepared reads on ONE pooled connection inside ONE
    /// deferred read transaction (a single WAL snapshot). `limits` is a
    /// shared budget across the whole batch, matching `Node.queryBatch`.
    pub fn queryBatch(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        queries: []const node_mod.BatchQuery,
        limits: node_mod.QueryLimits,
    ) !node_mod.BatchResult {
        if (queries.len == 0) return error.EmptyTransaction;
        if (queries.len > node_mod.batch_queries_max) return error.TooManyQueries;
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        const slot = try self.acquireReadSlot();
        defer self.releaseReadSlot(slot);
        try self.ensureSlotOpen(slot);
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const sets = try arena.allocator().alloc(
            node_mod.BatchResult.Set,
            queries.len,
        );
        try self.readOnSlot(slot, arena.allocator(), queries, sets, limits);
        return .{ .arena = arena, .sets = sets };
    }

    // ------------------------------------------------------------------
    // Writes and node-delegated operations: the serialized executor
    // ------------------------------------------------------------------

    pub fn execPrepared(
        self: *SharedNode,
        sql: []const u8,
        values: []const prepared.Value,
    ) !node_mod.ExecResult {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.execPrepared(sql, values);
    }

    pub fn execPreparedResult(
        self: *SharedNode,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        out_returning: *?node_mod.TypedResult,
    ) !node_mod.ExecResult {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.execPreparedResult(gpa, sql, values, out_returning);
    }

    pub fn execTransaction(
        self: *SharedNode,
        transaction: *prepared.Transaction,
    ) !node_mod.ExecResult {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.execTransaction(transaction);
    }

    pub fn execCheckedTransaction(
        self: *SharedNode,
        statements: []const prepared.CheckedStatement,
        out_failure: *?node_mod.CheckedFailure,
    ) !node_mod.ExecResult {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.execCheckedTransaction(statements, out_failure);
    }

    pub fn status(self: *SharedNode) !node_mod.Status {
        try self.enter();
        defer self.exit();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.status();
    }

    /// Streams a consistent logical backup into `destination`.
    pub fn backup(self: *SharedNode, destination: []const u8) !void {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.backup(destination);
    }

    pub fn integrityCheck(self: *SharedNode) !node_mod.IntegrityReport {
        try self.enter();
        defer self.exit();
        try self.maintainResync();
        try self.acquireNodeTurn();
        defer self.releaseNodeTurn();
        return self.inner.integrityCheck();
    }

    /// Publishes a durable state anchor. The underlying checkpoint
    /// truncates the WAL and rebuilds files pooled readers have open, so
    /// the exclusive gate drains and closes them first; they reopen
    /// lazily on the next read.
    pub fn createStateAnchor(self: *SharedNode) !void {
        try self.enter();
        defer self.exit();
        try self.acquireExclusive();
        defer self.releaseExclusive();
        return self.inner.createStateAnchor();
    }

    /// SQLite extended result code of the node's most recent saved SQL
    /// error. Read it immediately after a failed write call: the write
    /// executor serializes writes, but another writer failing between the
    /// caller's error and this read may replace the value. Hosts that need
    /// only a stable conflict category tolerate that window; the code is
    /// never authoritative beyond error classification.
    pub fn lastSqliteExtendedCode(self: *SharedNode) i32 {
        return self.inner.lastSqliteExtendedCode();
    }

    /// The node's most recent saved SQLite error message; same read-soon
    /// caveat as `lastSqliteExtendedCode`.
    pub fn lastSqliteMessage(self: *SharedNode) []const u8 {
        return self.inner.lastSqliteMessage();
    }

    // ------------------------------------------------------------------
    // Internal: state waits
    // ------------------------------------------------------------------

    fn enter(self: *SharedNode) error{SharedNodeClosed}!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) return error.SharedNodeClosed;
        self.entrants += 1;
    }

    fn exit(self: *SharedNode) void {
        self.mutex.lockUncancelable(self.io);
        self.entrants -= 1;
        self.bumpStateLocked();
        self.mutex.unlock(self.io);
    }

    /// Advances the state generation and wakes every sleeper. Safe with
    /// or without the mutex held; callers on a mutation path bump while
    /// still holding it so the wake can never be lost.
    fn bumpStateLocked(self: *SharedNode) void {
        _ = self.state_gen.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.state_gen.raw, std.math.maxInt(u32));
    }

    /// Releases the state mutex, sleeps until the generation moves past
    /// the value observed under the mutex (or the deadline passes), and
    /// relocks. Callers loop, re-checking predicate and deadline.
    /// Cancelation is treated as a spurious wake.
    fn waitStateChange(self: *SharedNode, deadline: ?Io.Clock.Timestamp) void {
        const observed = self.state_gen.load(.acquire);
        self.mutex.unlock(self.io);
        defer self.mutex.lockUncancelable(self.io);
        const timeout: Io.Timeout = if (deadline) |moment|
            .{ .deadline = moment }
        else
            .none;
        self.io.futexWaitTimeout(u32, &self.state_gen.raw, observed, timeout) catch {};
    }

    fn deadlineFromMs(self: *SharedNode, milliseconds: u64) Io.Clock.Timestamp {
        return .fromNow(self.io, .{
            .raw = .fromMilliseconds(@intCast(milliseconds)),
            .clock = .awake,
        });
    }

    fn deadlinePassed(self: *SharedNode, deadline: Io.Clock.Timestamp) bool {
        const now = Io.Clock.Timestamp.now(self.io, .awake);
        return now.compare(.gte, deadline);
    }

    // ------------------------------------------------------------------
    // Internal: serialized node executor
    // ------------------------------------------------------------------

    fn acquireNodeTurn(self: *SharedNode) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) return error.SharedNodeClosed;
        if (self.write_tickets >= self.options.write_queue_depth) {
            return error.WriteQueueFull;
        }
        self.write_tickets += 1;
        errdefer self.write_tickets -= 1;
        const deadline = self.deadlineFromMs(self.options.write_deadline_ms);
        while (self.node_busy or self.exclusive_held or
            self.exclusive_waiting != 0)
        {
            if (self.closed) return error.SharedNodeClosed;
            if (self.deadlinePassed(deadline)) return error.WriteDeadlineExceeded;
            self.waitStateChange(deadline);
        }
        if (self.closed) return error.SharedNodeClosed;
        self.node_busy = true;
    }

    fn releaseNodeTurn(self: *SharedNode) void {
        // The node was exclusively ours for the whole turn, so its
        // resync flag can be mirrored race-free here.
        const pending = self.inner.needsResync();
        self.mutex.lockUncancelable(self.io);
        self.node_busy = false;
        self.write_tickets -= 1;
        self.resync_pending = pending;
        self.bumpStateLocked();
        self.mutex.unlock(self.io);
    }

    // ------------------------------------------------------------------
    // Internal: exclusive maintenance gate
    // ------------------------------------------------------------------

    fn acquireExclusive(self: *SharedNode) error{SharedNodeClosed}!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.exclusive_waiting += 1;
        defer self.exclusive_waiting -= 1;
        while (self.node_busy or self.readers_active != 0 or
            self.exclusive_held)
        {
            if (self.closed) return error.SharedNodeClosed;
            self.waitStateChange(null);
        }
        if (self.closed) return error.SharedNodeClosed;
        self.exclusive_held = true;
        // Pooled descriptors go stale once the image is checkpointed or
        // rebuilt; close them now, reopen lazily afterwards.
        self.closePoolLocked();
    }

    fn releaseExclusive(self: *SharedNode) void {
        self.mutex.lockUncancelable(self.io);
        self.exclusive_held = false;
        self.bumpStateLocked();
        self.mutex.unlock(self.io);
    }

    /// Escalates to the exclusive gate when the node has flagged its
    /// image for resync, so the rebuild never races pooled readers. The
    /// mirror is best-effort at operation entry; a write that flags
    /// resync mid-flight is caught by the next operation.
    fn maintainResync(self: *SharedNode) !void {
        self.mutex.lockUncancelable(self.io);
        const pending = self.resync_pending;
        self.mutex.unlock(self.io);
        if (!pending) return;
        try self.acquireExclusive();
        defer self.releaseExclusive();
        if (self.inner.needsResync()) try self.inner.resyncImage();
        self.mutex.lockUncancelable(self.io);
        self.resync_pending = false;
        self.mutex.unlock(self.io);
    }

    // ------------------------------------------------------------------
    // Internal: read pool
    // ------------------------------------------------------------------

    fn acquireReadSlot(self: *SharedNode) !*ReadSlot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const deadline = self.deadlineFromMs(self.options.read_deadline_ms);
        while (true) {
            if (self.closed) return error.SharedNodeClosed;
            if (!self.exclusive_held and self.exclusive_waiting == 0) {
                if (self.freeSlotLocked()) |slot| {
                    slot.in_use = true;
                    self.readers_active += 1;
                    return slot;
                }
            }
            if (self.deadlinePassed(deadline)) {
                return error.ReadPoolDeadlineExceeded;
            }
            self.waitStateChange(deadline);
        }
    }

    fn freeSlotLocked(self: *SharedNode) ?*ReadSlot {
        // Prefer an already open connection before opening another one.
        for (self.pool) |*slot| {
            if (!slot.in_use and slot.open) return slot;
        }
        for (self.pool) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn releaseReadSlot(self: *SharedNode, slot: *ReadSlot) void {
        self.mutex.lockUncancelable(self.io);
        slot.in_use = false;
        self.readers_active -= 1;
        self.bumpStateLocked();
        self.mutex.unlock(self.io);
    }

    /// Lazily opens the slot's READ-ONLY connection against the node's
    /// materialized image. The slot is exclusively ours (in_use), so no
    /// lock is needed; `db_path` and `mmap_size` are immutable after
    /// `Node.open`.
    fn ensureSlotOpen(self: *SharedNode, slot: *ReadSlot) !void {
        if (slot.open) return;
        slot.db = try sqlite.Db.openWithOptions(self.inner.db_path, .{
            .mmap_size = self.inner.mmap_size,
            .read_only = true,
        });
        slot.guard = .{};
        slot.guard.install(&slot.db);
        slot.open = true;
    }

    fn closePoolLocked(self: *SharedNode) void {
        for (self.pool) |*slot| {
            std.debug.assert(!slot.in_use);
            if (slot.open) {
                slot.db.close();
                slot.open = false;
            }
        }
    }

    /// Runs `queries` on one pooled connection inside one deferred read
    /// transaction, filling `sets` from a shared budget. The begin and
    /// commit are facade statements in internal scope; the caller's
    /// statements are screened as application SQL.
    fn readOnSlot(
        self: *SharedNode,
        slot: *ReadSlot,
        alloc: std.mem.Allocator,
        queries: []const node_mod.BatchQuery,
        sets: []node_mod.BatchResult.Set,
        limits: node_mod.QueryLimits,
    ) !void {
        _ = self;
        var progress: node_mod.QueryProgress = undefined;
        node_mod.installVmBudget(&slot.db, limits.max_vm_steps, &progress);
        defer node_mod.clearVmBudget(&slot.db, limits.max_vm_steps);

        try slot.db.exec("begin");
        var committed = false;
        defer if (!committed) slot.db.exec("rollback") catch {};

        var budget = node_mod.ReadBudget{ .limits = limits };
        {
            slot.guard.scope = .application;
            defer slot.guard.scope = .internal;
            for (queries, sets) |batch_query, *set| {
                const materialized = try node_mod.materializeReadStatement(
                    &slot.db,
                    alloc,
                    batch_query.sql,
                    batch_query.values,
                    &budget,
                );
                set.* = .{
                    .tag = batch_query.tag,
                    .columns = materialized.columns,
                    .rows = materialized.rows,
                };
            }
        }
        try slot.db.exec("commit");
        committed = true;
    }
};

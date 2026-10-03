//! External-client remote pool (ZDS 0010 Gate B): a client-only handle
//! over `client.ClusterConnection` that opens no data directory and no
//! listener. One `Remote` owns a bounded pool of independent physical
//! connections; concurrency comes from the pool, never from concurrent
//! mutation of one connection.
//!
//! Slot 0 is the write lane. All writes serialize behind a first-in-
//! first-out ticket gate (the same hand-off pattern as the server's
//! writer gate), run under one replicated session with monotonically
//! increasing sequences, and retry the same session/sequence across
//! redirects and ambiguous connection loss. A writer whose admission
//! wait exceeds `write_admission_timeout_ms` leaves the queue with
//! `error.WriteQueueTimeout`: it provably sent nothing, so a plain
//! retry is safe. When the operation deadline expires with the write
//! fate unknown, the exact pending request is retained and every new
//! write refuses with `error.WritePending` until `resolvePending`
//! reaches a definitive response.
//!
//! The first successful status probe pins the cluster's database
//! identity; every other slot's first probe must observe the same
//! identity or that slot fails with `error.DatabaseMismatch`.

const std = @import("std");
const Io = std.Io;
const client = @import("client.zig");
const configuration = @import("configuration.zig");
const node_mod = @import("node.zig");
const prepared = @import("prepared.zig");
const search_api = @import("search_api.zig");
const server = @import("server.zig");
const tls = @import("tls.zig");

/// Seed bound: at most a full nine-voter cluster plus learners, and the
/// practical ceiling for one client's endpoint rotation.
pub const max_seeds = 36;
/// Hard cap on pool slots; one slot is one socket plus one retry state.
pub const max_pool_slots = 64;

pub const Level = enum { any, leader, linearizable };

/// Structured outcome of one replicated remote write.
pub const ExecInfo = struct {
    changes: i64,
    last_insert_rowid: ?i64,
    replayed: bool,
};

pub const OpenOptions = struct {
    /// `host:port` or `unix:<path>` seed addresses. A unix seed must be
    /// the only seed: one socket path names exactly one server.
    seeds: []const []const u8,
    /// Mutual TLS identity; production TCP requires it.
    tls: ?tls.Config = null,
    /// PSK provider file, loaded with the native regular-file, symlink,
    /// permission, and minimum-length checks.
    auth_file_path: ?[]const u8 = null,
    /// Development-only PSK TCP: requires the provider file, forbids
    /// TLS, and every seed must be a numeric loopback literal.
    allow_psk_only_loopback: bool = false,
    /// 0 selects the default `min(32, max(4, 2 * seed_count))`.
    pool_size: usize = 0,
    /// Bounds each slot's first status probe. 0 selects 5000.
    connect_timeout_ms: u64 = 0,
    /// Bounds one write's retry window. 0 selects 10000.
    operation_timeout_ms: u64 = 0,
    /// Bounds how long a writer may wait for admission to the ordered
    /// write lane before failing with `error.WriteQueueTimeout`.
    /// 0 means unbounded. A queue-timed-out write never left the
    /// process, so callers may retry it plainly.
    write_admission_timeout_ms: u64 = 0,
    /// When set, the first status probe must observe exactly this
    /// database identity instead of adopting whatever it sees.
    expected_database_id: ?u128 = null,
};

/// Parses and copies seed addresses into `arena`. Bounds are enforced
/// before any endpoint is parsed; the ZDS requires 1..=36 UNIQUE seeds,
/// and a unix seed is only legal alone.
pub fn parseSeeds(
    arena: std.mem.Allocator,
    seeds: []const []const u8,
) ![]client.Endpoint {
    if (seeds.len == 0) return error.NoSeeds;
    if (seeds.len > max_seeds) return error.TooManySeeds;
    for (seeds, 0..) |text, index| {
        for (seeds[0..index]) |earlier| {
            if (std.mem.eql(u8, text, earlier)) return error.DuplicateSeed;
        }
    }
    const endpoints = try arena.alloc(client.Endpoint, seeds.len);
    var any_unix = false;
    for (seeds, endpoints) |text, *endpoint| {
        endpoint.* = try client.Endpoint.parse(try arena.dupe(u8, text));
        if (endpoint.unix_path != null) any_unix = true;
    }
    if (any_unix and seeds.len != 1) return error.UnixSeedNotAlone;
    return endpoints;
}

/// Transport policy for an external client, mirroring the server's
/// rules: development PSK is loopback-only TCP with a secret and no
/// TLS; a unix seed composes with neither TLS nor the PSK flag; and
/// production TCP always requires mutual TLS.
pub fn checkTransportPolicy(
    endpoints: []const client.Endpoint,
    has_tls: bool,
    has_secret: bool,
    allow_psk_only_loopback: bool,
) !void {
    const unix = endpoints[0].unix_path != null;
    if (allow_psk_only_loopback) {
        if (unix) return error.DevPskWithUnixSocket;
        if (!has_secret) return error.DevPskNeedsSecret;
        if (has_tls) return error.DevPskWithTls;
        for (endpoints) |endpoint| {
            if (!isNumericLoopback(endpoint.host)) {
                return error.DevPskNeedsLoopback;
            }
        }
        return;
    }
    if (unix) {
        if (has_tls) return error.TlsWithUnixSocket;
        return;
    }
    if (!has_tls) return error.TcpNeedsTls;
}

/// Only the two numeric loopback literals qualify, never hostnames or
/// other ranges; this mirrors `Embedded`'s `--dev-psk` policy.
fn isNumericLoopback(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "::1");
}

/// Resolves the pool size: 0 selects the seed-scaled default, anything
/// else is clamped into `1..=max_pool_slots`.
pub fn poolSlotCount(requested: usize, seed_count: usize) usize {
    if (requested == 0) return @min(32, @max(4, 2 * seed_count));
    return std.math.clamp(requested, 1, max_pool_slots);
}

const default_connect_timeout_ms: u64 = 5000;
const default_operation_timeout_ms: u64 = 10_000;
const retry_pause_ms = 50;
/// Poll slice for deadline-bounded write-lane admission: a queued
/// bounded writer re-checks its grant and its deadline this often.
const admission_poll_ms = 10;

const Slot = struct {
    connection: client.ClusterConnection = undefined,
    initialized: bool = false,
    /// Set once this slot's first status probe confirmed the pinned
    /// database identity.
    probed: bool = false,
    in_use: bool = false,
};

const Pending = struct {
    sequence: u64,
    /// The exact serialized request, resent byte-for-byte until the
    /// server reports a definitive outcome.
    request: []u8,
};

const AcquireKind = enum { write, read_any, read_leader };

/// One parked writer awaiting first-in-first-out admission to the
/// write lane. Stack-allocated by the waiting thread; all links are
/// mutated under `pool_mutex`. Mirrors the server's `WriterTicket`.
const WriteTicket = struct {
    granted: bool = false,
    next: ?*WriteTicket = null,
};

pub const Remote = struct {
    gpa: std.mem.Allocator,
    io: Io,
    arena: std.heap.ArenaAllocator,
    endpoints: []const client.Endpoint,
    tls_context: ?tls.Context,
    secret: ?configuration.Secret,
    transport: client.Transport,
    connect_timeout_ms: u64,
    operation_timeout_ms: u64,
    write_admission_timeout_ms: u64,

    pool_mutex: Io.Mutex = .init,
    pool_cond: Io.Condition = .init,
    slots: []Slot,
    next_read_slot: usize = 0,
    /// Set by `close` under `pool_mutex`: new acquisitions and queued
    /// writers fail with `error.Closed`, and `close` waits until every
    /// slot is idle and the write lane is free before releasing memory.
    closing: bool = false,

    // Ordered write lane: a FIFO ticket gate (never a bare mutex), so
    // admission order is the session-sequence order (Invariant 20).
    // All gate state is protected by `pool_mutex`.
    write_gate_busy: bool = false,
    write_queue_head: ?*WriteTicket = null,
    write_queue_tail: ?*WriteTicket = null,
    write_cond: Io.Condition = .init,
    session_id: ?u64 = null,
    next_sequence: u64 = 1,
    pending: ?Pending = null,

    identity_mutex: Io.Mutex = .init,
    database_id: ?u128,

    // The most recent definitive server rejection, mirroring the C ABI
    // handle discipline: read only after a failed call on this handle.
    server_error_code_buffer: [64]u8 = undefined,
    server_error_code_length: usize = 0,
    server_error_message_buffer: [256]u8 = undefined,
    server_error_message_length: usize = 0,

    pub fn open(gpa: std.mem.Allocator, io: Io, options: OpenOptions) !*Remote {
        const self = try gpa.create(Remote);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .endpoints = &.{},
            .tls_context = null,
            .secret = null,
            .transport = .{},
            .connect_timeout_ms = if (options.connect_timeout_ms == 0)
                default_connect_timeout_ms
            else
                options.connect_timeout_ms,
            .operation_timeout_ms = if (options.operation_timeout_ms == 0)
                default_operation_timeout_ms
            else
                options.operation_timeout_ms,
            .write_admission_timeout_ms = options.write_admission_timeout_ms,
            .slots = &.{},
            .database_id = options.expected_database_id,
        };
        errdefer self.arena.deinit();
        const arena = self.arena.allocator();

        self.endpoints = try parseSeeds(arena, options.seeds);
        // The secret must outlive every slot: `ClusterConnection`
        // borrows the slice for the life of the pool.
        if (options.auth_file_path) |path| {
            self.secret = try configuration.loadSecret(gpa, io, path);
        }
        errdefer if (self.secret) |*secret| secret.deinit(gpa);
        try checkTransportPolicy(
            self.endpoints,
            options.tls != null,
            self.secret != null,
            options.allow_psk_only_loopback,
        );
        if (options.tls) |config| {
            self.tls_context = try tls.Context.initClient(config);
        }
        errdefer if (self.tls_context) |*context| context.deinit();

        self.transport = .{
            .secret = if (self.secret) |*secret| secret.bytes else null,
            .tls = if (self.tls_context) |*context| context else null,
        };
        self.slots = try arena.alloc(
            Slot,
            poolSlotCount(options.pool_size, self.endpoints.len),
        );
        @memset(self.slots, .{});

        try self.probeFirstSlot();
        return self;
    }

    fn probeFirstSlot(self: *Remote) !void {
        // Open-time probe (ZDS 0010): opening succeeds only when at
        // least one seed authenticates, reports the expected database
        // identity, and answers a client RPC. The first slot is dialed
        // and probed eagerly (bounded by `connect_timeout_ms`); every
        // other slot stays lazy.
        const first = &self.slots[0];
        first.connection = client.ClusterConnection.init(
            self.gpa,
            self.io,
            self.endpoints,
            self.transport,
        );
        first.initialized = true;
        errdefer {
            first.connection.deinit();
            first.initialized = false;
        }
        try self.probeSlot(first);
    }

    /// Releases every slot and transport credential. New acquisitions
    /// fail with `error.Closed` immediately; teardown then waits until
    /// every slot is idle and the write lane is free, so no thread is
    /// still inside a call on a slot when it is deinitialized. The wait
    /// is unbounded: callers own orderly shutdown, and a bounded wait
    /// that frees in-use slots would trade a hang for a use-after-free.
    /// An unresolved pending write is abandoned locally; it is never
    /// re-executed. A second concurrent `close` returns immediately and
    /// leaves teardown to the first caller.
    pub fn close(self: *Remote) void {
        self.pool_mutex.lockUncancelable(self.io);
        if (self.closing) {
            self.pool_mutex.unlock(self.io);
            return;
        }
        self.closing = true;
        // Wake parked acquirers and queued writers so they observe
        // `closing` and drain; then wait for in-flight calls to finish.
        self.pool_cond.broadcast(self.io);
        self.write_cond.broadcast(self.io);
        while (self.write_gate_busy or self.write_queue_head != null or
            self.anySlotInUseLocked())
        {
            self.pool_cond.waitUncancelable(self.io, &self.pool_mutex);
        }
        self.pool_mutex.unlock(self.io);

        if (self.pending) |pending| self.gpa.free(pending.request);
        for (self.slots) |*slot| {
            if (slot.initialized) slot.connection.deinit();
        }
        if (self.tls_context) |*context| context.deinit();
        if (self.secret) |*secret| secret.deinit(self.gpa);
        self.arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    fn anySlotInUseLocked(self: *const Remote) bool {
        for (self.slots) |slot| {
            if (slot.in_use) return true;
        }
        return false;
    }

    /// Executes one prepared statement through the write lane: FIFO
    /// admission, one session, the next sequence, and same-identity
    /// retry until the operation deadline. `error.WriteQueueTimeout`
    /// means admission timed out before anything was sent; a plain
    /// retry is safe. `error.WritePending` means the fate is unresolved
    /// and retained; call `resolvePending`.
    pub fn exec(
        self: *Remote,
        sql: []const u8,
        values: []const prepared.Value,
    ) !ExecInfo {
        try self.acquireWriteLane();
        defer self.releaseWriteLane();
        if (self.pending != null) return error.WritePending;

        const slot = try self.acquire(.write);
        defer self.release(slot);
        try self.probeSlot(slot);
        try self.ensureSession(slot);

        const sequence = self.next_sequence;
        const request = try buildExecRequest(
            self.gpa,
            sql,
            values,
            self.session_id.?,
            sequence,
        );
        return self.driveNewWrite(slot, sequence, request);
    }

    /// Executes one prepared statement once per parameter vector as ONE
    /// bounded typed-v1 batch, ONE replicated transaction, and ONE
    /// session sequence (the atomic remote `executemany`). The batch is
    /// bounded by `prepared.maximum_statements`; the reported change
    /// count is the whole batch's total, and any per-row failure rolls
    /// the entire batch back on the server.
    pub fn execBatch(
        self: *Remote,
        sql: []const u8,
        batch: []const []const prepared.Value,
    ) !ExecInfo {
        if (batch.len == 0) return error.EmptyBatch;
        if (batch.len > prepared.maximum_statements) {
            return error.TooManyStatements;
        }
        try self.acquireWriteLane();
        defer self.releaseWriteLane();
        if (self.pending != null) return error.WritePending;

        const slot = try self.acquire(.write);
        defer self.release(slot);
        try self.probeSlot(slot);
        try self.ensureSession(slot);

        const sequence = self.next_sequence;
        const request = try buildExecBatchRequest(
            self.gpa,
            sql,
            batch,
            self.session_id.?,
            sequence,
        );
        return self.driveNewWrite(slot, sequence, request);
    }

    /// Drives one freshly serialized write to a definitive outcome,
    /// retaining the exact request bytes when the deadline expires with
    /// the fate unknown. Owns `request` either way. Called with the
    /// write lane held.
    fn driveNewWrite(
        self: *Remote,
        slot: *Slot,
        sequence: u64,
        request: []u8,
    ) !ExecInfo {
        var retained = false;
        defer if (!retained) self.gpa.free(request);

        const outcome = self.driveWrite(slot, request) catch |err| switch (err) {
            error.WriteUnresolved => {
                self.pending = .{ .sequence = sequence, .request = request };
                retained = true;
                return error.WritePending;
            },
            else => return err,
        };
        self.next_sequence += 1;
        return outcome;
    }

    /// Retries the retained pending write with its original session and
    /// sequence until the server reports a definitive outcome. Success
    /// or an idempotent replay resolves it; a definitive rejection also
    /// resolves it (the statement never committed and never will).
    pub fn resolvePending(self: *Remote) !ExecInfo {
        try self.acquireWriteLane();
        defer self.releaseWriteLane();
        const pending = self.pending orelse return error.NoPendingWrite;

        const slot = try self.acquire(.write);
        defer self.release(slot);
        try self.probeSlot(slot);

        const outcome = self.driveWrite(slot, pending.request) catch |err|
            switch (err) {
                error.WriteUnresolved => return error.WritePending,
                else => {
                    self.clearPending();
                    return err;
                },
            };
        self.clearPending();
        self.next_sequence += 1;
        return outcome;
    }

    fn clearPending(self: *Remote) void {
        if (self.pending) |pending| self.gpa.free(pending.request);
        self.pending = null;
    }

    /// Runs one typed-v1 read. `any` uses the read slots round-robin;
    /// `leader` and `linearizable` may use any free slot because the
    /// connection itself follows the leader. The returned result is
    /// arena-owned by `result_gpa`.
    pub fn query(
        self: *Remote,
        result_gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        level: Level,
        freshness_ms: ?u64,
    ) !node_mod.TypedResult {
        const request = try buildQueryRequest(
            self.gpa,
            sql,
            values,
            level,
            freshness_ms,
        );
        defer self.gpa.free(request);

        const slot = try self.acquire(
            if (level == .any) .read_any else .read_leader,
        );
        defer self.release(slot);
        try self.probeSlot(slot);

        const body = try self.callSlot(slot, request, level != .any);
        defer self.gpa.free(body);
        return self.parseTypedQuery(result_gpa, body);
    }

    /// Runs one typed search through the server's validated ZDS 0009
    /// planner. Scheduling and consistency are identical to `query`.
    pub fn search(
        self: *Remote,
        result_gpa: std.mem.Allocator,
        request: search_api.Request,
        level: Level,
        freshness_ms: ?u64,
    ) !node_mod.TypedResult {
        const body_request = try buildSearchRequest(
            self.gpa,
            request,
            level,
            freshness_ms,
        );
        defer self.gpa.free(body_request);

        const slot = try self.acquire(
            if (level == .any) .read_any else .read_leader,
        );
        defer self.release(slot);
        try self.probeSlot(slot);

        const body = try self.callSlot(slot, body_request, level != .any);
        defer self.gpa.free(body);
        return self.parseTypedQuery(result_gpa, body);
    }

    /// Raw status passthrough from any healthy (identity-checked) slot,
    /// for host-side diagnostics. The caller owns the returned bytes.
    pub fn statusJson(self: *Remote, result_gpa: std.mem.Allocator) ![]u8 {
        const slot = try self.acquire(.read_leader);
        defer self.release(slot);
        try self.probeSlot(slot);
        const body = try self.callSlot(slot, "{\"op\":\"status\"}", false);
        defer self.gpa.free(body);
        return result_gpa.dupe(u8, body);
    }

    /// Error code of the most recent definitive server rejection.
    pub fn lastServerCode(self: *const Remote) []const u8 {
        return self.server_error_code_buffer[0..self.server_error_code_length];
    }

    /// Message of the most recent definitive server rejection.
    pub fn lastServerMessage(self: *const Remote) []const u8 {
        return self.server_error_message_buffer[0..self.server_error_message_length];
    }

    // ------------------------------------------------------------------
    // Pool
    // ------------------------------------------------------------------

    fn acquire(self: *Remote, kind: AcquireKind) error{Closed}!*Slot {
        self.pool_mutex.lockUncancelable(self.io);
        defer self.pool_mutex.unlock(self.io);
        while (true) {
            if (self.closing) return error.Closed;
            if (self.tryAcquireLocked(kind)) |slot| return slot;
            self.pool_cond.waitUncancelable(self.io, &self.pool_mutex);
        }
    }

    fn tryAcquireLocked(self: *Remote, kind: AcquireKind) ?*Slot {
        if (kind == .write or self.slots.len == 1) {
            return self.takeLocked(0);
        }
        // Slots 1..N serve reads. All free slots have zero calls in
        // flight, so least-in-flight reduces to round-robin rotation.
        const read_count = self.slots.len - 1;
        var offset: usize = 0;
        while (offset < read_count) : (offset += 1) {
            const index = 1 + (self.next_read_slot + offset) % read_count;
            if (self.takeLocked(index)) |slot| {
                self.next_read_slot =
                    (self.next_read_slot + offset + 1) % read_count;
                return slot;
            }
        }
        // Leader-level reads may borrow the idle write lane; `any`
        // reads keep it dedicated so a write never queues behind them.
        if (kind == .read_leader) return self.takeLocked(0);
        return null;
    }

    fn takeLocked(self: *Remote, index: usize) ?*Slot {
        const slot = &self.slots[index];
        if (slot.in_use) return null;
        if (!slot.initialized) {
            slot.connection = client.ClusterConnection.init(
                self.gpa,
                self.io,
                self.endpoints,
                self.transport,
            );
            slot.initialized = true;
        }
        slot.in_use = true;
        return slot;
    }

    fn release(self: *Remote, slot: *Slot) void {
        self.pool_mutex.lockUncancelable(self.io);
        slot.in_use = false;
        // Broadcast before unlocking so a closing thread can only
        // observe the idle slot after this thread is done touching it.
        self.pool_cond.broadcast(self.io);
        self.pool_mutex.unlock(self.io);
    }

    // ------------------------------------------------------------------
    // Ordered write lane (FIFO ticket gate, Invariant 20)
    // ------------------------------------------------------------------

    /// Admits this thread to the write lane. Admission is first-in-
    /// first-out: the releasing owner hands the gate directly to the
    /// oldest queued ticket, so writes reach the session sequence in
    /// arrival order. A bounded waiter that misses its admission
    /// deadline leaves the queue with `error.WriteQueueTimeout` having
    /// provably sent nothing.
    fn acquireWriteLane(self: *Remote) error{ Closed, WriteQueueTimeout }!void {
        self.pool_mutex.lockUncancelable(self.io);
        defer self.pool_mutex.unlock(self.io);
        if (self.closing) return error.Closed;
        if (!self.write_gate_busy and self.write_queue_head == null) {
            self.write_gate_busy = true;
            return;
        }
        var ticket = WriteTicket{};
        if (self.write_queue_tail) |tail| {
            tail.next = &ticket;
        } else {
            self.write_queue_head = &ticket;
        }
        self.write_queue_tail = &ticket;
        const start = self.timestamp();
        while (!ticket.granted) {
            if (self.closing) {
                self.removeWriteTicketLocked(&ticket);
                self.pool_cond.broadcast(self.io);
                return error.Closed;
            }
            if (self.write_admission_timeout_ms != 0 and
                self.elapsedMs(start) >= self.write_admission_timeout_ms)
            {
                self.removeWriteTicketLocked(&ticket);
                self.pool_cond.broadcast(self.io);
                return error.WriteQueueTimeout;
            }
            if (self.write_admission_timeout_ms == 0) {
                self.write_cond.waitUncancelable(self.io, &self.pool_mutex);
            } else {
                // No timed condition wait exists, so a bounded waiter
                // polls: the deadline is observed within one slice even
                // when no release ever signals.
                self.pool_mutex.unlock(self.io);
                self.sleepMs(admission_poll_ms);
                self.pool_mutex.lockUncancelable(self.io);
            }
        }
    }

    /// Releases the write lane, handing it directly to the oldest
    /// queued ticket so admission stays first-in-first-out. During
    /// close no hand-off happens: queued tickets drain via `closing`.
    fn releaseWriteLane(self: *Remote) void {
        self.pool_mutex.lockUncancelable(self.io);
        if (!self.closing) {
            if (self.write_queue_head) |next| {
                self.write_queue_head = next.next;
                if (self.write_queue_head == null) self.write_queue_tail = null;
                next.next = null;
                next.granted = true;
            } else {
                self.write_gate_busy = false;
            }
        } else {
            self.write_gate_busy = false;
        }
        // Broadcast before unlocking; see `release`.
        self.write_cond.broadcast(self.io);
        self.pool_cond.broadcast(self.io);
        self.pool_mutex.unlock(self.io);
    }

    /// Unlinks an abandoned ticket (admission deadline expiry or close)
    /// without disturbing queue order. Called under `pool_mutex`.
    fn removeWriteTicketLocked(self: *Remote, ticket: *WriteTicket) void {
        var previous: ?*WriteTicket = null;
        var cursor = self.write_queue_head;
        while (cursor) |current| : (cursor = current.next) {
            if (current == ticket) {
                if (previous) |before| {
                    before.next = current.next;
                } else {
                    self.write_queue_head = current.next;
                }
                if (self.write_queue_tail == current) {
                    self.write_queue_tail = previous;
                }
                return;
            }
            previous = current;
        }
    }

    fn callSlot(
        self: *Remote,
        slot: *Slot,
        request: []const u8,
        require_leader: bool,
    ) ![]u8 {
        var result = try slot.connection.call(request, require_leader);
        return result.takeBody(self.gpa);
    }

    // ------------------------------------------------------------------
    // Identity pinning
    // ------------------------------------------------------------------

    fn probeSlot(self: *Remote, slot: *Slot) !void {
        if (slot.probed) return;
        const start = self.timestamp();
        var last_error: anyerror = error.Unavailable;
        while (true) {
            if (self.probeOnce(slot)) {
                slot.probed = true;
                return;
            } else |err| switch (err) {
                error.DatabaseMismatch, error.TypedV1Unsupported => return err,
                else => last_error = err,
            }
            if (self.elapsedMs(start) >= self.connect_timeout_ms) {
                return last_error;
            }
            self.sleepMs(retry_pause_ms);
        }
    }

    fn probeOnce(self: *Remote, slot: *Slot) !void {
        const body = try self.callSlot(slot, "{\"op\":\"status\"}", false);
        defer self.gpa.free(body);
        const Status = struct {
            ok: bool = false,
            database_id: ?[]const u8 = null,
            typed_v1: bool = false,
        };
        const parsed = std.json.parseFromSlice(Status, self.gpa, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidResponse;
        defer parsed.deinit();
        if (!parsed.value.ok) return error.InvalidResponse;
        if (!parsed.value.typed_v1) return error.TypedV1Unsupported;
        const hex = parsed.value.database_id orelse return error.InvalidResponse;
        const observed = std.fmt.parseInt(u128, hex, 16) catch
            return error.InvalidResponse;

        self.identity_mutex.lockUncancelable(self.io);
        defer self.identity_mutex.unlock(self.io);
        if (self.database_id) |pinned| {
            if (pinned != observed) return error.DatabaseMismatch;
        } else {
            self.database_id = observed;
        }
    }

    // ------------------------------------------------------------------
    // Write lane
    // ------------------------------------------------------------------

    fn ensureSession(self: *Remote, slot: *Slot) !void {
        if (self.session_id != null) return;
        const start = self.timestamp();
        while (true) {
            if (self.sessionOnce(slot)) |session_id| {
                self.session_id = session_id;
                return;
            } else |err| switch (err) {
                error.ServerRejected => return err,
                else => {},
            }
            if (self.elapsedMs(start) >= self.operation_timeout_ms) {
                return error.Timeout;
            }
            self.sleepMs(retry_pause_ms);
        }
    }

    fn sessionOnce(self: *Remote, slot: *Slot) !u64 {
        const body = try self.callSlot(slot, "{\"op\":\"session\"}", true);
        defer self.gpa.free(body);
        const Session = struct {
            ok: bool = false,
            session_id: u64 = 0,
            @"error": ?[]const u8 = null,
            message: ?[]const u8 = null,
        };
        const parsed = std.json.parseFromSlice(Session, self.gpa, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidResponse;
        defer parsed.deinit();
        if (parsed.value.ok) return parsed.value.session_id;
        const code = parsed.value.@"error" orelse return error.InvalidResponse;
        // Opening a session carries no sequence, so any retryable
        // rejection may simply try again; the worst case is an unused
        // orphan session on the server.
        if (writeRetryable(code)) return error.Retry;
        self.recordServerError(code, parsed.value.message);
        return error.ServerRejected;
    }

    /// One bounded attempt loop for one serialized request. Transport
    /// failures and fate-unknown rejections resend the same bytes; a
    /// definitive rejection returns `error.ServerRejected` without
    /// advancing anything. Deadline expiry with the fate still unknown
    /// returns `error.WriteUnresolved`.
    fn driveWrite(self: *Remote, slot: *Slot, request: []const u8) !ExecInfo {
        const start = self.timestamp();
        while (true) {
            if (self.writeOnce(slot, request)) |outcome| {
                return outcome;
            } else |err| switch (err) {
                error.ServerRejected => return err,
                else => {},
            }
            if (self.elapsedMs(start) >= self.operation_timeout_ms) {
                return error.WriteUnresolved;
            }
            self.sleepMs(retry_pause_ms);
        }
    }

    fn writeOnce(self: *Remote, slot: *Slot, request: []const u8) !ExecInfo {
        const body = try self.callSlot(slot, request, true);
        defer self.gpa.free(body);
        const Response = struct {
            ok: bool = false,
            changes: i64 = 0,
            replayed: bool = false,
            last_insert_rowid: ?i64 = null,
            @"error": ?[]const u8 = null,
            message: ?[]const u8 = null,
            queued: bool = false,
        };
        const parsed = std.json.parseFromSlice(Response, self.gpa, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidResponse;
        defer parsed.deinit();
        if (parsed.value.ok) {
            return .{
                .changes = parsed.value.changes,
                .last_insert_rowid = parsed.value.last_insert_rowid,
                .replayed = parsed.value.replayed,
            };
        }
        const code = parsed.value.@"error" orelse return error.InvalidResponse;
        // `timeout` with `queued:true` never executed, so resending the
        // same sequence stays correct; without it, and for `ambiguous`,
        // the same-sequence replay is what resolves the unknown fate.
        if (writeRetryable(code)) return error.Retry;
        self.recordServerError(code, parsed.value.message);
        return error.ServerRejected;
    }

    fn writeRetryable(code: []const u8) bool {
        return std.mem.eql(u8, code, "timeout") or
            std.mem.eql(u8, code, "ambiguous") or
            std.mem.eql(u8, code, "retry") or
            std.mem.eql(u8, code, "unavailable");
    }

    fn recordServerError(
        self: *Remote,
        code: []const u8,
        message: ?[]const u8,
    ) void {
        const code_length = @min(code.len, self.server_error_code_buffer.len);
        @memcpy(self.server_error_code_buffer[0..code_length], code[0..code_length]);
        self.server_error_code_length = code_length;
        const text = message orelse code;
        const text_length = @min(text.len, self.server_error_message_buffer.len);
        @memcpy(
            self.server_error_message_buffer[0..text_length],
            text[0..text_length],
        );
        self.server_error_message_length = text_length;
    }

    // ------------------------------------------------------------------
    // Typed-v1 decoding
    // ------------------------------------------------------------------

    fn parseTypedQuery(
        self: *Remote,
        result_gpa: std.mem.Allocator,
        body: []const u8,
    ) !node_mod.TypedResult {
        const parsed = std.json.parseFromSlice(
            std.json.Value,
            self.gpa,
            body,
            .{},
        ) catch return error.InvalidResponse;
        defer parsed.deinit();
        const object = switch (parsed.value) {
            .object => |*value| value,
            else => return error.InvalidResponse,
        };
        const ok = object.get("ok") orelse return error.InvalidResponse;
        if (ok != .bool or !ok.bool) {
            const code = object.get("error") orelse return error.InvalidResponse;
            if (code != .string) return error.InvalidResponse;
            const message = object.get("message");
            self.recordServerError(
                code.string,
                if (message != null and message.? == .string)
                    message.?.string
                else
                    null,
            );
            return error.ServerRejected;
        }

        var arena = std.heap.ArenaAllocator.init(result_gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        const raw_columns = jsonArray(object.get("columns")) orelse
            return error.InvalidResponse;
        const columns = try alloc.alloc([]const u8, raw_columns.len);
        for (raw_columns, columns) |raw, *column| {
            if (raw != .string) return error.InvalidResponse;
            column.* = try alloc.dupe(u8, raw.string);
        }

        const raw_rows = jsonArray(object.get("rows")) orelse
            return error.InvalidResponse;
        const rows = try alloc.alloc([]const prepared.Value, raw_rows.len);
        for (raw_rows, rows) |raw_row, *row| {
            const raw_cells = jsonArray(raw_row) orelse
                return error.InvalidResponse;
            if (raw_cells.len != columns.len) return error.InvalidResponse;
            const cells = try alloc.alloc(prepared.Value, raw_cells.len);
            for (raw_cells, cells) |raw_cell, *cell| {
                cell.* = try decodeTypedCell(alloc, raw_cell);
            }
            row.* = cells;
        }
        return .{ .arena = arena, .columns = columns, .rows = rows };
    }

    fn jsonArray(value: ?std.json.Value) ?[]std.json.Value {
        const raw = value orelse return null;
        return switch (raw) {
            .array => |array| array.items,
            else => null,
        };
    }

    /// Decodes one typed-v1 cell: null, `{"t":"i","i":n}`,
    /// `{"t":"r","r":x}` (or `{"t":"r","x":"<16 hex>"}` for non-finite
    /// reals), `{"t":"t","v":"text"}`, or `{"t":"b","v":"<base64>"}`.
    fn decodeTypedCell(
        alloc: std.mem.Allocator,
        raw: std.json.Value,
    ) !prepared.Value {
        switch (raw) {
            .null => return .null_value,
            .object => |object| {
                const tag = object.get("t") orelse return error.InvalidResponse;
                if (tag != .string) return error.InvalidResponse;
                if (std.mem.eql(u8, tag.string, "i")) {
                    const number = object.get("i") orelse
                        return error.InvalidResponse;
                    if (number != .integer) return error.InvalidResponse;
                    return .{ .integer = number.integer };
                }
                if (std.mem.eql(u8, tag.string, "r")) {
                    if (object.get("r")) |number| return switch (number) {
                        .float => .{ .real = number.float },
                        .integer => .{
                            .real = @floatFromInt(number.integer),
                        },
                        else => error.InvalidResponse,
                    };
                    const hex = object.get("x") orelse
                        return error.InvalidResponse;
                    if (hex != .string or hex.string.len != 16) {
                        return error.InvalidResponse;
                    }
                    const bits = std.fmt.parseInt(u64, hex.string, 16) catch
                        return error.InvalidResponse;
                    return .{ .real = @bitCast(bits) };
                }
                if (std.mem.eql(u8, tag.string, "t")) {
                    const text = object.get("v") orelse
                        return error.InvalidResponse;
                    if (text != .string) return error.InvalidResponse;
                    return .{ .text = try alloc.dupe(u8, text.string) };
                }
                if (std.mem.eql(u8, tag.string, "b")) {
                    const encoded = object.get("v") orelse
                        return error.InvalidResponse;
                    if (encoded != .string) return error.InvalidResponse;
                    const decoder = std.base64.standard.Decoder;
                    const size = decoder.calcSizeForSlice(encoded.string) catch
                        return error.InvalidResponse;
                    const bytes = try alloc.alloc(u8, size);
                    decoder.decode(bytes, encoded.string) catch
                        return error.InvalidResponse;
                    return .{ .blob = bytes };
                }
                return error.InvalidResponse;
            },
            else => return error.InvalidResponse,
        }
    }

    // ------------------------------------------------------------------
    // Timing
    // ------------------------------------------------------------------

    fn timestamp(self: *Remote) Io.Clock.Timestamp {
        return Io.Clock.Timestamp.now(self.io, .awake);
    }

    fn elapsedMs(self: *Remote, start: Io.Clock.Timestamp) u64 {
        const elapsed = start.durationTo(self.timestamp());
        const nanoseconds = elapsed.raw.nanoseconds;
        if (nanoseconds <= 0) return 0;
        return @intCast(@divTrunc(nanoseconds, std.time.ns_per_ms));
    }

    fn sleepMs(self: *Remote, milliseconds: u64) void {
        self.io.sleep(
            .fromMilliseconds(@intCast(milliseconds)),
            .awake,
        ) catch {};
    }
};

// ----------------------------------------------------------------------
// Request serialization
// ----------------------------------------------------------------------

fn buildExecRequest(
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const prepared.Value,
    session: u64,
    sequence: u64,
) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const out = &buffer.writer;
    try out.writeAll("{\"op\":\"exec\",\"sql\":");
    try server.writeJsonString(out, sql);
    try out.writeAll(",\"format\":\"typed-v1\"");
    try writeParams(gpa, out, values);
    try out.print(
        ",\"session\":{d},\"sequence\":{d}}}",
        .{ session, sequence },
    );
    return buffer.toOwnedSlice();
}

/// Serializes the atomic batch exec request: the same typed-v1 exec op
/// with `param_batch` (one tagged parameter array per row) instead of
/// `params`, under one session and one sequence.
fn buildExecBatchRequest(
    gpa: std.mem.Allocator,
    sql: []const u8,
    batch: []const []const prepared.Value,
    session: u64,
    sequence: u64,
) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const out = &buffer.writer;
    try out.writeAll("{\"op\":\"exec\",\"sql\":");
    try server.writeJsonString(out, sql);
    try out.writeAll(",\"format\":\"typed-v1\",\"param_batch\":[");
    for (batch, 0..) |values, index| {
        if (index > 0) try out.writeAll(",");
        try writeParamArray(gpa, out, values);
    }
    try out.writeAll("]");
    try out.print(
        ",\"session\":{d},\"sequence\":{d}}}",
        .{ session, sequence },
    );
    return buffer.toOwnedSlice();
}

fn buildQueryRequest(
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const prepared.Value,
    level: Level,
    freshness_ms: ?u64,
) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const out = &buffer.writer;
    try out.writeAll("{\"op\":\"query\",\"sql\":");
    try server.writeJsonString(out, sql);
    try out.writeAll(",\"format\":\"typed-v1\"");
    try writeParams(gpa, out, values);
    try out.print(",\"level\":\"{s}\"", .{@tagName(level)});
    if (freshness_ms) |maximum| {
        try out.print(",\"freshness_ms\":{d}", .{maximum});
    }
    try out.writeAll("}");
    return buffer.toOwnedSlice();
}

fn buildSearchRequest(
    gpa: std.mem.Allocator,
    request: search_api.Request,
    level: Level,
    freshness_ms: ?u64,
) ![]u8 {
    if (!std.math.isFinite(request.text_weight) or
        !std.math.isFinite(request.vector_weight))
    {
        return error.InvalidWeight;
    }
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const out = &buffer.writer;
    try out.writeAll("{\"op\":\"search\",\"format\":\"typed-v1\"");
    try writeOptionalString(out, "fts_table", request.fts_table);
    try writeOptionalString(out, "vec_table", request.vec_table);
    try writeOptionalString(out, "text", request.text);
    try writeOptionalEmbedding(gpa, out, request.embedding);
    try out.print(
        ",\"k\":{d},\"fusion\":\"{s}\",\"text_weight\":{d}," ++
            "\"vector_weight\":{d}",
        .{
            request.k,
            @tagName(request.fusion),
            request.text_weight,
            request.vector_weight,
        },
    );
    if (request.candidate_count) |count| {
        try out.print(",\"candidate_count\":{d}", .{count});
    }
    try writeOptionalString(out, "metadata_table", request.metadata_table);
    try writeOptionalString(
        out,
        "metadata_id_column",
        request.metadata_id_column,
    );
    try writeMetadataColumns(out, request.metadata_columns);
    try out.print(",\"level\":\"{s}\"", .{@tagName(level)});
    if (freshness_ms) |maximum| {
        try out.print(",\"freshness_ms\":{d}", .{maximum});
    }
    try out.writeAll("}");
    return buffer.toOwnedSlice();
}

fn writeOptionalString(
    out: *Io.Writer,
    name: []const u8,
    value: ?[]const u8,
) !void {
    const text = value orelse return;
    try out.print(",\"{s}\":", .{name});
    try server.writeJsonString(out, text);
}

fn writeOptionalEmbedding(
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    value: ?[]const u8,
) !void {
    const bytes = value orelse return;
    const encoder = std.base64.standard.Encoder;
    const encoded = try gpa.alloc(u8, encoder.calcSize(bytes.len));
    defer gpa.free(encoded);
    _ = encoder.encode(encoded, bytes);
    try out.writeAll(",\"embedding\":\"");
    try out.writeAll(encoded);
    try out.writeAll("\"");
}

fn writeMetadataColumns(
    out: *Io.Writer,
    columns: []const []const u8,
) !void {
    if (columns.len == 0) return;
    try out.writeAll(",\"metadata_columns\":[");
    for (columns, 0..) |column, index| {
        if (index > 0) try out.writeAll(",");
        try server.writeJsonString(out, column);
    }
    try out.writeAll("]");
}

/// Writes the optional tagged typed-v1 `params` member (omitted when
/// there are no values).
fn writeParams(
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    values: []const prepared.Value,
) !void {
    if (values.len == 0) return;
    try out.writeAll(",\"params\":");
    try writeParamArray(gpa, out, values);
}

/// Writes one tagged typed-v1 parameter array. JSON has no non-finite
/// number literal and the wire tag carries no bit-pattern escape for
/// requests, so non-finite reals are refused here.
fn writeParamArray(
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    values: []const prepared.Value,
) !void {
    try out.writeAll("[");
    for (values, 0..) |value, index| {
        if (index > 0) try out.writeAll(",");
        switch (value) {
            .null_value => try out.writeAll("{\"t\":\"null\"}"),
            .integer => |number| try out.print(
                "{{\"t\":\"int\",\"i\":{d}}}",
                .{number},
            ),
            .real => |number| {
                if (!std.math.isFinite(number)) return error.NonFiniteReal;
                try out.print("{{\"t\":\"real\",\"r\":{d}}}", .{number});
            },
            .text => |bytes| {
                try out.writeAll("{\"t\":\"text\",\"v\":");
                try server.writeJsonString(out, bytes);
                try out.writeAll("}");
            },
            .blob => |bytes| {
                const encoder = std.base64.standard.Encoder;
                const encoded = try gpa.alloc(u8, encoder.calcSize(bytes.len));
                defer gpa.free(encoded);
                _ = encoder.encode(encoded, bytes);
                try out.print("{{\"t\":\"blob\",\"v\":\"{s}\"}}", .{encoded});
            },
        }
    }
    try out.writeAll("]");
}

// ----------------------------------------------------------------------
// Tests (pure logic; no sockets)
// ----------------------------------------------------------------------

test "seed parsing enforces bounds and unix isolation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectError(error.NoSeeds, parseSeeds(alloc, &.{}));

    var too_many: [max_seeds + 1][]const u8 = undefined;
    @memset(&too_many, "127.0.0.1:7001");
    try std.testing.expectError(
        error.TooManySeeds,
        parseSeeds(alloc, &too_many),
    );

    try std.testing.expectError(error.UnixSeedNotAlone, parseSeeds(
        alloc,
        &.{ "unix:/tmp/zx.sock", "127.0.0.1:7001" },
    ));

    // The ZDS requires unique seeds; a repeated address is refused
    // before any endpoint is parsed.
    try std.testing.expectError(error.DuplicateSeed, parseSeeds(
        alloc,
        &.{ "127.0.0.1:7001", "127.0.0.1:7002", "127.0.0.1:7001" },
    ));

    const single_unix = try parseSeeds(alloc, &.{"unix:/tmp/zx.sock"});
    try std.testing.expectEqualStrings(
        "/tmp/zx.sock",
        single_unix[0].unix_path.?,
    );

    const pair = try parseSeeds(
        alloc,
        &.{ "127.0.0.1:7001", "127.0.0.1:7002" },
    );
    try std.testing.expectEqual(@as(usize, 2), pair.len);
    try std.testing.expectEqual(@as(u16, 7002), pair[1].port);
}

test "pool sizing default and clamp" {
    try std.testing.expectEqual(@as(usize, 4), poolSlotCount(0, 1));
    try std.testing.expectEqual(@as(usize, 8), poolSlotCount(0, 4));
    try std.testing.expectEqual(@as(usize, 32), poolSlotCount(0, 36));
    try std.testing.expectEqual(@as(usize, 1), poolSlotCount(1, 36));
    try std.testing.expectEqual(
        @as(usize, max_pool_slots),
        poolSlotCount(1000, 3),
    );
    try std.testing.expectEqual(@as(usize, 17), poolSlotCount(17, 1));
}

test "batch exec request serializes one op, one session, one sequence" {
    const batch = [_][]const prepared.Value{
        &.{.{ .integer = 1 }},
        &.{.{ .text = "two" }},
        &.{.null_value},
    };
    const request = try buildExecBatchRequest(
        std.testing.allocator,
        "insert into t(v) values (?1)",
        &batch,
        7,
        42,
    );
    defer std.testing.allocator.free(request);
    try std.testing.expectEqualStrings(
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values (?1)\"," ++
            "\"format\":\"typed-v1\",\"param_batch\":[" ++
            "[{\"t\":\"int\",\"i\":1}]," ++
            "[{\"t\":\"text\",\"v\":\"two\"}]," ++
            "[{\"t\":\"null\"}]]," ++
            "\"session\":7,\"sequence\":42}",
        request,
    );
}

test "dev psk validation mirrors the server policy" {
    const loopback = [_]client.Endpoint{
        .{ .host = "127.0.0.1", .port = 7001 },
        .{ .host = "::1", .port = 7002 },
    };
    const routable = [_]client.Endpoint{
        .{ .host = "10.0.0.1", .port = 7001 },
    };
    const unix = [_]client.Endpoint{
        .{ .host = "/tmp/zx.sock", .unix_path = "/tmp/zx.sock" },
    };

    try checkTransportPolicy(&loopback, false, true, true);
    try std.testing.expectError(
        error.DevPskNeedsSecret,
        checkTransportPolicy(&loopback, false, false, true),
    );
    try std.testing.expectError(
        error.DevPskWithTls,
        checkTransportPolicy(&loopback, true, true, true),
    );
    try std.testing.expectError(
        error.DevPskNeedsLoopback,
        checkTransportPolicy(&routable, false, true, true),
    );
    try std.testing.expectError(
        error.DevPskWithUnixSocket,
        checkTransportPolicy(&unix, false, true, true),
    );

    try std.testing.expectError(
        error.TcpNeedsTls,
        checkTransportPolicy(&loopback, false, true, false),
    );
    try checkTransportPolicy(&loopback, true, false, false);
    try checkTransportPolicy(&unix, false, false, false);
    try std.testing.expectError(
        error.TlsWithUnixSocket,
        checkTransportPolicy(&unix, true, false, false),
    );
}

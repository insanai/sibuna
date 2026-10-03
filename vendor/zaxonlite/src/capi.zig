//! The zaxonlite C ABI: an embeddable replicated SQLite node behind a
//! small, stable C surface (see `include/zaxonlite.h`).
//!
//! Every handle owns its own `std.Io.Threaded` instance and node; handles
//! are independent and must be used from one thread at a time (or under
//! the caller's lock), matching SQLite's own connection discipline.
//!
//! Return codes mirror the CLI contract:
//!   0 ok, 1 SQL/session error, 2 misuse, 3 integrity failure,
//!   4 unavailable (locked, corrupt, or I/O failure).

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;
const Value = zaxonlite.Value;
const Embedded = zaxonlite.Embedded;

const ok_code: c_int = 0;
const sql_code: c_int = 1;
const misuse_code: c_int = 2;
const integrity_code: c_int = 3;
const unavailable_code: c_int = 4;

const Handle = struct {
    threaded: std.Io.Threaded,
    node: *Node,
    error_buffer: [512:0]u8 = undefined,
    error_category: c_int = 0,

    fn setError(self: *Handle, text: []const u8) void {
        const len = @min(text.len, self.error_buffer.len - 1);
        @memcpy(self.error_buffer[0..len], text[0..len]);
        self.error_buffer[len] = 0;
        self.error_category = category_none;
    }

    fn setCategorizedError(
        self: *Handle,
        text: []const u8,
        category: c_int,
    ) void {
        self.setError(text);
        self.error_category = category;
    }
};

const TransactionHandle = struct {
    owner: *Handle,
    transaction: zaxonlite.Transaction,
};

const ClusterHandle = struct {
    threaded: std.Io.Threaded,
    embedded: *Embedded,
    error_buffer: [512:0]u8 = undefined,

    fn setError(self: *ClusterHandle, text: []const u8) void {
        const len = @min(text.len, self.error_buffer.len - 1);
        @memcpy(self.error_buffer[0..len], text[0..len]);
        self.error_buffer[len] = 0;
    }
};

fn mapClusterError(handle: *ClusterHandle, err: anyerror) c_int {
    switch (err) {
        error.LocalNodeFailed, error.LocalNodeStopped => {
            handle.setError(@errorName(err));
            return unavailable_code;
        },
        else => {
            handle.setError(@errorName(err));
            return unavailable_code;
        },
    }
}

const CMember = extern struct {
    id: u32,
    address: ?[*:0]const u8,
    role: c_int,
};

const CClusterOptions = extern struct {
    directory: ?[*:0]const u8,
    node_id: u32,
    members: ?[*]const CMember,
    member_count: usize,
    cluster_id: ?[*:0]const u8,
    auth_secret: ?*const anyopaque,
    auth_secret_length: usize,
    tls_cert_path: ?[*:0]const u8,
    tls_key_path: ?[*:0]const u8,
    tls_ca_path: ?[*:0]const u8,
    startup_timeout_ms: u64,
    allow_insecure_test_tcp: bool,
};

/// Versioned cluster options (ZDS 0010). The v1 struct has no size or
/// version member, so fields must never be appended to it; v2 leads with
/// `struct_size` so later revisions can extend it compatibly.
const CClusterOptionsV2 = extern struct {
    struct_size: usize,
    directory: ?[*:0]const u8,
    node_id: u32,
    members: ?[*]const CMember,
    member_count: usize,
    cluster_id: ?[*:0]const u8,
    auth_secret: ?*const anyopaque,
    auth_secret_length: usize,
    /// PSK provider file, mutually exclusive with the raw `auth_secret`
    /// buffer. Loaded through the native provider path with its regular-
    /// file, symlink, permission, size, and minimum-length checks.
    auth_file_path: ?[*:0]const u8,
    tls_cert_path: ?[*:0]const u8,
    tls_key_path: ?[*:0]const u8,
    tls_ca_path: ?[*:0]const u8,
    startup_timeout_ms: u64,
    allow_insecure_test_tcp: bool,
    /// Development-only loopback PSK transport; see `Embedded.OpenOptions`.
    allow_psk_only_loopback: bool,
};

const CValue = extern struct {
    value_type: c_int,
    integer: i64,
    real: f64,
    bytes: ?*const anyopaque,
    length: usize,
};

const CExecResult = extern struct {
    changes: i64,
    last_insert_rowid: i64,
    has_last_insert_rowid: bool,
    replayed: bool,
};

pub const CSearchOptions = extern struct {
    fts_table: ?[*:0]const u8,
    vec_table: ?[*:0]const u8,
    text: ?*const anyopaque,
    text_length: usize,
    embedding: ?*const anyopaque,
    embedding_length: usize,
    k: u32,
    candidate_count: u32,
    has_candidate_count: bool,
    fusion: c_int,
    text_weight: f64,
    vector_weight: f64,
    metadata_table: ?[*:0]const u8,
    metadata_id_column: ?[*:0]const u8,
    metadata_columns: ?[*]const ?[*:0]const u8,
    metadata_column_count: usize,
};

const CStatementInfo = extern struct {
    parameter_count: u32,
    column_count: u32,
    read_only: bool,
    has_tail: bool,
};

// Stable error categories (`zaxonlite_last_error_category`). Values are
// part of the C ABI: only append.
const category_none: c_int = 0;
const category_constraint: c_int = 1;
const category_busy: c_int = 2;
const category_interrupt: c_int = 3;
const category_misuse: c_int = 4;
const category_storage: c_int = 5;
const category_integrity: c_int = 6;
const category_availability: c_int = 7;
const category_session: c_int = 8;
const category_sql_other: c_int = 9;
const category_validation: c_int = 10;

/// Opaque materialized typed result. Owns copied column names and cell
/// bytes; value pointers stay valid until `zaxonlite_result_close`.
pub const ResultHandle = struct {
    result: zaxonlite.TypedResult,
    column_names: []const [:0]const u8,
};

const gpa = std.heap.c_allocator;

// External-client (remote pool) C surface lives in its own file; this
// reference makes its exports part of the static library.
comptime {
    _ = @import("capi_remote.zig");
}

fn handleOf(pointer: ?*anyopaque) ?*Handle {
    return @ptrCast(@alignCast(pointer orelse return null));
}

fn mapError(handle: *Handle, err: anyerror) c_int {
    switch (err) {
        error.SqliteError, error.SqliteBusy, error.SqliteInterrupted => {
            handle.setCategorizedError(
                handle.node.lastSqliteMessage(),
                sqliteCategory(err, handle.node.lastSqliteExtendedCode()),
            );
            return sql_code;
        },
        error.UnknownSession, error.SequenceGap, error.ResultExpired => {
            handle.setCategorizedError(@errorName(err), category_session);
            return sql_code;
        },
        error.WriteInReadQuery, error.ParameterCountMismatch => {
            handle.setCategorizedError(
                "statement is not read-only",
                category_misuse,
            );
            return misuse_code;
        },
        error.TransactionFinished,
        error.EmptyTransaction,
        error.TooManyStatements,
        error.TransactionInputTooLarge,
        error.TransactionOpen,
        error.NoTransaction,
        error.ClusterTransactionUnsupported,
        => {
            handle.setCategorizedError(@errorName(err), category_misuse);
            return misuse_code;
        },
        error.NoRetriever,
        error.MissingText,
        error.MissingEmbedding,
        error.InvalidIdentifier,
        error.InvalidK,
        error.InvalidCandidateCount,
        error.InvalidEmbedding,
        error.InvalidWeight,
        error.InvalidMetadata,
        => {
            handle.setCategorizedError(@errorName(err), category_validation);
            return misuse_code;
        },
        error.StorageFailed => {
            handle.setCategorizedError(@errorName(err), category_storage);
            return unavailable_code;
        },
        else => {
            handle.setCategorizedError(@errorName(err), category_availability);
            return unavailable_code;
        },
    }
}

/// Categorizes an SQLite failure from its extended result code, so hosts
/// never parse message text. `SQLITE_CONSTRAINT` and its extensions map to
/// the constraint category; busy/locked and interrupt keep their own.
fn sqliteCategory(err: anyerror, extended_code: i32) c_int {
    if (err == error.SqliteBusy) return category_busy;
    if (err == error.SqliteInterrupted) return category_interrupt;
    return switch (extended_code & 0xff) {
        19 => category_constraint, // SQLITE_CONSTRAINT
        5, 6 => category_busy, // SQLITE_BUSY, SQLITE_LOCKED
        9 => category_interrupt, // SQLITE_INTERRUPT
        11 => category_integrity, // SQLITE_CORRUPT
        else => category_sql_other,
    };
}

export fn zaxonlite_version() [*:0]const u8 {
    return zaxonlite.version;
}

/// Opens (or creates) a node data directory. On success stores the handle
/// in `out_handle`.
export fn zaxonlite_open(
    directory: ?[*:0]const u8,
    out_handle: ?*?*anyopaque,
) c_int {
    const dir = directory orelse return misuse_code;
    const out = out_handle orelse return misuse_code;
    out.* = null;

    const handle = gpa.create(Handle) catch return unavailable_code;
    handle.* = .{
        .threaded = std.Io.Threaded.init(gpa, .{}),
        .node = undefined,
    };
    handle.error_buffer[0] = 0;
    const io = handle.threaded.io();

    handle.node = Node.open(gpa, io, .{
        .directory = std.mem.span(dir),
    }) catch |err| {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return switch (err) {
            error.NodeLocked => unavailable_code,
            else => unavailable_code,
        };
    };
    out.* = handle;
    return ok_code;
}

export fn zaxonlite_close(pointer: ?*anyopaque) void {
    const handle = handleOf(pointer) orelse return;
    handle.node.close();
    handle.threaded.deinit();
    gpa.destroy(handle);
}

/// Opens a transport-owning embedded cluster member (legacy v1 layout).
export fn zaxonlite_cluster_open(
    raw_options: ?*const CClusterOptions,
    out_handle: ?*?*anyopaque,
) c_int {
    const options = raw_options orelse return misuse_code;
    return clusterOpen(.{
        .struct_size = @sizeOf(CClusterOptionsV2),
        .directory = options.directory,
        .node_id = options.node_id,
        .members = options.members,
        .member_count = options.member_count,
        .cluster_id = options.cluster_id,
        .auth_secret = options.auth_secret,
        .auth_secret_length = options.auth_secret_length,
        .auth_file_path = null,
        .tls_cert_path = options.tls_cert_path,
        .tls_key_path = options.tls_key_path,
        .tls_ca_path = options.tls_ca_path,
        .startup_timeout_ms = options.startup_timeout_ms,
        .allow_insecure_test_tcp = options.allow_insecure_test_tcp,
        .allow_psk_only_loopback = false,
    }, out_handle);
}

/// Opens a transport-owning embedded cluster member with the versioned
/// options: a PSK provider file, the development loopback-PSK flag, and a
/// single-node Unix-domain listener named by a `unix:<path>` member
/// address.
export fn zaxonlite_cluster_open_v2(
    raw_options: ?*const CClusterOptionsV2,
    out_handle: ?*?*anyopaque,
) c_int {
    const options = raw_options orelse return misuse_code;
    if (options.struct_size != @sizeOf(CClusterOptionsV2)) return misuse_code;
    return clusterOpen(options.*, out_handle);
}

fn clusterOpen(options: CClusterOptionsV2, out_handle: ?*?*anyopaque) c_int {
    const out = out_handle orelse return misuse_code;
    out.* = null;
    _ = options.directory orelse return misuse_code;
    // Every declared count is reduced to the product limit before any
    // slice is formed or allocation sized from it.
    if (options.member_count == 0 or
        options.member_count > zaxonlite.embedded.max_registry_members)
    {
        return misuse_code;
    }
    // A provider file and a raw secret buffer are mutually exclusive.
    if (options.auth_file_path != null and
        (options.auth_secret != null or options.auth_secret_length != 0))
    {
        return misuse_code;
    }
    const raw_secret = parseAuthSecret(&options) catch return misuse_code;

    const members = parseClusterMembers(&options) catch |err| switch (err) {
        error.Misuse => return misuse_code,
        error.Unavailable => return unavailable_code,
    };
    defer gpa.free(members);

    const handle = gpa.create(ClusterHandle) catch return unavailable_code;
    handle.* = .{
        .threaded = std.Io.Threaded.init(gpa, .{}),
        .embedded = undefined,
    };
    handle.error_buffer[0] = 0;
    if (!validTlsOptions(&options)) {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return misuse_code;
    }

    handle.embedded = openEmbeddedCluster(
        handle,
        &options,
        members,
        raw_secret,
    ) catch |err| {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return clusterOpenErrorCode(err);
    };
    out.* = handle;
    return ok_code;
}

fn validTlsOptions(options: *const CClusterOptionsV2) bool {
    const any_tls = options.tls_cert_path != null or
        options.tls_key_path != null or options.tls_ca_path != null;
    return !any_tls or (options.tls_cert_path != null and
        options.tls_key_path != null and options.tls_ca_path != null);
}

fn openEmbeddedCluster(
    handle: *ClusterHandle,
    options: *const CClusterOptionsV2,
    members: []const zaxonlite.EmbeddedMember,
    raw_secret: ?[]const u8,
) !*Embedded {
    // Provider secrets are loaded through the native validation path
    // (regular file, no symlink, owner-only mode, bounded size) and zeroed
    // after `Embedded.open` copies the bytes it needs.
    var provider_secret: ?zaxonlite.configuration.Secret = null;
    defer if (provider_secret) |*secret| secret.deinit(gpa);
    var secret_bytes: ?[]const u8 = raw_secret;
    if (options.auth_file_path) |path| {
        provider_secret = zaxonlite.configuration.loadSecret(
            gpa,
            handle.threaded.io(),
            std.mem.span(path),
        ) catch return error.InvalidSecretProvider;
        secret_bytes = provider_secret.?.bytes;
    }
    const any_tls = options.tls_cert_path != null;
    return Embedded.open(gpa, handle.threaded.io(), .{
        .directory = std.mem.span(options.directory.?),
        .node_id = options.node_id,
        .members = members,
        .cluster_id = if (options.cluster_id) |text| std.mem.span(text) else null,
        .auth_secret = secret_bytes,
        .tls = if (any_tls) .{
            .cert_path = std.mem.span(options.tls_cert_path.?),
            .key_path = std.mem.span(options.tls_key_path.?),
            .ca_path = std.mem.span(options.tls_ca_path.?),
        } else null,
        .startup_timeout_ms = if (options.startup_timeout_ms == 0)
            10_000
        else
            options.startup_timeout_ms,
        .allow_insecure_test_tcp = options.allow_insecure_test_tcp,
        .allow_psk_only_loopback = options.allow_psk_only_loopback,
    });
}

fn clusterOpenErrorCode(err: anyerror) c_int {
    return switch (err) {
        error.InvalidSecretProvider,
        error.DevPskNeedsSecret,
        error.DevPskWithTls,
        error.DevPskWithInsecureTcp,
        error.DevPskNeedsLoopback,
        error.DevPskWithUnixSocket,
        error.UnixSocketNeedsSingleMember,
        error.UnixSocketGateway,
        error.InvalidEndpoint,
        error.InvalidMemberCount,
        error.InvalidNodeId,
        error.DuplicateNodeId,
        error.DuplicateEndpoint,
        error.InvalidVoterCount,
        error.CampaignerRequired,
        error.NotMember,
        => misuse_code,
        else => unavailable_code,
    };
}

fn parseAuthSecret(options: *const CClusterOptionsV2) !?[]const u8 {
    if (options.auth_secret) |pointer| {
        if (options.auth_secret_length == 0 or
            options.auth_secret_length > zaxonlite.configuration.maximum_secret_file_bytes)
        {
            return error.Misuse;
        }
        return @as([*]const u8, @ptrCast(pointer))[0..options.auth_secret_length];
    } else if (options.auth_secret_length == 0) {
        return null;
    }
    return error.Misuse;
}

fn parseClusterMembers(options: *const CClusterOptionsV2) ![]zaxonlite.EmbeddedMember {
    const raw_members = options.members orelse return error.Misuse;
    const members = gpa.alloc(zaxonlite.EmbeddedMember, options.member_count) catch
        return error.Unavailable;
    errdefer gpa.free(members);
    for (raw_members[0..options.member_count], members) |source, *destination| {
        const address = source.address orelse return error.Misuse;
        const role = std.enums.fromInt(zaxonlite.Role, source.role) orelse return error.Misuse;
        destination.* = .{
            .id = source.id,
            .address = std.mem.span(address),
            .role = role,
        };
    }
    return members;
}

export fn zaxonlite_cluster_close(pointer: ?*anyopaque) void {
    const handle: *ClusterHandle = @ptrCast(@alignCast(pointer orelse return));
    handle.embedded.close();
    handle.threaded.deinit();
    gpa.destroy(handle);
}

/// Returns the embedding-local lifecycle without routing through a peer:
/// 0 healthy, 1 stopping, 2 stopped, 4 failed. On failure, copies the first
/// error name into the caller's optional bounded buffer.
export fn zaxonlite_cluster_state(
    pointer: ?*anyopaque,
    out_failure: ?[*]u8,
    out_len: usize,
) c_int {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    if (out_failure == null and out_len != 0) return misuse_code;
    if (out_failure) |out| {
        if (out_len != 0) out[0] = 0;
    }
    return switch (handle.embedded.localServerState()) {
        .healthy => 0,
        .stopping => 1,
        .stopped => 2,
        .failed => |name| blk: {
            if (out_failure) |out| {
                if (out_len != 0) {
                    const len = @min(name.len, out_len - 1);
                    @memcpy(out[0..len], name[0..len]);
                    out[len] = 0;
                }
            }
            break :blk 4;
        },
    };
}

export fn zaxonlite_cluster_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const result = handle.embedded.exec(std.mem.span(statement)) catch |err| {
        return mapClusterError(handle, err);
    };
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_cluster_query_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    var result = handle.embedded.query(gpa, std.mem.span(statement)) catch |err| {
        return mapClusterError(handle, err);
    };
    defer result.deinit();
    return resultJson(&result, out);
}

export fn zaxonlite_cluster_call_json(
    pointer: ?*anyopaque,
    request: ?[*:0]const u8,
    require_leader: bool,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const body = request orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    const response = handle.embedded.call(
        std.mem.span(body),
        require_leader,
    ) catch |err| {
        return mapClusterError(handle, err);
    };
    defer gpa.free(response);
    const owned = gpa.alloc(u8, response.len + 1) catch return unavailable_code;
    @memcpy(owned[0..response.len], response);
    owned[response.len] = 0;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

export fn zaxonlite_cluster_last_error(pointer: ?*anyopaque) [*:0]const u8 {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return "invalid cluster handle",
    ));
    return &handle.error_buffer;
}

/// Executes one replicated write transaction.
export fn zaxonlite_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const result = handle.node.exec(std.mem.span(statement)) catch |err|
        return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_exec_prepared(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    const result = handle.node.execPrepared(
        std.mem.span(statement),
        values,
    ) catch |err| return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_transaction_begin(
    pointer: ?*anyopaque,
    out_transaction: ?*?*anyopaque,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const out = out_transaction orelse return misuse_code;
    out.* = null;
    const transaction = gpa.create(TransactionHandle) catch return unavailable_code;
    transaction.* = .{
        .owner = handle,
        .transaction = zaxonlite.Transaction.init(gpa),
    };
    out.* = transaction;
    return ok_code;
}

export fn zaxonlite_transaction_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
) c_int {
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        transaction.owner.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    transaction.transaction.exec(std.mem.span(statement), values) catch |err| {
        transaction.owner.setError(@errorName(err));
        return misuse_code;
    };
    return ok_code;
}

export fn zaxonlite_transaction_commit(
    pointer: ?*anyopaque,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const result = transaction.owner.node.execTransaction(
        &transaction.transaction,
    ) catch |err| return mapError(transaction.owner, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_transaction_close(pointer: ?*anyopaque) void {
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return,
    ));
    transaction.transaction.deinit();
    gpa.destroy(transaction);
}

/// Opens a replicated client session for idempotent retry.
export fn zaxonlite_session_open(
    pointer: ?*anyopaque,
    session_out: ?*u64,
) c_int {
    const out = session_out orelse return misuse_code;
    out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    out.* = handle.node.openSession() catch |err| return mapError(handle, err);
    return ok_code;
}

/// Executes `sequence` for `session` exactly once; a repeat of the last
/// sequence sets `replayed_out` and returns the recorded change count.
export fn zaxonlite_exec_idempotent(
    pointer: ?*anyopaque,
    session: u64,
    sequence: u64,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
    replayed_out: ?*bool,
) c_int {
    if (changes_out) |out| out.* = 0;
    if (replayed_out) |out| out.* = false;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const result = handle.node.execIdempotent(
        session,
        sequence,
        std.mem.span(statement),
    ) catch |err| return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    if (replayed_out) |out| out.* = result.replayed;
    return ok_code;
}

/// Runs a read-only query and returns one JSON object
/// `{"columns":[...],"rows":[[...]]}` in `json_out`, released with
/// `zaxonlite_free`.
export fn zaxonlite_query_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;

    return queryPreparedJson(handle, std.mem.span(statement), &.{}, out);
}

export fn zaxonlite_query_prepared_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    return queryPreparedJson(handle, std.mem.span(statement), values, out);
}

fn queryPreparedJson(
    handle: *Handle,
    sql: []const u8,
    values: []const Value,
    out: *?[*:0]u8,
) c_int {
    var result = handle.node.queryPrepared(gpa, sql, values) catch |err|
        return mapError(handle, err);
    defer result.deinit();

    return resultJson(&result, out);
}

fn resultJson(result: *const zaxonlite.QueryResult, out: *?[*:0]u8) c_int {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const writer = &buffer.writer;
    writeJson(writer, result) catch return unavailable_code;
    writer.writeByte(0) catch return unavailable_code;
    const owned = buffer.toOwnedSlice() catch return unavailable_code;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

fn valuesFromC(raw_values: ?[*]const CValue, count: usize) ![]Value {
    if (count == 0) return gpa.alloc(Value, 0);
    const source = raw_values orelse return error.NullValues;
    // Checked before the count sizes an allocation or slices caller memory.
    if (count > zaxonlite.prepared.maximum_statements * 64) {
        return error.TooManyValues;
    }
    const values = try gpa.alloc(Value, count);
    errdefer gpa.free(values);
    for (source[0..count], values) |source_value, *destination| {
        destination.* = switch (source_value.value_type) {
            0 => .null_value,
            1 => .{ .integer = source_value.integer },
            2 => .{ .real = source_value.real },
            3 => .{ .text = try cBytes(source_value) },
            4 => .{ .blob = try cBytes(source_value) },
            else => return error.InvalidValueType,
        };
    }
    return values;
}

fn cBytes(value: CValue) ![]const u8 {
    if (value.length == 0) return "";
    // A declared length beyond the transaction input limit can never be
    // valid, so it is rejected before the caller's memory is sliced.
    if (value.length > zaxonlite.prepared.maximum_input_bytes) {
        return error.ValueTooLarge;
    }
    const pointer = value.bytes orelse return error.NullValueBytes;
    return @as([*]const u8, @ptrCast(pointer))[0..value.length];
}

fn writeJson(writer: *std.Io.Writer, result: *const zaxonlite.QueryResult) !void {
    try writer.writeAll("{\"columns\":[");
    for (result.columns, 0..) |column, index| {
        if (index > 0) try writer.writeAll(",");
        try zaxonlite.server.writeJsonString(writer, column);
    }
    try writer.writeAll("],\"rows\":[");
    for (result.rows, 0..) |row, row_index| {
        if (row_index > 0) try writer.writeAll(",");
        try writer.writeAll("[");
        for (row, 0..) |cell, index| {
            if (index > 0) try writer.writeAll(",");
            if (cell) |text| {
                try zaxonlite.server.writeJsonString(writer, text);
            } else {
                try writer.writeAll("null");
            }
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]}");
}

/// Wraps a typed result in an opaque handle. Column names are re-copied
/// with NUL terminators into the result's own arena so their lifetime is
/// exactly the handle's.
pub fn typedResultHandle(result: zaxonlite.TypedResult) !*ResultHandle {
    var owned = result;
    errdefer owned.deinit();
    const alloc = owned.arena.allocator();
    const names = try alloc.alloc([:0]const u8, owned.columns.len);
    for (owned.columns, names) |column, *name| {
        name.* = try alloc.dupeSentinel(u8, column, 0);
    }
    const handle = try gpa.create(ResultHandle);
    handle.* = .{ .result = owned, .column_names = names };
    return handle;
}

fn resultHandleOf(pointer: ?*anyopaque) ?*ResultHandle {
    return @ptrCast(@alignCast(pointer orelse return null));
}

/// Runs a read-only prepared query and returns an opaque typed result in
/// `out_result`, released with `zaxonlite_result_close`.
export fn zaxonlite_query_prepared_result(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    out_result: ?*?*anyopaque,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = out_result orelse return misuse_code;
    out.* = null;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setCategorizedError(@errorName(err), category_misuse);
        return misuse_code;
    };
    defer gpa.free(values);
    const typed = handle.node.queryPreparedTyped(
        gpa,
        std.mem.span(statement),
        values,
    ) catch |err| return mapError(handle, err);
    out.* = typedResultHandle(typed) catch return unavailable_code;
    return ok_code;
}

/// Executes one prepared statement as a replicated write and reports the
/// structured result. When the statement has a `RETURNING` clause its
/// typed rows are stored in `out_returning` (release with
/// `zaxonlite_result_close`); pass null to discard them.
export fn zaxonlite_exec_prepared_result(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    exec_out: ?*CExecResult,
    out_returning: ?*?*anyopaque,
) c_int {
    if (exec_out) |out| out.* = .{
        .changes = 0,
        .last_insert_rowid = 0,
        .has_last_insert_rowid = false,
        .replayed = false,
    };
    if (out_returning) |out| out.* = null;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setCategorizedError(@errorName(err), category_misuse);
        return misuse_code;
    };
    defer gpa.free(values);
    var returning: ?zaxonlite.TypedResult = null;
    const result = handle.node.execPreparedResult(
        gpa,
        std.mem.span(statement),
        values,
        &returning,
    ) catch |err| return mapError(handle, err);
    if (exec_out) |out| out.* = .{
        .changes = result.changes,
        .last_insert_rowid = result.last_insert_rowid orelse 0,
        .has_last_insert_rowid = result.last_insert_rowid != null,
        .replayed = result.replayed,
    };
    if (returning) |typed| {
        if (out_returning) |out| {
            out.* = typedResultHandle(typed) catch return unavailable_code;
        } else {
            var owned = typed;
            owned.deinit();
        }
    }
    return ok_code;
}

export fn zaxonlite_result_column_count(pointer: ?*const anyopaque) usize {
    const handle: *const ResultHandle = @ptrCast(@alignCast(
        pointer orelse return 0,
    ));
    return handle.result.columns.len;
}

export fn zaxonlite_result_row_count(pointer: ?*const anyopaque) usize {
    const handle: *const ResultHandle = @ptrCast(@alignCast(
        pointer orelse return 0,
    ));
    return handle.result.rows.len;
}

/// Bounds-checked column name; null when the index is out of range.
export fn zaxonlite_result_column_name(
    pointer: ?*const anyopaque,
    column: usize,
) ?[*:0]const u8 {
    const handle: *const ResultHandle = @ptrCast(@alignCast(
        pointer orelse return null,
    ));
    if (column >= handle.column_names.len) return null;
    return handle.column_names[column].ptr;
}

/// Copies one cell into `out_value`. Text and blob bytes are borrowed and
/// stay valid until `zaxonlite_result_close`. Integer and real values
/// preserve SQLite's runtime storage class; zero-length text or blob is
/// distinct from NULL.
export fn zaxonlite_result_value(
    pointer: ?*const anyopaque,
    row: usize,
    column: usize,
    out_value: ?*CValue,
) c_int {
    const out = out_value orelse return misuse_code;
    out.* = .{
        .value_type = 0,
        .integer = 0,
        .real = 0,
        .bytes = null,
        .length = 0,
    };
    const handle: *const ResultHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    if (row >= handle.result.rows.len) return misuse_code;
    const cells = handle.result.rows[row];
    if (column >= cells.len) return misuse_code;
    switch (cells[column]) {
        .null_value => {},
        .integer => |number| {
            out.value_type = 1;
            out.integer = number;
        },
        .real => |number| {
            out.value_type = 2;
            out.real = number;
        },
        .text => |bytes| {
            out.value_type = 3;
            out.bytes = bytes.ptr;
            out.length = bytes.len;
        },
        .blob => |bytes| {
            out.value_type = 4;
            out.bytes = bytes.ptr;
            out.length = bytes.len;
        },
    }
    return ok_code;
}

/// Releases a typed result handle. Accepts null.
export fn zaxonlite_result_close(pointer: ?*anyopaque) void {
    const handle = resultHandleOf(pointer) orelse return;
    handle.result.deinit();
    gpa.destroy(handle);
}

/// Typed search (ZDS 0009) over the node's validated planner. Identifier,
/// weight, embedding-shape, and candidate-cap validation stay in Zig; the
/// result is a normal typed result handle.
export fn zaxonlite_search(
    pointer: ?*anyopaque,
    raw_options: ?*const CSearchOptions,
    out_result: ?*?*anyopaque,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const options = raw_options orelse return misuse_code;
    const out = out_result orelse return misuse_code;
    out.* = null;

    var metadata_buffer: [64][]const u8 = undefined;
    const request = searchRequest(
        handle,
        options,
        &metadata_buffer,
    ) orelse return misuse_code;
    const typed = handle.node.searchTyped(gpa, request, .{}) catch |err|
        return mapError(handle, err);
    out.* = typedResultHandle(typed) catch return unavailable_code;
    return ok_code;
}

fn searchRequest(
    handle: *Handle,
    options: *const CSearchOptions,
    metadata_buffer: *[64][]const u8,
) ?zaxonlite.SearchRequest {
    if (!validSearchBytes(options.text, options.text_length) or
        !validSearchBytes(options.embedding, options.embedding_length))
    {
        handle.setCategorizedError("InvalidSearchBytes", category_validation);
        return null;
    }
    if (options.metadata_column_count > 64) {
        handle.setCategorizedError("InvalidMetadata", category_validation);
        return null;
    }
    const metadata_columns =
        metadata_buffer[0..options.metadata_column_count];
    if (options.metadata_column_count > 0) {
        const raw_columns = options.metadata_columns orelse {
            handle.setCategorizedError("InvalidMetadata", category_validation);
            return null;
        };
        for (
            raw_columns[0..options.metadata_column_count],
            metadata_columns,
        ) |raw_column, *column| {
            const text = raw_column orelse {
                handle.setCategorizedError(
                    "InvalidMetadata",
                    category_validation,
                );
                return null;
            };
            column.* = std.mem.span(text);
        }
    }
    return .{
        .fts_table = if (options.fts_table) |text| std.mem.span(text) else null,
        .vec_table = if (options.vec_table) |text| std.mem.span(text) else null,
        .text = searchBytes(options.text, options.text_length),
        .embedding = searchBytes(options.embedding, options.embedding_length),
        .k = options.k,
        .candidate_count = if (options.has_candidate_count)
            options.candidate_count
        else
            null,
        .fusion = switch (options.fusion) {
            0 => .rrf,
            1 => .dbsf,
            else => {
                handle.setCategorizedError(
                    "invalid fusion",
                    category_validation,
                );
                return null;
            },
        },
        .text_weight = options.text_weight,
        .vector_weight = options.vector_weight,
        .metadata_table = if (options.metadata_table) |text|
            std.mem.span(text)
        else
            null,
        .metadata_id_column = if (options.metadata_id_column) |text|
            std.mem.span(text)
        else
            null,
        .metadata_columns = metadata_columns,
    };
}

fn validSearchBytes(pointer: ?*const anyopaque, length: usize) bool {
    if (length > zaxonlite.prepared.maximum_input_bytes) return false;
    return pointer != null or length == 0;
}

fn searchBytes(pointer: ?*const anyopaque, length: usize) ?[]const u8 {
    const raw = pointer orelse return null;
    return @as([*]const u8, @ptrCast(raw))[0..length];
}

/// Prepares (without executing) the first statement and reports parameter
/// count, result-column count, read-only classification, and whether a
/// trailing statement follows.
export fn zaxonlite_statement_describe(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    out_info: ?*CStatementInfo,
) c_int {
    const out = out_info orelse return misuse_code;
    out.* = .{
        .parameter_count = 0,
        .column_count = 0,
        .read_only = false,
        .has_tail = false,
    };
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const info = handle.node.statementInfo(std.mem.span(statement)) catch |err|
        return mapError(handle, err);
    out.* = .{
        .parameter_count = info.parameter_count,
        .column_count = info.column_count,
        .read_only = info.read_only,
        .has_tail = info.has_tail,
    };
    return ok_code;
}

/// Copies the NUL-terminated name of one bound parameter (1-based index)
/// into `buffer`; writes an empty string for positional parameters.
/// Returns misuse for an out-of-range index or a too-small buffer.
export fn zaxonlite_statement_parameter_name(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    index: u32,
    buffer: ?[*]u8,
    buffer_len: usize,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = buffer orelse return misuse_code;
    if (buffer_len == 0) return misuse_code;
    out[0] = 0;
    var name_buffer: [256]u8 = undefined;
    const len = handle.node.statementParameterName(
        std.mem.span(statement),
        index,
        &name_buffer,
    ) catch |err| return mapError(handle, err);
    if (len + 1 > buffer_len) {
        handle.setCategorizedError("parameter name buffer too small", category_misuse);
        return misuse_code;
    }
    @memcpy(out[0..len], name_buffer[0..len]);
    out[len] = 0;
    return ok_code;
}

/// Stable category of the most recent error on this handle:
/// 0 none, 1 constraint, 2 busy, 3 interrupt, 4 misuse, 5 storage,
/// 6 integrity, 7 availability, 8 session, 9 other SQL, 10 validation.
export fn zaxonlite_last_error_category(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return category_none;
    return handle.error_category;
}

// ----------------------------------------------------------------------
// Gate C: live transactions (single-member local handles only)
// ----------------------------------------------------------------------

/// Opens a live SQLite transaction on the writer connection. Later
/// statements observe earlier uncommitted writes; nothing replicates
/// until `zaxonlite_live_commit`.
export fn zaxonlite_live_begin(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.beginLive() catch |err| return mapError(handle, err);
    return ok_code;
}

/// Executes one statement inside the live transaction. Reads observe
/// uncommitted writes; `RETURNING` rows land in `out_returning`.
export fn zaxonlite_live_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    exec_out: ?*CExecResult,
    out_returning: ?*?*anyopaque,
) c_int {
    if (exec_out) |out| out.* = .{
        .changes = 0,
        .last_insert_rowid = 0,
        .has_last_insert_rowid = false,
        .replayed = false,
    };
    if (out_returning) |out| out.* = null;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setCategorizedError(@errorName(err), category_misuse);
        return misuse_code;
    };
    defer gpa.free(values);
    var returning: ?zaxonlite.TypedResult = null;
    const result = handle.node.liveExec(
        gpa,
        std.mem.span(statement),
        values,
        &returning,
    ) catch |err| return mapError(handle, err);
    if (exec_out) |out| out.* = .{
        .changes = result.changes,
        .last_insert_rowid = result.last_insert_rowid orelse 0,
        .has_last_insert_rowid = result.last_insert_rowid != null,
        .replayed = false,
    };
    if (returning) |typed| {
        if (out_returning) |out| {
            out.* = typedResultHandle(typed) catch return unavailable_code;
        } else {
            var owned = typed;
            owned.deinit();
        }
    }
    return ok_code;
}

/// Host-managed savepoints named by ordinal; arbitrary application
/// transaction-control SQL stays denied by the guard.
export fn zaxonlite_live_savepoint(pointer: ?*anyopaque, index: u32) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.liveSavepoint(index) catch |err| return mapError(handle, err);
    return ok_code;
}

export fn zaxonlite_live_release_savepoint(
    pointer: ?*anyopaque,
    index: u32,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.liveReleaseSavepoint(index) catch |err|
        return mapError(handle, err);
    return ok_code;
}

export fn zaxonlite_live_rollback_to_savepoint(
    pointer: ?*anyopaque,
    index: u32,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.liveRollbackToSavepoint(index) catch |err|
        return mapError(handle, err);
    return ok_code;
}

/// Commits the live transaction: one captured WAL transition, one
/// replicated batch, acknowledged only after the slot is applied.
export fn zaxonlite_live_commit(
    pointer: ?*anyopaque,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const result = handle.node.commitLive() catch |err|
        return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

/// Rolls the live transaction back; nothing is replicated.
export fn zaxonlite_live_rollback(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.rollbackLive() catch |err| return mapError(handle, err);
    return ok_code;
}

/// True while a live transaction is open on this handle.
export fn zaxonlite_live_active(pointer: ?*anyopaque) bool {
    const handle = handleOf(pointer) orelse return false;
    return handle.node.inLiveTransaction();
}

/// Releases a buffer returned by `zaxonlite_query_json`.
export fn zaxonlite_free(pointer: ?[*:0]u8) void {
    const raw = pointer orelse return;
    const body = std.mem.span(raw);
    gpa.free(raw[0 .. body.len + 1]);
}

/// Publishes a durable state anchor so recovery resumes from it instead
/// of replaying the whole retained journal (ZDS 0011).
export fn zaxonlite_state_anchor(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.createStateAnchor() catch |err| return mapError(handle, err);
    return ok_code;
}

/// Streams a consistent logical backup to `path`.
export fn zaxonlite_backup(pointer: ?*anyopaque, path: ?[*:0]const u8) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const destination = path orelse return misuse_code;
    handle.node.backup(std.mem.span(destination)) catch |err|
        return mapError(handle, err);
    return ok_code;
}

/// Verifies the SQLite image, the descriptor chain, and payload
/// availability. Returns 0 when everything passes, 3 otherwise.
export fn zaxonlite_integrity_check(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const report = handle.node.integrityCheck() catch |err|
        return mapError(handle, err);
    return if (report.ok()) ok_code else integrity_code;
}

/// Deletes sessions idle for more than `retain` recent session writes.
export fn zaxonlite_expire_sessions(
    pointer: ?*anyopaque,
    retain: u64,
    expired_out: ?*i64,
) c_int {
    if (expired_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const result = handle.node.expireSessions(retain) catch |err|
        return mapError(handle, err);
    if (expired_out) |out| out.* = result.changes;
    return ok_code;
}

/// The most recent error message for this handle.
export fn zaxonlite_last_error(pointer: ?*anyopaque) [*:0]const u8 {
    const handle = handleOf(pointer) orelse return "invalid handle";
    return &handle.error_buffer;
}

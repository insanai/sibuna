//! External-client remote pool C ABI (ZDS 0010 Gate B): the
//! `zaxonlite_remote_*` exports over `zaxonlite.remote.Remote`. Opens no
//! data directory and no listener; every handle owns its own
//! `std.Io.Threaded` instance, like the node and cluster handles, and
//! serves typed results through the same opaque representation as the
//! local `zaxonlite_result_*` accessors.

const std = @import("std");
const zaxonlite = @import("zaxonlite");
const capi = @import("capi.zig");

const remote_mod = zaxonlite.remote;
const Remote = remote_mod.Remote;
const Value = zaxonlite.Value;

const ok_code: c_int = 0;
const sql_code: c_int = 1;
const misuse_code: c_int = 2;
const integrity_code: c_int = 3;
const unavailable_code: c_int = 4;

// Mirrors capi.zig's stable error-category ABI values.
const category_none: c_int = 0;
const category_busy: c_int = 2;
const category_misuse: c_int = 4;
const category_integrity: c_int = 6;
const category_availability: c_int = 7;
const category_session: c_int = 8;
const category_sql_other: c_int = 9;
const category_validation: c_int = 10;

const gpa = std.heap.c_allocator;

/// Mirrors `zaxonlite_remote_options` in include/zaxonlite.h.
const CRemoteOptions = extern struct {
    seeds: ?[*]const ?[*:0]const u8,
    seed_count: usize,
    tls_ca_path: ?[*:0]const u8,
    tls_cert_path: ?[*:0]const u8,
    tls_key_path: ?[*:0]const u8,
    auth_file_path: ?[*:0]const u8,
    allow_psk_only_loopback: bool,
    pool_size: usize,
    connect_timeout_ms: u64,
    operation_timeout_ms: u64,
    has_expected_database_id: bool,
    expected_database_id: [16]u8,
    // Appended before the first release of this ABI (the struct has no
    // size/version member, so its layout freezes at release).
    write_admission_timeout_ms: u64,
};

// Local mirrors of the header's value and write-result structs; the
// layouts are fixed by the C ABI.
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

const RemoteHandle = struct {
    threaded: std.Io.Threaded,
    remote: *Remote,
    error_buffer: [512:0]u8 = undefined,
    error_category: c_int = 0,

    fn setError(self: *RemoteHandle, text: []const u8, category: c_int) void {
        const len = @min(text.len, self.error_buffer.len - 1);
        @memcpy(self.error_buffer[0..len], text[0..len]);
        self.error_buffer[len] = 0;
        self.error_category = category;
    }
};

fn remoteHandleOf(pointer: ?*anyopaque) ?*RemoteHandle {
    return @ptrCast(@alignCast(pointer orelse return null));
}

/// Maps a Remote failure onto the handle's error buffer, its stable
/// category, and the shared C return codes. Definitive server
/// rejections carry the server's own code and message.
fn mapRemoteError(handle: *RemoteHandle, err: anyerror) c_int {
    switch (err) {
        error.WritePending => {
            handle.setError(
                "write pending: call zaxonlite_remote_resolve_pending",
                category_availability,
            );
            return unavailable_code;
        },
        error.NoPendingWrite => {
            handle.setError("no pending write", category_misuse);
            return misuse_code;
        },
        error.DatabaseMismatch => {
            handle.setError(
                "seed answered for a different database identity",
                category_integrity,
            );
            return integrity_code;
        },
        error.TypedV1Unsupported => {
            handle.setError(
                "server does not advertise typed-v1",
                category_validation,
            );
            return unavailable_code;
        },
        error.ServerRejected => return mapServerRejection(handle),
        error.WriteQueueTimeout => {
            // Admission timed out before anything was sent: the write
            // never left the process, so a plain retry is safe.
            handle.setError(
                "write queue admission timed out",
                category_busy,
            );
            return unavailable_code;
        },
        error.Closed => {
            handle.setError(
                "remote handle is closing",
                category_misuse,
            );
            return misuse_code;
        },
        error.NonFiniteReal,
        error.InvalidValueType,
        error.NullValues,
        error.NullValueBytes,
        error.ValueTooLarge,
        error.TooManyValues,
        error.EmptyBatch,
        error.TooManyStatements,
        => {
            handle.setError(@errorName(err), category_misuse);
            return misuse_code;
        },
        error.InvalidWeight => {
            handle.setError("search weights must be finite", category_validation);
            return misuse_code;
        },
        else => {
            handle.setError(@errorName(err), category_availability);
            return unavailable_code;
        },
    }
}

fn mapServerRejection(handle: *RemoteHandle) c_int {
    const code = handle.remote.lastServerCode();
    const message = handle.remote.lastServerMessage();
    if (std.mem.eql(u8, code, "sql")) {
        handle.setError(message, category_sql_other);
        return sql_code;
    }
    if (std.mem.eql(u8, code, "session")) {
        handle.setError(message, category_session);
        return sql_code;
    }
    if (std.mem.eql(u8, code, "bad_request") or
        std.mem.eql(u8, code, "forbidden") or
        std.mem.eql(u8, code, "too_large"))
    {
        handle.setError(message, category_misuse);
        return misuse_code;
    }
    handle.setError(message, category_availability);
    return unavailable_code;
}

fn mapRemoteSearchError(handle: *RemoteHandle, err: anyerror) c_int {
    if (err == error.ServerRejected and
        std.mem.eql(u8, handle.remote.lastServerCode(), "bad_request"))
    {
        handle.setError(
            handle.remote.lastServerMessage(),
            category_validation,
        );
        return misuse_code;
    }
    return mapRemoteError(handle, err);
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
    if (value.length > zaxonlite.prepared.maximum_input_bytes) {
        return error.ValueTooLarge;
    }
    const pointer = value.bytes orelse return error.NullValueBytes;
    return @as([*]const u8, @ptrCast(pointer))[0..value.length];
}

/// Opens a pooled remote client over the seed list. Configuration is
/// validated (seed bounds and uniqueness, unix isolation, TLS triple,
/// PSK loopback policy, secret provider file) before the handle
/// exists, then one seed must authenticate, report the expected
/// database identity, and answer a client RPC (the open-time probe,
/// bounded by connect_timeout_ms); the remaining slots dial lazily.
export fn zaxonlite_remote_open(
    raw_options: ?*const CRemoteOptions,
    out_handle: ?*?*anyopaque,
) c_int {
    const options = raw_options orelse return misuse_code;
    const out = out_handle orelse return misuse_code;
    out.* = null;
    if (options.seed_count == 0 or options.seed_count > remote_mod.max_seeds) {
        return misuse_code;
    }
    const raw_seeds = options.seeds orelse return misuse_code;
    var seed_storage: [remote_mod.max_seeds][]const u8 = undefined;
    for (
        raw_seeds[0..options.seed_count],
        seed_storage[0..options.seed_count],
    ) |raw_seed, *seed| {
        const text = raw_seed orelse return misuse_code;
        seed.* = std.mem.span(text);
    }
    const any_tls = options.tls_ca_path != null or
        options.tls_cert_path != null or options.tls_key_path != null;
    if (!validTlsOptions(options, any_tls)) {
        return misuse_code;
    }

    const handle = gpa.create(RemoteHandle) catch return unavailable_code;
    handle.* = .{
        .threaded = std.Io.Threaded.init(gpa, .{}),
        .remote = undefined,
    };
    handle.error_buffer[0] = 0;

    handle.remote = openRemote(
        handle,
        options,
        seed_storage[0..options.seed_count],
        any_tls,
    ) catch |err| {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return remoteOpenErrorCode(err);
    };
    out.* = handle;
    return ok_code;
}

fn validTlsOptions(options: *const CRemoteOptions, any_tls: bool) bool {
    return !any_tls or (options.tls_ca_path != null and
        options.tls_cert_path != null and options.tls_key_path != null);
}

fn openRemote(
    handle: *RemoteHandle,
    options: *const CRemoteOptions,
    seeds: []const []const u8,
    any_tls: bool,
) !*Remote {
    return Remote.open(gpa, handle.threaded.io(), .{
        .seeds = seeds,
        .tls = if (any_tls) .{
            .cert_path = std.mem.span(options.tls_cert_path.?),
            .key_path = std.mem.span(options.tls_key_path.?),
            .ca_path = std.mem.span(options.tls_ca_path.?),
        } else null,
        .auth_file_path = if (options.auth_file_path) |path|
            std.mem.span(path)
        else
            null,
        .allow_psk_only_loopback = options.allow_psk_only_loopback,
        .pool_size = options.pool_size,
        .connect_timeout_ms = options.connect_timeout_ms,
        .operation_timeout_ms = options.operation_timeout_ms,
        .write_admission_timeout_ms = options.write_admission_timeout_ms,
        .expected_database_id = if (options.has_expected_database_id)
            std.mem.readInt(u128, &options.expected_database_id, .big)
        else
            null,
    });
}

fn remoteOpenErrorCode(err: anyerror) c_int {
    // Configuration faults are misuse; everything else is the
    // open-time probe failing to reach, authenticate against, or
    // identity-match any seed.
    return switch (err) {
        error.NoSeeds,
        error.TooManySeeds,
        error.DuplicateSeed,
        error.UnixSeedNotAlone,
        error.InvalidEndpoint,
        error.DevPskWithUnixSocket,
        error.DevPskNeedsSecret,
        error.DevPskWithTls,
        error.DevPskNeedsLoopback,
        error.TlsWithUnixSocket,
        error.TcpNeedsTls,
        error.SecretTooShort,
        => misuse_code,
        error.DatabaseMismatch => integrity_code,
        else => unavailable_code,
    };
}

/// Closes the pool and releases the handle. Calls racing the close fail
/// with the misuse code; close waits until every in-flight call on the
/// pool has finished before any memory is released. An unresolved
/// pending write is abandoned locally and never re-executed. Accepts
/// null.
export fn zaxonlite_remote_close(pointer: ?*anyopaque) void {
    const handle = remoteHandleOf(pointer) orelse return;
    handle.remote.close();
    handle.threaded.deinit();
    gpa.destroy(handle);
}

/// Executes one prepared statement through the serialized write lane
/// under the handle's replicated session and next sequence.
export fn zaxonlite_remote_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    exec_out: ?*CExecResult,
) c_int {
    if (exec_out) |out| out.* = .{
        .changes = 0,
        .last_insert_rowid = 0,
        .has_last_insert_rowid = false,
        .replayed = false,
    };
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err|
        return mapRemoteError(handle, err);
    defer gpa.free(values);
    const info = handle.remote.exec(std.mem.span(statement), values) catch |err|
        return mapRemoteError(handle, err);
    if (exec_out) |out| out.* = .{
        .changes = info.changes,
        .last_insert_rowid = info.last_insert_rowid orelse 0,
        .has_last_insert_rowid = info.last_insert_rowid != null,
        .replayed = info.replayed,
    };
    return ok_code;
}

/// Atomic remote `executemany`: executes one prepared statement once
/// per row of a flat value array (`row_count` rows of `per_row_count`
/// values each) as ONE typed-v1 batch, ONE replicated transaction, and
/// ONE session sequence. The reported change count is the whole
/// batch's total; any per-row failure rolls the entire batch back.
export fn zaxonlite_remote_exec_batch(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    per_row_count: usize,
    row_count: usize,
    exec_out: ?*CExecResult,
) c_int {
    if (exec_out) |out| out.* = .{
        .changes = 0,
        .last_insert_rowid = 0,
        .has_last_insert_rowid = false,
        .replayed = false,
    };
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    if (row_count == 0 or row_count > zaxonlite.prepared.maximum_statements) {
        handle.setError("invalid batch row count", category_misuse);
        return misuse_code;
    }
    // Checked before the counts size an allocation or slice caller memory.
    const total = std.math.mul(usize, per_row_count, row_count) catch {
        handle.setError("batch value count overflow", category_misuse);
        return misuse_code;
    };
    const values = valuesFromC(raw_values, total) catch |err|
        return mapRemoteError(handle, err);
    defer gpa.free(values);
    const rows = gpa.alloc([]const Value, row_count) catch
        return unavailable_code;
    defer gpa.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = values[index * per_row_count ..][0..per_row_count];
    }
    const info = handle.remote.execBatch(std.mem.span(statement), rows) catch |err|
        return mapRemoteError(handle, err);
    if (exec_out) |out| out.* = .{
        .changes = info.changes,
        .last_insert_rowid = info.last_insert_rowid orelse 0,
        .has_last_insert_rowid = info.last_insert_rowid != null,
        .replayed = info.replayed,
    };
    return ok_code;
}

/// Runs one typed-v1 read at the requested consistency level (0 any,
/// 1 leader, 2 linearizable; freshness_ms 0 means unset and is only
/// meaningful with level any). The result uses the same opaque typed
/// representation as local queries: release with zaxonlite_result_close.
export fn zaxonlite_remote_query(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    level: c_int,
    freshness_ms: u64,
    out_result: ?*?*anyopaque,
) c_int {
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = out_result orelse return misuse_code;
    out.* = null;
    const read_level: remote_mod.Level = switch (level) {
        0 => .any,
        1 => .leader,
        2 => .linearizable,
        else => {
            handle.setError("invalid read level", category_misuse);
            return misuse_code;
        },
    };
    const values = valuesFromC(raw_values, value_count) catch |err|
        return mapRemoteError(handle, err);
    defer gpa.free(values);
    const typed = handle.remote.query(
        gpa,
        std.mem.span(statement),
        values,
        read_level,
        if (freshness_ms == 0) null else freshness_ms,
    ) catch |err| return mapRemoteError(handle, err);
    out.* = capi.typedResultHandle(typed) catch return unavailable_code;
    return ok_code;
}

/// Runs typed search through the server's validated planner at the
/// requested consistency level. The returned cells use typed-v1.
export fn zaxonlite_remote_search(
    pointer: ?*anyopaque,
    raw_options: ?*const capi.CSearchOptions,
    level: c_int,
    freshness_ms: u64,
    out_result: ?*?*anyopaque,
) c_int {
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const options = raw_options orelse return misuse_code;
    const out = out_result orelse return misuse_code;
    out.* = null;
    const read_level = parseReadLevel(handle, level) orelse
        return misuse_code;
    var metadata_buffer: [64][]const u8 = undefined;
    const request = remoteSearchRequest(
        handle,
        options,
        &metadata_buffer,
    ) orelse return misuse_code;
    const typed = handle.remote.search(
        gpa,
        request,
        read_level,
        if (freshness_ms == 0) null else freshness_ms,
    ) catch |err| return mapRemoteSearchError(handle, err);
    out.* = capi.typedResultHandle(typed) catch return unavailable_code;
    return ok_code;
}

fn parseReadLevel(handle: *RemoteHandle, level: c_int) ?remote_mod.Level {
    return switch (level) {
        0 => .any,
        1 => .leader,
        2 => .linearizable,
        else => {
            handle.setError("invalid read level", category_misuse);
            return null;
        },
    };
}

fn remoteSearchRequest(
    handle: *RemoteHandle,
    options: *const capi.CSearchOptions,
    metadata_buffer: *[64][]const u8,
) ?zaxonlite.SearchRequest {
    if (!validOptionalBytes(options.text, options.text_length) or
        !validOptionalBytes(options.embedding, options.embedding_length))
    {
        handle.setError("invalid search byte buffer", category_validation);
        return null;
    }
    if (options.metadata_column_count > metadata_buffer.len) {
        handle.setError("too many metadata columns", category_validation);
        return null;
    }
    const columns = metadata_buffer[0..options.metadata_column_count];
    if (!copyMetadataColumns(handle, options, columns)) return null;
    return .{
        .fts_table = optionalString(options.fts_table),
        .vec_table = optionalString(options.vec_table),
        .text = optionalBytes(options.text, options.text_length),
        .embedding = optionalBytes(
            options.embedding,
            options.embedding_length,
        ),
        .k = options.k,
        .candidate_count = if (options.has_candidate_count)
            options.candidate_count
        else
            null,
        .fusion = switch (options.fusion) {
            0 => .rrf,
            1 => .dbsf,
            else => {
                handle.setError("invalid fusion", category_validation);
                return null;
            },
        },
        .text_weight = options.text_weight,
        .vector_weight = options.vector_weight,
        .metadata_table = optionalString(options.metadata_table),
        .metadata_id_column = optionalString(options.metadata_id_column),
        .metadata_columns = columns,
    };
}

fn validOptionalBytes(pointer: ?*const anyopaque, length: usize) bool {
    if (length > zaxonlite.prepared.maximum_input_bytes) return false;
    return pointer != null or length == 0;
}

fn copyMetadataColumns(
    handle: *RemoteHandle,
    options: *const capi.CSearchOptions,
    columns: [][]const u8,
) bool {
    if (columns.len == 0) return true;
    const raw_columns = options.metadata_columns orelse {
        handle.setError("metadata columns are missing", category_validation);
        return false;
    };
    for (raw_columns[0..columns.len], columns) |raw_column, *column| {
        column.* = optionalString(raw_column) orelse {
            handle.setError("metadata column is null", category_validation);
            return false;
        };
    }
    return true;
}

fn optionalString(pointer: ?[*:0]const u8) ?[]const u8 {
    return if (pointer) |text| std.mem.span(text) else null;
}

fn optionalBytes(pointer: ?*const anyopaque, length: usize) ?[]const u8 {
    const bytes = pointer orelse return null;
    return @as([*]const u8, @ptrCast(bytes))[0..length];
}

/// Retries the retained pending write with its original session and
/// sequence until the server reports a definitive outcome.
export fn zaxonlite_remote_resolve_pending(
    pointer: ?*anyopaque,
    exec_out: ?*CExecResult,
) c_int {
    if (exec_out) |out| out.* = .{
        .changes = 0,
        .last_insert_rowid = 0,
        .has_last_insert_rowid = false,
        .replayed = false,
    };
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const info = handle.remote.resolvePending() catch |err|
        return mapRemoteError(handle, err);
    if (exec_out) |out| out.* = .{
        .changes = info.changes,
        .last_insert_rowid = info.last_insert_rowid orelse 0,
        .has_last_insert_rowid = info.last_insert_rowid != null,
        .replayed = info.replayed,
    };
    return ok_code;
}

/// Raw status JSON from any healthy identity-checked member, for host
/// diagnostics. Release with zaxonlite_free.
export fn zaxonlite_remote_status_json(
    pointer: ?*anyopaque,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle = remoteHandleOf(pointer) orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    const body = handle.remote.statusJson(gpa) catch |err|
        return mapRemoteError(handle, err);
    defer gpa.free(body);
    const owned = gpa.alloc(u8, body.len + 1) catch return unavailable_code;
    @memcpy(owned[0..body.len], body);
    owned[body.len] = 0;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

/// The most recent error message for this remote handle.
export fn zaxonlite_remote_last_error(pointer: ?*anyopaque) [*:0]const u8 {
    const handle = remoteHandleOf(pointer) orelse return "invalid remote handle";
    return &handle.error_buffer;
}

/// Stable category of the most recent error on this remote handle,
/// using the same ABI values as zaxonlite_last_error_category.
export fn zaxonlite_remote_last_error_category(pointer: ?*anyopaque) c_int {
    const handle = remoteHandleOf(pointer) orelse return category_none;
    return handle.error_category;
}

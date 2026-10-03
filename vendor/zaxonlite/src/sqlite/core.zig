//! Narrow SQLite bindings: exactly the C API subset zaxonlite needs.
//!
//! The rest of the product never includes the C header directly. Zaxonlite
//! pins the amalgamation, runs one writer connection per node in WAL mode
//! with automatic checkpoints disabled, and captures committed WAL frames
//! through `sqlite3_wal_hook` plus direct reads of the `-wal` file.

const std = @import("std");
const c = @import("c");
const search_extension = @import("search_extension.zig");

pub const Error = error{
    SqliteError,
    SqliteBusy,
    SqliteMisuse,
    SqliteInterrupted,
};

/// SQLite's five storage classes as observed on a result column.
pub const ColumnType = enum { null, integer, real, text, blob };

/// Renders a REAL exactly as SQLite's own text conversion does
/// ("%!.15g" through sqlite3_snprintf), so typed results and the legacy
/// text presentation agree byte for byte.
pub fn formatReal(buffer: []u8, value: f64) []const u8 {
    _ = c.sqlite3_snprintf(
        @intCast(buffer.len),
        @ptrCast(buffer.ptr),
        "%!.15g",
        value,
    );
    return std.mem.sliceTo(@as([*:0]const u8, @ptrCast(buffer.ptr)), 0);
}

fn check(db: ?*c.sqlite3, rc: c_int) Error!void {
    switch (rc) {
        c.SQLITE_OK, c.SQLITE_DONE, c.SQLITE_ROW => {},
        c.SQLITE_BUSY, c.SQLITE_LOCKED => return error.SqliteBusy,
        c.SQLITE_MISUSE => return error.SqliteMisuse,
        c.SQLITE_INTERRUPT => return error.SqliteInterrupted,
        else => {
            if (db != null and std.debug.runtime_safety) {
                std.log.debug("sqlite error {d}: {s}", .{ rc, c.sqlite3_errmsg(db) });
            }
            return error.SqliteError;
        },
    }
}

pub const WalHook = *const fn (
    context: ?*anyopaque,
    db: ?*c.sqlite3,
    database_name: [*c]const u8,
    frame_count: c_int,
) callconv(.c) c_int;

pub const Authorizer = *const fn (
    context: ?*anyopaque,
    action: c_int,
    arg1: [*c]const u8,
    arg2: [*c]const u8,
    database_name: [*c]const u8,
    trigger_name: [*c]const u8,
) callconv(.c) c_int;

pub const ProgressHandler = *const fn (context: ?*anyopaque) callconv(.c) c_int;

/// Authorizer action and result codes re-exported for the guard, keeping
/// the translated C header confined to `src/sqlite/`.
pub const auth = struct {
    pub const ok: c_int = c.SQLITE_OK;
    pub const deny: c_int = c.SQLITE_DENY;
    pub const transaction: c_int = c.SQLITE_TRANSACTION;
    pub const savepoint: c_int = c.SQLITE_SAVEPOINT;
    pub const attach: c_int = c.SQLITE_ATTACH;
    pub const detach: c_int = c.SQLITE_DETACH;
    pub const pragma: c_int = c.SQLITE_PRAGMA;
    pub const read: c_int = c.SQLITE_READ;
    pub const insert: c_int = c.SQLITE_INSERT;
    pub const create_index: c_int = c.SQLITE_CREATE_INDEX;
    pub const drop_table: c_int = c.SQLITE_DROP_TABLE;
};

/// True when the linked amalgamation was compiled with `option`
/// (without the `SQLITE_` prefix), e.g. "OMIT_LOAD_EXTENSION".
pub fn compileOptionUsed(option: [:0]const u8) bool {
    return c.sqlite3_compileoption_used(option.ptr) != 0;
}

/// The linked SQLite library version, e.g. 3050400 for 3.50.4.
pub fn libversionNumber() c_int {
    return c.sqlite3_libversion_number();
}

/// SQLite's global heap high-water mark in bytes; optionally resets the
/// mark. Benchmarks use it to prove query heap scales with the candidate
/// count, not the corpus size (ZDS 0009).
pub fn memoryHighwater(reset: bool) i64 {
    return c.sqlite3_memory_highwater(@intFromBool(reset));
}

/// The statically linked sqlite-vec version, read once from a scratch
/// in-memory connection and copied into `buffer`.
pub fn vecVersion(buffer: []u8) Error![]const u8 {
    var db = try Db.open(":memory:");
    defer db.close();
    var stmt = try db.prepare("select vec_version()");
    defer stmt.finalize();
    if (!try stmt.step()) return error.SqliteError;
    const text = stmt.columnText(0);
    const len = @min(text.len, buffer.len);
    @memcpy(buffer[0..len], text[0..len]);
    return buffer[0..len];
}

/// zaxonlite rejects mapped-I/O limits above 1 GiB even where SQLite
/// would accept more (ZDS 0009).
pub const max_mmap_bytes: u64 = 1 << 30;

pub const OpenOptions = struct {
    /// SQLite-managed mapped-I/O limit in bytes. Zero — the default on
    /// every target — disables mmap; a nonzero value is an explicit
    /// operator opt-in bounded by `max_mmap_bytes` (ZDS 0009).
    mmap_size: u64 = 0,
    /// Opens the connection read-only (no CREATE): the connection can
    /// never write the database file. Pooled reader connections use this
    /// so a facade bug cannot mutate the materialized image.
    read_only: bool = false,
};

pub const Db = struct {
    handle: *c.sqlite3,
    /// The mapped-I/O limit SQLite actually accepted, read back after
    /// configuration. Stays zero where the VFS does not support mmap.
    effective_mmap_size: i64 = 0,

    pub fn open(path: [:0]const u8) Error!Db {
        return openWithOptions(path, .{});
    }

    /// The single registration boundary (ZDS 0009): every zaxonlite
    /// connection — live writer, read lease, test harness, restored-image
    /// or backup validation — passes through here, so FTS5, sqlite-vec,
    /// and the Zig search functions exist before any statement prepares.
    pub fn openWithOptions(path: [:0]const u8, options: OpenOptions) Error!Db {
        if (options.mmap_size > max_mmap_bytes) return error.SqliteMisuse;
        var handle: ?*c.sqlite3 = null;
        const flags: c_int = if (options.read_only)
            c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX | c.SQLITE_OPEN_EXRESCODE
        else
            c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE |
                c.SQLITE_OPEN_NOMUTEX | c.SQLITE_OPEN_EXRESCODE;
        const rc = c.sqlite3_open_v2(path.ptr, &handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (handle) |opened| _ = c.sqlite3_close(opened);
            return error.SqliteError;
        }
        var db = Db{ .handle = handle.? };
        errdefer _ = c.sqlite3_close(db.handle);
        // A connection must never serve a schema whose virtual-table
        // module is missing: registration failure fails the open.
        try search_extension.register(db.handle);
        try db.configureMmap(options.mmap_size);
        return db;
    }

    /// Applies the mapped-I/O limit explicitly — including the zero
    /// default — then reads back what SQLite accepted. `PRAGMA mmap_size`
    /// is advisory: platforms without mapped I/O silently keep zero.
    fn configureMmap(self: *Db, limit: u64) Error!void {
        var sql_buffer: [48]u8 = undefined;
        const sql = std.mem.printSentinel(
            &sql_buffer,
            "pragma mmap_size = {d}",
            .{limit},
            0,
        ) catch unreachable;
        try self.exec(sql);
        var stmt = try self.prepare("pragma mmap_size");
        defer stmt.finalize();
        self.effective_mmap_size = if (try stmt.step())
            stmt.columnInt64(0)
        else
            0;
    }

    pub fn close(self: *Db) void {
        _ = c.sqlite3_close(self.handle);
        self.* = undefined;
    }

    pub fn errmsg(self: *const Db) []const u8 {
        return std.mem.span(c.sqlite3_errmsg(self.handle));
    }

    /// The extended result code of the most recent failed call on this
    /// connection; drives stable host error categories.
    pub fn extendedErrcode(self: *const Db) i32 {
        return @intCast(c.sqlite3_extended_errcode(self.handle));
    }

    /// Executes SQL statements without result rows (or discarding them).
    pub fn exec(self: *Db, sql: [:0]const u8) Error!void {
        try check(self.handle, c.sqlite3_exec(self.handle, sql.ptr, null, null, null));
    }

    pub fn prepare(self: *Db, sql: []const u8) Error!Stmt {
        var stmt: ?*c.sqlite3_stmt = null;
        var tail: [*c]const u8 = null;
        try check(self.handle, c.sqlite3_prepare_v2(
            self.handle,
            sql.ptr,
            @intCast(sql.len),
            &stmt,
            &tail,
        ));
        if (stmt == null) return error.SqliteMisuse;
        return .{ .handle = stmt.?, .db = self.handle };
    }

    pub const PreparedStmt = struct {
        stmt: Stmt,
        /// The unconsumed remainder of the input after the first statement.
        tail: []const u8,
    };

    /// Prepares the first statement and reports the unconsumed tail, so a
    /// host can detect trailing statements without parsing SQL itself.
    pub fn prepareWithTail(self: *Db, sql: []const u8) Error!PreparedStmt {
        var stmt: ?*c.sqlite3_stmt = null;
        var tail: [*c]const u8 = null;
        try check(self.handle, c.sqlite3_prepare_v2(
            self.handle,
            sql.ptr,
            @intCast(sql.len),
            &stmt,
            &tail,
        ));
        if (stmt == null) return error.SqliteMisuse;
        const consumed = @intFromPtr(tail) - @intFromPtr(sql.ptr);
        return .{
            .stmt = .{ .handle = stmt.?, .db = self.handle },
            .tail = sql[consumed..],
        };
    }

    pub fn changes(self: *const Db) i64 {
        return c.sqlite3_changes64(self.handle);
    }

    pub fn lastInsertRowId(self: *const Db) i64 {
        return c.sqlite3_last_insert_rowid(self.handle);
    }

    pub fn totalChanges64(self: *const Db) i64 {
        return c.sqlite3_total_changes64(self.handle);
    }

    pub fn inTransaction(self: *const Db) bool {
        return c.sqlite3_get_autocommit(self.handle) == 0;
    }

    pub fn setWalHook(self: *Db, hook: WalHook, context: ?*anyopaque) void {
        _ = c.sqlite3_wal_hook(self.handle, hook, context);
    }

    /// Registers a WAL hook that stores the committed frame count after
    /// every commit into `counter`. The counter must outlive the hook.
    pub fn trackCommittedFrames(self: *Db, counter: *u32) void {
        self.setWalHook(frameCounterHook, counter);
    }

    /// Re-registers the frame-counting hook and reports whether the hook
    /// it replaced was already bound to `counter` — i.e. whether the
    /// capture hook survived everything executed since it was installed.
    pub fn frameHookIs(self: *Db, counter: *u32) bool {
        const previous = c.sqlite3_wal_hook(self.handle, frameCounterHook, counter);
        return previous == @as(?*anyopaque, counter);
    }

    /// Installs (or clears, with null) a prepare-time authorizer. The
    /// context must outlive the connection or the next call to this.
    pub fn setAuthorizer(
        self: *Db,
        authorizer: ?Authorizer,
        context: ?*anyopaque,
    ) void {
        _ = c.sqlite3_set_authorizer(self.handle, authorizer, context);
    }

    /// Invokes `handler` after roughly every `vm_operations` SQLite virtual
    /// machine instructions. Returning non-zero interrupts the statement.
    pub fn setProgressHandler(
        self: *Db,
        vm_operations: u32,
        handler: ?ProgressHandler,
        context: ?*anyopaque,
    ) void {
        c.sqlite3_progress_handler(
            self.handle,
            @intCast(vm_operations),
            handler,
            context,
        );
    }

    /// Returns SQLite page-cache misses since this connection opened.
    /// Benchmarks use the delta around a query batch as the number of
    /// pages SQLite had to read from its VFS (ZDS 0009).
    pub fn cacheMisses(self: *Db) Error!u64 {
        var current: c_int = 0;
        var highwater: c_int = 0;
        try check(self.handle, c.sqlite3_db_status(
            self.handle,
            c.SQLITE_DBSTATUS_CACHE_MISS,
            &current,
            &highwater,
            0,
        ));
        return @intCast(current);
    }

    /// Runs a TRUNCATE checkpoint; the WAL is empty afterwards. Requires no
    /// other connections and no open read transaction.
    pub fn checkpointTruncate(self: *Db) Error!void {
        var wal_frames: c_int = 0;
        var checkpointed: c_int = 0;
        try check(self.handle, c.sqlite3_wal_checkpoint_v2(
            self.handle,
            null,
            c.SQLITE_CHECKPOINT_TRUNCATE,
            &wal_frames,
            &checkpointed,
        ));
    }

    /// Returns the database page size via `PRAGMA page_size`.
    pub fn pageSize(self: *Db) Error!u32 {
        var stmt = try self.prepare("pragma page_size");
        defer stmt.finalize();
        if (!try stmt.step()) return error.SqliteError;
        return @intCast(stmt.columnInt64(0));
    }

    /// Runs `PRAGMA integrity_check` and returns true when it reports "ok".
    pub fn integrityCheckOk(self: *Db) Error!bool {
        var stmt = try self.prepare("pragma integrity_check");
        defer stmt.finalize();
        if (!try stmt.step()) return error.SqliteError;
        return std.mem.eql(u8, stmt.columnText(0), "ok");
    }
};

fn frameCounterHook(
    context: ?*anyopaque,
    db: ?*c.sqlite3,
    database_name: [*c]const u8,
    frame_count: c_int,
) callconv(.c) c_int {
    _ = db;
    _ = database_name;
    const counter: *u32 = @ptrCast(@alignCast(context.?));
    counter.* = @intCast(frame_count);
    return c.SQLITE_OK;
}

pub const Stmt = struct {
    handle: *c.sqlite3_stmt,
    db: *c.sqlite3,

    pub fn finalize(self: *Stmt) void {
        _ = c.sqlite3_finalize(self.handle);
        self.* = undefined;
    }

    pub fn reset(self: *Stmt) Error!void {
        try check(self.db, c.sqlite3_reset(self.handle));
    }

    pub fn isReadOnly(self: *const Stmt) bool {
        return c.sqlite3_stmt_readonly(self.handle) != 0;
    }

    /// Returns true when a result row is available.
    pub fn step(self: *Stmt) Error!bool {
        const rc = c.sqlite3_step(self.handle);
        if (rc == c.SQLITE_ROW) return true;
        if (rc == c.SQLITE_DONE) return false;
        try check(self.db, rc);
        return false;
    }

    /// Binds text without copying: `text` must stay alive until the
    /// statement finishes stepping or is reset. (The amalgamation's
    /// SQLITE_TRANSIENT macro is a -1 function pointer that Zig cannot
    /// represent, so the no-copy contract is explicit here instead.)
    pub fn bindText(self: *Stmt, index: u32, text: []const u8) Error!void {
        try check(self.db, c.sqlite3_bind_text(
            self.handle,
            @intCast(index),
            text.ptr,
            @intCast(text.len),
            null,
        ));
    }

    pub fn bindInt64(self: *Stmt, index: u32, value: i64) Error!void {
        try check(self.db, c.sqlite3_bind_int64(self.handle, @intCast(index), value));
    }

    pub fn bindDouble(self: *Stmt, index: u32, value: f64) Error!void {
        try check(self.db, c.sqlite3_bind_double(self.handle, @intCast(index), value));
    }

    /// Binds bytes without copying; they must outlive the final step.
    pub fn bindBlob(self: *Stmt, index: u32, value: []const u8) Error!void {
        try check(self.db, c.sqlite3_bind_blob(
            self.handle,
            @intCast(index),
            value.ptr,
            @intCast(value.len),
            null,
        ));
    }

    pub fn bindNull(self: *Stmt, index: u32) Error!void {
        try check(self.db, c.sqlite3_bind_null(self.handle, @intCast(index)));
    }

    /// The name of one bound parameter (":name", "@name", or "$name"),
    /// or null for a positional parameter. Indexes are 1-based, matching
    /// SQLite's binding convention.
    pub fn parameterName(self: *const Stmt, index: u32) ?[]const u8 {
        const name = c.sqlite3_bind_parameter_name(
            self.handle,
            @intCast(index),
        ) orelse return null;
        return std.mem.span(name);
    }

    pub fn parameterCount(self: *const Stmt) u32 {
        return @intCast(c.sqlite3_bind_parameter_count(self.handle));
    }

    pub fn columnCount(self: *const Stmt) u32 {
        return @intCast(c.sqlite3_column_count(self.handle));
    }

    pub fn columnName(self: *const Stmt, index: u32) []const u8 {
        const name = c.sqlite3_column_name(self.handle, @intCast(index));
        if (name == null) return "";
        return std.mem.span(name);
    }

    /// The storage class of one result cell in the current row.
    pub fn columnValueType(self: *const Stmt, index: u32) ColumnType {
        return switch (self.columnType(index)) {
            c.SQLITE_INTEGER => .integer,
            c.SQLITE_FLOAT => .real,
            c.SQLITE_TEXT => .text,
            c.SQLITE_BLOB => .blob,
            else => .null,
        };
    }

    pub fn columnType(self: *const Stmt, index: u32) c_int {
        return c.sqlite3_column_type(self.handle, @intCast(index));
    }

    pub fn columnInt64(self: *const Stmt, index: u32) i64 {
        return c.sqlite3_column_int64(self.handle, @intCast(index));
    }

    pub fn columnDouble(self: *const Stmt, index: u32) f64 {
        return c.sqlite3_column_double(self.handle, @intCast(index));
    }

    pub fn columnBlob(self: *const Stmt, index: u32) []const u8 {
        const len: usize = @intCast(c.sqlite3_column_bytes(self.handle, @intCast(index)));
        const ptr = c.sqlite3_column_blob(self.handle, @intCast(index));
        if (ptr == null) return "";
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub fn columnText(self: *const Stmt, index: u32) []const u8 {
        const len: usize = @intCast(c.sqlite3_column_bytes(self.handle, @intCast(index)));
        const ptr = c.sqlite3_column_text(self.handle, @intCast(index));
        if (ptr == null) return "";
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub fn isColumnNull(self: *const Stmt, index: u32) bool {
        return self.columnType(index) == c.SQLITE_NULL;
    }
};

const testing = std.testing;

test "narrow bindings execute and query" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realPath(testing.io, &path_buffer);
    var path_z_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const db_path = try std.mem.printSentinel(
        &path_z_buffer,
        "{s}/t.db",
        .{path_buffer[0..dir_path]},
        0,
    );

    var db = try Db.open(db_path);
    defer db.close();
    try db.exec("create table t(a integer, b text)");
    try db.exec("insert into t values (1, 'one'), (2, 'two')");
    try testing.expectEqual(@as(i64, 2), db.changes());

    var stmt = try db.prepare("select b from t where a = ?1");
    defer stmt.finalize();
    try stmt.bindInt64(1, 2);
    try testing.expect(try stmt.step());
    try testing.expectEqualStrings("two", stmt.columnText(0));
    try testing.expect(!try stmt.step());
    try testing.expect(try db.integrityCheckOk());
}

test "mmap defaults to zero and enforces the opt-in ceiling" {
    // On an in-memory database `PRAGMA mmap_size` returns no row at all;
    // the effective value therefore reads back as the zero default.
    var db = try Db.open(":memory:");
    defer db.close();
    try testing.expectEqual(@as(i64, 0), db.effective_mmap_size);

    // Limits above 1 GiB are rejected before the connection exists.
    try testing.expectError(
        error.SqliteMisuse,
        Db.openWithOptions(":memory:", .{ .mmap_size = max_mmap_bytes + 1 }),
    );
}

test "mmap opt-in reports what SQLite accepted" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realPath(testing.io, &path_buffer);
    var path_z_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const db_path = try std.mem.printSentinel(
        &path_z_buffer,
        "{s}/mmap.db",
        .{path_buffer[0..dir_path]},
        0,
    );
    const profile: u64 = 256 * 1024 * 1024;
    var db = try Db.openWithOptions(db_path, .{ .mmap_size = profile });
    defer db.close();
    // The stored value always equals what a read-back reports; a platform
    // without mapped I/O keeps zero, one with it accepts the profile.
    var stmt = try db.prepare("pragma mmap_size");
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    try testing.expectEqual(db.effective_mmap_size, stmt.columnInt64(0));
    try testing.expect(db.effective_mmap_size == 0 or
        db.effective_mmap_size == @as(i64, @intCast(profile)));
}

test "fts5 is compiled in and ranks with bm25" {
    // Build invariant (ZDS 0009): the amalgamation must carry FTS5.
    try testing.expect(compileOptionUsed("ENABLE_FTS5"));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realPath(testing.io, &path_buffer);
    var path_z_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const db_path = try std.mem.printSentinel(
        &path_z_buffer,
        "{s}/fts.db",
        .{path_buffer[0..dir_path]},
        0,
    );

    var db = try Db.open(db_path);
    defer db.close();
    try db.exec("create virtual table notes using fts5(body)");
    try db.exec(
        "insert into notes(body) values " ++
            "('paxos replicates sqlite pages'), " ++
            "('vectors rank media results')",
    );
    var stmt = try db.prepare(
        "select rowid from notes where notes match 'sqlite' " ++
            "order by bm25(notes), rowid",
    );
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    try testing.expectEqual(@as(i64, 1), stmt.columnInt64(0));
    try testing.expect(!try stmt.step());
}

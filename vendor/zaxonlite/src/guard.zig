//! SQLite invariant guard: a narrow authorizer for application SQL.
//!
//! Zaxonlite owns the outer transaction on the live writer connection and
//! captures committed WAL frames through its installed hook. Application
//! SQL arriving through any public surface must not end that transaction,
//! attach another database, touch the reserved `__zaxon_*` namespace, or
//! reconfigure capture-critical pragmas — any of those breaks the
//! replicated-state contract even though the application is trusted.
//!
//! This is deliberately not a sandbox for hostile tenants: everything
//! SQLite normally allows (DDL, triggers, views, ordinary pragmas such as
//! `user_version`) stays available. Statements run in one of two scopes:
//! `internal` for zaxonlite's own metadata statements, which the
//! authorizer waves through, and `application` for caller SQL, which it
//! screens at prepare time, before any side effect.

const std = @import("std");
const sqlite = @import("sqlite.zig");
const auth = sqlite.auth;

/// Object names beginning with this prefix are zaxonlite's replicated
/// metadata and are invisible to application statements.
pub const reserved_prefix = "__zaxon_";

/// Which rule set the authorizer applies to the statement being prepared.
pub const Scope = enum { internal, application };

pub const Decision = enum { allow, deny };

/// Pragmas that select or trigger SQLite's own checkpointing. Denied in
/// both read and write form: `pragma wal_checkpoint` checkpoints on read,
/// and a `wal_autocheckpoint` write replaces the installed WAL hook.
const checkpoint_pragmas = [_][]const u8{
    "wal_checkpoint",
    "wal_autocheckpoint",
};

/// Pragmas whose written value changes the capture or durability contract
/// (journal layout, page geometry, sync policy, or writability). Reading
/// them stays allowed so applications can inspect the configuration.
const write_denied_pragmas = [_][]const u8{
    "journal_mode",
    "synchronous",
    "page_size",
    "locking_mode",
    "auto_vacuum",
    "writable_schema",
    "query_only",
    // The mapped-I/O limit is connection policy owned by the host
    // (ZDS 0009): changing it mid-statement can silently no-op and would
    // make query memory behavior unpredictable. Reading stays allowed.
    "mmap_size",
};

/// Pure authorization rule for one application-scope action, separated
/// from the callback so the decision table is directly testable.
/// `arg1`/`arg2` follow `sqlite3_set_authorizer` conventions.
pub fn decide(action: c_int, arg1: ?[]const u8, arg2: ?[]const u8) Decision {
    switch (action) {
        // Ending or nesting the transaction detaches the commit from the
        // WAL capture that must represent it.
        auth.transaction, auth.savepoint => return .deny,
        // Attached databases produce WAL frames zaxonlite does not
        // replicate, so their writes would silently diverge replicas.
        auth.attach, auth.detach => return .deny,
        auth.pragma => return decidePragma(arg1, arg2),
        else => {
            if (namesReserved(arg1) or namesReserved(arg2)) return .deny;
            return .allow;
        },
    }
}

fn decidePragma(name: ?[]const u8, value: ?[]const u8) Decision {
    const pragma = name orelse return .allow;
    for (checkpoint_pragmas) |denied| {
        if (std.ascii.eqlIgnoreCase(pragma, denied)) {
            // Reading `wal_autocheckpoint` is harmless; running or
            // enabling a checkpoint is not.
            const is_read = value == null and
                std.ascii.eqlIgnoreCase(pragma, "wal_autocheckpoint");
            return if (is_read) .allow else .deny;
        }
    }
    if (value != null) {
        for (write_denied_pragmas) |denied| {
            if (std.ascii.eqlIgnoreCase(pragma, denied)) return .deny;
        }
    }
    return .allow;
}

fn namesReserved(name: ?[]const u8) bool {
    const text = name orelse return false;
    if (text.len < reserved_prefix.len) return false;
    return std.ascii.eqlIgnoreCase(text[0..reserved_prefix.len], reserved_prefix);
}

/// Per-connection authorizer state. The guard must outlive the connection
/// it is installed on; zaxonlite embeds it in the owning `Node`.
pub const Guard = struct {
    scope: Scope = .internal,

    /// Registers this guard on `db`. Statements prepared while `scope` is
    /// `.application` are screened by `decide`; internal scope allows all.
    pub fn install(self: *Guard, db: *sqlite.Db) void {
        db.setAuthorizer(authorize, self);
    }

    fn authorize(
        context: ?*anyopaque,
        action: c_int,
        arg1: [*c]const u8,
        arg2: [*c]const u8,
        database_name: [*c]const u8,
        trigger_name: [*c]const u8,
    ) callconv(.c) c_int {
        _ = database_name;
        _ = trigger_name;
        const self: *Guard = @ptrCast(@alignCast(context.?));
        if (self.scope == .internal) return auth.ok;
        const decision = decide(action, spanOrNull(arg1), spanOrNull(arg2));
        return switch (decision) {
            .allow => auth.ok,
            .deny => auth.deny,
        };
    }

    fn spanOrNull(text: [*c]const u8) ?[]const u8 {
        return std.mem.span(@as(?[*:0]const u8, text) orelse return null);
    }
};

/// Confirms the live writer connection still matches the capture contract
/// after an application batch and before commit and payload extraction:
/// the outer transaction is open, the journal is WAL with the expected
/// page size, and the frame-counting hook is still the installed one.
/// The authorizer already denies the statements that could change these;
/// this check keeps the invariant robust to future SQLite behavior.
pub fn verifyCaptureContract(
    db: *sqlite.Db,
    expected_page_size: u32,
    counter: *u32,
) !void {
    if (!db.inTransaction()) return error.CaptureContractViolated;
    if (!db.frameHookIs(counter)) return error.CaptureContractViolated;
    if (try db.pageSize() != expected_page_size) {
        return error.CaptureContractViolated;
    }
    var stmt = try db.prepare("pragma journal_mode");
    defer stmt.finalize();
    if (!try stmt.step()) return error.CaptureContractViolated;
    if (!std.ascii.eqlIgnoreCase(stmt.columnText(0), "wal")) {
        return error.CaptureContractViolated;
    }
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "decision table denies transaction control and attachment" {
    try testing.expectEqual(Decision.deny, decide(auth.transaction, "BEGIN", null));
    try testing.expectEqual(Decision.deny, decide(auth.transaction, "COMMIT", null));
    try testing.expectEqual(Decision.deny, decide(auth.transaction, "ROLLBACK", null));
    try testing.expectEqual(Decision.deny, decide(auth.savepoint, "BEGIN", "sp1"));
    try testing.expectEqual(Decision.deny, decide(auth.attach, ":memory:", null));
    try testing.expectEqual(Decision.deny, decide(auth.detach, "aux", null));
}

test "decision table protects the reserved namespace case-insensitively" {
    try testing.expectEqual(
        Decision.deny,
        decide(auth.read, "__zaxon_meta", "value"),
    );
    try testing.expectEqual(
        Decision.deny,
        decide(auth.insert, "__ZAXON_sessions", null),
    );
    try testing.expectEqual(
        Decision.deny,
        decide(auth.create_index, "idx", "__zaxon_meta"),
    );
    try testing.expectEqual(
        Decision.deny,
        decide(auth.drop_table, "__zaxon_meta", null),
    );
    try testing.expectEqual(Decision.allow, decide(auth.read, "users", "name"));
    try testing.expectEqual(Decision.allow, decide(auth.insert, "zaxon", null));
}

test "decision table screens pragmas by capture impact" {
    // Checkpoint control is denied in every form.
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "wal_checkpoint", null),
    );
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "wal_autocheckpoint", "1000"),
    );
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "wal_autocheckpoint", null),
    );
    // Capture-contract pragmas are read-only for applications.
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "journal_mode", "delete"),
    );
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "journal_mode", null),
    );
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "Synchronous", "off"),
    );
    try testing.expectEqual(Decision.deny, decide(auth.pragma, "page_size", "512"));
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "writable_schema", "on"),
    );
    // Mapped-I/O policy is host-owned: reads allowed, writes denied.
    try testing.expectEqual(
        Decision.deny,
        decide(auth.pragma, "mmap_size", "268435456"),
    );
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "mmap_size", null),
    );
    // Ordinary application pragmas keep working.
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "user_version", "7"),
    );
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "foreign_keys", "on"),
    );
    try testing.expectEqual(
        Decision.allow,
        decide(auth.pragma, "integrity_check", null),
    );
}

fn openGuardedDb(tmp: *testing.TmpDir, guard: *Guard) !sqlite.Db {
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    var path_z: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const db_path = try std.mem.printSentinel(
        &path_z,
        "{s}/guarded.db",
        .{path_buffer[0..dir_len]},
        0,
    );
    var db = try sqlite.Db.open(db_path);
    guard.install(&db);
    return db;
}

test "guarded connection denies invariant-breaking application SQL" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var guard = Guard{};
    var db = try openGuardedDb(&tmp, &guard);
    defer db.close();

    // Internal scope bootstraps reserved state exactly like the node.
    try db.exec("create table __zaxon_meta(key text primary key, value)");
    try db.exec("create table t(a integer)");

    guard.scope = .application;
    defer guard.scope = .internal;

    // Ordinary application SQL is untouched.
    try db.exec("insert into t values (1)");
    try db.exec("create table u(b text)");
    try db.exec("pragma user_version = 3");

    // Each denied operation fails at prepare, before side effects.
    try testing.expectError(error.SqliteError, db.exec("commit"));
    try testing.expectError(error.SqliteError, db.exec("begin"));
    try testing.expectError(error.SqliteError, db.exec("savepoint s1"));
    try testing.expectError(
        error.SqliteError,
        db.exec("attach database ':memory:' as extra"),
    );
    try testing.expectError(
        error.SqliteError,
        db.exec("select * from __zaxon_meta"),
    );
    try testing.expectError(
        error.SqliteError,
        db.exec("insert into __zaxon_meta values ('k', 'v')"),
    );
    try testing.expectError(
        error.SqliteError,
        db.exec("drop table __zaxon_meta"),
    );
    try testing.expectError(
        error.SqliteError,
        db.exec("pragma wal_autocheckpoint = 100"),
    );
    try testing.expectError(error.SqliteError, db.exec("pragma wal_checkpoint"));
    try testing.expectError(
        error.SqliteError,
        db.exec("pragma journal_mode = delete"),
    );
    try testing.expectError(
        error.SqliteError,
        db.exec("pragma mmap_size = 268435456"),
    );
    // Reading the mapped-I/O limit stays available to applications.
    try db.exec("pragma mmap_size");

    // A trigger reaching into the reserved namespace is rejected when the
    // firing statement is prepared, so the write never happens.
    try db.exec(
        "create trigger t_evil after insert on t begin " ++
            "insert into __zaxon_meta values ('x', 'y'); end",
    );
    try testing.expectError(error.SqliteError, db.exec("insert into t values (2)"));

    guard.scope = .internal;
    try db.exec("select count(*) from __zaxon_meta");
}

test "capture contract verification detects a replaced WAL hook" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var guard = Guard{};
    var db = try openGuardedDb(&tmp, &guard);
    defer db.close();
    try db.exec("pragma journal_mode = wal");
    var counter: u32 = 0;
    db.trackCommittedFrames(&counter);
    const page_size = try db.pageSize();

    try db.exec("begin immediate");
    try verifyCaptureContract(&db, page_size, &counter);

    // Outside a transaction the contract no longer holds.
    try db.exec("commit");
    try testing.expectError(
        error.CaptureContractViolated,
        verifyCaptureContract(&db, page_size, &counter),
    );

    // A different hook context means capture frames would be lost.
    var other: u32 = 0;
    db.trackCommittedFrames(&other);
    try db.exec("begin immediate");
    defer db.exec("rollback") catch {};
    try testing.expectError(
        error.CaptureContractViolated,
        verifyCaptureContract(&db, page_size, &counter),
    );
}

test "extension loading stays compiled out of the SQL surface" {
    // Build invariant: the amalgamation must keep SQLITE_OMIT_LOAD_EXTENSION.
    try testing.expect(sqlite.compileOptionUsed("OMIT_LOAD_EXTENSION"));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var guard = Guard{};
    var db = try openGuardedDb(&tmp, &guard);
    defer db.close();
    // No `load_extension`, `readfile`, or `writefile` SQL function exists.
    try testing.expectError(
        error.SqliteError,
        db.exec("select load_extension('evil')"),
    );
    try testing.expectError(error.SqliteError, db.exec("select readfile('/etc/hosts')"));
    try testing.expectError(error.SqliteError, db.exec("select writefile('x', 'y')"));
}

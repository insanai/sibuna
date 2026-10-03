//! Prepared values and the explicit transaction builder.
//!
//! A transaction builder owns copied SQL and parameter bytes but does not hold
//! a live SQLite transaction. `Node.execTransaction` executes the completed
//! builder under the node's one-writer gate and proposes exactly one captured
//! WAL transition. This prevents application think-time from holding locks or
//! leaving speculative SQLite state across a Paxos leadership change.

const std = @import("std");
const sqlite = @import("sqlite.zig");

pub const maximum_statements: usize = 1024;
pub const maximum_input_bytes: usize = 64 * 1024 * 1024;

pub const Value = union(enum) {
    null_value,
    integer: i64,
    real: f64,
    text: []const u8,
    blob: []const u8,
};

pub const Statement = struct {
    sql: []const u8,
    values: []const Value,
};

/// Longest text or blob value a `scalar_equals` expectation may carry.
/// The cap bounds comparison work inside the write path; an observed cell
/// longer than the cap can never equal a valid expected value.
pub const scalar_bytes_max: usize = 4096;

/// Per-statement verification for a checked transaction. A failed
/// expectation rolls the whole transaction back before any WAL frame is
/// captured or appended to the replicated log.
pub const Expectation = union(enum) {
    /// No verification; the statement only has to execute successfully.
    any,
    /// The statement's own change count (rows inserted, updated, or
    /// deleted, by SQLite's total-changes delta) must equal this value.
    changes_exactly: u64,
    /// The statement must produce exactly this many result rows.
    rows_exactly: u64,
    /// The statement must produce exactly one row with one column whose
    /// typed value equals this one. Text and blob expectations are
    /// bounded by `scalar_bytes_max`.
    scalar_equals: Value,
};

/// One statement of a checked transaction: SQL, bound values, and the
/// expectation the write path verifies before the transaction commits.
pub const CheckedStatement = struct {
    sql: []const u8,
    values: []const Value,
    expectation: Expectation = .any,
};

/// Validates checked-transaction bounds before any SQL executes: the
/// statement-count and input-byte limits shared with the transaction
/// builder, plus the scalar expectation byte cap.
pub fn validateCheckedBounds(statements: []const CheckedStatement) !void {
    if (statements.len == 0) return error.EmptyTransaction;
    if (statements.len > maximum_statements) return error.TooManyStatements;
    var input_bytes: usize = 0;
    for (statements) |statement| {
        var added_bytes = statement.sql.len;
        for (statement.values) |value| {
            added_bytes = std.math.add(usize, added_bytes, valueBytes(value)) catch
                return error.TransactionInputTooLarge;
        }
        input_bytes = std.math.add(usize, input_bytes, added_bytes) catch
            return error.TransactionInputTooLarge;
        if (input_bytes > maximum_input_bytes) return error.TransactionInputTooLarge;
        switch (statement.expectation) {
            .scalar_equals => |expected| switch (expected) {
                .text, .blob => if (valueBytes(expected) > scalar_bytes_max) {
                    return error.ScalarExpectationTooLarge;
                },
                else => {},
            },
            else => {},
        }
    }
}

pub const Transaction = struct {
    arena: std.heap.ArenaAllocator,
    statements: std.ArrayList(Statement) = .empty,
    input_bytes: usize = 0,
    finished: bool = false,

    pub fn init(gpa: std.mem.Allocator) Transaction {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    pub fn deinit(self: *Transaction) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Adds one prepared SQL statement. SQL, text, and BLOB bytes are copied;
    /// callers may release their inputs immediately after this call.
    pub fn exec(
        self: *Transaction,
        sql: []const u8,
        values: []const Value,
    ) !void {
        if (self.finished) return error.TransactionFinished;
        if (self.statements.items.len >= maximum_statements) {
            return error.TooManyStatements;
        }
        var added_bytes = sql.len;
        for (values) |value| {
            added_bytes = std.math.add(usize, added_bytes, valueBytes(value)) catch
                return error.TransactionInputTooLarge;
        }
        const next_bytes = std.math.add(usize, self.input_bytes, added_bytes) catch
            return error.TransactionInputTooLarge;
        if (next_bytes > maximum_input_bytes) return error.TransactionInputTooLarge;

        const allocator = self.arena.allocator();
        const owned_sql = try allocator.dupe(u8, sql);
        const owned_values = try allocator.alloc(Value, values.len);
        for (values, owned_values) |value, *destination| {
            destination.* = try copyValue(allocator, value);
        }
        try self.statements.append(allocator, .{
            .sql = owned_sql,
            .values = owned_values,
        });
        self.input_bytes = next_bytes;
    }

    pub fn slice(self: *const Transaction) []const Statement {
        return self.statements.items;
    }

    pub fn markFinished(self: *Transaction) !void {
        if (self.finished) return error.TransactionFinished;
        if (self.statements.items.len == 0) return error.EmptyTransaction;
        self.finished = true;
    }
};

fn valueBytes(value: Value) usize {
    return switch (value) {
        .text => |bytes| bytes.len,
        .blob => |bytes| bytes.len,
        else => @sizeOf(Value),
    };
}

fn copyValue(allocator: std.mem.Allocator, value: Value) !Value {
    return switch (value) {
        .text => |bytes| .{ .text = try allocator.dupe(u8, bytes) },
        .blob => |bytes| .{ .blob = try allocator.dupe(u8, bytes) },
        else => value,
    };
}

pub fn bind(stmt: *sqlite.Stmt, values: []const Value) !void {
    if (stmt.parameterCount() != values.len) return error.ParameterCountMismatch;
    for (values, 1..) |value, index| {
        switch (value) {
            .null_value => try stmt.bindNull(@intCast(index)),
            .integer => |number| try stmt.bindInt64(@intCast(index), number),
            .real => |number| try stmt.bindDouble(@intCast(index), number),
            .text => |bytes| try stmt.bindText(@intCast(index), bytes),
            .blob => |bytes| try stmt.bindBlob(@intCast(index), bytes),
        }
    }
}

/// Executes every statement in order, discarding result rows. The surrounding
/// caller owns `BEGIN`, `COMMIT`, rollback, and WAL capture.
pub fn execute(db: *sqlite.Db, statements: []const Statement) !void {
    for (statements) |statement| {
        var stmt = try db.prepare(statement.sql);
        defer stmt.finalize();
        try bind(&stmt, statement.values);
        while (try stmt.step()) {}
    }
}

test "transaction builder copies prepared inputs" {
    var transaction = Transaction.init(std.testing.allocator);
    defer transaction.deinit();
    var text = [_]u8{ 't', 'e', 'a' };
    try transaction.exec(
        "insert into t(v) values (?1)",
        &.{.{ .text = &text }},
    );
    text[0] = 'x';
    try std.testing.expectEqualStrings(
        "tea",
        transaction.slice()[0].values[0].text,
    );
    try transaction.markFinished();
    try std.testing.expectError(
        error.TransactionFinished,
        transaction.exec("select 1", &.{}),
    );
}

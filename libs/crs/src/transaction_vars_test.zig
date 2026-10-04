//! Private mutations either complete within reserved bounds or poison the transaction.
const std = @import("std");
const tx = @import("transaction_vars.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");

const Scratch = struct {
    entries: [8]variables.Entry = undefined,
    bytes: [256]u8 = undefined,

    fn store(self: *Scratch) tx.Store {
        return tx.Store.init(&self.entries, &self.bytes);
    }
};

test "unique TX updates preserve order spelling empty values and old value lifetimes" {
    var scratch: Scratch = .{};
    var store = scratch.store();
    var budget: work.Budget = .{ .remaining = 10_000 };
    try std.testing.expect(try store.get("missing", &budget) == null);
    try store.put("Score", "1", &budget);
    try store.put("other", "", &budget);
    const old = (try store.get("SCORE", &budget)).?;
    const old_key = (try store.values())[0].key;
    try store.put("sCoRe", "2", &budget);
    const entries = try store.values();
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("Score", entries[0].key);
    try std.testing.expectEqualStrings("2", entries[0].value);
    try std.testing.expectEqualStrings("", (try store.get("OTHER", &budget)).?);
    try std.testing.expectEqualStrings("1", old);
    try std.testing.expectEqualStrings("Score", old_key);
    const bytes_before = store.byte_used;
    try std.testing.expect(try store.remove("score", &budget));
    try std.testing.expectEqualStrings("other", (try store.values())[0].key);
    try std.testing.expectEqualStrings("1", old);
    try std.testing.expectEqual(bytes_before, store.byte_used);
    try std.testing.expect(!try store.remove("absent", &budget));
}

test "TX copies borrowed action arguments and supports existing pool values as operands" {
    var scratch: Scratch = .{};
    var store = scratch.store();
    var budget: work.Budget = .{ .remaining = 10_000 };
    var key = "name".*;
    var value = "first".*;
    try store.put(&key, &value, &budget);
    @memset(&key, 'x');
    @memset(&value, 'x');
    const old = (try store.get("name", &budget)).?;
    try std.testing.expectEqualStrings("first", old);
    try store.put("copied", old, &budget);
    try store.put("name", old, &budget);
    try std.testing.expectEqualStrings("first", (try store.get("copied", &budget)).?);
}

test "TX arithmetic uses checked stoi prefix conversion with invalid operands as zero" {
    var scratch: Scratch = .{};
    var store = scratch.store();
    var budget: work.Budget = .{ .remaining = 10_000 };
    try store.update("score", .add, " \t+005suffix", &budget);
    try std.testing.expectEqualStrings("5", (try store.get("score", &budget)).?);
    try store.update("score", .add, "-2", &budget);
    try std.testing.expectEqualStrings("3", (try store.get("score", &budget)).?);
    try store.update("score", .subtract, "-7", &budget);
    try std.testing.expectEqualStrings("10", (try store.get("score", &budget)).?);
    try store.update("score", .add, "2147483648", &budget);
    try std.testing.expectEqualStrings("10", (try store.get("score", &budget)).?);
    try store.put("score", "invalid", &budget);
    try store.update("score", .add, "1", &budget);
    try std.testing.expectEqualStrings("1", (try store.get("score", &budget)).?);
    try store.put("score", "-2147483648", &budget);
    try store.update("score", .add, "2147483647", &budget);
    try std.testing.expectEqualStrings("-1", (try store.get("score", &budget)).?);
}

test "overflow never wraps an anomaly score or permits continued transaction execution" {
    for ([_]struct { previous: []const u8, operand: []const u8, operation: tx.Operation }{
        .{ .previous = "2147483647", .operand = "1", .operation = .add },
        .{ .previous = "-2147483648", .operand = "1", .operation = .subtract },
        .{ .previous = "2147483647", .operand = "-1", .operation = .subtract },
    }) |case| {
        var scratch: Scratch = .{};
        var store = scratch.store();
        var budget: work.Budget = .{ .remaining = 10_000 };
        try store.put("score", case.previous, &budget);
        const bytes_before = store.byte_used;
        try std.testing.expectError(
            error.NumericLimit,
            store.update("score", case.operation, case.operand, &budget),
        );
        try std.testing.expectEqualStrings(case.previous, store.entries[0].value);
        try std.testing.expectEqual(bytes_before, store.byte_used);
        try std.testing.expectError(error.TransactionFailed, store.values());
        try std.testing.expectError(error.TransactionFailed, store.put("score", "0", &budget));
        try std.testing.expectError(error.TransactionFailed, store.get("score", &budget));
        try std.testing.expectError(error.TransactionFailed, store.remove("score", &budget));
    }
}

test "TX entry and monotonic byte bounds do not change committed private state on failure" {
    var scratch: Scratch = .{};
    var store = tx.Store.init(scratch.entries[0..1], scratch.bytes[0..8]);
    var budget: work.Budget = .{ .remaining = 10_000 };
    try store.put("key", "value", &budget);
    try std.testing.expectError(error.EntryLimit, store.put("new", "", &budget));
    try std.testing.expectEqual(@as(usize, 1), store.used);
    try std.testing.expectEqualStrings("value", store.entries[0].value);
    store = tx.Store.init(scratch.entries[0..1], scratch.bytes[0..8]);
    try store.put("key", "value", &budget);
    try std.testing.expectError(error.ByteLimit, store.put("key", "x", &budget));
    try std.testing.expectEqual(@as(usize, 8), store.byte_used);
    try std.testing.expectEqualStrings("value", store.entries[0].value);
    store = scratch.store();
    try std.testing.expectError(error.InvalidKey, store.put("", "value", &budget));
    try std.testing.expect(store.failed);
    try std.testing.expectEqual(@as(usize, 0), store.used);
    store = scratch.store();
    try std.testing.expectError(error.InvalidKey, store.get("bad\x00key", &budget));
}

test "every insufficient work allowance leaves a TX write atomic and poisoned" {
    for (0..40) |allowance| {
        var scratch: Scratch = .{};
        @memset(&scratch.bytes, 0xaa);
        var store = scratch.store();
        var budget: work.Budget = .{ .remaining = 10_000 };
        try store.put("key", "before", &budget);
        const bytes_before = scratch.bytes;
        const used_before = store.byte_used;
        budget.remaining = allowance;
        if (store.put("KEY", "after", &budget)) |_| {
            try std.testing.expectEqualStrings("after", store.entries[0].value);
            try std.testing.expect(!store.failed);
        } else |err| {
            try std.testing.expectEqual(error.WorkLimit, err);
            try std.testing.expectEqualStrings("before", store.entries[0].value);
            try std.testing.expectEqualSlices(u8, &bytes_before, &scratch.bytes);
            try std.testing.expectEqual(used_before, store.byte_used);
            budget.remaining = 10_000;
            try std.testing.expectError(
                error.TransactionFailed,
                store.put("key", "after", &budget),
            );
        }
    }
}

test "exhausted deletion does not shift metadata or invalidate old borrows" {
    var scratch: Scratch = .{};
    var store = scratch.store();
    var budget: work.Budget = .{ .remaining = 10_000 };
    try store.put("one", "1", &budget);
    try store.put("two", "2", &budget);
    budget.remaining = 9;
    try std.testing.expectError(error.WorkLimit, store.remove("one", &budget));
    try std.testing.expectEqual(@as(usize, 2), store.used);
    try std.testing.expectEqualStrings("one", store.entries[0].key);
    try std.testing.expectEqualStrings("two", store.entries[1].key);
    try std.testing.expect(store.failed);
}

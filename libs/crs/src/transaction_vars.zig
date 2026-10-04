//! Caller-owned unique TX keys and monotonic bytes. No allocation during mutation.
//! Old value slices remain valid through the transaction despite metadata replacement.
const std = @import("std");
const variables = @import("variables.zig");
const primitives = @import("primitives.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const decimal_format = @import("decimal_format.zig");
pub const Error = work.Error || error{
    NumericLimit,
    InvalidKey,
    EntryLimit,
    ByteLimit,
    TransactionFailed,
};
pub const Operation = enum { assign, add, subtract };

pub const Store = struct {
    entries: []variables.Entry,
    bytes: []u8,
    used: usize = 0,
    byte_used: usize = 0,
    failed: bool = false,

    /// Reserved buffers belong exclusively to one transaction. Reinitialization
    /// invalidates old borrows; deleting a key never reclaims bytes within that lifetime.
    pub fn init(entries: []variables.Entry, bytes: []u8) Store {
        buffers.assertDisjoint(std.mem.sliceAsBytes(entries), bytes);
        return .{ .entries = entries, .bytes = bytes };
    }

    pub fn values(self: *const Store) Error![]const variables.Entry {
        if (self.failed) return error.TransactionFailed;
        return self.entries[0..self.used];
    }

    pub fn get(self: *Store, key: []const u8, budget: *work.Budget) Error!?[]const u8 {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        const position = try self.locate(key, budget) orelse return null;
        return self.entries[position].value;
    }

    /// A single write is atomic with respect to both capacity and work failures.
    /// The first key spelling is retained; only the new value is copied on replacement.
    pub fn put(self: *Store, key: []const u8, value: []const u8, budget: *work.Budget) Error!void {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        const existing = try self.locate(key, budget);
        if (existing == null and self.used == self.entries.len) return error.EntryLimit;
        const key_bytes = if (existing == null) key.len else 0;
        if (key_bytes > self.bytes.len - self.byte_used) return error.ByteLimit;
        if (value.len > self.bytes.len - self.byte_used - key_bytes) return error.ByteLimit;
        const copied = key_bytes + value.len;
        try budget.debit(@intCast(copied));
        const destination = self.bytes[self.byte_used..][0..copied];
        buffers.assertDisjoint(key, destination);
        buffers.assertDisjoint(value, destination);
        const owned_key = if (existing) |index| self.entries[index].key else blk: {
            @memcpy(destination[0..key_bytes], key);
            break :blk destination[0..key_bytes];
        };
        @memcpy(destination[key_bytes..], value);
        const index = existing orelse self.used;
        self.entries[index] = .{
            .collection = .tx,
            .key = owned_key,
            .value = destination[key_bytes..],
        };
        self.byte_used += copied;
        if (existing == null) self.used += 1;
    }

    pub fn remove(self: *Store, key: []const u8, budget: *work.Budget) Error!bool {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        const index = try self.locate(key, budget) orelse return false;
        const shifted = self.used - index - 1;
        const cost = std.math.mul(u64, @intCast(shifted), @sizeOf(variables.Entry)) catch
            return error.WorkLimit;
        try budget.debit(cost);
        std.mem.copyForwards(
            variables.Entry,
            self.entries[index .. self.used - 1],
            self.entries[index + 1 .. self.used],
        );
        self.used -= 1;
        return true;
    }

    pub fn update(
        self: *Store,
        key: []const u8,
        operation: Operation,
        operand: []const u8,
        budget: *work.Budget,
    ) Error!void {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        if (operation == .assign) return self.put(key, operand, budget);
        const previous = try self.get(key, budget) orelse "";
        const left = try primitives.integer32(previous, budget);
        const right = try primitives.integer32(operand, budget);
        const result = if (operation == .add)
            std.math.add(i32, left, right) catch return error.NumericLimit
        else
            std.math.sub(i32, left, right) catch return error.NumericLimit;
        var output: [decimal_format.capacity(i32)]u8 = undefined;
        const value = try decimal_format.write(i32, result, &output, budget);
        try self.put(key, value, budget);
    }

    fn locate(self: *const Store, key: []const u8, budget: *work.Budget) Error!?usize {
        const cost = std.math.add(u64, @intCast(key.len), 1) catch return error.WorkLimit;
        try budget.debit(cost);
        if (key.len == 0 or std.mem.indexOfScalar(u8, key, 0) != null) return error.InvalidKey;
        for (self.entries[0..self.used], 0..) |entry, index| {
            try budget.debit(1);
            if (try variables.keyEqual(entry.key, key, budget)) return index;
        }
        return null;
    }
};

test {
    _ = @import("transaction_vars_test.zig");
}

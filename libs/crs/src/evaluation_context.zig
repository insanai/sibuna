//! Reserved transaction state; acquired bytes and every saved value outlive evaluation.
//! Merged metadata is separate from target snapshots and mutable TX metadata.
const std = @import("std");
const variables = @import("variables.zig");
const tx = @import("transaction_vars.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = tx.Error || variables.Error || error{
    ReservedCollection,
    ViewLimit,
    MatchedLimit,
};
pub const Scratch = struct {
    view: []variables.Entry,
    matched: []variables.Entry,
    bytes: []u8,
};
pub const Context = struct {
    acquired: variables.View,
    store: *tx.Store,
    scratch: Scratch,
    matched_used: usize = 0,
    byte_used: usize = 0,
    failed: bool = false,
    processor: ?[]const u8 = null,

    /// The context and all scratch belong exclusively to one reserved slot. Resetting
    /// invalidates borrows; clearing matches does not reclaim monotonic byte storage.
    pub fn init(acquired: variables.View, store: *tx.Store, scratch: Scratch) Error!Context {
        for (acquired.entries) |entry| {
            if (owned(entry.collection)) return error.ReservedCollection;
        }
        const regions = [_][]const u8{
            std.mem.sliceAsBytes(acquired.entries),
            std.mem.sliceAsBytes(store.entries),
            store.bytes,
            std.mem.sliceAsBytes(scratch.view),
            std.mem.sliceAsBytes(scratch.matched),
            scratch.bytes,
        };
        buffers.assertExclusive(&regions);
        return .{ .acquired = acquired, .store = store, .scratch = scratch };
    }

    pub fn poison(self: *Context) void {
        self.failed = true;
        self.store.failed = true;
    }

    /// Between phases the connector supplies another immutable acquired view.
    /// Preserve TX and copied matched values; rebuilding Context would erase them.
    pub fn acquire(self: *Context, acquired: variables.View, budget: *work.Budget) Error!void {
        if (self.failed or self.store.failed) return error.TransactionFailed;
        errdefer self.poison();
        _ = try Context.init(acquired, self.store, self.scratch);
        try budget.debit(acquired.entries.len);
        self.acquired = acquired;
    }

    /// Caller consumes this view before another rebuild. Entries borrow immutable
    /// acquired bytes or monotonic pools, never macro or transformation scratch.
    pub fn view(self: *Context, budget: *work.Budget) Error!variables.View {
        if (self.failed) return error.TransactionFailed;
        errdefer self.poison();
        const stored = try self.store.values();
        const scalar_count: usize = (if (self.matched_used == 0) @as(usize, 0) else 2) +
            (if (self.processor == null) @as(usize, 0) else 1);
        var total: usize = 0;
        const lengths = [_]usize{
            self.acquired.entries.len, stored.len, self.matched_used, scalar_count,
        };
        for (lengths) |length| {
            if (length > self.scratch.view.len - total) return error.ViewLimit;
            total += length;
        }
        try budget.debit(@intCast(total));
        var cursor: usize = 0;
        const lists = [_][]const variables.Entry{
            self.acquired.entries, stored, self.scratch.matched[0..self.matched_used],
        };
        for (lists) |list| for (list) |entry| {
            if (self.processor != null and entry.collection == .reqbody_processor) continue;
            self.scratch.view[cursor] = entry;
            cursor += 1;
        };
        cursor = self.appendScalars(cursor);
        var result = self.acquired;
        result.entries = self.scratch.view[0..cursor];
        if (self.processor != null) {
            result.coverage[@backingInt(variables.Collection.reqbody_processor)] = .complete;
        }
        inline for (std.enums.values(variables.Collection)) |collection| {
            if (comptime owned(collection)) result.coverage[@backingInt(collection)] = .complete;
        }
        return result;
    }

    fn appendScalars(self: *Context, start: usize) usize {
        var cursor = start;
        if (self.processor) |label| {
            self.scratch.view[cursor] = .{ .collection = .reqbody_processor, .value = label };
            cursor += 1;
        }
        if (self.matched_used != 0) {
            const last = self.scratch.matched[self.matched_used - 2];
            self.scratch.view[cursor] = .{ .collection = .matched_var, .value = last.value };
            self.scratch.view[cursor + 1] = .{
                .collection = .matched_var_name,
                .value = last.key,
            };
            cursor += 2;
        }
        return cursor;
    }

    /// The positive predicate's value must be copied before transform replay advances.
    /// Repeated matches append occurrences, rather than replacing a keyed entry.
    pub fn record(
        self: *Context,
        entry: variables.Entry,
        counted: bool,
        value: []const u8,
        budget: *work.Budget,
    ) Error!void {
        if (self.failed or self.store.failed) return error.TransactionFailed;
        errdefer self.poison();
        if (self.scratch.matched.len - self.matched_used < 2) return error.MatchedLimit;
        const label = @tagName(entry.collection);
        const prefix: usize = if (counted) 1 else 0;
        const suffix: usize = if (entry.key.len == 0) 0 else entry.key.len + 1;
        const name_length = std.math.add(usize, label.len + prefix, suffix) catch
            return error.ByteLimit;
        const available = self.scratch.bytes.len - self.byte_used;
        if (name_length > available or value.len > available - name_length) {
            return error.ByteLimit;
        }
        try budget.debit(@intCast(name_length + value.len + 2));
        const name = self.scratch.bytes[self.byte_used..][0..name_length];
        const saved = self.scratch.bytes[self.byte_used + name_length ..][0..value.len];
        buffers.assertDisjoint(value, saved);
        buffers.assertDisjoint(entry.key, name);
        if (counted) name[0] = '&';
        for (label, name[prefix..][0..label.len]) |byte, *out| out.* = std.ascii.toUpper(byte);
        if (suffix != 0) {
            name[prefix + label.len] = ':';
            @memcpy(name[prefix + label.len + 1 ..], entry.key);
        }
        @memcpy(saved, value);
        self.scratch.matched[self.matched_used] = .{
            .collection = .matched_vars,
            .key = name,
            .value = saved,
        };
        self.scratch.matched[self.matched_used + 1] = .{
            .collection = .matched_vars_names,
            .key = name,
            .value = name,
        };
        self.matched_used += 2;
        self.byte_used += name_length + value.len;
    }

    pub fn clearMatches(self: *Context) Error!void {
        if (self.failed or self.store.failed) return error.TransactionFailed;
        self.matched_used = 0;
    }
};

fn owned(collection: variables.Collection) bool {
    return switch (collection) {
        .tx, .matched_var, .matched_var_name, .matched_vars, .matched_vars_names => true,
        else => false,
    };
}

test {
    _ = @import("evaluation_context_test.zig");
}

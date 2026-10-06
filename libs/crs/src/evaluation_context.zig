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
    /// Advances when acquired, matched or processor state changes.
    revision: u64 = 0,
    /// Rules usually read without writing, so the merged view is rebuilt only when its
    /// inputs changed. Work is still charged per read, keeping budgets independent of reuse.
    /// TX values are read live from the store and never invalidate it.
    cached: ?Cached = null,
    ranges: [variables.count]variables.Range = undefined,

    const Cached = struct { revision: u64, len: usize };

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
        self.revision += 1;
    }

    pub fn setProcessor(self: *Context, label: ?[]const u8) void {
        self.processor = label;
        self.revision += 1;
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
        if (self.cached) |cached| if (cached.revision == self.revision) {
            return self.merged(cached.len, stored);
        };
        var synthetic: [3]variables.Entry = undefined;
        const lists = [_][]const variables.Entry{
            self.acquired.entries,
            self.scratch.matched[0..self.matched_used],
            self.scalars(&synthetic),
        };
        // A stable counting sort groups collections while keeping each one's order, so a
        // selector reads only its collection. It runs on rebuilds, not on every read.
        var sizes: [variables.count]u32 = @splat(0);
        for (lists, 0..) |list, source| for (list) |entry| {
            if (source == 0 and self.shadowed(entry)) continue;
            sizes[@backingInt(entry.collection)] += 1;
        };
        var start: u32 = 0;
        for (&self.ranges, sizes) |*range, size| {
            range.* = .{ .start = start, .end = start };
            start += size;
        }
        for (lists, 0..) |list, source| for (list) |entry| {
            if (source == 0 and self.shadowed(entry)) continue;
            const range = &self.ranges[@backingInt(entry.collection)];
            self.scratch.view[range.end] = entry;
            range.end += 1;
        };
        self.cached = .{ .revision = self.revision, .len = start };
        return self.merged(start, stored);
    }

    /// An explicit body processor replaces the connector's acquired label; the synthetic
    /// label that carries the explicit choice is never shadowed.
    fn shadowed(self: *const Context, entry: variables.Entry) bool {
        return self.processor != null and entry.collection == .reqbody_processor;
    }

    fn merged(self: *const Context, len: usize, stored: []const variables.Entry) variables.View {
        var result = self.acquired;
        result.entries = self.scratch.view[0..len];
        result.ranges = &self.ranges;
        result.tx = stored;
        if (self.processor != null) {
            result.coverage[@backingInt(variables.Collection.reqbody_processor)] = .complete;
        }
        inline for (std.enums.values(variables.Collection)) |collection| {
            if (comptime owned(collection)) result.coverage[@backingInt(collection)] = .complete;
        }
        return result;
    }

    fn scalars(self: *const Context, output: *[3]variables.Entry) []const variables.Entry {
        var used: usize = 0;
        if (self.processor) |label| {
            output[used] = .{ .collection = .reqbody_processor, .value = label };
            used += 1;
        }
        if (self.matched_used != 0) {
            const last = self.scratch.matched[self.matched_used - 2];
            output[used] = .{ .collection = .matched_var, .value = last.value };
            output[used + 1] = .{ .collection = .matched_var_name, .value = last.key };
            used += 2;
        }
        return output[0..used];
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
        self.revision += 1;
    }

    pub fn clearMatches(self: *Context) Error!void {
        if (self.failed or self.store.failed) return error.TransactionFailed;
        // Most rules do not match; leave the cached view valid when nothing was cleared.
        if (self.matched_used == 0) return;
        self.matched_used = 0;
        self.revision += 1;
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

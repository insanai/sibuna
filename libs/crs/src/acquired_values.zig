//! Monotonic acquired collections. Parsers publish complete coverage only after
//! success; a capacity or parsing failure makes every partial view inaccessible.
const std = @import("std");
const variables = @import("variables.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const decimal = @import("decimal_format.zig");
pub const Error = work.Error || error{
    AcquisitionFailed,
    AcquisitionEntryLimit,
    AcquisitionByteLimit,
    ReservedCollection,
};
pub const Record = struct { key: []const u8 = "", value: []const u8 };
pub const Origin = enum { query, form, json };
pub const Builder = struct {
    entries: []variables.Entry,
    bytes: []u8,
    used: usize = 0,
    byte_used: usize = 0,
    args_size: u64 = 0,
    coverage: [variables.count]variables.Coverage = @splat(.unavailable),
    failed: bool = false,

    pub fn init(entries: []variables.Entry, bytes: []u8) Builder {
        buffers.assertDisjoint(std.mem.sliceAsBytes(entries), bytes);
        return .{ .entries = entries, .bytes = bytes };
    }

    pub fn poison(self: *Builder) void {
        self.failed = true;
    }

    pub fn view(self: *const Builder) Error!variables.View {
        if (self.failed) return error.AcquisitionFailed;
        return .{ .entries = self.entries[0..self.used], .coverage = self.coverage };
    }

    pub fn complete(self: *Builder, collections: []const variables.Collection) Error!void {
        if (self.failed) return error.AcquisitionFailed;
        errdefer self.poison();
        for (collections) |collection| try allowed(collection);
        for (collections) |collection| self.coverage[@backingInt(collection)] = .complete;
    }

    pub fn add(
        self: *Builder,
        collection: variables.Collection,
        record: Record,
        budget: *work.Budget,
    ) Error!void {
        errdefer self.poison();
        try allowed(collection);
        const saved = try self.save(record, 1, budget);
        self.publish(collection, saved);
    }

    /// Alias metadata shares one immutable copy of the key and value, while every
    /// duplicate occurrence gets its own entries. Names contain the actual key.
    pub fn named(
        self: *Builder,
        collection: variables.Collection,
        names: variables.Collection,
        record: Record,
        budget: *work.Budget,
    ) Error!void {
        errdefer self.poison();
        try allowed(collection);
        try allowed(names);
        const saved = try self.save(record, 2, budget);
        self.publish(collection, saved);
        self.publish(names, .{ .key = saved.key, .value = saved.key });
    }

    pub fn field(self: *Builder, origin: Origin, record: Record, budget: *work.Budget) Error!void {
        errdefer self.poison();
        const count: usize = if (origin == .json) 2 else 4;
        const bytes = std.math.add(u64, record.key.len, record.value.len) catch
            return error.AcquisitionByteLimit;
        const combined = std.math.add(u64, self.args_size, bytes) catch
            return error.AcquisitionByteLimit;
        const saved = try self.save(record, count, budget);
        self.publish(.args, saved);
        self.publish(.args_names, .{ .key = saved.key, .value = saved.key });
        switch (origin) {
            .query => {
                self.publish(.args_get, saved);
                self.publish(.args_get_names, .{ .key = saved.key, .value = saved.key });
            },
            .form => {
                self.publish(.args_post, saved);
                self.publish(.args_post_names, .{ .key = saved.key, .value = saved.key });
            },
            .json => {},
        }
        self.args_size = combined;
    }

    /// Raw entity bytes use the separately reserved entity buffers. They must stay
    /// immutable until all phases finish; parsed field storage is not charged twice.
    pub fn borrow(self: *Builder, entry: variables.Entry, budget: *work.Budget) Error!void {
        errdefer self.poison();
        try allowed(entry.collection);
        try self.capacity(1, 0);
        try budget.debit(1);
        // Borrow external immutable bytes or existing monotonic owned bytes.
        // Neither may refer to capacity that future appends will overwrite.
        buffers.assertDisjoint(entry.key, self.bytes[self.byte_used..]);
        buffers.assertDisjoint(entry.value, self.bytes[self.byte_used..]);
        self.entries[self.used] = entry;
        self.used += 1;
    }

    /// Namespace URI and decoded attribute storage shares the acquired byte bound.
    /// This copy publishes no collection entry and survives parser scratch reuse.
    pub fn own(self: *Builder, record: Record, budget: *work.Budget) Error!Record {
        errdefer self.poison();
        return self.save(record, 0, budget);
    }

    pub fn xml(
        self: *Builder,
        kind: variables.Xml,
        value: []const u8,
        budget: *work.Budget,
    ) Error!void {
        const selector = if (kind == .element) "/*" else "//@*";
        try self.add(.xml, .{ .key = selector, .value = value }, budget);
        self.entries[self.used - 1].xml = kind;
    }

    pub fn sizes(self: *Builder, budget: *work.Budget) Error!void {
        errdefer self.poison();
        var digits: [decimal.capacity(u64)]u8 = undefined;
        const integer = try decimal.write(u64, self.args_size, &digits, budget);
        var number: [decimal.capacity(u64) + 7]u8 = undefined;
        try budget.debit(integer.len + 7);
        @memcpy(number[0..integer.len], integer);
        @memcpy(number[integer.len..][0..7], ".000000");
        try self.scalar(.args_combined_size, number[0 .. integer.len + 7], budget);
        try self.complete(&.{.args_combined_size});
    }

    /// Updating a scalar keeps prior borrowed bytes valid until the slot resets.
    pub fn scalar(
        self: *Builder,
        collection: variables.Collection,
        value: []const u8,
        budget: *work.Budget,
    ) Error!void {
        errdefer self.poison();
        try allowed(collection);
        std.debug.assert(!collection.keyed());
        if (self.failed) return error.AcquisitionFailed;
        try budget.debit(self.used);
        for (self.entries[0..self.used]) |*entry| {
            if (entry.collection != collection) continue;
            const saved = try self.save(.{ .value = value }, 0, budget);
            entry.value = saved.value;
            return;
        }
        try self.add(collection, .{ .value = value }, budget);
    }

    fn save(self: *Builder, record: Record, count: usize, budget: *work.Budget) Error!Record {
        const size = std.math.add(usize, record.key.len, record.value.len) catch
            return error.AcquisitionByteLimit;
        try self.capacity(count, size);
        const cost = std.math.add(u64, size, count) catch return error.WorkLimit;
        try budget.debit(cost);
        const destination = self.bytes[self.byte_used..][0..size];
        buffers.assertDisjoint(record.key, destination);
        buffers.assertDisjoint(record.value, destination);
        @memcpy(destination[0..record.key.len], record.key);
        @memcpy(destination[record.key.len..], record.value);
        self.byte_used += size;
        return .{
            .key = destination[0..record.key.len],
            .value = destination[record.key.len..],
        };
    }

    fn capacity(self: *const Builder, count: usize, bytes: usize) Error!void {
        if (self.failed) return error.AcquisitionFailed;
        if (count > self.entries.len - self.used) return error.AcquisitionEntryLimit;
        if (bytes > self.bytes.len - self.byte_used) return error.AcquisitionByteLimit;
    }

    fn publish(self: *Builder, collection: variables.Collection, record: Record) void {
        std.debug.assert(self.used < self.entries.len);
        self.entries[self.used] = .{
            .collection = collection,
            .key = record.key,
            .value = record.value,
        };
        self.used += 1;
    }
};

fn allowed(collection: variables.Collection) Error!void {
    switch (collection) {
        .tx, .matched_var, .matched_var_name, .matched_vars, .matched_vars_names => {
            return error.ReservedCollection;
        },
        else => {},
    }
}

test {
    _ = @import("acquired_values_test.zig");
}

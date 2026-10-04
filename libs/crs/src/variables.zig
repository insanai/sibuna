//! Shared phase-specific transaction view. Input bytes remain caller-owned.
const std = @import("std");
const collections = @import("collections.zig");
const work = @import("work.zig");
pub const Collection = collections.Collection;
pub const count = @typeInfo(Collection).@"enum".field_names.len;
pub const Coverage = enum { unavailable, complete, incomplete };
pub const Error = work.Error || error{
    UnavailableCollection,
    IncompleteCollection,
    AmbiguousVariable,
};
pub const Xml = enum { element, attribute };
pub const Entry = struct {
    collection: Collection,
    key: []const u8 = "",
    value: []const u8,
    xml: ?Xml = null,
};
pub const Reference = struct { collection: Collection, key: ?[]const u8 = null };

pub const View = struct {
    entries: []const Entry,
    coverage: [count]Coverage = @splat(.unavailable),

    pub fn require(self: *const View, collection: Collection) Error!void {
        return switch (self.coverage[@backingInt(collection)]) {
            .complete => {},
            .unavailable => error.UnavailableCollection,
            .incomplete => error.IncompleteCollection,
        };
    }

    /// Macros require a unique value. Selectors instead iterate all entries.
    /// The C reference's multimap ordering is not a portable duplicate tie-breaker.
    pub fn lookup(self: *const View, reference: Reference, budget: *work.Budget) Error![]const u8 {
        return (try self.lookupOptional(reference, budget)) orelse "";
    }

    /// Connector metadata distinguishes an absent header from a present empty
    /// header. Keep the same uniqueness and coverage checks as macro lookup.
    pub fn lookupOptional(
        self: *const View,
        reference: Reference,
        budget: *work.Budget,
    ) Error!?[]const u8 {
        try budget.debit(1);
        try self.require(reference.collection);
        var found: ?[]const u8 = null;
        for (self.entries) |entry| {
            try budget.debit(1);
            if (entry.collection != reference.collection) continue;
            if (reference.key) |key| {
                if (!try keyEqual(key, entry.key, budget)) continue;
            }
            if (found != null) return error.AmbiguousVariable;
            found = entry.value;
        }
        return found;
    }
};

pub fn keyEqual(left: []const u8, right: []const u8, budget: *work.Budget) work.Error!bool {
    if (left.len != right.len) return false;
    try budget.debit(@intCast(left.len));
    return std.ascii.eqlIgnoreCase(left, right);
}

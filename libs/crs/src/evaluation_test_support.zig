//! Small reserved slots shared by condition and context contract tests.
const variables = @import("variables.zig");
const context = @import("evaluation_context.zig");
const tx = @import("transaction_vars.zig");
const condition = @import("condition.zig");
const work = @import("work.zig");

pub const Slot = struct {
    tx_entries: [32]variables.Entry = undefined,
    tx_bytes: [4096]u8 = undefined,
    merged: [128]variables.Entry = undefined,
    matched: [64]variables.Entry = undefined,
    matched_bytes: [4096]u8 = undefined,
    snapshot: [32]variables.Entry = undefined,
    count: [20]u8 = undefined,
    first: [256]u8 = undefined,
    second: [256]u8 = undefined,
    prefixes: [256]usize = undefined,
    pieces: [16][]const u8 = undefined,
    key_output: [256]u8 = undefined,
    value_output: [256]u8 = undefined,
    argument_output: [256]u8 = undefined,
    budget: work.Budget = .{ .remaining = 1_000_000 },
    store: tx.Store = undefined,
    context: context.Context = undefined,

    /// Initialize in place; Context borrows this slot's Store throughout its lifetime.
    pub fn init(self: *Slot, entries: []const variables.Entry) !void {
        self.budget = .{ .remaining = 1_000_000 };
        self.store = tx.Store.init(&self.tx_entries, &self.tx_bytes);
        self.context = try context.Context.init(.{
            .entries = entries,
            .coverage = @splat(.complete),
        }, &self.store, .{
            .view = &self.merged,
            .matched = &self.matched,
            .bytes = &self.matched_bytes,
        });
    }

    pub fn frame(self: *Slot) condition.Frame {
        return .{
            .context = &self.context,
            .snapshot = &self.snapshot,
            .count = &self.count,
            .transforms = .{ &self.first, &self.second },
            .prefixes = &self.prefixes,
            .pieces = &self.pieces,
            .key_output = &self.key_output,
            .value_output = &self.value_output,
            .argument_output = &self.argument_output,
            .budget = &self.budget,
        };
    }

    pub fn get(self: *Slot, key: []const u8) !?[]const u8 {
        return self.store.get(key, &self.budget);
    }
};

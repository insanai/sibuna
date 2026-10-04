//! Action operand preparation and mutation without rule-action timing assumptions.
const std = @import("std");
const set_var = @import("set_var.zig");
const tx = @import("transaction_vars.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");

const Scratch = struct {
    entries: [8]variables.Entry = undefined,
    bytes: [256]u8 = undefined,
    keys: [32]u8 = undefined,
    values: [32]u8 = undefined,
    pieces: [8][]const u8 = undefined,
    budget: work.Budget = .{ .remaining = 100_000 },

    fn frame(self: *Scratch, store: *tx.Store, view: *const variables.View) set_var.Frame {
        return .{
            .store = store,
            .view = view,
            .pieces = &self.pieces,
            .key_output = &self.keys,
            .value_output = &self.values,
            .budget = &self.budget,
        };
    }
};

fn apply(source: []const u8, frame: set_var.Frame) !void {
    var program = try set_var.compile(std.testing.allocator, source);
    defer program.deinit();
    try program.execute(frame);
}

test "prepared TX actions preserve assignment addition subtraction unset and bare semantics" {
    var scratch: Scratch = .{};
    var store = tx.Store.init(&scratch.entries, &scratch.bytes);
    const view: variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    const frame = scratch.frame(&store, &view);
    try apply("tx.score=3", frame);
    try apply("tx.score=+5", frame);
    try apply("TX.score=-2", frame);
    try std.testing.expectEqualStrings("6", (try store.get("score", &scratch.budget)).?);
    try apply("tx.present", frame);
    try std.testing.expectEqualStrings("1", (try store.get("present", &scratch.budget)).?);
    try apply("tx.empty=", frame);
    try std.testing.expectEqualStrings("", (try store.get("empty", &scratch.budget)).?);
    try apply("!tx.present", frame);
    try std.testing.expect(try store.get("present", &scratch.budget) == null);
    try apply("tx.text=one=two", frame);
    try std.testing.expectEqualStrings("one=two", (try store.get("text", &scratch.budget)).?);
}

test "dynamic target and operand values are copied before caller scratch is reused" {
    var scratch: Scratch = .{};
    var store = tx.Store.init(&scratch.entries, &scratch.bytes);
    try store.put("target", "score", &scratch.budget);
    try store.put("contribution", "5", &scratch.budget);
    const view: variables.View = .{
        .entries = try store.values(),
        .coverage = @splat(.complete),
    };
    var program = try set_var.compile(
        std.testing.allocator,
        "tx.%{tx.target}=+%{tx.contribution}",
    );
    defer program.deinit();
    try program.execute(scratch.frame(&store, &view));
    @memset(&scratch.keys, 'x');
    @memset(&scratch.values, 'x');
    try std.testing.expectEqualStrings("5", (try store.get("score", &scratch.budget)).?);
    try std.testing.expectEqualStrings("score", store.entries[2].key);
}

test "failed dynamic resolution changes no stored bytes and prevents continued action execution" {
    var scratch: Scratch = .{};
    var store = tx.Store.init(&scratch.entries, &scratch.bytes);
    try store.put("score", "1", &scratch.budget);
    var view: variables.View = .{
        .entries = try store.values(),
        .coverage = @splat(.complete),
    };
    view.coverage[@backingInt(variables.Collection.request_headers)] = .unavailable;
    var program = try set_var.compile(
        std.testing.allocator,
        "tx.%{REQUEST_HEADERS.name}=+%{tx.score}",
    );
    defer program.deinit();
    const before = store.byte_used;
    try std.testing.expectError(
        error.UnavailableCollection,
        program.execute(scratch.frame(&store, &view)),
    );
    try std.testing.expectEqual(before, store.byte_used);
    try std.testing.expectEqualStrings("1", store.entries[0].value);
    try std.testing.expect(store.failed);
    try std.testing.expectError(
        error.TransactionFailed,
        program.execute(scratch.frame(&store, &view)),
    );
}

test "unsupported namespaces malformed deletion and empty resolved keys reject explicitly" {
    for ([_][]const u8{ "global.name=1", "ip.name=1", "tx.", "name=1", "=1" }) |source| {
        try std.testing.expectError(
            error.UnsupportedNamespace,
            set_var.compile(std.testing.allocator, source),
        );
    }
    try std.testing.expectError(
        error.InvalidAssignment,
        set_var.compile(std.testing.allocator, "!tx.name=1"),
    );
    var scratch: Scratch = .{};
    var store = tx.Store.init(&scratch.entries, &scratch.bytes);
    const view: variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var program = try set_var.compile(std.testing.allocator, "tx.%{tx.missing}=1");
    defer program.deinit();
    try std.testing.expectError(error.InvalidKey, program.execute(scratch.frame(&store, &view)));
    try std.testing.expectEqual(@as(usize, 0), store.used);
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try set_var.compile(allocator, "tx.%{tx.target}=+%{tx.amount}");
    defer program.deinit();
    var unset = try set_var.compile(allocator, "!tx.name");
    defer unset.deinit();
}

test "prepared TX actions own both programs and release partial compilation on failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
    var source = "tx.name=value".*;
    var program = try set_var.compile(std.testing.allocator, &source);
    defer program.deinit();
    @memset(&source, 'x');
    try std.testing.expectEqualStrings("name", program.key.source);
    try std.testing.expectEqualStrings("value", program.value.?.source);
}

test "every action work failure leaves stored values unchanged and poisons execution" {
    var program = try set_var.compile(std.testing.allocator, "tx.score=+%{tx.amount}");
    defer program.deinit();
    for (0..150) |allowance| {
        var scratch: Scratch = .{};
        var store = tx.Store.init(&scratch.entries, &scratch.bytes);
        try store.put("score", "1", &scratch.budget);
        try store.put("amount", "5", &scratch.budget);
        const before = store.byte_used;
        const view: variables.View = .{
            .entries = try store.values(),
            .coverage = @splat(.complete),
        };
        scratch.budget.remaining = allowance;
        if (program.execute(scratch.frame(&store, &view))) |_| {
            try std.testing.expectEqualStrings("6", store.entries[0].value);
            try std.testing.expect(!store.failed);
        } else |err| {
            try std.testing.expectEqual(error.WorkLimit, err);
            try std.testing.expectEqualStrings("1", store.entries[0].value);
            try std.testing.expectEqualStrings("5", store.entries[1].value);
            try std.testing.expectEqual(before, store.byte_used);
            scratch.budget.remaining = 100_000;
            try std.testing.expectError(
                error.TransactionFailed,
                program.execute(scratch.frame(&store, &view)),
            );
        }
    }
}

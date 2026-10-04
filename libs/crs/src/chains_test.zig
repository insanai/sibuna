const std = @import("std");
const compiler = @import("compiler.zig");
const condition = @import("condition.zig");
const chains = @import("chains.zig");
const variables = @import("variables.zig");
const support = @import("evaluation_test_support.zig");
const model = @import("model.zig");

const Prepared = struct {
    allocator: std.mem.Allocator,
    topology: chains.Program,
    conditions: []condition.Program,

    fn init(allocator: std.mem.Allocator, source: []const u8) !Prepared {
        var builder = compiler.Compiler.init(allocator, .{});
        defer builder.deinit();
        try builder.addSource("test.conf", source);
        var plan = try builder.finish();
        defer plan.deinit();
        var topology = try chains.compile(allocator, plan.conditions, .{});
        errdefer topology.deinit();
        const programs = try allocator.alloc(condition.Program, plan.conditions.len);
        var used: usize = 0;
        errdefer {
            for (programs[0..used]) |*program| program.deinit();
            allocator.free(programs);
        }
        for (plan.conditions, programs) |*item, *program| {
            program.* = try condition.compile(allocator, item, &.{}, .{});
            used += 1;
        }
        return .{ .allocator = allocator, .topology = topology, .conditions = programs };
    }

    fn deinit(self: *Prepared) void {
        for (self.conditions) |*program| program.deinit();
        self.allocator.free(self.conditions);
        self.topology.deinit();
        self.* = undefined;
    }
};

const chain_source =
    \\SecRule ARGS "@streq yes" "id:1,chain,setvar:tx.parent=+1"
    \\SecRule TX:parent "@eq 2" "chain,setvar:tx.child=+1"
    \\SecRule TX:child "@eq 1" "setvar:tx.leaf=1"
    \\SecRule ARGS "@streq no" "id:2"
;

test "chains evaluate all parent fields then each child once and unwind from leaf" {
    var prepared = try Prepared.init(std.testing.allocator, chain_source);
    defer prepared.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "q", .value = "yes" },
        .{ .collection = .args, .key = "q", .value = "yes" },
    };
    var slot: support.Slot = .{};
    try slot.init(&input);
    var unwind: [3]usize = undefined;
    const result = try prepared.topology.evaluate(prepared.conditions, 0, slot.frame(), &unwind);
    try std.testing.expect(result.matched);
    try std.testing.expectEqualSlices(usize, &.{ 2, 1, 0 }, result.unwind);
    try std.testing.expectEqual(@as(usize, 3), result.next_root);
    try std.testing.expectEqual(@as(usize, 3), prepared.topology.maximum_depth);
    try std.testing.expectEqualStrings("2", (try slot.get("parent")).?);
    try std.testing.expectEqualStrings("1", (try slot.get("child")).?);
    try std.testing.expectEqualStrings("1", (try slot.get("leaf")).?);
}

test "a failed child yields no post-match actions and retains parent transaction writes" {
    var prepared = try Prepared.init(std.testing.allocator, chain_source);
    defer prepared.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "yes" }};
    var slot: support.Slot = .{};
    try slot.init(&input);
    var unwind: [3]usize = @splat(99);
    const result = try prepared.topology.evaluate(prepared.conditions, 0, slot.frame(), &unwind);
    try std.testing.expect(!result.matched);
    try std.testing.expectEqual(@as(usize, 0), result.unwind.len);
    try std.testing.expectEqualSlices(usize, &.{ 99, 99, 99 }, &unwind);
    try std.testing.expectEqualStrings("1", (try slot.get("parent")).?);
    try std.testing.expect(try slot.get("child") == null);
    try std.testing.expectEqual(@as(usize, 0), slot.context.matched_used);
    try std.testing.expect(!slot.context.failed);
}

test "invalid root program count and insufficient unwind storage fail before effects" {
    var prepared = try Prepared.init(std.testing.allocator, chain_source);
    defer prepared.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "yes" }};
    for (0..3) |scenario| {
        var slot: support.Slot = .{};
        try slot.init(&input);
        var unwind: [3]usize = undefined;
        const expected: chains.Error = switch (scenario) {
            0 => error.InvalidRoot,
            1 => error.ProgramCount,
            2 => error.UnwindLimit,
            else => unreachable,
        };
        try std.testing.expectError(expected, prepared.topology.evaluate(
            prepared.conditions[0 .. prepared.conditions.len - @intFromBool(scenario == 1)],
            if (scenario == 0) 1 else 0,
            slot.frame(),
            unwind[0..if (scenario == 2) 2 else 3],
        ));
        try std.testing.expectEqual(@as(usize, 0), slot.store.used);
        try std.testing.expect(slot.context.failed and slot.store.failed);
    }
}

test "every traversal work failure invalidates the transaction permanently" {
    var prepared = try Prepared.init(std.testing.allocator, chain_source);
    defer prepared.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "q", .value = "yes" },
        .{ .collection = .args, .key = "q", .value = "yes" },
    };
    for (0..400) |allowance| {
        var slot: support.Slot = .{};
        try slot.init(&input);
        slot.budget.remaining = allowance;
        var unwind: [3]usize = undefined;
        if (prepared.topology.evaluate(prepared.conditions, 0, slot.frame(), &unwind)) |result| {
            try std.testing.expect(result.matched);
        } else |err| {
            try std.testing.expectEqual(error.WorkLimit, err);
            try std.testing.expect(slot.context.failed and slot.store.failed);
            slot.budget.remaining = 1_000_000;
            try std.testing.expectError(error.TransactionFailed, prepared.topology.evaluate(
                prepared.conditions,
                0,
                slot.frame(),
                &unwind,
            ));
        }
    }
}

test "topology rejects inconsistent IDs phases links roots markers and capacities" {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf", chain_source);
    var plan = try builder.finish();
    defer plan.deinit();
    for (0..6) |scenario| {
        const original = plan.conditions[1];
        defer plan.conditions[1] = original;
        switch (scenario) {
            0 => plan.conditions[1].id = 100,
            1 => plan.conditions[1].phase = .logging,
            2 => plan.conditions[1].root = 1,
            3 => plan.conditions[1].chain_next = 0,
            4 => plan.conditions[1].skip_to = 2,
            5 => plan.conditions[1].skip_to = 100,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidTopology, chains.compile(
            std.testing.allocator,
            plan.conditions,
            .{},
        ));
    }
    try std.testing.expectError(error.ChainLimit, chains.compile(
        std.testing.allocator,
        plan.conditions,
        .{ .depth = 2 },
    ));
    try std.testing.expectError(error.ConditionLimit, chains.compile(
        std.testing.allocator,
        plan.conditions,
        .{ .conditions = 3 },
    ));
    var empty = try chains.compile(std.testing.allocator, &.{}, .{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.maximum_depth);
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    // Arena growth can remap in place depending on backing addresses. Refuse
    // remaps here so failure enumeration visits the same allocation sequence
    // every time and exercises the allocating fallback's cleanup as well.
    var fixed = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    var prepared = try Prepared.init(fixed.allocator(), chain_source);
    defer prepared.deinit();
}

test "prepared chain ownership releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

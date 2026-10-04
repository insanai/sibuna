const std = @import("std");
const prepare = @import("rule_program_test.zig").prepare;
const slots = @import("transaction_slot.zig");
const rules = @import("rule_program.zig");
const variables = @import("variables.zig");
const Result = @import("executor.zig").Result;
pub const limits: slots.Limits = .{
    .entries = 8,
    .bytes = 256,
    .request = 64,
    .response = 64,
    .events = 8,
    .tags = 16,
    .exclusions = 8,
    .pieces = 16,
    .work = 100_000,
    .reservation = 1024 * 1024,
};

test "reserved slot runs without allocations and reset cannot leak prior TX or evidence" {
    var program = try prepare(
        \\SecRule ARGS "@rx (x+)" "id:1,capture,msg:'%{TX.1}',setvar:tx.score=+1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "xx" }};
    const empty: variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var first = try slot.begin(.{ .entries = &input, .coverage = @splat(.complete) }, true);
    try std.testing.expectError(error.ActiveSlot, slot.begin(empty, true));
    try std.testing.expectEqual(Result.complete, try first.run(.request_body));
    try std.testing.expectEqualStrings("1", (try slot.store.get("score", &slot.budget)).?);
    try std.testing.expectEqualStrings("xx", slot.state.events[0].message);
    slot.finish();
    var second = try slot.begin(empty, false);
    try std.testing.expectEqual(Result.complete, try second.run(.request_body));
    try std.testing.expect(try slot.store.get("score", &slot.budget) == null);
    try std.testing.expectEqual(@as(usize, 0), slot.state.event_used);
    try std.testing.expectEqual(@as(usize, 0), slot.context.matched_used);
    slot.finish();
}

test "phase acquisition preserves copied matched state and TX while updating coverage" {
    var program = try prepare(
        \\SecRule ARGS "@contains x" "id:1,phase:1,setvar:tx.score=1"
        \\SecRule RESPONSE_BODY "@streq safe" "id:2,phase:4,setvar:tx.score=+1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    const request = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "xx" }};
    const response = [_]variables.Entry{.{ .collection = .response_body, .value = "safe" }};
    const view: variables.View = .{ .entries = &request, .coverage = @splat(.complete) };
    try std.testing.expectError(error.InactiveSlot, slot.acquire(view));
    var state = try slot.begin(view, true);
    defer slot.finish();
    _ = try state.run(.request_headers);
    try slot.acquire(.{ .entries = &response, .coverage = @splat(.complete) });
    try std.testing.expectEqualStrings("xx", slot.matched[0].value);
    _ = try state.run(.response_body);
    try std.testing.expectEqualStrings("2", (try slot.store.get("score", &slot.budget)).?);
}

fn failAllocation(allocator: std.mem.Allocator, program: *const rules.Program) !void {
    var slot: slots.Slot = undefined;
    // Backing reallocations depend on heap placement; disable them so failure
    // injection enumerates a deterministic set of arena node allocations.
    var fixed = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    try slot.init(fixed.allocator(), program, limits);
    defer slot.deinit();
}

test "slot reservations release every partially allocated arena on allocation failure" {
    var program = try prepare(
        \\SecRule ARGS "@rx (x+)" "id:1,capture"
    , &.{});
    defer program.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, failAllocation, .{&program});
    var slot: slots.Slot = undefined;
    var too_small = limits;
    too_small.reservation = 1;
    try std.testing.expectError(
        error.ReservationLimit,
        slot.init(std.testing.allocator, &program, too_small),
    );
    var invalid = limits;
    invalid.entries = std.math.maxInt(usize);
    try std.testing.expectError(
        error.InvalidSlotLimits,
        slot.init(std.testing.allocator, &program, invalid),
    );
}

test "one slot charges acquisition and evaluation across header and JSON body phases" {
    var program = try prepare(
        \\SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,setvar:tx.score=1"
        \\SecRule ARGS:json.q "@contains SELECT" "id:2,phase:2,setvar:tx.score=+1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var state = try slot.begin(.{ .entries = &.{} }, true);
    defer slot.finish();
    const original_work = slot.budget.remaining;
    try slot.input.scalar(.request_method, "POST", &slot.budget);
    try slot.input.complete(&.{.request_method});
    try slot.acquire(try slot.input.view());
    _ = try state.run(.request_headers);
    try std.testing.expectEqualStrings("1", (try slot.store.get("score", &slot.budget)).?);
    try @import("json_acquisition.zig").parse(
        "{\"q\":\"SELECT\"}",
        &slot.input,
        slot.jsonScratch(),
        &slot.budget,
    );
    try slot.input.complete(&.{ .args, .args_names });
    try slot.acquire(try slot.input.view());
    _ = try state.run(.request_body);
    try std.testing.expectEqualStrings("2", (try slot.store.get("score", &slot.budget)).?);
    try std.testing.expect(slot.budget.remaining < original_work);
    try std.testing.expectEqualStrings("POST", slot.matched[0].value);
    try std.testing.expectEqualStrings(
        "SELECT",
        slot.matched[slot.context.matched_used - 2].value,
    );
}

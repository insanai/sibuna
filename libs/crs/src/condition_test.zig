const std = @import("std");
const compiler = @import("compiler.zig");
const condition = @import("condition.zig");
const variables = @import("variables.zig");
const regex = @import("regex.zig");
const support = @import("evaluation_test_support.zig");
const controls = @import("controls.zig");

fn prepare(allocator: std.mem.Allocator, source: []const u8) !condition.Program {
    var builder = compiler.Compiler.init(allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf", source);
    var plan = try builder.finish();
    defer plan.deinit();
    return condition.compile(allocator, &plan.conditions[0], &.{}, .{});
}

test "runtime tag exclusions refresh dynamic tags after preceding candidate writes" {
    var program = try prepare(std.testing.allocator,
        \\SecRule ARGS "@contains x" "id:1,tag:'%{TX.kind}',\
        \\ setvar:tx.kind=drop,setvar:tx.score=+1"
    );
    defer program.deinit();
    var removal = try controls.compile(std.testing.allocator, "ruleRemoveTargetByTag=drop;ARGS:b");
    defer removal.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "a", .value = "x" },
        .{ .collection = .args, .key = "b", .value = "x" },
    };
    var slot: support.Slot = .{};
    try slot.init(&input);
    try slot.store.put("kind", "keep", &slot.budget);
    var exclusions: [1]controls.Exclusion = undefined;
    var control: controls.State = .{ .exclusions = &exclusions };
    try control.apply(&removal, &slot.budget);
    var frame = slot.frame();
    frame.control = &control;
    try std.testing.expect(try program.evaluate(frame));
    try std.testing.expectEqualStrings("1", (try slot.get("score")).?);
    try std.testing.expectEqual(@as(usize, 2), slot.context.matched_used);
    try std.testing.expectEqualStrings("ARGS:a", slot.matched[0].key);
}

test "runtime target exclusions are applied before count aggregation and rule effects" {
    var program = try prepare(std.testing.allocator,
        \\SecRule &ARGS "@eq 1" "id:1,setvar:tx.score=+1"
    );
    defer program.deinit();
    var removal = try controls.compile(std.testing.allocator, "ruleRemoveTargetById=1;ARGS:b");
    defer removal.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "a", .value = "x" },
        .{ .collection = .args, .key = "b", .value = "x" },
    };
    var slot: support.Slot = .{};
    try slot.init(&input);
    var exclusions: [1]controls.Exclusion = undefined;
    var control: controls.State = .{ .exclusions = &exclusions };
    try control.apply(&removal, &slot.budget);
    var frame = slot.frame();
    frame.control = &control;
    try std.testing.expect(try program.evaluate(frame));
    try std.testing.expectEqualStrings("1", (try slot.get("score")).?);
    try std.testing.expectEqualStrings("1", slot.matched[0].value);
}

test "excluded actions have no writes and unavailable exclusion tags poison evaluation" {
    var program = try prepare(std.testing.allocator,
        \\SecAction "id:1,tag:'%{REQUEST_BODY}',setvar:tx.score=+1"
    );
    defer program.deinit();
    var removal = try controls.compile(std.testing.allocator, "ruleRemoveByTag=drop");
    defer removal.deinit();
    const input = [_]variables.Entry{.{ .collection = .request_body, .value = "drop" }};
    for ([_]bool{ true, false }) |available| {
        var slot: support.Slot = .{};
        try slot.init(&input);
        var exclusions: [1]controls.Exclusion = undefined;
        var control: controls.State = .{ .exclusions = &exclusions };
        try control.apply(&removal, &slot.budget);
        var frame = slot.frame();
        frame.control = &control;
        if (available) {
            try std.testing.expect(!try program.evaluate(frame));
            try std.testing.expect(try slot.get("score") == null);
        } else {
            slot.context.acquired.coverage[@backingInt(variables.Collection.request_body)] =
                .unavailable;
            try std.testing.expectError(error.UnavailableCollection, program.evaluate(frame));
            try std.testing.expect(slot.context.failed and slot.store.failed and control.failed);
        }
    }
}

test "each field and multiMatch stage sees prior writes and owns its matched value" {
    var program = try prepare(
        std.testing.allocator,
        "SecRule ARGS \"@contains x\" \"id:1,multiMatch,t:lowercase,t:hexEncode," ++
            "setvar:tx.score=+1,setvar:tx.last=%{MATCHED_VAR}\"",
    );
    defer program.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "a", .value = "Xx" },
        .{ .collection = .args, .key = "a", .value = "xx" },
    };
    var slot: support.Slot = .{};
    try slot.init(&input);
    try std.testing.expect(try program.evaluate(slot.frame()));
    try std.testing.expectEqualStrings("3", (try slot.get("score")).?);
    try std.testing.expectEqualStrings("xx", (try slot.get("last")).?);
    try std.testing.expectEqual(@as(usize, 6), slot.context.matched_used);
    try std.testing.expectEqualStrings("Xx", slot.matched[0].value);
    try std.testing.expectEqualStrings("xx", slot.matched[2].value);
    try std.testing.expectEqualStrings("xx", slot.matched[4].value);
}

test "one target snapshots TX metadata while later targets see its mutations" {
    var program = try prepare(
        std.testing.allocator,
        "SecRule TX|TX:b \"@streq yes\" \"id:1,t:none,setvar:tx.b=changed," ++
            "setvar:!tx.a,setvar:tx.score=+1\"",
    );
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(&.{});
    try slot.store.put("a", "yes", &slot.budget);
    try slot.store.put("b", "yes", &slot.budget);
    try std.testing.expect(try program.evaluate(slot.frame()));
    try std.testing.expectEqualStrings("2", (try slot.get("score")).?);
    try std.testing.expectEqualStrings("changed", (try slot.get("b")).?);
    try std.testing.expect(try slot.get("a") == null);
    try std.testing.expectEqualStrings("TX:a", slot.matched[0].key);
    try std.testing.expectEqualStrings("TX:b", slot.matched[2].key);
}

test "capture precedes negation and false conditions clear matches without undoing TX" {
    var program = try prepare(std.testing.allocator,
        \\SecRule ARGS "!@rx (x+)" "id:1,t:none,capture,setvar:tx.score=+1"
    );
    defer program.deinit();
    var workspace = try regex.Workspace.init(std.testing.allocator, &program.predicate.?.regex);
    defer workspace.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "xx" }};
    var slot: support.Slot = .{};
    try slot.init(&input);
    try slot.store.put("score", "7", &slot.budget);
    try slot.context.record(input[0], false, "earlier", &slot.budget);
    var frame = slot.frame();
    frame.regex = &workspace.scratch;
    try std.testing.expect(!try program.evaluate(frame));
    try std.testing.expectEqualStrings("xx", (try slot.get("0")).?);
    try std.testing.expectEqualStrings("xx", (try slot.get("1")).?);
    try std.testing.expectEqualStrings("7", (try slot.get("score")).?);
    try std.testing.expectEqual(@as(usize, 0), slot.context.matched_used);
}

test "unconditional actions rebuild the view between ordered writes" {
    var program = try prepare(std.testing.allocator,
        \\SecAction "id:1,setvar:tx.a=1,setvar:tx.b=%{tx.a},setvar:tx.a=+%{tx.b}"
    );
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(&.{});
    try std.testing.expect(try program.evaluate(slot.frame()));
    try std.testing.expectEqualStrings("2", (try slot.get("a")).?);
    try std.testing.expectEqualStrings("1", (try slot.get("b")).?);
}

test "empty regex operators succeed without replacing older capture keys" {
    var program = try prepare(std.testing.allocator,
        \\SecRule ARGS "@rx" "id:1,capture,setvar:tx.score=+1"
    );
    defer program.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "uncaptured" }};
    var slot: support.Slot = .{};
    try slot.init(&input);
    try slot.store.put("0", "old capture", &slot.budget);
    try std.testing.expect(try program.evaluate(slot.frame()));
    try std.testing.expectEqualStrings("1", (try slot.get("score")).?);
    try std.testing.expectEqualStrings("old capture", (try slot.get("0")).?);
    const view = try slot.context.view(&slot.budget);
    try std.testing.expectEqualStrings("uncaptured", try view.lookup(.{
        .collection = .matched_var,
    }, &slot.budget));
}

test "missing coverage and every exhausted budget poison continued evaluation" {
    var program = try prepare(std.testing.allocator,
        \\SecRule ARGS "@contains x" "id:1,t:lowercase,setvar:tx.score=+1"
    );
    defer program.deinit();
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "X" }};
    for (0..200) |allowance| {
        var slot: support.Slot = .{};
        try slot.init(&input);
        slot.budget.remaining = allowance;
        if (program.evaluate(slot.frame())) |matched| {
            try std.testing.expect(matched);
        } else |err| {
            try std.testing.expectEqual(error.WorkLimit, err);
            try std.testing.expect(slot.context.failed and slot.store.failed);
            slot.budget.remaining = 1_000_000;
            try std.testing.expectError(error.TransactionFailed, program.evaluate(slot.frame()));
        }
    }
    var slot: support.Slot = .{};
    try slot.init(&input);
    slot.context.acquired.coverage[@backingInt(variables.Collection.args)] = .incomplete;
    try std.testing.expectError(error.IncompleteCollection, program.evaluate(slot.frame()));
    try std.testing.expect(slot.context.failed);
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try prepare(allocator,
        \\SecRule ARGS "/x/" "id:1,t:lowercase,setvar:tx.a=1,setvar:tx.b=%{tx.a}"
    );
    defer program.deinit();
}

test "prepared conditions own source bytes and release every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

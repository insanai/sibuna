const std = @import("std");
const support = @import("evaluation_test_support.zig");
const variables = @import("variables.zig");
const context = @import("evaluation_context.zig");

test "merged views expose current TX and occurrence-ordered stable matched bytes" {
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "raw" }};
    var slot: support.Slot = .{};
    try slot.init(&input);
    try slot.store.put("score", "1", &slot.budget);
    var temporary = "changed".*;
    try slot.context.record(input[0], false, &temporary, &slot.budget);
    @memset(&temporary, 'x');
    const previous = try slot.context.view(&slot.budget);
    try std.testing.expectEqualStrings("changed", try previous.lookup(.{
        .collection = .matched_var,
    }, &slot.budget));
    try slot.store.put("score", "2", &slot.budget);
    try slot.context.record(input[0], false, "again", &slot.budget);
    const current = try slot.context.view(&slot.budget);
    try std.testing.expectEqualStrings("2", try current.lookup(.{
        .collection = .tx,
        .key = "score",
    }, &slot.budget));
    try std.testing.expectEqualStrings("again", try current.lookup(.{
        .collection = .matched_var,
    }, &slot.budget));
    try std.testing.expectEqualStrings("ARGS:q", try current.lookup(.{
        .collection = .matched_var_name,
    }, &slot.budget));
    try std.testing.expectEqualStrings("changed", slot.matched[0].value);
    try std.testing.expectEqualStrings("again", slot.matched[2].value);
    try std.testing.expectError(error.AmbiguousVariable, current.lookup(.{
        .collection = .matched_vars,
        .key = "ARGS:q",
    }, &slot.budget));
    const before = slot.context.byte_used;
    try slot.context.clearMatches();
    const cleared = try slot.context.view(&slot.budget);
    try std.testing.expectEqual(before, slot.context.byte_used);
    try std.testing.expectEqualStrings("", try cleared.lookup(.{
        .collection = .matched_var,
    }, &slot.budget));
    try std.testing.expectEqualStrings("2", (try slot.get("score")).?);
}

test "context refuses externally populated internal collections" {
    const owned = .{ .tx, .matched_var, .matched_var_name, .matched_vars, .matched_vars_names };
    inline for (owned) |c| {
        var slot: support.Slot = .{};
        const entries = [_]variables.Entry{.{ .collection = c, .value = "forged" }};
        try std.testing.expectError(error.ReservedCollection, slot.init(&entries));
    }
}

test "merged-view and matched capacity failures poison both owners" {
    const input = [_]variables.Entry{.{ .collection = .args, .key = "q", .value = "x" }};
    for (0..3) |scenario| {
        var slot: support.Slot = .{};
        try slot.init(&input);
        if (scenario == 0) {
            slot.context.scratch.view = &.{};
            try std.testing.expectError(error.ViewLimit, slot.context.view(&slot.budget));
        } else {
            if (scenario == 1) slot.context.scratch.matched = slot.matched[0..1];
            if (scenario == 2) slot.context.scratch.bytes = slot.matched_bytes[0..1];
            const expected: context.Error = if (scenario == 1)
                error.MatchedLimit
            else
                error.ByteLimit;
            try std.testing.expectError(expected, slot.context.record(
                input[0],
                false,
                "x",
                &slot.budget,
            ));
            try std.testing.expectEqual(@as(usize, 0), slot.context.matched_used);
            try std.testing.expectEqual(@as(usize, 0), slot.context.byte_used);
        }
        try std.testing.expect(slot.context.failed and slot.store.failed);
        slot.budget.remaining = 1_000_000;
        try std.testing.expectError(error.TransactionFailed, slot.context.view(&slot.budget));
    }
}

test "count names and every refused copy preserve previous metadata" {
    const entry: variables.Entry = .{ .collection = .args, .value = "0" };
    for (0..16) |allowance| {
        var slot: support.Slot = .{};
        try slot.init(&.{});
        slot.budget.remaining = allowance;
        if (slot.context.record(entry, true, "0", &slot.budget)) |_| {
            try std.testing.expectEqualStrings("&ARGS", slot.matched[0].key);
        } else |err| {
            try std.testing.expectEqual(error.WorkLimit, err);
            try std.testing.expectEqual(@as(usize, 0), slot.context.matched_used);
            try std.testing.expectEqual(@as(usize, 0), slot.context.byte_used);
            try std.testing.expect(slot.context.failed and slot.store.failed);
        }
    }
}

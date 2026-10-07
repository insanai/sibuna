const std = @import("std");
const macros = @import("macros.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const t = std.testing;

test "macro parts own source and expand once using exact case-insensitive references" {
    var source = ("%{TX.score}/%{request_headers:Host}/%{matched_var_name}/%{tx.missing}").*;
    var program = try macros.compile(t.allocator, &source, .{});
    defer program.deinit();
    @memset(&source, 'x');
    const entries = [_]variables.Entry{
        .{ .collection = .tx, .key = "SCORE", .value = "7" },
        .{ .collection = .request_headers, .key = "host", .value = "example.com" },
        .{ .collection = .matched_var_name, .value = "%{tx.score}" },
    };
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var pieces: [8][]const u8 = undefined;
    var output: [128]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1000 };
    const expanded = try program.expand(.{
        .view = &view,
        .pieces = &pieces,
        .output = &output,
        .budget = &budget,
    });
    try t.expectEqualStrings("7/example.com/%{tx.score}/", expanded);
}

test "reference-free programs expose their literal text" {
    var tag = try macros.compile(t.allocator, "attack-xss", .{});
    defer tag.deinit();
    try t.expectEqualStrings("attack-xss", tag.fixed().?);
    var empty = try macros.compile(t.allocator, "", .{});
    defer empty.deinit();
    try t.expectEqualStrings("", empty.fixed().?);
    var level = try macros.compile(t.allocator, "paranoia-level/%{tx.level}", .{});
    defer level.deinit();
    try t.expect(level.fixed() == null);
}

test "missing values require complete coverage and duplicate macros fail explicitly" {
    const entries = [_]variables.Entry{
        .{ .collection = .args, .key = "Name", .value = "first" },
        .{ .collection = .args, .key = "NAME", .value = "second" },
    };
    var view: variables.View = .{ .entries = &entries };
    var budget: work.Budget = .{ .remaining = 1000 };
    const reference: variables.Reference = .{ .collection = .args, .key = "name" };
    try t.expectError(error.UnavailableCollection, view.lookup(reference, &budget));
    view.coverage[@backingInt(variables.Collection.args)] = .incomplete;
    try t.expectError(error.IncompleteCollection, view.lookup(reference, &budget));
    view.coverage[@backingInt(variables.Collection.args)] = .complete;
    try t.expectError(error.AmbiguousVariable, view.lookup(reference, &budget));
    const missing = try view.lookup(.{ .collection = .args, .key = "absent" }, &budget);
    try t.expectEqualStrings("", missing);
}

test "every expansion work and capacity failure leaves output unchanged" {
    var program = try macros.compile(t.allocator, "before%{tx.value}after", .{});
    defer program.deinit();
    const entries = [_]variables.Entry{
        .{ .collection = .tx, .key = "value", .value = "123" },
    };
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var pieces: [3][]const u8 = undefined;
    var output: [32]u8 = @splat(0x55);
    var budget: work.Budget = .{ .remaining = 1000 };
    var frame: macros.Frame = .{
        .view = &view,
        .pieces = &pieces,
        .output = &output,
        .budget = &budget,
    };
    try t.expectEqualStrings("before123after", try program.expand(frame));
    const cost = 1000 - budget.remaining;
    for (0..cost) |allowance| {
        @memset(&output, 0x55);
        budget.remaining = allowance;
        try t.expectError(error.WorkLimit, program.expand(frame));
        for (output) |byte| try t.expectEqual(@as(u8, 0x55), byte);
    }
    budget.remaining = 1000;
    frame.output = output[0..8];
    try t.expectError(error.OutputLimit, program.expand(frame));
    frame.pieces = pieces[0..2];
    try t.expectError(error.ScratchLimit, program.expand(frame));
    for (output) |byte| try t.expectEqual(@as(u8, 0x55), byte);
}

test "macro compilation rejects malformed unknown nested and oversized profiles" {
    for ([_][]const u8{ "%{", "%{}", "%{tx.}", "%{remote_addr.key}", "nul\x00" }) |source| {
        try t.expectError(error.InvalidMacro, macros.compile(t.allocator, source, .{}));
    }
    try t.expectError(error.UnknownCollection, macros.compile(t.allocator, "%{UNKNOWN}", .{}));
    try t.expectError(error.UnsupportedMacro, macros.compile(t.allocator, "%{TX}", .{}));
    try t.expectError(
        error.UnsupportedMacro,
        macros.compile(t.allocator, "%{tx.%{matched_var}}", .{}),
    );
    try t.expectError(error.SourceLimit, macros.compile(t.allocator, "1234", .{ .source = 3 }));
    try t.expectError(error.PartLimit, macros.compile(t.allocator, "x%{tx.a}y", .{ .parts = 2 }));
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try macros.compile(allocator, "first%{tx.value}last%{REMOTE_ADDR}", .{});
    defer program.deinit();
    try t.expectEqual(@as(usize, 4), program.parts.len);
}

test "macro ownership releases all allocations after every failed compile" {
    try t.checkAllAllocationFailures(t.allocator, allocationScenario, .{});
}

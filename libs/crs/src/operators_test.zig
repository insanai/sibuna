//! Compiled predicate ownership, capture contracts and shared request-path bounds.
const std = @import("std");
const operators = @import("operators.zig");
const model = @import("model.zig");
const regex = @import("regex.zig");
const work = @import("work.zig");
const variables = @import("variables.zig");

const Case = struct {
    kind: model.Operator,
    argument: []const u8 = "",
    input: []const u8,
    matched: bool = true,
    capture: ?[]const u8 = null,
};

fn check(case: Case) !void {
    var program = try operators.compile(std.testing.allocator, .{
        .kind = case.kind,
        .argument = case.argument,
    }, .{});
    defer program.deinit();
    var prefixes: [256]usize = undefined;
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    const result = try program.evaluate(.{
        .input = case.input,
        .prefixes = &prefixes,
        .budget = &budget,
    });
    try std.testing.expectEqual(case.matched, result.matched);
    if (case.capture) |capture| {
        try std.testing.expectEqualStrings(capture, result.captured(case.input, 0).?);
    } else {
        try std.testing.expect(result.captured(case.input, 0) == null);
    }
    try std.testing.expect(result.captured(case.input, 1) == null);
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, program.evaluate(.{
        .input = case.input,
        .prefixes = &prefixes,
        .budget = &budget,
    }));
}

test "prepared predicates expose only the pinned operator capture contracts" {
    const cases = [_]Case{
        .{ .kind = .contains, .argument = "abc", .input = "0abc" },
        .{ .kind = .contains, .argument = "abc", .input = "ABC", .matched = false },
        .{ .kind = .streq, .argument = "abc", .input = "abc" },
        .{ .kind = .within, .argument = "GET POST", .input = "GET" },
        .{ .kind = .begins_with, .argument = "ab", .input = "abc" },
        .{ .kind = .ends_with, .argument = "bc", .input = "abc" },
        .{ .kind = .eq, .argument = "1", .input = "01suffix" },
        .{ .kind = .gt, .argument = "1", .input = "2" },
        .{ .kind = .ge, .argument = "1", .input = "1" },
        .{ .kind = .lt, .argument = "1", .input = "0" },
        .{ .kind = .unconditional_match, .input = "" },
        .{ .kind = .rx, .input = "" },
        .{ .kind = .rx, .input = "an empty pattern leaves this uncaptured" },
        .{ .kind = .validate_byte_range, .argument = "32-126", .input = "\x00" },
        .{ .kind = .validate_byte_range, .argument = "32-126", .input = "a", .matched = false },
        .{ .kind = .validate_url_encoding, .input = "%bad%" },
        .{ .kind = .validate_utf8_encoding, .input = "\xff" },
        .{ .kind = .ip_match, .argument = "::1,127.0.0.1", .input = "::1" },
        .{ .kind = .pm, .argument = "BAD dog", .input = "bad", .capture = "BAD" },
        .{ .kind = .detect_sqli, .input = "1 OR 1=1", .capture = "1&1" },
        .{ .kind = .detect_sqli, .input = "ordinary", .matched = false },
        .{ .kind = .detect_xss, .input = "<script>", .capture = "<script>" },
        .{ .kind = .detect_xss, .input = "ordinary", .matched = false },
    };
    for (cases) |case| try check(case);
}

test "compiled regex retains group offsets without borrowing mutable scratch" {
    var program = try operators.compile(std.testing.allocator, .{
        .kind = .rx,
        .argument = "(ab)(c)?",
    }, .{});
    defer program.deinit();
    var workspace = try regex.Workspace.init(std.testing.allocator, &program.regex);
    defer workspace.deinit();
    var budget: work.Budget = .{ .remaining = 100_000 };
    const result = try program.evaluate(.{
        .input = "zabc",
        .budget = &budget,
        .regex = &workspace.scratch,
    });
    _ = try program.evaluate(.{
        .input = "ab",
        .budget = &budget,
        .regex = &workspace.scratch,
    });
    try std.testing.expectEqual(program.regex.instructions.len, program.regexStates());
    try std.testing.expectEqualStrings("abc", result.captured("zabc", 0).?);
    try std.testing.expectEqualStrings("ab", result.captured("zabc", 1).?);
    try std.testing.expectEqualStrings("c", result.captured("zabc", 2).?);
    try std.testing.expect(result.captured("zabc", 3) == null);
    try std.testing.expectError(error.ScratchTooSmall, program.evaluate(.{
        .input = "abc",
        .budget = &budget,
    }));
}

test "dynamic regex arguments reject explicitly instead of matching their macro spelling" {
    try std.testing.expectError(error.UnsupportedDynamicRegex, operators.compile(
        std.testing.allocator,
        .{ .kind = .rx, .argument = "%{TX.pattern}" },
        .{},
    ));
}

test "owned static literal needles require no transaction prefix scratch" {
    var source = [_]u8{ 'a', 'b', 'c' };
    var program = try operators.compile(std.testing.allocator, .{
        .kind = .contains,
        .argument = &source,
    }, .{});
    defer program.deinit();
    @memset(&source, 'x');
    var budget: work.Budget = .{ .remaining = 1000 };
    const result = try program.evaluate(.{ .input = "zabc", .budget = &budget });
    try std.testing.expect(result.matched);
    try std.testing.expectEqual(@as(usize, 0), program.regexStates());
}

test "dynamic arguments require complete variable coverage and caller expansion scratch" {
    var program = try operators.compile(std.testing.allocator, .{
        .kind = .contains,
        .argument = "%{TX.needle}",
    }, .{});
    defer program.deinit();
    var view: variables.View = .{
        .entries = &.{.{ .collection = .tx, .key = "NEEDLE", .value = "bc" }},
        .coverage = @splat(.complete),
    };
    var budget: work.Budget = .{ .remaining = 1000 };
    var pieces: [1][]const u8 = undefined;
    var output: [16]u8 = @splat('x');
    var prefixes: [16]usize = undefined;
    var frame: operators.Frame = .{
        .input = "abc",
        .budget = &budget,
        .variables = &view,
        .pieces = &pieces,
        .argument_output = &output,
        .prefixes = &prefixes,
    };
    try std.testing.expect((try program.evaluate(frame)).matched);
    frame.prefixes = &.{};
    try std.testing.expectError(error.ScratchLimit, program.evaluate(frame));
    frame.variables = null;
    try std.testing.expectError(error.VariableContextRequired, program.evaluate(frame));
    frame.variables = &view;
    view.coverage[@backingInt(variables.Collection.tx)] = .incomplete;
    @memset(&output, 'x');
    try std.testing.expectError(error.IncompleteCollection, program.evaluate(frame));
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat('x'))), &output);
}

test "phrase resource failures and diagnostic profiles cannot produce an executable predicate" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.MissingPhraseFile, operators.compile(allocator, .{
        .kind = .pm_from_file,
        .argument = "words.data",
    }, .{}));
    try std.testing.expectError(error.UnexpectedPhraseFile, operators.compile(allocator, .{
        .kind = .contains,
        .argument = "a",
        .phrase_files = &.{"abc"},
    }, .{}));
    try std.testing.expectError(error.DiagnosticProfile, operators.compile(allocator, .{
        .kind = .pm,
        .argument = "a",
    }, .{ .phrases = .{ .profile = .modsecurity_3_0_14 } }));
    try std.testing.expectError(error.SourceLimit, operators.compile(allocator, .{
        .kind = .rx,
        .argument = "12345",
    }, .{ .source = 4 }));
    var program = try operators.compile(allocator, .{
        .kind = .pm_from_file,
        .argument = "one.data two.data",
        .phrase_files = &.{ "ab", "c\n" },
    }, .{});
    defer program.deinit();
    var budget: work.Budget = .{ .remaining = 1000 };
    const result = try program.evaluate(.{ .input = "C", .budget = &budget });
    try std.testing.expectEqualStrings("c", result.captured("C", 0).?);
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    const sources = [_]operators.Source{
        .{ .kind = .contains, .argument = "needle" },
        .{ .kind = .contains, .argument = "%{TX.needle}" },
        .{ .kind = .rx, .argument = "(ab)+" },
        .{ .kind = .pm, .argument = "one two" },
        .{ .kind = .pm_from_file, .argument = "a", .phrase_files = &.{"one\ntwo"} },
        .{ .kind = .ip_match, .argument = "::1,127.0.0.1" },
    };
    for (sources) |source| {
        var program = try operators.compile(allocator, source, .{});
        defer program.deinit();
    }
}

test "compiled predicates release every owned branch on allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

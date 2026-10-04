const std = @import("std");
const regex = @import("regex.zig");
const work = @import("work.zig");

const Fixture = struct {
    program: regex.types.Program,
    workspace: regex.Workspace,

    fn init(pattern: []const u8) !Fixture {
        const allocator = std.testing.allocator;
        var program = try regex.compile(allocator, pattern, .{});
        errdefer program.deinit();
        return .{ .program = program, .workspace = try regex.Workspace.init(allocator, &program) };
    }

    fn deinit(self: *Fixture) void {
        self.workspace.deinit();
        self.program.deinit();
    }

    fn expect(self: *Fixture, input: []const u8, expected: ?[]const u8) !void {
        var budget: work.Budget = .{ .remaining = 16_000_000 };
        const result = try regex.match.search(
            &self.program,
            input,
            &self.workspace.scratch,
            &budget,
        );
        if (expected) |bytes| {
            const span = (result orelse return error.ExpectedMatch).span(0).?;
            try std.testing.expectEqualStrings(bytes, input[span.start..span.end]);
        } else try std.testing.expect(result == null);
    }
};

test "ordered regex preserves leftmost, branch and quantifier priorities" {
    var first = try Fixture.init("(a|ab)");
    defer first.deinit();
    try first.expect("zab", "a");
    var longest = try Fixture.init("(ab|a)");
    defer longest.deinit();
    try longest.expect("zab", "ab");
    var greedy = try Fixture.init("a+");
    defer greedy.deinit();
    try greedy.expect("zaaa", "aaa");
    var lazy = try Fixture.init("a+?");
    defer lazy.deinit();
    try lazy.expect("zaaa", "a");
}

test "first-byte filtering bounds a long nonmatching prefix without changing captures" {
    var fixture = try Fixture.init("\\b(cat|dog)([0-9]+)");
    defer fixture.deinit();
    var input: [65536]u8 = @splat('z');
    const suffix = " dog123 cat7";
    @memcpy(input[input.len - suffix.len ..], suffix);
    var budget: work.Budget = .{ .remaining = 100_000 };
    const result = (try regex.match.search(
        &fixture.program,
        &input,
        &fixture.workspace.scratch,
        &budget,
    )).?;
    const word = result.span(1).?;
    const digits = result.span(2).?;
    try std.testing.expectEqualStrings("dog", input[word.start..word.end]);
    try std.testing.expectEqualStrings("123", input[digits.start..digits.end]);
    try std.testing.expect(budget.remaining > 0);
    var nullable = try Fixture.init("(?:a?|\\b)(b|c)?$");
    defer nullable.deinit();
    try nullable.expect("", "");
    try nullable.expect("zb", "b");
    try nullable.expect("z", "");
}

test "flags, anchors, ranges and binary bytes are explicit" {
    var fixture = try Fixture.init("(?i)\\b[a-c]{2,3}\\b");
    defer fixture.deinit();
    try fixture.expect(" zz ABc zz ", "ABc");
    try fixture.expect("abcd", null);
    var scoped = try Fixture.init("(?i:a)b");
    defer scoped.deinit();
    try scoped.expect("Ab", "Ab");
    try scoped.expect("AB", null);
    var end = try Fixture.init("a$");
    defer end.deinit();
    try end.expect("a\n", "a");
    var absolute = try Fixture.init("a\\z");
    defer absolute.deinit();
    try absolute.expect("a\n", null);
    var binary = try Fixture.init("[\\x00-\\x{ff}]{2}");
    defer binary.deinit();
    try binary.expect("\x00\xff", "\x00\xff");
}

test "captures remain valid and caller owned after matching" {
    var fixture = try Fixture.init("(a+)(b?)");
    defer fixture.deinit();
    var budget: work.Budget = .{ .remaining = 16_000_000 };
    const input = "zaaab";
    const result = (try regex.match.search(
        &fixture.program,
        input,
        &fixture.workspace.scratch,
        &budget,
    )).?;
    const group = result.span(1).?;
    try std.testing.expectEqualStrings("aaa", input[group.start..group.end]);
    const optional = result.span(2).?;
    try std.testing.expectEqualStrings("b", input[optional.start..optional.end]);
}

test "SecLang defaults use multiline dotall and empty-expression substitution" {
    const cases = [_]struct { pattern: []const u8, input: []const u8, matched: []const u8 }{
        .{ .pattern = "^a.b$", .input = "prefix\na\nb\nsuffix", .matched = "a\nb" },
        .{ .pattern = "(?-ms:^a.b$)", .input = "a b", .matched = "a b" },
        .{ .pattern = "", .input = "a\nb", .matched = "a\nb" },
    };
    for (cases) |case| {
        var program = try regex.secLang(std.testing.allocator, case.pattern, false);
        defer program.deinit();
        var fixture: Fixture = .{
            .program = program,
            .workspace = try regex.Workspace.init(std.testing.allocator, &program),
        };
        defer fixture.workspace.deinit();
        try fixture.expect(case.input, case.matched);
    }
    var program = try regex.secLang(std.testing.allocator, "^header$", true);
    defer program.deinit();
    var fixture: Fixture = .{
        .program = program,
        .workspace = try regex.Workspace.init(std.testing.allocator, &program),
    };
    defer fixture.workspace.deinit();
    try fixture.expect("HEADER", "HEADER");
}

test "shared regex workspace charges active states and survives program changes" {
    const allocator = std.testing.allocator;
    var large = try regex.compile(allocator, "z{2000}", .{});
    defer large.deinit();
    var small = try regex.compile(allocator, "a", .{});
    defer small.deinit();
    var workspace = try regex.Workspace.init(allocator, &large);
    defer workspace.deinit();
    var budget: work.Budget = .{ .remaining = 600 };
    const first = try regex.match.search(&small, "a", &workspace.scratch, &budget);
    try std.testing.expect(first != null);
    budget.remaining = 100_000;
    try std.testing.expectEqual(
        @as(?regex.match.Match, null),
        try regex.match.search(&large, "zz", &workspace.scratch, &budget),
    );
    budget.remaining = 600;
    const reused = try regex.match.search(&small, "a", &workspace.scratch, &budget);
    try std.testing.expect(reused != null);
}

test "epsilon cycles and hostile regexes terminate within their work budget" {
    var cycle = try Fixture.init("(?:a?)*");
    defer cycle.deinit();
    try cycle.expect("aaa", "aaa");
    try std.testing.expectError(
        error.UnsupportedRegex,
        regex.compile(std.testing.allocator, "(a?)*", .{}),
    );
    var hostile = try Fixture.init("(a+)+b");
    defer hostile.deinit();
    var budget: work.Budget = .{ .remaining = 100 };
    try std.testing.expectError(
        error.WorkLimit,
        regex.match.search(
            &hostile.program,
            "aaaaaaaaaaaaaaaa",
            &hostile.workspace.scratch,
            &budget,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedRegex,
        regex.compile(std.testing.allocator, "(a)\\1", .{}),
    );
    try std.testing.expectError(
        error.UnsupportedRegex,
        regex.compile(std.testing.allocator, "a++", .{}),
    );
    try std.testing.expectError(
        error.RegexLimit,
        regex.compile(std.testing.allocator, "a{1000}", .{ .instructions = 10 }),
    );
}

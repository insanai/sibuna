//! Property, ownership and compatibility-witness tests for immutable phrase programs.
const std = @import("std");
const phrases = @import("phrases.zig");
const work = @import("work.zig");

fn match(program: *const phrases.Program, input: []const u8) !?phrases.Match {
    var budget: work.Budget = .{ .remaining = 100_000 };
    return program.search(input, &budget);
}

test "reference suffix captures preserve insertion text instead of a matched suffix" {
    const words: []const []const u8 = &.{ "abcd", "bc" };
    var standard = try phrases.compile(std.testing.allocator, words, .{});
    defer standard.deinit();
    var reference = try phrases.compile(std.testing.allocator, words, .{
        .profile = .modsecurity_3_0_14,
    });
    defer reference.deinit();
    const expected = (try match(&standard, "ABC")).?;
    try std.testing.expectEqualStrings("bc", expected.capture);
    try std.testing.expectEqual(@as(usize, 1), expected.start);
    const compatible = (try match(&reference, "ABC")).?;
    try std.testing.expectEqualStrings("abc", compatible.capture);
    try std.testing.expectEqual(@as(usize, 0), compatible.start);
}

test "reference failure construction remains distinct from complete suffix matching" {
    const words: []const []const u8 = &.{ "aabcx", "bc" };
    var standard = try phrases.compile(std.testing.allocator, words, .{});
    defer standard.deinit();
    var reference = try phrases.compile(std.testing.allocator, words, .{
        .profile = .modsecurity_3_0_14,
    });
    defer reference.deinit();
    try std.testing.expectEqualStrings("bc", (try match(&standard, "aabc")).?.capture);
    try std.testing.expect(try match(&reference, "aabc") == null);
}

test "native byte dictionaries match Unicode markers and binary fields while empty sets do not" {
    var program = try phrases.compile(std.testing.allocator, &.{ "\xffAB", "bc" }, .{});
    defer program.deinit();
    const result = (try match(&program, "\x00\xffab")).?;
    try std.testing.expectEqualStrings("\xffAB", result.capture);
    try std.testing.expectEqual(@as(usize, 1), result.start);
    var empty = try phrases.compile(std.testing.allocator, &.{}, .{});
    defer empty.deinit();
    try std.testing.expect(try match(&empty, "anything") == null);
}

fn naive(words: []const []const u8, input: []const u8) ?usize {
    for (0..input.len) |index| {
        const end = index + 1;
        for (words) |word| {
            if (word.len > end) continue;
            if (std.ascii.eqlIgnoreCase(word, input[end - word.len .. end])) return end;
        }
    }
    return null;
}

test "general matching agrees with an independent dictionary scan" {
    var random = std.Random.DefaultPrng.init(0x41484f);
    var storage: [8][8]u8 = undefined;
    var words: [8][]const u8 = undefined;
    var input: [128]u8 = undefined;
    const alphabet = "abcABCx";
    for (0..256) |iteration| {
        for (&storage, &words) |*bytes, *word| {
            const length = 1 + random.random().uintLessThan(usize, bytes.len);
            for (bytes[0..length]) |*byte| {
                byte.* = alphabet[random.random().uintLessThan(usize, alphabet.len)];
            }
            word.* = bytes[0..length];
        }
        var program = try phrases.compile(std.testing.allocator, &words, .{});
        defer program.deinit();
        const length = iteration % (input.len + 1);
        for (input[0..length]) |*byte| {
            byte.* = alphabet[random.random().uintLessThan(usize, alphabet.len)];
        }
        const expected = naive(&words, input[0..length]);
        const actual = try match(&program, input[0..length]);
        try std.testing.expectEqual(expected, if (actual) |value| value.end else null);
        if (actual) |value| {
            try std.testing.expect(std.ascii.eqlIgnoreCase(
                value.capture,
                input[value.start..value.end],
            ));
        }
    }
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var source = [_]u8{ 'A', 'B' };
    var program = try phrases.compile(allocator, &.{ &source, "abcd", "bc" }, .{});
    defer program.deinit();
    @memset(&source, 0);
    try std.testing.expectEqualStrings("AB", (try match(&program, "ab")).?.capture);
}

test "program ownership survives source mutation and every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

test "invalid dictionaries and compile or search exhaustion cannot become negative matches" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EmptyPhrase, phrases.compile(allocator, &.{""}, .{}));
    try std.testing.expectError(error.NulPhrase, phrases.compile(allocator, &.{"a\x00b"}, .{}));
    try std.testing.expectError(error.NonAsciiPhrase, phrases.compile(allocator, &.{"\xff"}, .{
        .profile = .modsecurity_3_0_14,
    }));
    try std.testing.expectError(
        error.SourceLimit,
        phrases.compile(allocator, &.{"abc"}, .{ .bytes = 2 }),
    );
    try std.testing.expectError(
        error.NodeLimit,
        phrases.compile(allocator, &.{"abc"}, .{ .nodes = 3 }),
    );
    try std.testing.expectError(
        error.WorkLimit,
        phrases.compile(allocator, &.{"abc"}, .{ .compile_work = 0 }),
    );
    var program = try phrases.compile(allocator, &.{"abc"}, .{});
    defer program.deinit();
    var budget: work.Budget = .{ .remaining = 1 };
    try std.testing.expectError(error.WorkLimit, program.search("abc", &budget));
}

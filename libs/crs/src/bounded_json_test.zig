const std = @import("std");
const tokens = @import("bounded_json.zig");
const work = @import("work.zig");

fn check(input: []const u8) !void {
    var bits: [1]u8 = undefined;
    var output: [64]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10000 };
    var scanner: tokens.Scanner = undefined;
    try scanner.init(input, &output, &bits, 8, &budget);
    while (try scanner.next() != .end_of_document) {}
}

test "standard scanner rejects invalid complete JSON without allocation" {
    for ([_][]const u8{
        "",            "[1,]",        "{\"a\":}", "{}{}",          "01", "[true false]", "[",
        "\"\\uD800\"", "\"\\uDC00\"", "\"\xff\"", "\"raw\nline\"",
    }) |input| try std.testing.expectError(error.InvalidJson, check(input));
    for ([_][]const u8{
        "{}", "[]", "1e-3", "null", "\"\\ud83d\\ude00\"", "{\"a\":1,\"a\":2}",
    }) |input| try check(input);
}

test "depth and decoded string bounds are enforced before growing borrowed storage" {
    try std.testing.expectError(error.JsonDepthLimit, check("[[[[[[[[[]]]]]]]]]"));
    var bits: [1]u8 = undefined;
    var output: [2]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10000 };
    var scanner: tokens.Scanner = undefined;
    try scanner.init("\"\\ud83d\\ude00\"", &output, &bits, 1, &budget);
    try std.testing.expectError(error.JsonValueLimit, scanner.next());
    budget.remaining = 0;
    try std.testing.expectError(
        error.WorkLimit,
        scanner.init("{}", &output, &bits, 1, &budget),
    );
}

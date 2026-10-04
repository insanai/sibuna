const std = @import("std");
const lexical = @import("sql_tokens.zig");
const folding = @import("sql_folding.zig");
const detector = @import("sql_detector.zig");
const work = @import("work.zig");
const t = std.testing;

test "SQLi captures own positive fingerprints and negative input cannot retain stale capture" {
    var prefixes: [128]usize = undefined;
    var scratch: folding.Result = .{};
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    var context: lexical.Context = .{
        .input = "1 UNION SELECT password FROM users",
        .prefixes = &prefixes,
        .budget = &budget,
    };
    const result = try detector.detect(&context, &scratch);
    try t.expect(result.matched);
    try t.expect(result.length > 0 and result.length <= 5);
    const captured = result.fingerprint;
    context.input = "ordinary application text";
    const safe = try detector.detect(&context, &scratch);
    try t.expect(!safe.matched);
    try t.expectEqual(@as(usize, 0), safe.capture().len);
    try t.expectEqualSlices(u8, &captured, &result.fingerprint);
    budget.remaining = 0;
    try t.expectError(error.WorkLimit, detector.detect(&context, &scratch));
    budget.remaining = 1_000_000;
    try t.expectError(error.WorkLimit, detector.detect(&context, &scratch));
}

test "binary SQLi detector inputs never allocate or exceed the five-token capture bound" {
    var generator: std.Random.DefaultPrng = .init(0x63727373716c6465);
    const rng = generator.random();
    for (0..1024) |_| {
        var input: [256]u8 = undefined;
        rng.bytes(&input);
        var prefixes: [256]usize = undefined;
        var budget: work.Budget = .{ .remaining = 1_000_000 };
        var context: lexical.Context = .{
            .input = &input,
            .prefixes = &prefixes,
            .budget = &budget,
        };
        var scratch: folding.Result = .{};
        const result = try detector.detect(&context, &scratch);
        try t.expect(result.capture().len <= 5);
        try t.expect(result.matched == (result.capture().len > 0));
    }
}

const std = @import("std");
const lexical = @import("sql_tokens.zig");
const folding = @import("sql_folding.zig");
const work = @import("work.zig");
const t = std.testing;

test "folding remains bounded and every fingerprint byte retains its owned token kind" {
    var generator: std.Random.DefaultPrng = .init(0x63727373716c6664);
    const rng = generator.random();
    for (0..2048) |_| {
        var input: [256]u8 = undefined;
        rng.bytes(&input);
        var prefixes: [256]usize = undefined;
        var budget: work.Budget = .{ .remaining = 1_000_000 };
        var context: lexical.Context = .{
            .input = &input,
            .prefixes = &prefixes,
            .budget = &budget,
            .options = .{ .dialect = if (rng.boolean()) .ansi else .mysql },
        };
        var result: folding.Result = .{};
        try folding.fingerprint(&context, &result);
        try t.expect(result.length <= 5);
        for (result.bytes(), result.tokens[0..result.length]) |kind, token| {
            try t.expectEqual(kind, @backingInt(token.kind));
            try t.expect(token.length < token.value.len);
        }
        @memset(&input, '?');
        try t.expect(result.signature[result.length] == 0);
    }
}

test "folding cannot turn resource exhaustion into a usable fingerprint on retry" {
    var prefixes: [16]usize = undefined;
    var budget: work.Budget = .{ .remaining = 0 };
    var context: lexical.Context = .{
        .input = "SELECT 1",
        .prefixes = &prefixes,
        .budget = &budget,
    };
    var result: folding.Result = .{};
    try t.expectError(error.WorkLimit, folding.fingerprint(&context, &result));
    budget.remaining = 4096;
    try t.expectError(error.WorkLimit, folding.fingerprint(&context, &result));
}

const std = @import("std");
const tokens = @import("sql_tokens.zig");
const work = @import("work.zig");
const t = std.testing;

test "SQL lexical values own bounded bytes while source positions refer to original input" {
    var input = "SELECT abcdefghijklmnopqrstuvwxyzabcdefghijklmnop".*;
    var prefixes: [64]usize = undefined;
    var budget: work.Budget = .{ .remaining = 4096 };
    var state: tokens.Context = .{ .input = &input, .prefixes = &prefixes, .budget = &budget };
    var token: tokens.Token = .{};
    try t.expect(try tokens.next(&state, &token));
    try t.expectEqualStrings("SELECT", token.bytes());
    try t.expectEqual(@as(usize, 0), token.position);
    try t.expect(try tokens.next(&state, &token));
    try t.expectEqual(@as(usize, 7), token.position);
    try t.expectEqual(@as(usize, 31), token.length);
    @memset(&input, '?');
    try t.expectEqualStrings("abcdefghijklmnopqrstuvwxyzabcde", token.bytes());
    try t.expectEqual(@as(u8, 0), token.value[31]);
}

test "SQL quote simulation escaped delimiters and dollar strings retain quote markers" {
    const cases = [_]struct {
        input: []const u8,
        quote: @import("sql_token_context.zig").Quote = .none,
        bytes: []const u8,
        open: u8,
        close: u8,
    }{
        .{ .input = "'a''b'", .bytes = "a''b", .open = '\'', .close = '\'' },
        .{ .input = "a'b", .quote = .single, .bytes = "a", .open = 0, .close = '\'' },
        .{ .input = "q'[a]b]'", .bytes = "a]b", .open = 'q', .close = 'q' },
        .{ .input = "$tag$a$ta$tag$", .bytes = "a$ta", .open = '$', .close = '$' },
        .{ .input = "U&'abc'", .bytes = "abc", .open = 'u', .close = 'u' },
    };
    for (cases) |case| {
        var prefixes: [64]usize = undefined;
        var budget: work.Budget = .{ .remaining = 4096 };
        var state: tokens.Context = .{
            .input = case.input,
            .prefixes = &prefixes,
            .budget = &budget,
            .options = .{ .quote = case.quote },
        };
        var token: tokens.Token = .{};
        try t.expect(try tokens.next(&state, &token));
        try t.expectEqualStrings(case.bytes, token.bytes());
        try t.expectEqual(case.open, token.open);
        try t.expectEqual(case.close, token.close);
    }
}

test "SQL tokenization cannot resume as a successful empty stream after resource failure" {
    var prefixes: [2]usize = undefined;
    var budget: work.Budget = .{ .remaining = 4096 };
    var state: tokens.Context = .{
        .input = "$longtag$abc$longtag$",
        .prefixes = &prefixes,
        .budget = &budget,
    };
    var token: tokens.Token = .{};
    try t.expectError(error.ScratchLimit, tokens.next(&state, &token));
    try t.expectError(error.WorkLimit, tokens.next(&state, &token));
    state = .{ .input = "SELECT", .prefixes = &prefixes, .budget = &budget };
    budget.remaining = 0;
    try t.expectError(error.WorkLimit, tokens.next(&state, &token));
}

test "hostile binary SQL lexical inputs make progress and keep token values bounded" {
    var generator: std.Random.DefaultPrng = .init(0x63727373716c746b);
    const rng = generator.random();
    for (0..1024) |_| {
        var input: [256]u8 = undefined;
        rng.bytes(&input);
        var prefixes: [256]usize = undefined;
        var budget: work.Budget = .{ .remaining = 1_000_000 };
        var state: tokens.Context = .{ .input = &input, .prefixes = &prefixes, .budget = &budget };
        var token: tokens.Token = .{};
        var count: usize = 0;
        while (try tokens.next(&state, &token)) {
            try t.expect(token.length <= 31);
            try t.expect(token.position <= input.len);
            try t.expect(token.length <= input.len - token.position);
            try t.expect(token.value[token.length] == 0);
            count += 1;
            try t.expect(count <= input.len);
        }
        try t.expectEqual(input.len, state.position);
    }
}

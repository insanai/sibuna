const std = @import("std");
const lexical = @import("html_tokens.zig");
const work = @import("work.zig");
const t = std.testing;

test "HTML tokenizer distinguishes names values closures comments and declarations" {
    const input = "text<a href='url'/>tail<!--x--><![CDATA[data]]><!doctype html>";
    const expected = [_]struct { lexical.Kind, []const u8 }{
        .{ .data, "text" },
        .{ .tag_open, "a" },
        .{ .attribute_name, "href" },
        .{ .attribute_value, "url" },
        .{ .tag_self_close, "/>" },
        .{ .data, "tail" },
        .{ .comment, "x" },
        .{ .data, "data" },
        .{ .doctype, "doctype html" },
    };
    var budget: work.Budget = .{ .remaining = 1000 };
    var context = lexical.Context.init(input, &budget, .data);
    for (expected) |item| {
        const token = (try lexical.next(&context)) orelse return error.MissingToken;
        try t.expectEqual(item[0], token.kind);
        try t.expectEqualStrings(item[1], token.bytes(input));
    }
    try t.expect(try lexical.next(&context) == null);
}

test "long malformed slash runs use constant stack and exhaustion poisons HTML context" {
    var input: [64 * 1024]u8 = @splat('/');
    input[0] = '<';
    input[1] = 'a';
    input[input.len - 1] = '>';
    var budget: work.Budget = .{ .remaining = input.len * 8 };
    var context = lexical.Context.init(&input, &budget, .data);
    try t.expectEqual(lexical.Kind.tag_open, (try lexical.next(&context)).?.kind);
    try t.expectEqual(lexical.Kind.tag_self_close, (try lexical.next(&context)).?.kind);
    try t.expect(try lexical.next(&context) == null);
    context = lexical.Context.init(&input, &budget, .data);
    budget.remaining = 0;
    try t.expectError(error.WorkLimit, lexical.next(&context));
    budget.remaining = 1_000_000;
    try t.expectError(error.WorkLimit, lexical.next(&context));
}

test "all HTML initial contexts retain bounded slices for arbitrary binary input" {
    var generator: std.Random.DefaultPrng = .init(0x63727368746d6c35);
    const rng = generator.random();
    for (0..1024) |_| {
        var input: [256]u8 = undefined;
        rng.bytes(&input);
        for (std.enums.values(lexical.Initial)) |initial| {
            var budget: work.Budget = .{ .remaining = 1_000_000 };
            var context = lexical.Context.init(&input, &budget, initial);
            var count: usize = 0;
            while (try lexical.next(&context)) |token| {
                _ = token.bytes(&input);
                count += 1;
                try t.expect(count <= 2 * input.len + 1);
            }
        }
    }
}

test "pinned signed-byte EOF sentinel is explicit in attribute whitespace scanning" {
    var budget: work.Budget = .{ .remaining = 1000 };
    var context = lexical.Context.init("\xff", &budget, .unquoted);
    try t.expect(try lexical.next(&context) == null);
    context = lexical.Context.init("\xff", &budget, .data);
    try t.expectEqualStrings("\xff", (try lexical.next(&context)).?.bytes(context.input));
}

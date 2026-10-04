//! Native lexical stage of the pinned libinjection detector; not a SQLi decision.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const context = @import("sql_token_context.zig");
const strings = @import("sql_tokens_strings.zig");
const words = @import("sql_tokens_words.zig");
const comments = @import("sql_tokens_comments.zig");
const numbers = @import("sql_tokens_numbers.zig");

pub const Token = context.Token;
pub const Context = context.Context;
pub const Options = context.Options;
pub const Error = context.Error;

pub fn next(state: *Context, token: *Token) Error!bool {
    if (state.failed) return error.WorkLimit;
    errdefer state.failed = true;
    std.debug.assert(state.position <= state.input.len);
    try state.budget.debit(36);
    token.* = .{};
    if (state.input.len == 0) return false;
    const frame: context.Frame = .{ .state = state, .token = token };
    if (state.position == 0 and state.options.quote != .none) {
        state.position = try strings.quoted(frame, 0, @backingInt(state.options.quote), 0);
        state.stats.tokens += 1;
        return true;
    }
    while (state.position < state.input.len) {
        const previous = state.position;
        try state.budget.debit(1);
        state.position = try dispatch(frame);
        std.debug.assert(state.position > previous and state.position <= state.input.len);
        if (token.kind == .none) continue;
        state.stats.tokens += 1;
        return true;
    }
    return false;
}

fn dispatch(frame: context.Frame) Error!usize {
    const byte = try frame.byte(frame.state.position);
    return switch (byte) {
        0...32, 127, 160 => frame.state.position + 1,
        '%', '+', '^', '~' => comments.symbol(frame, .operator),
        '!', '&', '*', ':', '<', '=', '>', '|' => comments.operator(frame),
        '(', ')', ',', ';', '{', '}' => comments.symbol(frame, @fromBackingInt(@intCast(byte))),
        '?', ']' => comments.symbol(frame, .unknown),
        '\'', '"' => strings.quoted(frame, frame.state.position, byte, 1),
        '#' => comments.hash(frame),
        '-' => comments.dash(frame),
        '/' => comments.slash(frame),
        '\\' => comments.backslash(frame),
        '0'...'9', '.' => numbers.number(frame),
        '$' => words.money(frame),
        '@' => words.variable(frame),
        '[' => words.bracket(frame),
        '`' => strings.tick(frame),
        'b', 'B' => strings.numeric(frame, .binary),
        'x', 'X' => strings.numeric(frame, .hexadecimal),
        'e', 'E' => strings.escaped(frame),
        'u', 'U' => strings.unicode(frame),
        'q', 'Q' => strings.alternate(frame, 0),
        'n', 'N' => strings.national(frame),
        else => words.word(frame),
    };
}

test {
    _ = @import("sql_tokens_test.zig");
}

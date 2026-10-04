//! Pinned libinjection fingerprint construction; the whitelist decision is separate.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const lexical = @import("sql_tokens.zig");
const fold = @import("sql_fold_context.zig");
const pairs = @import("sql_fold_pairs.zig");
const triples = @import("sql_fold_triples.zig");

pub const Result = fold.Result;
pub const Error = fold.Error;

pub fn fingerprint(context: *lexical.Context, out: *Result) Error!void {
    if (context.failed) return error.WorkLimit;
    errdefer context.failed = true;
    try context.budget.debit(@sizeOf(Result));
    out.* = .{};
    context.position = 0;
    context.stats = .{};
    var state: fold.State = .{ .context = context, .out = out };
    try run(&state);
    // The reference can return six tokens only through an evil-token early exit;
    // its final normalization then collapses the whole fingerprint to one 'X'.
    std.debug.assert(out.length <= 6);
    if (out.length > 2) {
        const last = &out.tokens[out.length - 1];
        if (last.kind == .bareword and last.open == '`' and last.length == 0 and last.close == 0) {
            last.kind = .comment;
        }
    }
    for (out.tokens[0..out.length], 0..) |token, index| {
        try context.budget.debit(1);
        out.signature[index] = @backingInt(token.kind);
    }
    if (std.mem.indexOfScalar(u8, out.signature[0..out.length], 'X') != null) {
        try context.budget.debit(40);
        out.signature = @splat(0);
        out.signature[0] = 'X';
        out.tokens[0].kind = .evil;
        @memset(&out.tokens[0].value, 0);
        out.tokens[0].value[0] = 'X';
        out.tokens[1].kind = .none;
        out.length = 1;
    }
    std.debug.assert(out.length <= 5);
}

fn run(state: *fold.State) Error!void {
    while (state.more) {
        state.more = try lexical.next(state.context, &state.out.tokens[0]);
        const token = &state.out.tokens[0];
        if (!fold.oneOf(token.kind, &.{ .comment, .left_paren, .sql_type }) and
            !fold.unary(token)) break;
    }
    if (!state.more) return;
    state.position = 1;
    while (true) {
        // Reserve the fixed predicate/metadata work in a window step. Byte scans,
        // compound lookup and full-array copies debit their actual bounds separately.
        try state.context.budget.debit(256);
        std.debug.assert(state.position <= 6 and state.left <= state.position);
        if (state.position >= 5 and collapseFive(state)) {
            if (state.position > 5) {
                try state.copy(1, 5);
                state.position = 2;
            } else state.position = 1;
            state.left = 0;
        }
        if (!state.more or state.left >= 5) {
            state.left = state.position;
            break;
        }
        try fill(state, 2);
        if (state.position - state.left < 2) {
            state.left = state.position;
            continue;
        }
        if (try pairs.rewrite(state)) {
            if (state.finished) return;
            continue;
        }
        try fill(state, 3);
        if (state.position - state.left < 3) {
            state.left = state.position;
            continue;
        }
        if (try triples.rewrite(state)) continue;
        state.left += 1;
    }
    if (state.left < 5 and state.last_comment.kind == .comment) {
        try state.context.budget.debit(@sizeOf(lexical.Token));
        state.out.tokens[state.left] = state.last_comment;
        state.left += 1;
    }
    state.out.length = @min(state.left, 5);
}

fn fill(state: *fold.State, count: usize) Error!void {
    while (state.more and state.position <= 5 and state.position - state.left < count) {
        const token = &state.out.tokens[state.position];
        state.more = try lexical.next(state.context, token);
        if (!state.more) continue;
        if (token.kind == .comment) {
            try state.context.budget.debit(@sizeOf(lexical.Token));
            state.last_comment = token.*;
        } else {
            state.last_comment.kind = .none;
            state.position += 1;
        }
    }
}

fn collapseFive(state: *const fold.State) bool {
    const tokens = &state.out.tokens;
    return (tokens[0].kind == .number and
        fold.oneOf(tokens[1].kind, &.{ .operator, .comma }) and tokens[2].kind == .left_paren and
        tokens[3].kind == .number and tokens[4].kind == .right_paren) or
        (tokens[0].kind == .bareword and tokens[1].kind == .operator and
            tokens[2].kind == .left_paren and
            fold.oneOf(tokens[3].kind, &.{ .bareword, .number }) and
            tokens[4].kind == .right_paren) or
        (tokens[0].kind == .number and tokens[1].kind == .right_paren and
            tokens[2].kind == .comma and tokens[3].kind == .left_paren and
            tokens[4].kind == .number) or
        (tokens[0].kind == .bareword and tokens[1].kind == .right_paren and
            tokens[2].kind == .operator and tokens[3].kind == .left_paren and
            tokens[4].kind == .bareword);
}

test {
    _ = @import("sql_folding_test.zig");
}

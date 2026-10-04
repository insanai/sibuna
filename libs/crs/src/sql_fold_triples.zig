//! Ordered triple rewrites, ported from libinjection b9fcaaf (Nick Galbreath, BSD-3-Clause).
const fold = @import("sql_fold_context.zig");
const State = fold.State;
const Error = fold.Error;
const oneOf = fold.oneOf;

pub fn rewrite(state: *State) Error!bool {
    const first = state.at(0);
    const second = state.at(1);
    const third = state.at(2);
    if ((first.kind == .number and second.kind == .operator and third.kind == .number) or
        (first.kind == .operator and second.kind != .left_paren and third.kind == .operator) or
        (first.kind == .logical and third.kind == .logical) or
        (first.kind == .variable and second.kind == .operator and
            oneOf(third.kind, &.{ .variable, .number, .bareword })) or
        (oneOf(first.kind, &.{ .bareword, .number }) and second.kind == .operator and
            oneOf(third.kind, &.{ .number, .bareword })))
    {
        state.drop(2, 0);
        state.left = 0;
        return true;
    }
    if (oneOf(first.kind, &.{ .bareword, .number, .variable, .string }) and
        second.kind == .operator and try state.textEqual(second, "::") and third.kind == .sql_type)
    {
        state.drop(2, 2);
        state.left = 0;
        return true;
    }
    const values: []const fold.Kind = &.{ .bareword, .number, .string, .variable };
    if (oneOf(first.kind, values) and second.kind == .comma and oneOf(third.kind, values)) {
        state.drop(2, 0);
        state.left = 0;
        return true;
    }
    if (oneOf(first.kind, &.{ .expression, .group, .comma }) and
        fold.unary(second) and third.kind == .left_paren)
    {
        try state.copy(state.left + 1, state.left + 2);
        state.drop(1, 0);
        state.left = 0;
        return true;
    }
    return remaining(state);
}

fn remaining(state: *State) Error!bool {
    const first = state.at(0);
    const second = state.at(1);
    const third = state.at(2);
    if (oneOf(first.kind, &.{ .keyword, .expression, .group }) and fold.unary(second) and
        oneOf(third.kind, &.{ .number, .bareword, .variable, .string, .function }))
    {
        try state.copy(state.left + 1, state.left + 2);
        state.drop(1, 0);
        state.left = 0;
        return true;
    }
    if (first.kind == .comma and fold.unary(second) and
        oneOf(third.kind, &.{ .number, .bareword, .variable, .string, .function }))
    {
        try state.copy(state.left + 1, state.left + 2);
        state.drop(if (third.kind == .function) 1 else 3, 0);
        state.left = 0;
        return true;
    }
    if (first.kind == .bareword and second.kind == .dot and third.kind == .bareword) {
        state.drop(2, 0);
        state.left = 0;
        return true;
    }
    if (first.kind == .expression and second.kind == .dot and third.kind == .bareword) {
        try state.copy(state.left + 1, state.left + 2);
        state.drop(1, 0);
        state.left = 0;
        return true;
    }
    if (first.kind == .function and second.kind == .left_paren and
        third.kind != .right_paren and try state.equal(first, "USER"))
    {
        first.kind = .bareword;
    }
    return false;
}

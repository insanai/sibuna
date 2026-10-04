//! Ordered pair rewrites, ported from libinjection b9fcaaf (Nick Galbreath, BSD-3-Clause).
const std = @import("std");
const fold = @import("sql_fold_context.zig");
const State = fold.State;
const Error = fold.Error;
const oneOf = fold.oneOf;

fn functionName(state: *State) Error!bool {
    for ([_][]const u8{
        "USER_ID",
        "USER_NAME",
        "DATABASE",
        "PASSWORD",
        "USER",
        "CURRENT_USER",
        "CURRENT_DATE",
        "CURRENT_TIME",
        "CURRENT_TIMESTAMP",
        "LOCALTIME",
        "LOCALTIMESTAMP",
    }) |name| {
        if (try state.equal(state.at(0), name)) return true;
    }
    return false;
}

/// true restarts the window; false continues with third-token lookahead. A matched
/// no-op branch must still skip subsequent pair rules, as the reference else-if does.
pub fn rewrite(state: *State) Error!bool {
    const first = state.at(0);
    const second = state.at(1);
    if ((first.kind == .string and second.kind == .string) or
        (first.kind == .semicolon and second.kind == .semicolon))
    {
        state.drop(1, 1);
        return true;
    }
    if (oneOf(first.kind, &.{ .operator, .logical }) and
        (fold.unary(second) or second.kind == .sql_type))
    {
        state.drop(1, 1);
        state.left = 0;
        return true;
    }
    if (first.kind == .left_paren and fold.unary(second)) {
        state.drop(1, 1);
        state.left -|= 1;
        return true;
    }
    if (try state.compound()) {
        state.drop(1, 1);
        state.left -|= 1;
        return true;
    }
    if (first.kind == .semicolon and second.kind == .function and
        std.ascii.startsWithIgnoreCase(second.bytes(), "IF"))
    {
        second.kind = .tsql;
        return true;
    }
    if (oneOf(first.kind, &.{ .bareword, .variable }) and
        second.kind == .left_paren and try functionName(state))
    {
        first.kind = .function;
        return true;
    }
    if (first.kind == .keyword and
        (try state.equal(first, "IN") or try state.equal(first, "NOT IN")))
    {
        first.kind = if (second.kind == .left_paren) .operator else .bareword;
        return true;
    }
    return remaining(state);
}

fn remaining(state: *State) Error!bool {
    const first = state.at(0);
    const second = state.at(1);
    if (first.kind == .operator and
        (try state.equal(first, "LIKE") or try state.equal(first, "NOT LIKE")))
    {
        if (second.kind == .left_paren) first.kind = .function;
        return false;
    }
    if (first.kind == .sql_type and oneOf(second.kind, &.{
        .bareword, .number, .sql_type, .left_paren, .function, .variable, .string,
    })) {
        try state.copy(state.left, state.left + 1);
        state.drop(1, 1);
        state.left = 0;
        return true;
    }
    if (first.kind == .collate and second.kind == .bareword) {
        try state.context.budget.debit(@intCast(second.length * 2 + 1));
        if (std.mem.indexOfScalar(u8, second.text(), '_') != null) {
            second.kind = .sql_type;
            state.left = 0;
        }
        return false;
    }
    if (first.kind == .backslash) {
        if (fold.arithmetic(second)) {
            first.kind = .number;
        } else {
            try state.copy(state.left, state.left + 1);
            state.drop(1, 1);
        }
        state.left = 0;
        return true;
    }
    if ((first.kind == .left_paren and second.kind == .left_paren) or
        (first.kind == .right_paren and second.kind == .right_paren))
    {
        state.drop(1, 1);
        state.left = 0;
        return true;
    }
    if (first.kind == .left_brace and second.kind == .bareword) {
        if (second.length == 0) {
            second.kind = .evil;
            state.out.length = state.left + 2;
            state.finished = true;
            return true;
        }
        state.left = 0;
        state.drop(2, 2);
        return true;
    }
    if (second.kind == .right_brace) {
        state.drop(1, 1);
        state.left = 0;
        return true;
    }
    return false;
}

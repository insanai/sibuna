//! Finite SQL folding state. No input, scratch or token can escape its caller owner.
//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const std = @import("std");
const lexical = @import("sql_tokens.zig");
const dictionary = @import("injection_dictionary.zig");

pub const Token = lexical.Token;
pub const Kind = dictionary.Kind;
pub const Error = lexical.Error;
pub const Result = struct {
    tokens: [8]Token = @splat(.{}),
    signature: [8]u8 = @splat(0),
    length: usize = 0,
    folds: usize = 0,

    pub fn bytes(self: *const Result) []const u8 {
        std.debug.assert(self.length <= 5);
        return self.signature[0..self.length];
    }
};

pub fn oneOf(kind: Kind, choices: []const Kind) bool {
    return std.mem.indexOfScalar(Kind, choices, kind) != null;
}

pub fn arithmetic(token: *const Token) bool {
    return token.kind == .operator and token.length == 1 and
        std.mem.indexOfScalar(u8, "*/-+%", token.value[0]) != null;
}

pub fn unary(token: *const Token) bool {
    if (token.kind != .operator) return false;
    return switch (token.length) {
        1 => std.mem.indexOfScalar(u8, "+-!~", token.value[0]) != null,
        2 => std.mem.eql(u8, token.bytes(), "!!"),
        3 => std.ascii.eqlIgnoreCase(token.bytes(), "NOT"),
        else => false,
    };
}

pub const State = struct {
    context: *lexical.Context,
    out: *Result,
    position: usize = 0,
    left: usize = 0,
    more: bool = true,
    last_comment: Token = .{},
    finished: bool = false,

    pub fn at(self: *State, offset: usize) *Token {
        std.debug.assert(self.left + offset < self.out.tokens.len);
        return &self.out.tokens[self.left + offset];
    }

    pub fn copy(self: *State, destination: usize, source: usize) Error!void {
        try self.context.budget.debit(@sizeOf(Token));
        self.out.tokens[destination] = self.out.tokens[source];
    }

    pub fn drop(self: *State, count: usize, folds: usize) void {
        std.debug.assert(count <= self.position);
        self.position -= count;
        self.out.folds += folds;
    }

    pub fn equal(self: *State, token: *const Token, value: []const u8) Error!bool {
        try self.context.budget.debit(@intCast(token.length + 1));
        return std.ascii.eqlIgnoreCase(token.bytes(), value);
    }

    pub fn textEqual(self: *State, token: *const Token, value: []const u8) Error!bool {
        try self.context.budget.debit(@intCast(token.length * 2 + 1));
        return std.mem.eql(u8, token.text(), value);
    }

    pub fn compound(self: *State) Error!bool {
        const first = self.at(0);
        const second = self.at(1);
        const kinds: []const Kind = &.{
            .keyword, .bareword, .operator, .sql_union, .function, .expression, .tsql, .sql_type,
        };
        if (!oneOf(first.kind, kinds) or
            (!oneOf(second.kind, kinds) and second.kind != .logical)) return false;
        const size = first.length + second.length + 1;
        if (size >= 32) return false;
        try self.context.budget.debit(@intCast(size * 2 + 2));
        var merged: [32]u8 = undefined;
        @memcpy(merged[0..first.length], first.bytes());
        merged[first.length] = ' ';
        @memcpy(merged[first.length + 1 ..][0..second.length], second.bytes());
        const kind = try dictionary.lookup(merged[0..size], self.context.budget);
        if (kind == .none) return false;
        first.kind = kind;
        first.length = size;
        @memcpy(first.value[0..size], merged[0..size]);
        first.value[size] = 0;
        return true;
    }
};

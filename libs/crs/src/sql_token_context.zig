//! Caller-owned detector state shared by lexical routines. No allocation or callbacks.
//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const std = @import("std");
const dictionary = @import("injection_dictionary.zig");
const work = @import("work.zig");
const substring = @import("substring.zig");

pub const Kind = dictionary.Kind;
pub const Error = substring.Error;
pub const Quote = enum(u8) { none = 0, single = '\'', double = '"' };
pub const Options = struct { dialect: enum { ansi, mysql } = .ansi, quote: Quote = .none };
pub const Stats = struct { tokens: usize = 0, dash_comment: usize = 0, hash: usize = 0 };
pub const Token = struct {
    kind: Kind = .none,
    position: usize = 0,
    length: usize = 0,
    count: u8 = 0,
    open: u8 = 0,
    close: u8 = 0,
    value: [32]u8 = @splat(0),

    pub fn bytes(self: *const Token) []const u8 {
        std.debug.assert(self.length < self.value.len);
        return self.value[0..self.length];
    }

    /// Some pinned folding decisions use strcmp rather than the stored length.
    pub fn text(self: *const Token) []const u8 {
        const bytes_value = self.bytes();
        return bytes_value[0 .. std.mem.indexOfScalar(u8, bytes_value, 0) orelse self.length];
    }
};

pub const Context = struct {
    input: []const u8,
    prefixes: []usize,
    budget: *work.Budget,
    options: Options = .{},
    position: usize = 0,
    stats: Stats = .{},
    failed: bool = false,
};

pub const Span = enum(u3) { digits, hexadecimal, binary, money, letters, word, variable };

pub fn white(byte: u8) bool {
    return byte == 0 or byte == 160 or std.ascii.isWhitespace(byte);
}

const word_delimiters = " []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0";
const variable_delimiters = " <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"";

fn accepts(mode: Span, byte: u8) bool {
    // strchr includes its terminating NUL in both positive and negative sets.
    if (byte == 0) return mode != .word and mode != .variable and mode != .digits;
    return switch (mode) {
        .digits => std.ascii.isDigit(byte),
        .hexadecimal => std.ascii.isHex(byte),
        .binary => byte == '0' or byte == '1',
        .money => std.ascii.isDigit(byte) or byte == '.' or byte == ',',
        .letters => std.ascii.isAlphabetic(byte),
        .word => std.mem.indexOfScalar(u8, word_delimiters, byte) == null,
        .variable => std.mem.indexOfScalar(u8, variable_delimiters, byte) == null,
    };
}

const spans = blk: {
    @setEvalBranchQuota(100_000);
    var table: [256]u8 = @splat(0);
    for (0..256) |byte| {
        for (0..7) |index| {
            const mode: Span = @fromBackingInt(@intCast(index));
            if (accepts(mode, @intCast(byte))) table[byte] |= @as(u8, 1) << @backingInt(mode);
        }
    }
    break :blk table;
};

pub const Frame = struct {
    state: *Context,
    token: *Token,

    pub fn byte(self: Frame, index: usize) Error!u8 {
        std.debug.assert(index < self.state.input.len);
        try self.state.budget.debit(1);
        return self.state.input[index];
    }

    pub fn assign(self: Frame, kind: Kind, start: usize, length: usize) Error!void {
        std.debug.assert(start <= self.state.input.len and length <= self.state.input.len - start);
        const size: usize = @min(length, 31);
        try self.state.budget.debit(@intCast(size + 4));
        self.token.kind = kind;
        self.token.position = start;
        self.token.length = size;
        @memcpy(self.token.value[0..size], self.state.input[start..][0..size]);
        self.token.value[size] = 0;
    }

    pub fn span(self: Frame, start: usize, mode: Span) Error!usize {
        std.debug.assert(start <= self.state.input.len);
        var position = start;
        while (position < self.state.input.len) : (position += 1) {
            try self.state.budget.debit(2);
            const bit = @as(u8, 1) << @backingInt(mode);
            if (spans[self.state.input[position]] & bit == 0) break;
        }
        return position;
    }

    pub fn find(self: Frame, start: usize, byte_value: u8) Error!?usize {
        std.debug.assert(start <= self.state.input.len);
        var index = start;
        while (index < self.state.input.len) : (index += 1) {
            try self.state.budget.debit(1);
            if (self.state.input[index] == byte_value) return index;
        }
        return null;
    }

    pub fn pair(self: Frame, start: usize, end: usize, first: u8, second: u8) Error!?usize {
        std.debug.assert(start <= end and end <= self.state.input.len);
        var position = start;
        while (end - position >= 2) : (position += 1) {
            try self.state.budget.debit(2);
            if (self.state.input[position] == first and self.state.input[position + 1] == second) {
                return position;
            }
        }
        return null;
    }

    pub fn lookup(self: Frame, bytes: []const u8) Error!Kind {
        return dictionary.lookup(bytes, self.state.budget);
    }

    pub fn delimiter(self: Frame, start: usize, needle: []const u8) Error!?usize {
        const pattern = try substring.prepare(needle, self.state.prefixes, self.state.budget);
        const offset = try pattern.find(self.state.input[start..], self.state.budget) orelse
            return null;
        return start + offset;
    }
};

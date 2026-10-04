//! Bounded libinjection HTML lexical context. Tokens borrow the caller's input.
//! Adapted from libinjection, Copyright 2012-2016 Nick Galbreath; BSD-3-Clause.
const std = @import("std");
const work = @import("work.zig");

pub const Error = work.Error;
pub const Kind = enum(u8) {
    data,
    tag_open,
    tag_name_close,
    tag_self_close,
    tag_data,
    tag_close,
    attribute_name,
    attribute_value,
    comment,
    doctype,
};
pub const Initial = enum(u8) { data, unquoted, single, double, backtick };
pub const State = enum {
    eof,
    data,
    tag_open,
    tag_name,
    end_tag,
    name_close,
    self_close,
    before_name,
    name,
    after_name,
    before_value,
    single,
    double,
    backtick,
    unquoted,
    after_value,
    bogus,
    percent_comment,
    declaration,
    comment,
    cdata,
    doctype,
};
pub const Step = enum { transition, token, end };
pub const Token = struct {
    kind: Kind = .data,
    position: usize = 0,
    length: usize = 0,

    pub fn bytes(self: Token, input: []const u8) []const u8 {
        std.debug.assert(self.position <= input.len);
        std.debug.assert(self.length <= input.len - self.position);
        return input[self.position..][0..self.length];
    }
};
pub const Context = struct {
    input: []const u8,
    budget: *work.Budget,
    position: usize = 0,
    state: State = .data,
    closing: bool = false,
    failed: bool = false,
    token: Token = .{},

    pub fn init(input: []const u8, budget: *work.Budget, initial: Initial) Context {
        return .{ .input = input, .budget = budget, .state = switch (initial) {
            .data => .data,
            .unquoted => .before_name,
            .single => .single,
            .double => .double,
            .backtick => .backtick,
        } };
    }

    pub fn byte(self: *Context, position: usize) Error!u8 {
        std.debug.assert(position < self.input.len);
        try self.budget.debit(1);
        return self.input[position];
    }

    pub fn emit(self: *Context, kind: Kind, start: usize, end: usize) Step {
        std.debug.assert(start <= end and end <= self.input.len);
        self.token = .{ .kind = kind, .position = start, .length = end - start };
        return .token;
    }

    pub fn find(self: *Context, start: usize, target: u8) Error!?usize {
        var position = start;
        while (position < self.input.len) : (position += 1) {
            if (try self.byte(position) == target) return position;
        }
        return null;
    }

    pub fn white(self: *Context) Error!?u8 {
        while (self.position < self.input.len) {
            const value = try self.byte(self.position);
            // The pinned signed-char skip routine returns 0xff as its EOF sentinel.
            if (value == 0xff) return null;
            if (!isWhite(value)) return value;
            self.position += 1;
        }
        return null;
    }
};

pub fn isWhite(byte: u8) bool {
    // C strchr also recognizes its terminating NUL; the pin relies on that quirk.
    return byte == 0 or byte == ' ' or (byte >= 9 and byte <= 13);
}

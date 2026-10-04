//! Pinned libinjection SQLi decision and capture. No allocation or policy side effects.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const lexical = @import("sql_tokens.zig");
const folding = @import("sql_folding.zig");
const dictionary = @import("injection_dictionary.zig");
const substring = @import("substring.zig");

pub const Error = lexical.Error || error{InvalidDetectorState};
pub const Result = struct {
    matched: bool = false,
    fingerprint: [8]u8 = @splat(0),
    length: usize = 0,

    pub fn capture(self: *const Result) []const u8 {
        std.debug.assert(self.length <= 5);
        return self.fingerprint[0..self.length];
    }
};

pub fn detect(context: *lexical.Context, scratch: *folding.Result) Error!Result {
    if (context.failed) return error.WorkLimit;
    errdefer context.failed = true;
    try context.budget.debit(1);
    if (context.input.len == 0) return .{};
    if (try pass(context, scratch, .{})) return found(scratch);
    if (reparse(context) and try pass(context, scratch, .{ .dialect = .mysql })) {
        return found(scratch);
    }
    if (try containsQuote(context, '\'')) {
        if (try pass(context, scratch, .{ .quote = .single })) return found(scratch);
        if (reparse(context) and
            try pass(context, scratch, .{ .dialect = .mysql, .quote = .single }))
        {
            return found(scratch);
        }
    }
    if (try containsQuote(context, '"') and
        try pass(context, scratch, .{ .dialect = .mysql, .quote = .double }))
    {
        return found(scratch);
    }
    return .{};
}

fn found(scratch: *const folding.Result) Result {
    return .{ .matched = true, .fingerprint = scratch.signature, .length = scratch.length };
}

fn reparse(context: *const lexical.Context) bool {
    return context.stats.dash_comment > 0 or context.stats.hash > 0;
}

fn containsQuote(context: *lexical.Context, quote: u8) Error!bool {
    for (0..context.input.len) |index| {
        try context.budget.debit(1);
        if (context.input[index] == quote) return true;
    }
    return false;
}

fn pass(context: *lexical.Context, scratch: *folding.Result, options: lexical.Options) Error!bool {
    context.options = options;
    try folding.fingerprint(context, scratch);
    if (scratch.length == 0) return false;
    try context.budget.debit(8);
    var key: [8]u8 = undefined;
    key[0] = '0';
    @memcpy(key[1..][0..scratch.length], scratch.bytes());
    if (try dictionary.lookup(key[0 .. scratch.length + 1], context.budget) != .fingerprint) {
        return false;
    }
    return whitelist(context, scratch);
}

fn passwordException(context: *lexical.Context) Error!bool {
    const needle = "sp_password";
    if (context.input.len < needle.len) return false;
    const prepared = try substring.prepare(needle, context.prefixes, context.budget);
    return try prepared.find(context.input, context.budget) != null;
}

fn whitelist(context: *lexical.Context, result: *const folding.Result) Error!bool {
    // Cover the fixed five-token predicates separately from scans and byte comparison.
    try context.budget.debit(64);
    if (result.length > 1 and result.signature[result.length - 1] == 'c' and
        try passwordException(context)) return true;
    return switch (result.length) {
        2 => shortPair(context, result),
        3 => shortTriple(context, result),
        else => true,
    };
}

fn shortPair(context: *lexical.Context, result: *const folding.Result) Error!bool {
    const first = &result.tokens[0];
    const second = &result.tokens[1];
    if (result.signature[1] == 'U') return context.stats.tokens != 2;
    if (second.value[0] == '#') return false;
    if (first.kind == .bareword and second.kind == .comment and second.value[0] != '/') {
        return false;
    }
    if (first.kind == .number and second.kind == .comment) {
        if (second.value[0] == '/' or context.stats.tokens > 2) return true;
        // The reference indexes by the clipped token length, not its source
        // position. Retain that quirk while refusing its potential undefined read.
        const index = first.length;
        if (index >= context.input.len) return error.InvalidDetectorState;
        try context.budget.debit(1);
        const byte = context.input[index];
        if (byte <= 32 or byte >= 128) return true;
        if (byte != '/' and byte != '-') return false;
        if (context.input.len - index < 2) return error.InvalidDetectorState;
        try context.budget.debit(1);
        return (byte == '/' and context.input[index + 1] == '*') or
            (byte == '-' and context.input[index + 1] == '-');
    }
    return !(second.length > 2 and second.value[0] == '-');
}

fn shortTriple(context: *lexical.Context, result: *const folding.Result) Error!bool {
    try context.budget.debit(32);
    const signature = result.bytes();
    if (std.mem.eql(u8, signature, "sos") or std.mem.eql(u8, signature, "s&s")) {
        const first = &result.tokens[0];
        const third = &result.tokens[2];
        return first.open == 0 and third.close == 0 and first.close == third.open;
    }
    const small = [_][]const u8{ "s&n", "n&1", "1&1", "1&v", "1&s" };
    for (small) |pattern| {
        if (std.mem.eql(u8, signature, pattern)) return context.stats.tokens != 3;
    }
    const second = &result.tokens[1];
    if (second.kind == .keyword) {
        return second.length >= 5 and std.ascii.eqlIgnoreCase(second.value[0..4], "INTO");
    }
    return true;
}

test {
    _ = @import("sql_detector_test.zig");
}

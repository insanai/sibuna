//! Pinned libinjection XSS classification with explicit byte bounds and work charges.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const tables = @import("libinjection-data").xss;
const work = @import("work.zig");
pub const Attribute = tables.Attribute;
pub const Error = work.Error;

/// Exact comparison after skipping NUL in input, using fixed ASCII case conversion.
pub fn equal(input: []const u8, expected: []const u8, budget: *work.Budget) Error!bool {
    var position: usize = 0;
    for (input) |byte| {
        try budget.debit(1);
        if (byte == 0) continue;
        if (position == expected.len or std.ascii.toUpper(byte) != expected[position]) {
            return false;
        }
        position += 1;
    }
    return position == expected.len;
}

fn prefix(input: []const u8, expected: []const u8, budget: *work.Budget) Error!bool {
    if (input.len < expected.len) return false;
    return equal(input[0..expected.len], expected, budget);
}

pub fn tag(input: []const u8, budget: *work.Budget) Error!bool {
    if (input.len < 3) return false;
    for (tables.tags) |expected| {
        try budget.debit(1);
        if (try equal(input, expected, budget)) return true;
    }
    // These prefixes do not skip NUL, unlike the preceding complete-name table.
    try budget.debit(6);
    return std.ascii.eqlIgnoreCase(input[0..3], "SVG") or
        std.ascii.eqlIgnoreCase(input[0..3], "XSL");
}

pub fn attribute(input: []const u8, budget: *work.Budget) Error!Attribute {
    if (input.len < 2) return .none;
    if (input.len >= 5) {
        try budget.debit(2);
        if (std.ascii.eqlIgnoreCase(input[0..2], "ON")) {
            for (tables.events) |event| {
                try budget.debit(1);
                // The C pin reads strlen(event) without checking the token bound.
                if (try prefix(input[2..], event, budget)) return .black;
            }
        }
        if (try prefix(input, "XMLNS", budget) or try prefix(input, "XLINK", budget)) {
            return .black;
        }
    }
    for (tables.attributes) |entry| {
        try budget.debit(1);
        if (try equal(input, entry[0], budget)) return entry[1];
    }
    return .none;
}

const Decoded = struct { value: u32, consumed: usize = 1 };

fn digit(byte: u8, base: u32) ?u32 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (base == 16) {
        const upper = std.ascii.toUpper(byte);
        if (upper >= 'A' and upper <= 'F') return upper - 'A' + 10;
    }
    return null;
}

fn decode(input: []const u8, budget: *work.Budget) Error!Decoded {
    std.debug.assert(input.len > 0);
    try budget.debit(1);
    const literal: Decoded = .{ .value = input[0] };
    if (input[0] != '&' or input.len < 3) return literal;
    try budget.debit(1);
    if (input[1] != '#') return literal;
    try budget.debit(1);
    const hex = input[2] == 'x' or input[2] == 'X';
    var position: usize = if (hex) 3 else 2;
    if (position == input.len) return literal;
    const base: u32 = if (hex) 16 else 10;
    try budget.debit(1);
    var value = digit(input[position], base) orelse return literal;
    position += 1;
    while (position < input.len) : (position += 1) {
        try budget.debit(1);
        const byte = input[position];
        if (byte == ';') return .{ .value = value, .consumed = position + 1 };
        const next = digit(byte, base) orelse return .{ .value = value, .consumed = position };
        // The previous value cannot exceed 0x1000ff; its next product fits u32.
        std.debug.assert(value <= 0x1000ff);
        value = value * base + next;
        if (value > 0x1000ff) return literal;
    }
    return .{ .value = value, .consumed = position };
}

fn encodedPrefix(input: []const u8, expected: []const u8, budget: *work.Budget) Error!bool {
    var position: usize = 0;
    var matched: usize = 0;
    var first = true;
    while (position < input.len) {
        try budget.debit(1);
        if (matched == expected.len) return true;
        const decoded = try decode(input[position..], budget);
        position += decoded.consumed;
        var value = decoded.value;
        if (first and value <= 32) continue;
        first = false;
        if (value == 0 or value == 10) continue;
        if (value >= 'a' and value <= 'z') value -= 32;
        // The pin compares a C char after decoding, rather than a Unicode point.
        if (@as(u8, @truncate(value)) != expected[matched]) return false;
        matched += 1;
    }
    return matched == expected.len;
}

pub fn url(input: []const u8, budget: *work.Budget) Error!bool {
    var position: usize = 0;
    while (position < input.len) : (position += 1) {
        try budget.debit(1);
        if (input[position] > 32 and input[position] < 127) break;
    }
    for ([_][]const u8{ "DATA", "VIEW-SOURCE", "JAVA", "VBSCRIPT" }) |expected| {
        try budget.debit(1);
        if (try encodedPrefix(input[position..], expected, budget)) return true;
    }
    return false;
}

pub fn comment(input: []const u8, budget: *work.Budget) Error!bool {
    for (input) |byte| {
        try budget.debit(1);
        if (byte == '`') return true;
    }
    if (input.len > 3) {
        try budget.debit(6);
        if ((input[0] == '[' and std.ascii.eqlIgnoreCase(input[1..3], "IF")) or
            std.ascii.eqlIgnoreCase(input[0..3], "XML")) return true;
    }
    if (input.len > 5) {
        return try prefix(input, "IMPORT", budget) or try prefix(input, "ENTITY", budget);
    }
    return false;
}

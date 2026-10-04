//! Length-aware literal and numeric predicates for the pinned SecLang profile.
//! Arguments are already macro-expanded. Selection, transforms, negation and actions
//! belong to transaction execution and are not implied by this primitive result.
const std = @import("std");
const model = @import("model.zig");
const work = @import("work.zig");
const substring = @import("substring.zig");

pub const Error = error{ UnsupportedOperator, NumericLimit } || substring.Error;
pub const Context = struct { prefixes: []usize, budget: *work.Budget };
pub const Location = struct { domain: enum { input, argument }, start: usize, end: usize };
pub const Result = struct { matched: bool, location: ?Location = null };

pub const Predicate = struct {
    kind: model.Operator,
    argument: []const u8,

    pub fn evaluate(self: Predicate, input: []const u8, context: Context) Error!Result {
        if (!supported(self.kind)) return error.UnsupportedOperator;
        try context.budget.debit(1);
        return switch (self.kind) {
            .unconditional_match => .{ .matched = true },
            .eq, .ge, .gt, .lt => .{
                .matched = try numeric(self.kind, input, self.argument, context.budget),
            },
            .contains => try find(input, self.argument, .input, context),
            .within => try find(self.argument, input, .argument, context),
            .begins_with, .ends_with, .streq => try self.edge(input, context.budget),
            .validate_url_encoding => .{ .matched = try invalidUrl(input, context.budget) },
            else => unreachable,
        };
    }

    fn edge(self: Predicate, input: []const u8, budget: *work.Budget) Error!Result {
        if (input.len < self.argument.len or
            (self.kind == .streq and input.len != self.argument.len))
        {
            return .{ .matched = false };
        }
        const start = if (self.kind == .ends_with) input.len - self.argument.len else 0;
        try budget.debit(@intCast(self.argument.len));
        if (!std.mem.eql(u8, input[start..][0..self.argument.len], self.argument)) {
            return .{ .matched = false };
        }
        return .{ .matched = true, .location = .{
            .domain = .input,
            .start = start,
            .end = start + self.argument.len,
        } };
    }
};

pub fn supported(kind: model.Operator) bool {
    return switch (kind) {
        .begins_with => true,
        .contains => true,
        .ends_with => true,
        .eq => true,
        .ge => true,
        .gt => true,
        .lt => true,
        .streq => true,
        .within => true,
        .unconditional_match => true,
        .validate_url_encoding => true,
        else => false,
    };
}

fn find(
    haystack: []const u8,
    needle: []const u8,
    domain: @FieldType(Location, "domain"),
    context: Context,
) Error!Result {
    if (needle.len > haystack.len) return .{ .matched = false };
    const pattern = try substring.prepare(needle, context.prefixes, context.budget);
    const offset = try pattern.find(haystack, context.budget) orelse
        return .{ .matched = false };
    return .{ .matched = true, .location = .{
        .domain = domain,
        .start = offset,
        .end = offset + needle.len,
    } };
}

fn invalidUrl(input: []const u8, budget: *work.Budget) Error!bool {
    var position: usize = 0;
    while (position < input.len) {
        try budget.debit(1);
        if (input[position] != '%') {
            position += 1;
            continue;
        }
        if (input.len - position < 3) return true;
        try budget.debit(2);
        if (!std.ascii.isHex(input[position + 1]) or !std.ascii.isHex(input[position + 2])) {
            return true;
        }
        position += 3;
    }
    return false;
}

const Number = struct {
    value: i64 = 0,
    overflow: bool = false,

    fn eqValue(self: Number) i64 {
        // ModSecurity's eq uses std::stoi(int), converting exceptions to zero.
        if (self.overflow or self.value < std.math.minInt(i32) or
            self.value > std.math.maxInt(i32)) return 0;
        return self.value;
    }
};

fn numeric(
    kind: model.Operator,
    input: []const u8,
    argument: []const u8,
    budget: *work.Budget,
) Error!bool {
    const left = try decimal(input, budget);
    const right = try decimal(argument, budget);
    if (kind == .eq) return left.eqValue() == right.eqValue();
    // ge/gt/lt use atoll, whose overflow is not portable. The native profile returns
    // an explicit limit outcome instead of guessing a saturated or wrapped value.
    if (left.overflow or right.overflow) return error.NumericLimit;
    return switch (kind) {
        .ge => left.value >= right.value,
        .gt => left.value > right.value,
        .lt => left.value < right.value,
        else => unreachable,
    };
}

fn decimal(bytes: []const u8, budget: *work.Budget) Error!Number {
    var position: usize = 0;
    while (position < bytes.len) {
        try budget.debit(1);
        if (!std.ascii.isWhitespace(bytes[position])) break;
        position += 1;
    }
    if (position == bytes.len) return .{};
    const negative = bytes[position] == '-';
    if (negative or bytes[position] == '+') position += 1;
    const maximum: u64 = @as(u64, std.math.maxInt(i64)) + @intFromBool(negative);
    var magnitude: u64 = 0;
    while (position < bytes.len) : (position += 1) {
        try budget.debit(1);
        const byte = bytes[position];
        if (!std.ascii.isDigit(byte)) break;
        const digit = byte - '0';
        if (magnitude > (maximum - digit) / 10) return .{ .overflow = true };
        magnitude = magnitude * 10 + digit;
    }
    if (negative and magnitude == @as(u64, 1) << 63) {
        return .{ .value = std.math.minInt(i64) };
    }
    const value: i64 = @intCast(magnitude);
    return .{ .value = if (negative) -value else value };
}

test "literal predicates retain binary data, empty matches and match provenance" {
    const cases = [_]struct {
        kind: model.Operator,
        argument: []const u8,
        input: []const u8,
        matched: bool,
    }{
        .{ .kind = .contains, .argument = "\x00B", .input = "A\x00B", .matched = true },
        .{ .kind = .contains, .argument = "ab", .input = "AB", .matched = false },
        .{ .kind = .begins_with, .argument = "ab", .input = "abc", .matched = true },
        .{ .kind = .ends_with, .argument = "bc", .input = "abc", .matched = true },
        .{ .kind = .streq, .argument = "ab", .input = "abc", .matched = false },
        .{ .kind = .within, .argument = "GET POST", .input = "GET", .matched = true },
        .{ .kind = .within, .argument = "", .input = "", .matched = true },
        .{ .kind = .contains, .argument = "", .input = "", .matched = true },
    };
    var prefixes: [16]usize = undefined;
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 4096 };
        const predicate: Predicate = .{ .kind = case.kind, .argument = case.argument };
        const result = try predicate.evaluate(case.input, .{
            .prefixes = &prefixes,
            .budget = &budget,
        });
        try std.testing.expectEqual(case.matched, result.matched);
        if (result.location) |location| {
            const source = if (location.domain == .input) case.input else case.argument;
            const match = if (case.kind == .within) case.input else case.argument;
            try std.testing.expectEqualStrings(match, source[location.start..location.end]);
        }
    }
}

test "numeric predicates preserve prefix conversion and eq's narrower integer domain" {
    var prefixes: [1]usize = undefined;
    var budget: work.Budget = .{ .remaining = 4096 };
    const context: Context = .{ .prefixes = &prefixes, .budget = &budget };
    const zero: Predicate = .{ .kind = .eq, .argument = "0" };
    try std.testing.expect((try zero.evaluate("nonnumeric", context)).matched);
    try std.testing.expect((try zero.evaluate("2147483648", context)).matched);
    const five: Predicate = .{ .kind = .eq, .argument = "5" };
    try std.testing.expect((try five.evaluate(" \t+005ignored\x00suffix", context)).matched);
    const greater: Predicate = .{ .kind = .gt, .argument = "2147483647" };
    try std.testing.expect((try greater.evaluate("2147483648", context)).matched);
    const minimum: Predicate = .{ .kind = .lt, .argument = "0" };
    try std.testing.expect((try minimum.evaluate("-9223372036854775808", context)).matched);
    try std.testing.expectError(
        error.NumericLimit,
        greater.evaluate("9223372036854775808", context),
    );
}

test "encoding predicates and unsupported operators cannot hide exhaustion" {
    var prefixes: [1]usize = undefined;
    var budget: work.Budget = .{ .remaining = 4096 };
    const context: Context = .{ .prefixes = &prefixes, .budget = &budget };
    const predicate: Predicate = .{ .kind = .validate_url_encoding, .argument = "" };
    try std.testing.expect(!(try predicate.evaluate("a%00%ff+b\x00", context)).matched);
    try std.testing.expect((try predicate.evaluate("%u1234", context)).matched);
    try std.testing.expect((try predicate.evaluate("a%1", context)).matched);
    const absent: Predicate = .{ .kind = .detect_sqli, .argument = "" };
    try std.testing.expectError(error.UnsupportedOperator, absent.evaluate("1 or 1=1", context));
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, predicate.evaluate("valid", context));
}

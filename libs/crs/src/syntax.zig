//! Borrowed SecLang syntax. No action, regex or escape is evaluated by this reader.
const std = @import("std");
const source = @import("source.zig");

pub const Error = source.Error || error{
    MissingArgument,
    UnknownDirective,
    InvalidAction,
    InvalidOperator,
};

pub const Rule = struct {
    selectors: source.Token,
    operator: source.Token,
    actions: ?source.Token,
};

pub const TargetUpdate = struct {
    id: source.Token,
    selectors: source.Token,
};

pub const Directive = union(enum) {
    rule: Rule,
    action: source.Token,
    marker: source.Token,
    defaults: source.Token,
    component: source.Token,
    update_target: TargetUpdate,
};

/// Strict stock-profile directive reader. Unknown directives are never discarded.
pub fn parse(line: []const u8) Error!Directive {
    var args: source.Arguments = .{ .bytes = line };
    const name = (try args.next() orelse return error.MissingArgument).bytes;
    const result: Directive = if (std.mem.eql(u8, name, "SecRule")) .{ .rule = .{
        .selectors = try required(&args),
        .operator = try required(&args),
        .actions = try args.next(),
    } } else if (std.mem.eql(u8, name, "SecAction")) .{
        .action = try required(&args),
    } else if (std.mem.eql(u8, name, "SecMarker")) .{
        .marker = try required(&args),
    } else if (std.mem.eql(u8, name, "SecDefaultAction")) .{
        .defaults = try required(&args),
    } else if (std.mem.eql(u8, name, "SecComponentSignature")) .{
        .component = try required(&args),
    } else if (std.mem.eql(u8, name, "SecRuleUpdateTargetById")) .{ .update_target = .{
        .id = try required(&args),
        .selectors = try required(&args),
    } } else return error.UnknownDirective;
    if (try args.next() != null) return error.TooManyArguments;
    return result;
}

fn required(args: *source.Arguments) Error!source.Token {
    return try args.next() orelse error.MissingArgument;
}

pub const Action = struct {
    name: []const u8,
    /// The action value is borrowed, with matching outer quotes removed.
    value: ?[]const u8,
};

pub const Actions = struct {
    bytes: []const u8,
    offset: usize = 0,

    /// SecLang permits trailing commas. Quoted commas remain part of a value.
    pub fn next(self: *Actions) Error!?Action {
        while (self.offset < self.bytes.len) {
            const start = self.offset;
            var quote: ?u8 = null;
            while (self.offset < self.bytes.len) {
                const byte = self.bytes[self.offset];
                self.offset += 1;
                if (byte == '\\' and self.offset < self.bytes.len) {
                    self.offset += 1;
                    continue;
                }
                if (quote != null) {
                    if (byte == quote.?) quote = null;
                } else if (byte == '"' or byte == '\'') {
                    quote = byte;
                } else if (byte == ',') break;
            }
            if (quote != null) return error.UnterminatedQuote;
            const end = if (self.bytes[self.offset - 1] == ',') self.offset - 1 else self.offset;
            const item = std.mem.trim(u8, self.bytes[start..end], " \t\r");
            if (item.len == 0) {
                if (self.offset < self.bytes.len) return error.InvalidAction;
                return null;
            }
            const colon = std.mem.indexOfScalar(u8, item, ':') orelse item.len;
            const name = item[0..colon];
            for (name) |byte| {
                if (!std.ascii.isAlphanumeric(byte)) return error.InvalidAction;
            }
            if (name.len == 0) return error.InvalidAction;
            const value = if (colon < item.len) try actionValue(item[colon + 1 ..]) else null;
            return .{ .name = name, .value = value };
        }
        return null;
    }
};

fn actionValue(bytes: []const u8) Error![]const u8 {
    if (bytes.len == 0) return error.InvalidAction;
    if (bytes[0] != '\'' and bytes[0] != '"') return bytes;
    var args: source.Arguments = .{ .bytes = bytes };
    const token = try required(&args);
    if (try args.next() != null) return error.InvalidAction;
    return token.bytes;
}

pub const Operator = struct {
    name: []const u8,
    argument: []const u8,
    negated: bool,

    pub fn parse(bytes: []const u8) Error!Operator {
        const negated = bytes.len > 0 and bytes[0] == '!';
        const value = if (negated) bytes[1..] else bytes;
        if (value.len == 0) return error.InvalidOperator;
        if (value[0] != '@') return .{
            .name = "rx",
            .argument = value,
            .negated = negated,
        };
        const end = std.mem.indexOfAny(u8, value, " \t") orelse value.len;
        const name = value[1..end];
        if (name.len == 0) return error.InvalidOperator;
        for (name) |byte| if (!std.ascii.isAlphanumeric(byte)) return error.InvalidOperator;
        return .{
            .name = name,
            .argument = std.mem.trimStart(u8, value[end..], " \t"),
            .negated = negated,
        };
    }
};

test "actions distinguish quoted commas, macros and repeatable transforms" {
    var actions: Actions = .{
        .bytes = "id:1,msg:'one, two',setvar:'tx.n=+%{tx.severity}',t:none,t:lowercase,",
    };
    try std.testing.expectEqualStrings("id", (try actions.next()).?.name);
    try std.testing.expectEqualStrings("one, two", (try actions.next()).?.value.?);
    try std.testing.expectEqualStrings("tx.n=+%{tx.severity}", (try actions.next()).?.value.?);
    try std.testing.expectEqualStrings("none", (try actions.next()).?.value.?);
    try std.testing.expectEqualStrings("lowercase", (try actions.next()).?.value.?);
    try std.testing.expect((try actions.next()) == null);
}

test "stock syntax is strict about arity and unknown directives" {
    const rule = (try parse("SecRule ARGS \"!@rx x\" \"id:1,phase:2\"")).rule;
    const operator = try Operator.parse(rule.operator.bytes);
    try std.testing.expect(operator.negated);
    try std.testing.expectEqualStrings("rx", operator.name);
    try std.testing.expectEqualStrings("x", operator.argument);
    try std.testing.expectError(error.MissingArgument, parse("SecRule ARGS"));
    try std.testing.expectError(error.TooManyArguments, parse("SecMarker END EXTRA"));
    try std.testing.expectError(error.UnknownDirective, parse("SecRuleEngine On"));
    var actions: Actions = .{ .bytes = "id:1,,phase:2" };
    _ = try actions.next();
    try std.testing.expectError(error.InvalidAction, actions.next());
}

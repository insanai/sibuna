//! Recursive descent with explicit nesting limits and balanced concatenation trees.
//! The source is borrowed only during off-path compilation.
const std = @import("std");
const types = @import("regex_types.zig");
const escape = @import("regex_escape.zig");

pub const Parser = struct {
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: types.Limits,
    nodes: std.ArrayList(types.Node) = .empty,
    offset: usize = 0,
    depth: usize = 0,
    groups: u8 = 0,
    flags: types.Flags = .{},

    pub fn parse(self: *Parser) types.Error!u32 {
        if (self.bytes.len > self.limits.pattern_bytes) return error.RegexLimit;
        const root = try self.alternation();
        if (self.offset != self.bytes.len) return error.InvalidRegex;
        return root;
    }

    fn node(self: *Parser, value: types.NodeValue) types.Error!u32 {
        if (self.nodes.items.len == self.limits.nodes) return error.RegexLimit;
        const index: u32 = @intCast(self.nodes.items.len);
        const nullable = switch (value) {
            .empty, .assertion => true,
            .class => false,
            .concat => |pair| self.nodes.items[pair.left].nullable and
                self.nodes.items[pair.right].nullable,
            .alternate => |pair| self.nodes.items[pair.left].nullable or
                self.nodes.items[pair.right].nullable,
            .repeat => |repeat| repeat.minimum == 0 or self.nodes.items[repeat.child].nullable,
            .capture => |capture| self.nodes.items[capture.child].nullable,
        };
        const captures = switch (value) {
            .capture => true,
            .concat, .alternate => |pair| self.nodes.items[pair.left].captures or
                self.nodes.items[pair.right].captures,
            .repeat => |repeat| self.nodes.items[repeat.child].captures,
            else => false,
        };
        try self.nodes.append(self.allocator, .{
            .value = value,
            .nullable = nullable,
            .captures = captures,
        });
        return index;
    }

    fn alternation(self: *Parser) types.Error!u32 {
        var children: std.ArrayList(u32) = .empty;
        defer children.deinit(self.allocator);
        try children.append(self.allocator, try self.sequence());
        while (self.offset < self.bytes.len and self.bytes[self.offset] == '|') {
            self.offset += 1;
            try children.append(self.allocator, try self.sequence());
        }
        return self.balanced(children.items, true);
    }

    fn sequence(self: *Parser) types.Error!u32 {
        var children: std.ArrayList(u32) = .empty;
        defer children.deinit(self.allocator);
        while (self.offset < self.bytes.len) {
            if (self.bytes[self.offset] == ')' or self.bytes[self.offset] == '|') break;
            try children.append(self.allocator, try self.quantified());
        }
        return self.balanced(children.items, false);
    }

    fn balanced(self: *Parser, children: []const u32, alternate: bool) types.Error!u32 {
        if (children.len == 0) return self.node(.empty);
        if (children.len == 1) return children[0];
        const middle = children.len / 2;
        const pair: types.Pair = .{
            .left = try self.balanced(children[0..middle], alternate),
            .right = try self.balanced(children[middle..], alternate),
        };
        return self.node(if (alternate) .{ .alternate = pair } else .{ .concat = pair });
    }

    fn quantified(self: *Parser) types.Error!u32 {
        const child = try self.atom();
        if (self.offset == self.bytes.len) return child;
        var repeat: types.Repeat = .{
            .child = child,
            .minimum = 0,
            .maximum = null,
            .lazy = false,
        };
        switch (self.bytes[self.offset]) {
            '*' => self.offset += 1,
            '+' => {
                repeat.minimum = 1;
                self.offset += 1;
            },
            '?' => {
                repeat.maximum = 1;
                self.offset += 1;
            },
            '{' => {
                if (self.offset + 1 == self.bytes.len) return child;
                if (!std.ascii.isDigit(self.bytes[self.offset + 1])) {
                    return child;
                }
                try self.counted(&repeat);
            },
            else => return child,
        }
        if (self.offset < self.bytes.len) {
            if (self.bytes[self.offset] == '+') return error.UnsupportedRegex;
            if (self.bytes[self.offset] == '?') {
                repeat.lazy = true;
                self.offset += 1;
            }
        }
        return self.node(.{ .repeat = repeat });
    }

    fn counted(self: *Parser, repeat: *types.Repeat) types.Error!void {
        self.offset += 1;
        repeat.minimum = try self.number();
        repeat.maximum = repeat.minimum;
        if (self.offset < self.bytes.len and self.bytes[self.offset] == ',') {
            self.offset += 1;
            repeat.maximum = if (self.offset < self.bytes.len and self.bytes[self.offset] == '}')
                null
            else
                try self.number();
        }
        if (self.offset == self.bytes.len or self.bytes[self.offset] != '}') {
            return error.InvalidRegex;
        }
        self.offset += 1;
        if (repeat.maximum) |maximum| if (maximum < repeat.minimum) return error.InvalidRegex;
    }

    fn number(self: *Parser) types.Error!usize {
        const start = self.offset;
        var result: usize = 0;
        while (self.offset < self.bytes.len and std.ascii.isDigit(self.bytes[self.offset])) {
            const digit: usize = self.bytes[self.offset] - '0';
            if (digit > self.limits.repeat or result > (self.limits.repeat - digit) / 10) {
                return error.RegexLimit;
            }
            result = result * 10 + digit;
            self.offset += 1;
        }
        if (self.offset == start) return error.InvalidRegex;
        return result;
    }

    fn atom(self: *Parser) types.Error!u32 {
        const byte = self.bytes[self.offset];
        self.offset += 1;
        return switch (byte) {
            '(' => self.group(),
            '[' => self.characterClass(),
            '.' => blk: {
                var class: types.Class = .{ .bits = @splat(std.math.maxInt(u64)) };
                if (!self.flags.dotall) class.bits[0] &= ~(@as(u64, 1) << 10);
                break :blk self.node(.{ .class = class });
            },
            '^', '$' => self.node(.{ .assertion = .{
                .kind = if (byte == '^') .start else .end,
                .multiline = self.flags.multiline,
            } }),
            '\\' => self.escaped(),
            '*', '+', '?' => error.InvalidRegex,
            else => self.literal(byte),
        };
    }

    fn literal(self: *Parser, byte: u8) types.Error!u32 {
        var class: types.Class = .{};
        class.add(byte);
        if (self.flags.insensitive) class.fold();
        return self.node(.{ .class = class });
    }

    fn escaped(self: *Parser) types.Error!u32 {
        const value = try escape.read(self.bytes, &self.offset, false);
        return switch (value) {
            .byte => |byte| self.literal(byte),
            .class => |original| blk: {
                var class = original;
                if (self.flags.insensitive) class.fold();
                break :blk self.node(.{ .class = class });
            },
            .assertion => |kind| self.node(.{ .assertion = .{ .kind = kind } }),
        };
    }

    fn group(self: *Parser) types.Error!u32 {
        if (self.depth == self.limits.depth) return error.DepthLimit;
        self.depth += 1;
        defer self.depth -= 1;
        const original = self.flags;
        var restore_flags = true;
        defer if (restore_flags) {
            self.flags = original;
        };
        var capturing = true;
        if (self.offset < self.bytes.len and self.bytes[self.offset] == '?') {
            self.offset += 1;
            capturing = false;
            if (try self.inlineFlags()) {
                restore_flags = false;
                return self.node(.empty);
            }
        }
        var group_index: ?u8 = null;
        if (capturing) {
            if (self.groups == types.max_groups) return error.CaptureLimit;
            self.groups += 1;
            group_index = self.groups;
        }
        const child = try self.alternation();
        if (self.offset == self.bytes.len or self.bytes[self.offset] != ')') {
            return error.InvalidRegex;
        }
        self.offset += 1;
        if (group_index) |index| {
            return self.node(.{ .capture = .{ .child = child, .group = index } });
        }
        return child;
    }

    /// A standalone flag group affects its surrounding sequence. Its closing ')'
    /// is consumed here, and group() must preserve that new flag state on return.
    fn inlineFlags(self: *Parser) types.Error!bool {
        var enabled = true;
        var changed = false;
        while (self.offset < self.bytes.len) {
            const byte = self.bytes[self.offset];
            self.offset += 1;
            switch (byte) {
                ':' => return false,
                ')' => if (changed) return true else return error.InvalidRegex,
                '-' => {
                    if (!enabled) return error.InvalidRegex;
                    enabled = false;
                },
                'i' => {
                    self.flags.insensitive = enabled;
                    changed = true;
                },
                'm' => {
                    self.flags.multiline = enabled;
                    changed = true;
                },
                's' => {
                    self.flags.dotall = enabled;
                    changed = true;
                },
                else => return error.UnsupportedRegex,
            }
        }
        return error.InvalidRegex;
    }

    fn characterClass(self: *Parser) types.Error!u32 {
        var class: types.Class = .{};
        const inverted = self.offset < self.bytes.len and self.bytes[self.offset] == '^';
        if (inverted) self.offset += 1;
        var first = true;
        while (self.offset < self.bytes.len) {
            if (self.bytes[self.offset] == ']' and !first) {
                self.offset += 1;
                if (self.flags.insensitive) class.fold();
                if (inverted) class.invert();
                return self.node(.{ .class = class });
            }
            const left = try self.classValue();
            first = false;
            if (self.offset + 1 < self.bytes.len and self.bytes[self.offset] == '-' and
                self.bytes[self.offset + 1] != ']')
            {
                self.offset += 1;
                const right = try self.classValue();
                if (left != .byte or right != .byte or left.byte > right.byte) {
                    return error.InvalidRegex;
                }
                for (@as(usize, left.byte)..@as(usize, right.byte) + 1) |value| {
                    class.add(@intCast(value));
                }
            } else switch (left) {
                .byte => |byte| class.add(byte),
                .class => |value| class.merge(value),
                .assertion => unreachable,
            }
        }
        return error.InvalidRegex;
    }

    fn classValue(self: *Parser) types.Error!escape.Escape {
        if (self.offset == self.bytes.len) return error.InvalidRegex;
        const byte = self.bytes[self.offset];
        self.offset += 1;
        if (byte == '\\') return escape.read(self.bytes, &self.offset, true);
        // POSIX classes need their own parser and are rejected until implemented.
        if (byte == '[' and self.offset < self.bytes.len and self.bytes[self.offset] == ':') {
            return error.UnsupportedRegex;
        }
        return .{ .byte = byte };
    }
};

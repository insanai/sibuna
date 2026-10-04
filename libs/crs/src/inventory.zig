//! Bounded source inventory, deliberately independent of executable compatibility.
//! Names are copied into fixed storage because line buffers are reused by the reader.
const std = @import("std");
const syntax = @import("syntax.zig");

pub const Error = syntax.Error || error{ TooManyNames, NameTooLong };
pub const max_names = 128;
pub const max_name_bytes = 64;

pub const NameCount = struct {
    bytes: [max_name_bytes]u8 = undefined,
    size: u8 = 0,
    count: usize = 0,

    pub fn name(self: *const NameCount) []const u8 {
        return self.bytes[0..self.size];
    }
};

pub const Names = struct {
    entries: [max_names]NameCount = undefined,
    size: usize = 0,

    pub fn add(self: *Names, name: []const u8) Error!void {
        if (name.len > max_name_bytes) return error.NameTooLong;
        for (self.entries[0..self.size]) |*entry| {
            if (std.mem.eql(u8, entry.name(), name)) {
                entry.count += 1;
                return;
            }
        }
        if (self.size == max_names) return error.TooManyNames;
        const entry = &self.entries[self.size];
        entry.* = .{ .size = @intCast(name.len), .count = 1 };
        @memcpy(entry.bytes[0..name.len], name);
        self.size += 1;
    }

    pub fn count(self: *const Names, name: []const u8) usize {
        for (self.entries[0..self.size]) |*entry| {
            if (std.mem.eql(u8, entry.name(), name)) return entry.count;
        }
        return 0;
    }
};

pub const Inventory = struct {
    directives: [@typeInfo(syntax.Directive).@"union".field_names.len]usize = @splat(0),
    operators: Names = .{},
    actions: Names = .{},
    transforms: Names = .{},

    pub fn add(self: *Inventory, directive: syntax.Directive) Error!void {
        const actions: ?[]const u8 = switch (directive) {
            .rule => |rule| blk: {
                const operator = try syntax.Operator.parse(rule.operator.bytes);
                try self.operators.add(operator.name);
                break :blk if (rule.actions) |token| token.bytes else null;
            },
            .action, .defaults => |token| token.bytes,
            else => null,
        };
        if (actions) |bytes| {
            var iterator: syntax.Actions = .{ .bytes = bytes };
            while (try iterator.next()) |action| {
                try self.actions.add(action.name);
                if (std.mem.eql(u8, action.name, "t")) {
                    try self.transforms.add(action.value orelse return error.InvalidAction);
                }
            }
        }
        self.directives[@backingInt(std.meta.activeTag(directive))] += 1;
    }
};

test "inventory owns names and counts defaults as actions, not rules" {
    var inventory: Inventory = .{};
    try inventory.add(try syntax.parse("SecDefaultAction \"phase:1,log,pass\""));
    var mutable = "SecRule ARGS \"@rx x\" \"id:1,t:none,t:lowercase,chain\"".*;
    try inventory.add(try syntax.parse(&mutable));
    @memset(&mutable, 'x');
    try std.testing.expectEqual(@as(usize, 1), inventory.operators.count("rx"));
    try std.testing.expectEqual(@as(usize, 1), inventory.actions.count("chain"));
    try std.testing.expectEqual(@as(usize, 2), inventory.transforms.size);
    try std.testing.expectEqual(@as(usize, 1), inventory.directives[0]);
}

test "name capacity is explicit and does not silently discard constructs" {
    var names: Names = .{};
    const long: [65]u8 = @splat('x');
    try std.testing.expectError(error.NameTooLong, names.add(&long));
    names.size = max_names;
    for (&names.entries) |*entry| entry.* = .{ .size = 1, .count = 1 };
    for (&names.entries) |*entry| entry.bytes[0] = 'x';
    try std.testing.expectError(error.TooManyNames, names.add("new"));
}

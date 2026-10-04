//! Flatten complete JSON documents using the pinned reference's ARGS paths.
//! The standard token scanner owns syntax/Unicode validation; this adapter owns
//! bounded path construction, duplicate ordering and collection publication.
const std = @import("std");
const tokens = @import("bounded_json.zig");
const values = @import("acquired_values.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const decimal = @import("decimal_format.zig");
pub const Error = tokens.Error || values.Error || error{JsonPathLimit};
pub const Frame = struct {
    prefix: usize,
    array: bool,
    expect_key: bool,
    ordinal: u64 = 0,
};
pub const Scratch = struct {
    value: []u8,
    path: []u8,
    bits: []u8,
    frames: []Frame,
};
const Parser = struct {
    builder: *values.Builder,
    scratch: Scratch,
    budget: *work.Budget,
    depth: usize = 0,
    path_used: usize = 0,

    fn push(self: *Parser, array: bool) Error!void {
        if (self.depth == self.scratch.frames.len) return error.JsonDepthLimit;
        try self.name();
        if (!array) try self.append(".");
        self.scratch.frames[self.depth] = .{
            .prefix = self.path_used,
            .array = array,
            .expect_key = !array,
        };
        self.depth += 1;
    }

    fn pop(self: *Parser) Error!void {
        std.debug.assert(self.depth > 0);
        self.depth -= 1;
        try self.completed();
    }

    fn string(self: *Parser, value: []const u8) Error!void {
        if (self.depth != 0) {
            const top = &self.scratch.frames[self.depth - 1];
            if (!top.array and top.expect_key) {
                self.path_used = top.prefix;
                try self.append(if (value.len == 0) "empty-key" else value);
                top.expect_key = false;
                return;
            }
        }
        try self.scalar(value);
    }

    fn scalar(self: *Parser, value: []const u8) Error!void {
        try self.name();
        try self.builder.field(.json, .{
            .key = self.scratch.path[0..self.path_used],
            .value = value,
        }, self.budget);
        try self.completed();
    }

    fn completed(self: *Parser) Error!void {
        if (self.depth == 0) {
            self.path_used = 0;
            return;
        }
        const top = &self.scratch.frames[self.depth - 1];
        self.path_used = top.prefix;
        top.expect_key = !top.array;
        if (top.array) {
            try self.budget.debit(1);
            top.ordinal = std.math.add(u64, top.ordinal, 1) catch return error.JsonPathLimit;
        }
    }

    fn name(self: *Parser) Error!void {
        if (self.depth == 0) {
            self.path_used = 0;
            return self.append("json");
        }
        const top = &self.scratch.frames[self.depth - 1];
        if (!top.array) {
            std.debug.assert(!top.expect_key);
            return;
        }
        self.path_used = top.prefix;
        try self.append(".array_");
        var digits: [decimal.capacity(u64)]u8 = undefined;
        try self.append(try decimal.write(u64, top.ordinal, &digits, self.budget));
    }

    fn append(self: *Parser, bytes: []const u8) Error!void {
        if (bytes.len > self.scratch.path.len - self.path_used) return error.JsonPathLimit;
        try self.budget.debit(bytes.len);
        const destination = self.scratch.path[self.path_used..][0..bytes.len];
        buffers.assertDisjoint(bytes, destination);
        @memcpy(destination, bytes);
        self.path_used += bytes.len;
    }
};

pub fn parse(
    input: []const u8,
    builder: *values.Builder,
    scratch: Scratch,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    buffers.assertExclusive(&.{
        input,
        builder.bytes,
        scratch.value,
        scratch.path,
        scratch.bits,
        std.mem.sliceAsBytes(scratch.frames),
        std.mem.sliceAsBytes(builder.entries),
    });
    var scanner: tokens.Scanner = undefined;
    try scanner.init(input, scratch.value, scratch.bits, scratch.frames.len, budget);
    var parser: Parser = .{ .builder = builder, .scratch = scratch, .budget = budget };
    while (true) {
        switch (try scanner.next()) {
            .object_begin => try parser.push(false),
            .array_begin => try parser.push(true),
            .object_end, .array_end => try parser.pop(),
            .string => |value| try parser.string(value),
            .number => |value| try parser.scalar(value),
            .true => try parser.scalar("true"),
            .false => try parser.scalar("false"),
            .null => try parser.scalar(""),
            .end_of_document => break,
            else => unreachable,
        }
    }
    std.debug.assert(parser.depth == 0);
    try builder.sizes(budget);
    // Combined ARGS becomes complete only after the connector has populated all
    // query/body contributors. JSON never claims URL-encoded POST collection data.
}

test {
    _ = @import("json_acquisition_test.zig");
}

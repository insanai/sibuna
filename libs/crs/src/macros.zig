//! Off-path runtime-string compilation and atomic zero-allocation expansion.
//! SID 0010 defines the finite reference profile and unavailable-input semantics.
const std = @import("std");
const variables = @import("variables.zig");
const collections = @import("collections.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = std.mem.Allocator.Error || variables.Error || error{
    InvalidMacro,
    UnknownCollection,
    UnsupportedMacro,
    SourceLimit,
    PartLimit,
    ScratchLimit,
    OutputLimit,
};
pub const Limits = struct { source: usize = 64 * 1024, parts: usize = 1024 };
pub const Part = union(enum) { literal: []const u8, reference: variables.Reference };
pub const Frame = struct {
    view: *const variables.View,
    pieces: [][]const u8,
    output: []u8,
    budget: *work.Budget,
};

pub const Program = struct {
    owner: std.heap.ArenaAllocator,
    source: []const u8,
    parts: []const Part,

    pub fn deinit(self: *Program) void {
        self.owner.deinit();
        self.* = undefined;
    }

    /// The fixed text of a program without references; it needs no view or copy.
    pub fn fixed(self: *const Program) ?[]const u8 {
        return switch (self.parts.len) {
            0 => "",
            1 => switch (self.parts[0]) {
                .literal => |text| text,
                .reference => null,
            },
            else => null,
        };
    }

    /// Output is disjoint from source and view values. Resolution and work
    /// reservation finish before any copy, leaving output unchanged on failure.
    pub fn expand(self: *const Program, frame: Frame) Error![]const u8 {
        if (frame.pieces.len < self.parts.len) return error.ScratchLimit;
        var length: usize = 0;
        for (self.parts, 0..) |part, index| {
            try frame.budget.debit(1);
            const bytes = switch (part) {
                .literal => |literal| literal,
                .reference => |reference| try frame.view.lookup(reference, frame.budget),
            };
            if (bytes.len > frame.output.len - length) return error.OutputLimit;
            buffers.assertDisjoint(bytes, frame.output);
            length += bytes.len;
            frame.pieces[index] = bytes;
        }
        try frame.budget.debit(@intCast(length));
        var position: usize = 0;
        for (frame.pieces[0..self.parts.len]) |piece| {
            @memcpy(frame.output[position..][0..piece.len], piece);
            position += piece.len;
        }
        std.debug.assert(position == length);
        return frame.output[0..length];
    }
};

pub fn compile(allocator: std.mem.Allocator, input: []const u8, limits: Limits) Error!Program {
    if (input.len > limits.source) return error.SourceLimit;
    if (std.mem.indexOfScalar(u8, input, 0) != null) return error.InvalidMacro;
    var owner = std.heap.ArenaAllocator.init(allocator);
    errdefer owner.deinit();
    const arena = owner.allocator();
    const source = try arena.dupe(u8, input);
    var parts: std.ArrayList(Part) = .empty;
    var start: usize = 0;
    while (std.mem.indexOf(u8, source[start..], "%{")) |offset| {
        const position = start + offset;
        if (position > start) {
            try append(arena, &parts, .{ .literal = source[start..position] }, limits);
        }
        const begin = position + 2;
        const close = std.mem.indexOfScalar(u8, source[begin..], '}') orelse
            return error.InvalidMacro;
        const end = begin + close;
        const reference = try parseReference(source[begin..end]);
        try append(arena, &parts, .{ .reference = reference }, limits);
        start = end + 1;
    }
    if (start < source.len) try append(arena, &parts, .{ .literal = source[start..] }, limits);
    return .{ .owner = owner, .source = source, .parts = try parts.toOwnedSlice(arena) };
}

fn append(
    allocator: std.mem.Allocator,
    parts: *std.ArrayList(Part),
    part: Part,
    limits: Limits,
) Error!void {
    if (parts.items.len == limits.parts) return error.PartLimit;
    try parts.append(allocator, part);
}

fn parseReference(bytes: []const u8) Error!variables.Reference {
    if (bytes.len == 0) return error.InvalidMacro;
    if (std.mem.indexOfAny(u8, bytes, "%{}") != null) return error.UnsupportedMacro;
    const separator = std.mem.indexOfAny(u8, bytes, ".:");
    const collection = collections.lookup(bytes[0 .. separator orelse bytes.len]) orelse
        return error.UnknownCollection;
    if (separator) |index| {
        if (!collection.keyed() or index + 1 == bytes.len) return error.InvalidMacro;
        return .{ .collection = collection, .key = bytes[index + 1 ..] };
    }
    if (collection.keyed()) return error.UnsupportedMacro;
    return .{ .collection = collection };
}

test {
    _ = @import("macros_test.zig");
}

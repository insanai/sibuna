//! Bounded byte-oriented regular expressions. Unsupported PCRE extensions are errors.
const std = @import("std");

pub const max_groups = 16;
pub const capture_slots = 2 * (max_groups + 1);
pub const unset = std.math.maxInt(usize);
pub const missing = std.math.maxInt(u32);
pub const Error = std.mem.Allocator.Error || error{
    InvalidRegex,
    UnsupportedRegex,
    RegexLimit,
    CaptureLimit,
    DepthLimit,
};

pub const Limits = struct {
    pattern_bytes: usize = 64 * 1024,
    nodes: usize = 16384,
    instructions: usize = 16384,
    depth: usize = 64,
    repeat: usize = 4096,
};

pub const Class = struct {
    bits: [4]u64 = @splat(0),

    pub fn add(self: *Class, byte: u8) void {
        self.bits[byte / 64] |= @as(u64, 1) << @as(u6, @intCast(byte % 64));
    }

    pub fn contains(self: Class, byte: u8) bool {
        return self.bits[byte / 64] & (@as(u64, 1) << @as(u6, @intCast(byte % 64))) != 0;
    }

    pub fn merge(self: *Class, other: Class) void {
        for (&self.bits, other.bits) |*left, right| left.* |= right;
    }

    pub fn invert(self: *Class) void {
        for (&self.bits) |*word| word.* = ~word.*;
    }

    pub fn fold(self: *Class) void {
        for ('a'..'z' + 1) |byte| {
            const lower: u8 = @intCast(byte);
            const upper = std.ascii.toUpper(lower);
            if (self.contains(lower) or self.contains(upper)) {
                self.add(lower);
                self.add(upper);
            }
        }
    }
};

pub const Flags = struct {
    insensitive: bool = false,
    multiline: bool = false,
    dotall: bool = false,
};
pub const AssertKind = enum {
    start,
    end,
    absolute_start,
    absolute_end,
    final_end,
    word,
    not_word,
};
pub const Assertion = struct { kind: AssertKind, multiline: bool = false };
pub const Pair = struct { left: u32, right: u32 };
pub const Repeat = struct { child: u32, minimum: usize, maximum: ?usize, lazy: bool };
pub const Capture = struct { child: u32, group: u8 };

pub const NodeValue = union(enum) {
    empty,
    class: Class,
    assertion: Assertion,
    concat: Pair,
    alternate: Pair,
    repeat: Repeat,
    capture: Capture,
};

pub const Node = struct {
    value: NodeValue,
    nullable: bool,
    captures: bool,
    first: Class,
};

pub const Instruction = struct {
    op: union(enum) { class: Class, assertion: Assertion, split, jump, save: u8, accept },
    next: u32 = missing,
    alternative: u32 = missing,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    instructions: []const Instruction,
    start: u32,
    groups: u8,
    first: Class = .{ .bits = @splat(std.math.maxInt(u64)) },
    nullable: bool = true,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.instructions);
        self.* = undefined;
    }
};

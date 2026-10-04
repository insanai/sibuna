//! Thompson construction with linked pending edges; compilation allocates off-path.
//! Pending edge chains never escape into the immutable executable regex program.
const std = @import("std");
const types = @import("regex_types.zig");
const parser = @import("regex_parser.zig");

const Patches = struct { head: u32 = types.missing, tail: u32 = types.missing };
const Fragment = struct { start: u32, outs: Patches };

pub fn compile(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: types.Limits,
) types.Error!types.Program {
    return configured(allocator, bytes, .{ .limits = limits });
}

pub const Config = struct {
    limits: types.Limits = .{},
    flags: types.Flags = .{},
};

/// The byte profile is explicit; callers must not infer SecLang options from PCRE defaults.
pub fn configured(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    config: Config,
) types.Error!types.Program {
    const limits = config.limits;
    if (limits.nodes > std.math.maxInt(u32) or
        limits.instructions > std.math.maxInt(u32) / 2) return error.RegexLimit;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    var reader: parser.Parser = .{
        .allocator = arena.allocator(),
        .bytes = bytes,
        .limits = limits,
        .flags = config.flags,
    };
    const root = try reader.parse();
    var emitter: Emitter = .{
        .allocator = arena.allocator(),
        .nodes = reader.nodes.items,
        .limit = limits.instructions,
    };
    const fragment = try emitter.capture(.{ .child = root, .group = 0 });
    const accept = try emitter.emit(.{ .op = .accept });
    emitter.patch(fragment.outs, accept);
    return .{
        .allocator = allocator,
        .instructions = try allocator.dupe(types.Instruction, emitter.instructions.items),
        .start = fragment.start,
        .groups = reader.groups,
        .first = reader.nodes.items[root].first,
        .nullable = reader.nodes.items[root].nullable,
    };
}

const Emitter = struct {
    allocator: std.mem.Allocator,
    nodes: []const types.Node,
    limit: usize,
    instructions: std.ArrayList(types.Instruction) = .empty,

    fn emit(self: *Emitter, instruction: types.Instruction) types.Error!u32 {
        if (self.instructions.items.len == self.limit) return error.RegexLimit;
        const index: u32 = @intCast(self.instructions.items.len);
        try self.instructions.append(self.allocator, instruction);
        return index;
    }

    fn edge(self: *Emitter, encoded: u32) *u32 {
        const instruction = &self.instructions.items[encoded / 2];
        return if (encoded % 2 == 0) &instruction.next else &instruction.alternative;
    }

    fn pending(index: u32, alternative: bool) Patches {
        const encoded = index * 2 + @intFromBool(alternative);
        return .{ .head = encoded, .tail = encoded };
    }

    fn merge(self: *Emitter, left: Patches, right: Patches) Patches {
        if (left.head == types.missing) return right;
        if (right.head == types.missing) return left;
        self.edge(left.tail).* = right.head;
        return .{ .head = left.head, .tail = right.tail };
    }

    fn patch(self: *Emitter, outs: Patches, target: u32) void {
        var next = outs.head;
        while (next != types.missing) {
            const link = self.edge(next);
            const previous = link.*;
            link.* = target;
            next = previous;
        }
    }

    fn join(self: *Emitter, left: Fragment, right: Fragment) Fragment {
        self.patch(left.outs, right.start);
        return .{ .start = left.start, .outs = right.outs };
    }

    fn single(self: *Emitter, op: @FieldType(types.Instruction, "op")) types.Error!Fragment {
        const index = try self.emit(.{ .op = op });
        return .{ .start = index, .outs = pending(index, false) };
    }

    fn build(self: *Emitter, index: u32) types.Error!Fragment {
        return switch (self.nodes[index].value) {
            .empty => self.single(.jump),
            .class => |class| self.single(.{ .class = class }),
            .assertion => |assertion| self.single(.{ .assertion = assertion }),
            .concat => |pair| blk: {
                const left = try self.build(pair.left);
                const right = try self.build(pair.right);
                break :blk self.join(left, right);
            },
            .alternate => |pair| blk: {
                const left = try self.build(pair.left);
                const right = try self.build(pair.right);
                const split = try self.emit(.{
                    .op = .split,
                    .next = left.start,
                    .alternative = right.start,
                });
                break :blk .{ .start = split, .outs = self.merge(left.outs, right.outs) };
            },
            .repeat => |repeat| self.repeated(repeat),
            .capture => |value| self.capture(value),
        };
    }

    fn capture(self: *Emitter, value: types.Capture) types.Error!Fragment {
        const open = try self.single(.{ .save = value.group * 2 });
        const child = try self.build(value.child);
        const close = try self.single(.{ .save = value.group * 2 + 1 });
        return self.join(self.join(open, child), close);
    }

    fn optional(self: *Emitter, child: Fragment, lazy: bool, loop: bool) types.Error!Fragment {
        const split = try self.emit(.{
            .op = .split,
            .next = if (lazy) types.missing else child.start,
            .alternative = if (lazy) child.start else types.missing,
        });
        const exit = pending(split, !lazy);
        if (loop) {
            self.patch(child.outs, split);
            return .{ .start = split, .outs = exit };
        }
        return .{ .start = split, .outs = self.merge(child.outs, exit) };
    }

    fn repeated(self: *Emitter, repeat: types.Repeat) types.Error!Fragment {
        // PCRE repeats an empty captured iteration once before stopping. Ordinary
        // Pike state deduplication cannot preserve that capture; refuse this form
        // until its distinct semantics have an independently verified lowering.
        const child_properties = self.nodes[repeat.child];
        if (repeat.maximum == null and child_properties.nullable and child_properties.captures) {
            return error.UnsupportedRegex;
        }
        var result = try self.single(.jump);
        for (0..repeat.minimum) |_| result = self.join(result, try self.build(repeat.child));
        if (repeat.maximum) |maximum| {
            for (repeat.minimum..maximum) |_| {
                const child = try self.build(repeat.child);
                result = self.join(result, try self.optional(child, repeat.lazy, false));
            }
        } else {
            const child = try self.build(repeat.child);
            result = self.join(result, try self.optional(child, repeat.lazy, true));
        }
        return result;
    }
};

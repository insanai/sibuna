//! Owned literal/numeric arguments, with off-path preparation for static needles.
const std = @import("std");
const model = @import("model.zig");
const macros = @import("macros.zig");
const substring = @import("substring.zig");
const primitives = @import("primitives.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");

pub const Error = macros.Error || primitives.Error || error{VariableContextRequired};
pub const Argument = union(enum) { fixed: []const u8, dynamic: macros.Program };
pub const Program = struct {
    owner: std.heap.ArenaAllocator,
    kind: model.Operator,
    argument: Argument,
    prefixes: []const usize = &.{},

    pub fn deinit(self: *Program) void {
        if (self.argument == .dynamic) self.argument.dynamic.deinit();
        self.owner.deinit();
        self.* = undefined;
    }

    pub fn resolve(self: *const Program, frame: ?macros.Frame) Error![]const u8 {
        return switch (self.argument) {
            .fixed => |fixed| fixed,
            .dynamic => |*dynamic| dynamic.expand(
                frame orelse return error.VariableContextRequired,
            ),
        };
    }

    pub fn evaluate(
        self: *const Program,
        input: []const u8,
        context: primitives.Context,
        expansion: ?macros.Frame,
    ) Error!bool {
        if (self.argument == .dynamic) {
            // Expansion cannot overwrite the value whose predicate is being evaluated.
            if (expansion) |frame| buffers.assertDisjoint(input, frame.output);
        }
        const argument = try self.resolve(expansion);
        if (self.kind == .contains and self.argument == .fixed) {
            const prepared: substring.Pattern = .{ .bytes = argument, .prefixes = self.prefixes };
            return try prepared.find(input, context.budget) != null;
        }
        const predicate: primitives.Predicate = .{ .kind = self.kind, .argument = argument };
        return (try predicate.evaluate(input, context)).matched;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    kind: model.Operator,
    source: []const u8,
) Error!Program {
    std.debug.assert(primitives.supported(kind));
    var owner = std.heap.ArenaAllocator.init(allocator);
    errdefer owner.deinit();
    if (runtimeArgument(kind) and std.mem.indexOf(u8, source, "%{") != null) {
        const dynamic = try macros.compile(allocator, source, .{});
        return .{ .owner = owner, .kind = kind, .argument = .{ .dynamic = dynamic } };
    }
    const arena = owner.allocator();
    const argument = try arena.dupe(u8, source);
    var prefixes: []const usize = &.{};
    if (kind == .contains) {
        const storage = try arena.alloc(usize, argument.len);
        var budget: work.Budget = .{ .remaining = 64_000_000 };
        _ = try substring.prepare(argument, storage, &budget);
        prefixes = storage;
    }
    return .{
        .owner = owner,
        .kind = kind,
        .argument = .{ .fixed = argument },
        .prefixes = prefixes,
    };
}

fn runtimeArgument(kind: model.Operator) bool {
    return switch (kind) {
        .eq, .ge, .gt, .lt, .streq, .within, .begins_with, .ends_with, .contains => true,
        else => false,
    };
}

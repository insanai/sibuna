//! Owned targets and complete per-target snapshots in caller metadata scratch.
//! Bytes outlive rule evaluation; no indices into mutable transaction tables escape.
const std = @import("std");
const selectors = @import("selectors.zig");
const variables = @import("variables.zig");
const regex = @import("regex.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const decimal_format = @import("decimal_format.zig");
const controls = @import("controls.zig");

pub const Error = regex.types.Error || regex.match.Error || variables.Error ||
    controls.Error || error{
    SelectorLimit,
    InvalidTarget,
    SnapshotLimit,
    InvalidXmlMetadata,
};
pub const Limits = struct { targets: usize = 128, regex: regex.types.Limits = .{} };
pub const Pattern = struct { source: []const u8, program: regex.types.Program };
pub const Selection = union(enum) {
    all,
    name: []const u8,
    pattern: Pattern,
    xml: selectors.Xml,
};
pub const Target = struct {
    collection: variables.Collection,
    mode: selectors.Mode,
    selection: Selection,
};
pub const Frame = struct {
    view: *const variables.View,
    output: []variables.Entry,
    count: *[20]u8,
    regex: ?*regex.match.Scratch = null,
    budget: *work.Budget,
    filter: ?controls.Filter = null,
    pieces: [][]const u8 = &.{},
    macro_output: []u8 = &.{},
};
pub const Snapshot = struct {
    entries: []const variables.Entry,
    counted: bool = false,
};
pub const Program = struct {
    owner: std.heap.ArenaAllocator,
    targets: []const Target,
    exclusions: []const Target,
    regex_states: usize,

    pub fn deinit(self: *Program) void {
        self.owner.deinit();
        self.* = undefined;
    }

    /// No partial result escapes on capacity, coverage or work failure. Scratch may
    /// contain partial metadata after failure and must not be evaluated as a snapshot.
    pub fn select(self: *const Program, index: usize, frame: Frame) Error!Snapshot {
        std.debug.assert(index < self.targets.len);
        buffers.assertDisjoint(
            std.mem.sliceAsBytes(frame.view.entries),
            std.mem.sliceAsBytes(frame.output),
        );
        const target = &self.targets[index];
        try frame.budget.debit(1);
        if (try self.omitted(target, frame.budget)) return .{ .entries = &.{} };
        const name = key(target);
        if (try controlled(.{
            .collection = target.collection,
            .key = if (name.len == 0) null else name,
        }, frame)) return .{ .entries = &.{} };
        try frame.view.require(target.collection);
        var count: usize = 0;
        for (frame.view.entries) |entry| {
            try frame.budget.debit(1);
            if (!try matches(target, entry, frame)) continue;
            if (try self.excluded(entry, frame)) continue;
            if (target.mode == .count and try controlled(.{
                .collection = entry.collection,
                .key = if (entry.key.len == 0) null else entry.key,
            }, frame)) continue;
            if (target.mode != .count) {
                if (count == frame.output.len) return error.SnapshotLimit;
                frame.output[count] = entry;
            }
            count += 1;
        }
        if (target.mode == .count) {
            if (frame.output.len == 0) return error.SnapshotLimit;
            frame.output[0] = .{
                .collection = target.collection,
                .key = key(target),
                .value = try decimal_format.write(u64, @intCast(count), frame.count, frame.budget),
            };
            return .{ .entries = frame.output[0..1], .counted = true };
        }
        return .{ .entries = frame.output[0..count] };
    }

    fn omitted(self: *const Program, target: *const Target, budget: *work.Budget) Error!bool {
        for (self.exclusions) |*exclude| {
            try budget.debit(1);
            if (target.collection != exclude.collection) continue;
            if (exclude.selection == .all) return true;
            if (target.selection == .name and exclude.selection == .name) {
                const equal = try variables.keyEqual(
                    target.selection.name,
                    exclude.selection.name,
                    budget,
                );
                if (equal) {
                    return true;
                }
            }
            if (target.selection == .xml and exclude.selection == .xml and
                target.selection.xml == exclude.selection.xml) return true;
        }
        return false;
    }

    fn excluded(self: *const Program, entry: variables.Entry, frame: Frame) Error!bool {
        for (self.exclusions) |*exclude| {
            try frame.budget.debit(1);
            if (try matches(exclude, entry, frame)) return true;
        }
        return false;
    }
};

fn controlled(target: controls.Target, frame: Frame) Error!bool {
    const filter = frame.filter orelse return false;
    return filter.excludes(target, .{
        .view = frame.view,
        .pieces = frame.pieces,
        .output = frame.macro_output,
        .budget = frame.budget,
    });
}

fn key(target: *const Target) []const u8 {
    return switch (target.selection) {
        .name => |name| name,
        .pattern => |pattern| pattern.source,
        .all => "",
        .xml => |kind| if (kind == .elements) "/*" else "//@*",
    };
}

fn matches(target: *const Target, entry: variables.Entry, frame: Frame) Error!bool {
    if (target.collection != entry.collection) return false;
    return switch (target.selection) {
        .all => true,
        .name => |name| variables.keyEqual(name, entry.key, frame.budget),
        .pattern => |*pattern| try regex.match.search(
            &pattern.program,
            entry.key,
            frame.regex orelse return error.ScratchTooSmall,
            frame.budget,
        ) != null,
        .xml => |kind| blk: {
            const metadata = entry.xml orelse return error.InvalidXmlMetadata;
            break :blk metadata == (if (kind == .elements)
                variables.Xml.element
            else
                variables.Xml.attribute);
        },
    };
}

pub fn compile(
    allocator: std.mem.Allocator,
    source: []const selectors.Selector,
    limits: Limits,
) Error!Program {
    if (source.len == 0) return error.InvalidTarget;
    if (source.len > limits.targets) return error.SelectorLimit;
    var owner = std.heap.ArenaAllocator.init(allocator);
    errdefer owner.deinit();
    const arena = owner.allocator();
    var targets: std.ArrayList(Target) = .empty;
    var exclusions: std.ArrayList(Target) = .empty;
    var states: usize = 0;
    for (source) |item| {
        try validate(item);
        const target: Target = .{
            .collection = item.collection,
            .mode = item.mode,
            .selection = try prepare(arena, item.selection, limits.regex),
        };
        if (target.selection == .pattern) {
            states = @max(states, target.selection.pattern.program.instructions.len);
        }
        const list = if (item.mode == .exclude) &exclusions else &targets;
        try list.append(arena, target);
    }
    return .{
        .owner = owner,
        .targets = try targets.toOwnedSlice(arena),
        .exclusions = try exclusions.toOwnedSlice(arena),
        .regex_states = states,
    };
}

fn validate(item: selectors.Selector) Error!void {
    switch (item.selection) {
        .xml => if (item.collection != .xml) return error.InvalidTarget,
        .name, .pattern => if (!item.collection.keyed() or item.collection == .xml) {
            return error.InvalidTarget;
        },
        .all => {},
    }
}

fn prepare(
    allocator: std.mem.Allocator,
    source: selectors.Selection,
    limits: regex.types.Limits,
) Error!Selection {
    return switch (source) {
        .all => .all,
        .name => |name| .{ .name = try allocator.dupe(u8, name) },
        .xml => |kind| .{ .xml = kind },
        .pattern => |pattern| .{ .pattern = .{
            .source = try allocator.dupe(u8, pattern),
            .program = try regex.configured(allocator, if (pattern.len == 0) ".*" else pattern, .{
                .limits = limits,
                .flags = .{ .dotall = true, .multiline = true, .insensitive = true },
            }),
        } },
    };
}

test {
    _ = @import("selection_test.zig");
}

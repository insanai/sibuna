//! Snapshot semantics, explicit coverage and complete selection without request allocation.
const std = @import("std");
const selection = @import("selection.zig");
const selectors = @import("selectors.zig");
const variables = @import("variables.zig");
const regex = @import("regex.zig");
const work = @import("work.zig");

fn compile(allocator: std.mem.Allocator, text: []const u8) !selection.Program {
    const targets = try selectors.parse(allocator, text, 128);
    defer allocator.free(targets);
    return selection.compile(allocator, targets, .{});
}

const entries = [_]variables.Entry{
    .{ .collection = .args, .key = "one", .value = "first" },
    .{ .collection = .args, .key = "ONE", .value = "duplicate" },
    .{ .collection = .request_headers, .key = "one", .value = "header" },
    .{ .collection = .args, .key = "two", .value = "second" },
    .{ .collection = .args, .key = "empty", .value = "" },
};

const Scratch = struct {
    items: [16]variables.Entry = undefined,
    count: [20]u8 = undefined,
    budget: work.Budget = .{ .remaining = 100_000 },

    fn frame(self: *Scratch, view: *const variables.View) selection.Frame {
        return .{
            .view = view,
            .output = &self.items,
            .count = &self.count,
            .budget = &self.budget,
        };
    }
};

test "target snapshots preserve duplicates empty values and positive selector order" {
    var program = try compile(std.testing.allocator, "ARGS|ARGS:one|&ARGS|&ARGS:missing");
    defer program.deinit();
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    const all = try program.select(0, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 4), all.entries.len);
    try std.testing.expectEqualStrings("first", all.entries[0].value);
    try std.testing.expectEqualStrings("duplicate", all.entries[1].value);
    try std.testing.expectEqualStrings("second", all.entries[2].value);
    try std.testing.expectEqualStrings("", all.entries[3].value);
    const named = try program.select(1, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 2), named.entries.len);
    const count = try program.select(2, scratch.frame(&view));
    try std.testing.expect(count.counted);
    try std.testing.expectEqualStrings("4", count.entries[0].value);
    const missing = try program.select(3, scratch.frame(&view));
    try std.testing.expectEqualStrings("0", missing.entries[0].value);
}

test "collection scoped exclusions apply before values and counts including exact keys" {
    var program = try compile(
        std.testing.allocator,
        "ARGS|&ARGS|ARGS:one|REQUEST_HEADERS|!ARGS:ONE",
    );
    defer program.deinit();
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    const all = try program.select(0, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 2), all.entries.len);
    try std.testing.expectEqualStrings("second", all.entries[0].value);
    const count = try program.select(1, scratch.frame(&view));
    try std.testing.expectEqualStrings("2", count.entries[0].value);
    const omitted = try program.select(2, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 0), omitted.entries.len);
    const header = try program.select(3, scratch.frame(&view));
    try std.testing.expectEqualStrings("header", header.entries[0].value);
}

test "key patterns use case insensitive selector flags and bounded shared scratch" {
    var program = try compile(std.testing.allocator, "ARGS:/^O/|&ARGS|!ARGS:/^T/");
    defer program.deinit();
    var workspace = try regex.Workspace.init(
        std.testing.allocator,
        &program.targets[0].selection.pattern.program,
    );
    defer workspace.deinit();
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    var frame = scratch.frame(&view);
    frame.regex = &workspace.scratch;
    const named = try program.select(0, frame);
    try std.testing.expectEqual(@as(usize, 2), named.entries.len);
    const count = try program.select(1, frame);
    try std.testing.expectEqualStrings("3", count.entries[0].value);
    try std.testing.expect(program.regex_states > 0);
    frame.regex = null;
    try std.testing.expectError(error.ScratchTooSmall, program.select(0, frame));
}

test "complete empty unavailable and incomplete collections cannot be conflated" {
    var program = try compile(std.testing.allocator, "ARGS|&ARGS");
    defer program.deinit();
    var view: variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    const empty = try program.select(0, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 0), empty.entries.len);
    const count = try program.select(1, scratch.frame(&view));
    try std.testing.expectEqualStrings("0", count.entries[0].value);
    view.coverage[@backingInt(variables.Collection.args)] = .unavailable;
    try std.testing.expectError(
        error.UnavailableCollection,
        program.select(0, scratch.frame(&view)),
    );
    view.coverage[@backingInt(variables.Collection.args)] = .incomplete;
    try std.testing.expectError(
        error.IncompleteCollection,
        program.select(1, scratch.frame(&view)),
    );
    var omitted = try compile(std.testing.allocator, "&ARGS|!ARGS");
    defer omitted.deinit();
    const none = try omitted.select(0, scratch.frame(&view));
    try std.testing.expectEqual(@as(usize, 0), none.entries.len);
    try std.testing.expect(!none.counted);
}

test "XML selectors require explicit acquisition classification" {
    var program = try compile(std.testing.allocator, "XML:/*|XML://@*");
    defer program.deinit();
    var xml = [_]variables.Entry{
        .{ .collection = .xml, .key = "/root/child", .value = "text", .xml = .element },
        .{ .collection = .xml, .key = "/root/@name", .value = "attr", .xml = .attribute },
    };
    const view: variables.View = .{ .entries = &xml, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    const elements = try program.select(0, scratch.frame(&view));
    try std.testing.expectEqualStrings("text", elements.entries[0].value);
    const attributes = try program.select(1, scratch.frame(&view));
    try std.testing.expectEqualStrings("attr", attributes.entries[0].value);
    xml[1].xml = null;
    try std.testing.expectError(error.InvalidXmlMetadata, program.select(0, scratch.frame(&view)));
}

test "snapshot metadata survives transaction table edits while subsequent targets see edits" {
    var program = try compile(std.testing.allocator, "TX|TX");
    defer program.deinit();
    var tx = [_]variables.Entry{.{ .collection = .tx, .key = "score", .value = "1" }};
    const view: variables.View = .{ .entries = &tx, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    const old = try program.select(0, scratch.frame(&view));
    tx[0].value = "2";
    try std.testing.expectEqualStrings("1", old.entries[0].value);
    const next = try program.select(1, scratch.frame(&view));
    try std.testing.expectEqualStrings("2", next.entries[0].value);
}

test "capacity failures never return a partial snapshot and exhaustion is explicit" {
    var program = try compile(std.testing.allocator, "ARGS|&ARGS");
    defer program.deinit();
    const view: variables.View = .{ .entries = &entries, .coverage = @splat(.complete) };
    var scratch: Scratch = .{};
    var frame = scratch.frame(&view);
    frame.output = frame.output[0..1];
    try std.testing.expectError(error.SnapshotLimit, program.select(0, frame));
    const count = try program.select(1, frame);
    try std.testing.expectEqualStrings("4", count.entries[0].value);
    frame.output = &.{};
    try std.testing.expectError(error.SnapshotLimit, program.select(1, frame));
    scratch.budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, program.select(0, scratch.frame(&view)));
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try compile(allocator, "ARGS:one|ARGS:/^T/|XML:/*|&ARGS|!ARGS:/^O/");
    defer program.deinit();
}

test "selection compilation owns source keys and releases partial regexes on failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
    var source = "ARGS:one".*;
    var program = try compile(std.testing.allocator, &source);
    defer program.deinit();
    @memset(&source, 'x');
    try std.testing.expectEqualStrings("one", program.targets[0].selection.name);
    try std.testing.expectError(error.InvalidTarget, selection.compile(std.testing.allocator, &.{
        .{ .collection = .request_method, .mode = .values, .selection = .{ .name = "x" } },
    }, .{}));
}

test "bare XML does not silently select wildcard acquisition values" {
    var iterator: @import("selectors.zig").Iterator = .{ .bytes = "XML" };
    try std.testing.expectError(error.UnsupportedXPath, iterator.next());
    try std.testing.expectError(error.InvalidTarget, @import("selection.zig").compile(
        std.testing.allocator,
        &.{.{ .collection = .xml, .mode = .values, .selection = .all }},
        .{},
    ));
}

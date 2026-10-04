//! Source-level conformance against the signed, pinned stock release.
//! This is not an executable FTW or detection-compatibility test.
const std = @import("std");
const fixture = @import("crs-fixture");
const compiler = @import("compiler.zig");
const inventory = @import("inventory.zig");
const source = @import("source.zig");
const syntax = @import("syntax.zig");
const model = @import("model.zig");

test "CRS 4.30.0 stock source preserves every condition and exclusion" {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    try std.testing.expectEqualStrings("OWASP_CRS/4.30.0", plan.signature.?);
    try std.testing.expectEqual(@as(usize, 701), plan.conditions.len);
    try std.testing.expectEqual(@as(usize, 31), plan.markers.len);
    try std.testing.expectEqual(@as(usize, 55), plan.updates.len);
    var roots: usize = 0;
    var chains: usize = 0;
    var jumps: usize = 0;
    for (plan.conditions, 0..) |condition, index| {
        roots += @intFromBool(condition.root == index);
        chains += @intFromBool(condition.chain_next != null);
        jumps += @intFromBool(condition.skip_to != null);
    }
    try std.testing.expectEqual(@as(usize, 628), roots);
    try std.testing.expectEqual(@as(usize, 73), chains);
    try std.testing.expectEqual(@as(usize, 201), jumps);
    for (plan.updates) |update| try std.testing.expect(update.root != null);
    for (plan.defaults) |defaults| try std.testing.expect(defaults != null);
    try std.testing.expect(!model.Plan.executable);
}

test "CRS source inventory agrees with the independently reviewed release" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(scratch);
    const counts = try allocator.create(inventory.Inventory);
    defer allocator.destroy(counts);
    counts.* = .{};
    for (fixture.sources) |file| {
        var reader: source.Reader = .{ .source = file.bytes };
        while (try reader.next(scratch)) |line| try counts.add(try syntax.parse(line.bytes));
    }
    try std.testing.expectEqual(@as(usize, 19), counts.operators.size);
    try std.testing.expectEqual(@as(usize, 20), counts.transforms.size);
    try std.testing.expectEqual(@as(usize, 23), counts.actions.size);
    try std.testing.expectEqual(@as(usize, 693), counts.directives[0]);
    try std.testing.expectEqual(@as(usize, 8), counts.directives[1]);
    try std.testing.expectEqual(@as(usize, 320), counts.operators.count("rx"));
    try std.testing.expectEqual(@as(usize, 435), counts.transforms.count("none"));
}

test "every stock rule regex compiles within the published native limits" {
    const regex = @import("regex.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    var largest: usize = 0;
    var captures: usize = 0;
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        if (expression.kind != .rx) continue;
        var program = try regex.secLang(std.testing.allocator, expression.argument, false);
        defer program.deinit();
        count += 1;
        largest = @max(largest, program.instructions.len);
        captures = @max(captures, program.groups);
    }
    try std.testing.expectEqual(@as(usize, 320), count);
    try std.testing.expectEqual(@as(usize, 6653), largest);
    try std.testing.expectEqual(@as(usize, 3), captures);
}

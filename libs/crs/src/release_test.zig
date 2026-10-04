//! Source-level conformance against the signed, pinned stock release.
//! This is not an executable FTW or detection-compatibility test.
const std = @import("std");
const fixture = @import("crs-fixture");
const compiler = @import("compiler.zig");
const inventory = @import("inventory.zig");
const source = @import("source.zig");
const syntax = @import("syntax.zig");
const model = @import("model.zig");
const collections = @import("collections.zig");

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

test "stock collection selectors and key regexes fit the native profile" {
    const regex = @import("regex.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    const collection_capacity = @typeInfo(collections.Collection).@"enum".field_names.len;
    var seen: [collection_capacity]bool = @splat(false);
    var patterns: usize = 0;
    for (plan.conditions) |condition| {
        for (condition.targets) |target| {
            seen[@backingInt(target.collection)] = true;
            if (target.selection == .pattern) {
                var program = try regex.secLang(
                    std.testing.allocator,
                    target.selection.pattern,
                    true,
                );
                defer program.deinit();
                patterns += 1;
            }
        }
    }
    var collection_count: usize = 0;
    for (seen) |present| collection_count += @intFromBool(present);
    try std.testing.expectEqual(@as(usize, 33), collection_count);
    try std.testing.expect(patterns > 0);
    for (plan.updates) |update| try std.testing.expect(update.targets.len > 0);
}

test "every stock transform pipeline compiles and has bounded intermediate scratch" {
    const pipeline = @import("pipeline.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    for (plan.conditions) |condition| {
        var compiled = try pipeline.compile(std.testing.allocator, .{
            .inherited = condition.inherited_actions,
            .local = condition.actions,
        });
        defer compiled.deinit();
        // A future source profile cannot silently omit a transform or reserve
        // overflowing expansion. Full execution also checks per-field capacity.
        _ = try compiled.requiredScratch(64 * 1024);
    }
}

test "every stock phrase operator and its complete data file compile in the native profile" {
    const phrase = @import("phrases_source.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        if (expression.kind == .pm) {
            var program = try phrase.inlineWords(std.testing.allocator, expression.argument, .{});
            defer program.deinit();
        } else if (expression.kind == .pm_from_file) {
            const bytes = findData(expression.argument) orelse return error.MissingDataFixture;
            var program = try phrase.fileWords(std.testing.allocator, bytes, .{});
            defer program.deinit();
            for (program.words) |word| {
                var budget: @import("work.zig").Budget = .{ .remaining = 1_000_000 };
                try std.testing.expect(try program.search(word, &budget) != null);
            }
        }
    }
}

fn findData(name: []const u8) ?[]const u8 {
    for (fixture.data) |file| {
        if (std.mem.eql(u8, file.path["rules/".len..], name)) return file.bytes;
    }
    return null;
}

test "every stock address operator compiles without mapping IPv4 into IPv6" {
    const addresses = @import("address_set.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        if (expression.kind != .ip_match) continue;
        var program = try addresses.compile(std.testing.allocator, expression.argument, .{});
        defer program.deinit();
        var budget: @import("work.zig").Budget = .{ .remaining = 4096 };
        try std.testing.expect(try program.contains("127.0.0.1", &budget));
        try std.testing.expect(try program.contains("::1", &budget));
        try std.testing.expect(!try program.contains("::ffff:127.0.0.1", &budget));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

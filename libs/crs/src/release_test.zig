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

test "every stock runtime macro compiles into bounded typed parts" {
    const macros = @import("macros.zig");
    const primitives = @import("primitives.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    for (plan.conditions) |condition| {
        for (condition.actions) |action| {
            const value = action.value orelse continue;
            if (std.mem.indexOf(u8, value, "%{") == null) continue;
            var program = try macros.compile(std.testing.allocator, value, .{});
            defer program.deinit();
            count += 1;
        }
        const expression = condition.expression orelse continue;
        if (!primitives.supported(expression.kind) or
            std.mem.indexOf(u8, expression.argument, "%{") == null) continue;
        var program = try macros.compile(std.testing.allocator, expression.argument, .{});
        defer program.deinit();
        count += 1;
    }
    try std.testing.expect(count > 1000);
}

test "every stock setvar action prepares its target operand and typed operation" {
    const set_var = @import("set_var.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    for (plan.conditions) |condition| {
        for (condition.actions) |action| {
            if (action.kind != .set_var) continue;
            var program = try set_var.compile(std.testing.allocator, action.value.?);
            defer program.deinit();
            count += 1;
        }
    }
    try std.testing.expect(count > 600);
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

test "every stock target list prepares with owned exclusions and shared matcher bounds" {
    const selection = @import("selection.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    for (plan.conditions) |condition| {
        if (condition.targets.len == 0) continue;
        var program = try selection.compile(std.testing.allocator, condition.targets, .{});
        defer program.deinit();
        try std.testing.expect(program.targets.len > 0);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 693), count);
    for (plan.updates) |update| {
        var program = try selection.compile(std.testing.allocator, update.targets, .{});
        defer program.deinit();
    }
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
        try stockReplay(&compiled, "Aa\t/<script>\x00\xff");
    }
}

fn stockReplay(program: *const @import("pipeline.zig").Pipeline, input: []const u8) !void {
    const pipeline = @import("pipeline.zig");
    const replay = @import("pipeline_replay.zig");
    const allocator = std.testing.allocator;
    const capacity = try program.requiredScratch(input.len);
    const first = try allocator.alloc(u8, capacity);
    defer allocator.free(first);
    const second = try allocator.alloc(u8, capacity);
    defer allocator.free(second);
    var expected: std.ArrayList([]const u8) = .empty;
    defer expected.deinit(allocator);
    defer for (expected.items) |bytes| allocator.free(bytes);
    var budget: @import("work.zig").Budget = .{ .remaining = 16_000_000 };
    const frame: pipeline.Frame = .{
        .input = input,
        .scratch = .{ first, second },
        .budget = &budget,
    };
    var iterator = pipeline.Iterator.init(program, frame);
    while (try iterator.next()) |value| {
        const owned = try allocator.dupe(u8, value.bytes);
        errdefer allocator.free(owned);
        try expected.append(allocator, owned);
    }
    const cost = 16_000_000 - budget.remaining;
    // multiMatch replays a validated pass; a single final value is charged once.
    budget.remaining = if (program.multi_match) cost * 2 else cost;
    var repeated: replay.Replay = .{};
    try repeated.init(program, frame);
    for (expected.items) |bytes| {
        try std.testing.expectEqualStrings(bytes, (try repeated.next()).?.bytes);
    }
    try std.testing.expect(try repeated.next() == null);
    try std.testing.expectEqual(@as(u64, 0), budget.remaining);
    try std.testing.expectEqual(@as(u64, 0), repeated.reserved.remaining);
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

test "every stock condition prepares through the shared native operator interface" {
    const operators = @import("operators.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    const kinds = @typeInfo(model.Operator).@"enum".field_names.len;
    var counts: [kinds]usize = @splat(0);
    var total: usize = 0;
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        var files: [256][]const u8 = undefined;
        var program = try operators.compile(std.testing.allocator, .{
            .kind = expression.kind,
            .argument = expression.argument,
            .phrase_files = try phraseFiles(expression, &files),
        }, .{});
        defer program.deinit();
        counts[@backingInt(expression.kind)] += 1;
        total += 1;
    }
    try std.testing.expectEqual(@as(usize, 693), total);
    for (counts) |count| try std.testing.expect(count > 0);
}

fn phraseFiles(expression: model.Expression, output: [][]const u8) ![]const []const u8 {
    if (expression.kind != .pm_from_file) return &.{};
    var names = std.mem.tokenizeAny(u8, expression.argument, " \t\r\n");
    var used: usize = 0;
    while (names.next()) |name| {
        if (used == output.len) return error.TooManyDataFixtures;
        output[used] = findData(name) orelse return error.MissingDataFixture;
        used += 1;
    }
    return output[0..used];
}

test "all stock conditions compose selection transforms predicates and pre-chain writes" {
    const evaluator = @import("condition.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var topology = try @import("chains.zig").compile(std.testing.allocator, plan.conditions, .{});
    defer topology.deinit();
    try stockPhaseScans(&topology);
    for (plan.conditions) |*condition| {
        var files: [256][]const u8 = undefined;
        const data = if (condition.expression) |expression|
            try phraseFiles(expression, &files)
        else
            &.{};
        var program = try evaluator.compile(std.testing.allocator, condition, data, .{});
        defer program.deinit();
        try std.testing.expect(program.regexStates() <= 16384);
    }
    try std.testing.expectEqual(@as(usize, 701), plan.conditions.len);
    // Preparing the match portion does not validate post-match or phase execution.
    try std.testing.expect(!model.Plan.executable);
}

fn stockPhaseScans(topology: *const @import("chains.zig").Program) !void {
    const cursor = @import("phase_cursor.zig");
    var state = cursor.Cursor.init(topology);
    var budget: @import("work.zig").Budget = .{ .remaining = 100_000 };
    var seen: [4096]bool = @splat(false);
    var total: usize = 0;
    for (std.enums.values(model.Phase)) |phase| {
        try state.begin(phase);
        while (try state.next(&budget)) |root| {
            try std.testing.expect(!seen[root]);
            try std.testing.expectEqual(root, topology.rows[root].root);
            try std.testing.expectEqual(phase, topology.rows[root].phase);
            seen[root] = true;
            total += 1;
            try state.complete(false);
        }
    }
    try std.testing.expectEqual(@as(usize, 628), total);
}

test "every stock transaction control prepares a typed bounded operation" {
    const controls = @import("controls.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var count: usize = 0;
    for (plan.conditions) |condition| {
        for (condition.actions) |action| {
            if (action.kind != .control) continue;
            var program = try controls.compile(std.testing.allocator, action.value.?);
            defer program.deinit();
            count += 1;
        }
    }
    try std.testing.expect(count > 10);
}

test "every stock full-match program prepares controls metadata and disruption" {
    const actions = @import("post_actions.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    for (plan.conditions) |*condition| {
        var program = try actions.compile(std.testing.allocator, condition);
        defer program.deinit();
        try std.testing.expectEqual(condition.id, program.id);
        try std.testing.expectEqual(condition.phase, program.phase);
    }
}

test "stock rule graph composes every condition action data file and static update" {
    const rules = @import("rule_program.zig");
    const data = @import("rule_data.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var files: [fixture.data.len]data.File = undefined;
    for (fixture.data, &files) |file, *prepared| prepared.* = .{
        .path = file.path,
        .bytes = file.bytes,
    };
    var program = try rules.compile(std.testing.allocator, &plan, &files, .{});
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, 701), program.conditions.len);
    try std.testing.expectEqual(@as(usize, 701), program.actions.len);
    try std.testing.expectEqualStrings("OWASP_CRS/4.30.0", program.signature);
    try std.testing.expectEqual(@as(usize, 6653), program.regex_states);
    // In particular the common-cookie exceptions are part of published selectors.
    for (plan.updates) |update| {
        const selected = program.conditions[update.root.?].targets.?;
        try std.testing.expect(selected.exclusions.len > 0);
    }
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

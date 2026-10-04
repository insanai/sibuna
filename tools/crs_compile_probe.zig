//! Compile-only portability probe; this object is not linked into Sibuna.
//! The allocator remains caller-owned across compilation and zero-allocation matching.
const std = @import("std");
const crs = @import("crs");

pub export fn crsCompileProbe(allocator: *const std.mem.Allocator) u8 {
    const activation: crs.config.Activation = .{};
    activation.validate(.request_metadata, .source_only) catch return 7;
    var compiler = crs.compiler.Compiler.init(allocator.*, .{});
    defer compiler.deinit();
    compiler.addSource("probe.conf", "SecRule ARGS \"@rx (x+)\" \"id:1,phase:1\"") catch return 1;
    var plan = compiler.finish() catch return 2;
    defer plan.deinit();
    var program = crs.regex.compile(
        allocator.*,
        plan.conditions[0].expression.?.argument,
        .{},
    ) catch return 3;
    defer program.deinit();
    var workspace = crs.regex.Workspace.init(allocator.*, &program) catch return 4;
    defer workspace.deinit();
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    var pipeline = crs.pipeline.compile(allocator.*, .{
        .inherited = plan.conditions[0].inherited_actions,
        .local = plan.conditions[0].actions,
    }) catch return 10;
    defer pipeline.deinit();
    var transformed: [4]u8 = undefined;
    var alternate: [4]u8 = undefined;
    var iterator = crs.pipeline.Iterator.init(&pipeline, .{
        .input = "xx",
        .scratch = .{ &transformed, &alternate },
        .budget = &budget,
    });
    _ = iterator.next() catch return 11;
    _ = crs.transforms.apply(.lowercase, .{
        .input = "XX",
        .output = &transformed,
        .budget = &budget,
    }) catch return 8;
    var prefixes: [2]usize = undefined;
    const predicate: crs.primitives.Predicate = .{ .kind = .contains, .argument = "x" };
    _ = predicate.evaluate("xx", .{ .prefixes = &prefixes, .budget = &budget }) catch return 9;
    const range = crs.byte_range.compile("32-126") catch return 12;
    _ = range.inspect("xx", &budget) catch return 13;
    var phrase = crs.phrases_source.inlineWords(allocator.*, "x y", .{}) catch return 14;
    defer phrase.deinit();
    _ = phrase.search("xx", &budget) catch return 15;
    var addresses = crs.address_set.compile(allocator.*, "127.0.0.1,::1", .{}) catch return 16;
    defer addresses.deinit();
    _ = addresses.contains("::1", &budget) catch return 17;
    if (!detectorProbe(&budget)) return 18;
    if (!macroProbe(allocator.*, &budget)) return 24;
    if (!operatorProbe(allocator.*, &budget)) return 25;
    if (!selectionProbe(allocator.*, &budget)) return 26;
    const result = crs.regex.match.search(
        &program,
        "xx",
        &workspace.scratch,
        &budget,
    ) catch return 5;
    return if (result != null) 0 else 6;
}

fn detectorProbe(budget: *crs.work.Budget) bool {
    _ = crs.injection_dictionary.lookup("SELECT", budget) catch return false;
    var prefixes: [2]usize = undefined;
    var lexical: crs.sql_tokens.Context = .{
        .input = "SELECT 1",
        .prefixes = &prefixes,
        .budget = budget,
    };
    var token: crs.sql_tokens.Token = .{};
    _ = crs.sql_tokens.next(&lexical, &token) catch return false;
    var fingerprint: crs.sql_folding.Result = .{};
    crs.sql_folding.fingerprint(&lexical, &fingerprint) catch return false;
    _ = crs.sql_detector.detect(&lexical, &fingerprint) catch return false;
    var html = crs.html_tokens.Context.init("<a href='url'>", budget, .data);
    _ = crs.html_tokens.next(&html) catch return false;
    var xss: crs.xss_detector.Context = .{ .input = "<script>", .budget = budget };
    _ = crs.xss_detector.detect(&xss) catch return false;
    return true;
}

fn macroProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var program = crs.macros.compile(allocator, "%{TX.value}", .{}) catch return false;
    defer program.deinit();
    const view: crs.variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var pieces: [1][]const u8 = undefined;
    var output: [16]u8 = undefined;
    _ = program.expand(.{
        .view = &view,
        .pieces = &pieces,
        .output = &output,
        .budget = budget,
    }) catch return false;
    return true;
}

fn operatorProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var program = crs.operators.compile(allocator, .{
        .kind = .contains,
        .argument = "x",
    }, .{}) catch return false;
    defer program.deinit();
    const result = program.evaluate(.{ .input = "xx", .budget = budget }) catch return false;
    return result.matched and result.captured("xx", 0) == null;
}

fn selectionProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    const targets = crs.selectors.parse(allocator, "&ARGS", 1) catch return false;
    defer allocator.free(targets);
    var program = crs.selection.compile(allocator, targets, .{}) catch return false;
    defer program.deinit();
    const view: crs.variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var entries: [1]crs.variables.Entry = undefined;
    var count: [20]u8 = undefined;
    const result = program.select(0, .{
        .view = &view,
        .output = &entries,
        .count = &count,
        .budget = budget,
    }) catch return false;
    return result.counted and std.mem.eql(u8, result.entries[0].value, "0");
}

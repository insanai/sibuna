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
    const result = crs.regex.match.search(
        &program,
        "xx",
        &workspace.scratch,
        &budget,
    ) catch return 5;
    return if (result != null) 0 else 6;
}

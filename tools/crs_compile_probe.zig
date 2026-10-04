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
    const result = crs.regex.match.search(
        &program,
        "xx",
        &workspace.scratch,
        &budget,
    ) catch return 5;
    return if (result != null) 0 else 6;
}

const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    crs: *std.Build.Module,
    net: *std.Build.Module,
) *std.Build.Module {
    const module = b.addModule("sibuna-crs-update", .{
        .root_source_file = b.path("libs/crs-update/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "net", .module = net },
        },
    });
    const tests = b.addTest(.{ .root_module = module });
    const step = b.step("crs-update-test", "Test bounded authenticated update preparation");
    step.dependOn(&b.addRunArtifact(tests).step);
    addCommandTest(b, step, target, crs, module);
    b.top_level_steps.get("test").?.step.dependOn(step);
    return module;
}

fn addCommandTest(
    b: *std.Build,
    step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    crs: *std.Build.Module,
    update: *std.Build.Module,
) void {
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/crs_command.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "crs-update", .module = update },
        },
    }) });
    step.dependOn(&b.addRunArtifact(tests).step);
}

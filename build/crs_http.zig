const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    crs: *std.Build.Module,
    net: *std.Build.Module,
) void {
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/crs_entity.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "net", .module = net },
            .{ .name = "text", .module = b.modules.get("sibuna-text").? },
        },
    }) });
    const step = b.step("crs-http-test", "Test CRS composition with HTTP representation holdback");
    step.dependOn(&b.addRunArtifact(tests).step);
    b.top_level_steps.get("test").?.step.dependOn(step);
}

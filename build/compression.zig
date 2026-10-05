const std = @import("std");

pub fn add(b: *std.Build) *std.Build.Module {
    const module = b.addModule("sibuna-compression", .{
        .root_source_file = b.path("libs/compression/src/root.zig"),
    });
    const text = b.modules.get("sibuna-text").?;
    module.addImport("text", text);
    const host = b.createModule(.{
        .root_source_file = b.path("libs/compression/src/root.zig"),
        .target = b.graph.host,
        .imports = &.{.{ .name = "text", .module = text }},
    });
    const tests = b.addTest(.{ .root_module = host });
    const step = b.step("compression-test", "Test bounded native gzip and zlib expansion");
    step.dependOn(&b.addRunArtifact(tests).step);
    b.top_level_steps.get("test").?.step.dependOn(step);
    return module;
}

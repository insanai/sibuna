const std = @import("std");

pub const Modules = struct {
    protocol: *std.Build.Module,
    console: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
    const protocol = b.addModule("console-protocol", .{
        .root_source_file = b.path("libs/console-protocol/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const console = b.addModule("sibuna-console", .{
        .root_source_file = b.path("libs/console/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "console_protocol", .module = protocol }},
    });
    const step = b.step("console-test", "Test console contracts and bounded ownership");
    for ([_]*std.Build.Module{ protocol, console }) |module| {
        const tests = b.addTest(.{ .root_module = module });
        step.dependOn(&b.addRunArtifact(tests).step);
    }
    // Compile the same protocol for the browser without importing native service code.
    const wasm = b.addObject(.{
        .name = "console-protocol-wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("libs/console-protocol/src/root.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = .ReleaseSmall,
        }),
    });
    step.dependOn(&wasm.step);
    return .{ .protocol = protocol, .console = console };
}

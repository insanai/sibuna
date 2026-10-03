const std = @import("std");

// Standalone package build for `zaxon_cli_ui`. Inside the zaxonlite
// monorepo the same sources are wired directly by zaxonlite/build.zig;
// this file makes the directory a self-contained Zig package so it can
// live as its own repository (insanai/zaxon-cli-ui) and be fetched by
// downstream consumers.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The libvaxis terminal layer is the module's only dependency.
    const vaxis = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    }).module("vaxis");

    const ui = b.addModule("zaxon_cli_ui", .{
        .root_source_file = b.path("ui.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vaxis", .module = vaxis },
        },
    });

    // Pure state machines: key sequences drive the editor, text drives the
    // tokenizer and history, renderers are checked against golden strings.
    // No TTY is opened.
    const unit_tests = b.addTest(.{ .root_module = ui });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run the terminal UI unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

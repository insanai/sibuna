//! Pure evidence contracts inherit each importing root's target, including Wasm.
//! One module identity keeps engine, storage and console values interchangeable.
const std = @import("std");

pub fn add(b: *std.Build) *std.Build.Module {
    if (b.modules.get("security-evidence")) |module| return module;
    const module = b.addModule("security-evidence", .{
        .root_source_file = b.path("libs/core/src/security_evidence.zig"),
    });
    const host = b.createModule(.{
        .root_source_file = b.path("libs/core/src/security_evidence.zig"),
        .target = b.graph.host,
    });
    const check = b.addRunArtifact(b.addTest(.{ .root_module = host }));
    b.step("evidence-test", "Test pure native and browser evidence contracts")
        .dependOn(&check.step);
    b.top_level_steps.get("test").?.step.dependOn(&check.step);
    return module;
}

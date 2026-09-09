//! The country lookup library: a standard-library-only module shared by the console, its
//! tools and tests, plus the optional embedded snapshot chosen with -Dgeoip-data.
const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.addModule("sibuna-geoip", .{
        .root_source_file = b.path("libs/geoip/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
}

/// `geoip-snapshot` validates provider files or a snapshot and can write one; the
/// executable is shared with `console-geoip-check`.
pub fn addTools(b: *std.Build, geoip: *std.Build.Module) void {
    const executable = b.addExecutable(.{
        .name = "geoip-snapshot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/geoip_snapshot.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "geoip", .module = geoip }},
        }),
    });
    const names = .{ "geoip-snapshot", "console-geoip-check" };
    const descriptions = .{
        "Validate country data files or a snapshot and optionally write a snapshot",
        "Validate downloaded country data or a snapshot without opening storage",
    };
    inline for (names, descriptions) |name, description| {
        const run = b.addRunArtifact(executable);
        if (b.args) |args| run.addArgs(args);
        b.step(name, description).dependOn(&run.step);
    }
}

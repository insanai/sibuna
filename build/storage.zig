const std = @import("std");

/// The pinned Zaxonlite dependency with its C/TLS/import configuration. Release 0.6.2
/// carries the sealed-journal iterator correction upstream, so no generated-source patch
/// is applied any more.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    cluster: bool,
) *std.Build.Module {
    const dependency = b.dependency("zaxonlite", .{
        .target = target,
        .optimize = optimize,
        .tls = cluster,
    });
    return dependency.module("zaxonlite");
}

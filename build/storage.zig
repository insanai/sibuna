const std = @import("std");

/// Preserve the pinned dependency and all of its C/TLS/import configuration. Only the
/// generated Zig source tree receives the reviewed sealed-journal iterator correction.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cluster: bool,
) *std.Build.Module {
    const dependency = b.dependency("zaxonlite", .{
        .target = target,
        .optimize = optimize,
        .tls = cluster,
    });
    const module = dependency.module("zaxonlite");
    const patch = b.addSystemCommand(&.{"python3"});
    patch.addFileArg(b.path("tools/patch_zaxonlite.py"));
    patch.addFileArg(dependency.path("src/journal.zig"));
    patch.addFileArg(b.path("build/patches/zaxonlite-0.6.1-journal.patch"));
    const journal = patch.addOutputFileArg("journal.zig");
    const sources = b.addWriteFiles();
    const directory = sources.addCopyDirectory(dependency.path("src"), "src", .{
        .exclude_extensions = &.{"journal.zig"},
    });
    _ = sources.addCopyFile(journal, "src/journal.zig");
    module.root_source_file = directory.path(b, "root.zig");
    return module;
}

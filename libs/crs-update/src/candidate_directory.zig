//! An exclusive candidate directory is not an active revision or store commit.
//! The operator owns its parent; existing directories are never reused or replaced.
const std = @import("std");
const crs = @import("crs");
const prepared = @import("prepared.zig");
const staging = @import("staging.zig");
const Io = std.Io;
pub const Error = staging.Error || Io.Dir.CreateDirError || Io.Dir.OpenError ||
    error{InvalidCandidateName};
pub const Config = struct { io: Io, parent: Io.Dir, name: []const u8, now: u64 };

pub fn write(
    config: Config,
    manifest: crs.artifact_manifest.Manifest,
    source: *const prepared.Prepared,
) Error!void {
    try validateName(config.name);
    try config.parent.createDir(config.io, config.name, if (@import("builtin").os.tag == .windows)
        .default_dir
    else
        @fromBackingInt(0o700));
    const directory = try config.parent.openDir(config.io, config.name, .{
        .follow_symlinks = false,
    });
    defer directory.close(config.io);
    // On failure, keep only this private partial candidate for operator recovery.
    // No selector references it, and deleting unknown files could destroy edits.
    const destination: staging.Config = .{
        .io = config.io,
        .directory = directory,
        .now = config.now,
    };
    try staging.write(destination, manifest, source);
}

fn validateName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > 255 or std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, "..")) return error.InvalidCandidateName;
    for (name) |byte| if (byte == 0 or byte == '/' or byte == '\\' or byte == ':')
        return error.InvalidCandidateName;
}

test "candidate paths cannot escape the operator-owned parent or replace a directory" {
    const t = std.testing;
    const invalid = [_][]const u8{ "", ".", "..", "../rules", "a/b", "a\\b", "C:rules", "a\x00b" };
    for (invalid) |name| try t.expectError(error.InvalidCandidateName, validateName(name));
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    const parent = temporary.dir;
    const io = t.io;
    try parent.createDir(io, "existing", .default_dir);
    // No signed source or metadata may be accessed when the destination exists.
    const source: prepared.Prepared = undefined;
    const manifest = std.mem.zeroes(crs.artifact_manifest.Manifest);
    try t.expectError(error.PathAlreadyExists, write(.{
        .io = io,
        .parent = parent,
        .name = "existing",
        .now = 1,
    }, manifest, &source));
}

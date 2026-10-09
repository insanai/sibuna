//! File preparation for CLI checks. This creates a verified restart candidate;
//! management selection, expected revisions and runtime updates are separate.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const Io = std.Io;
pub const ReadError = updater.files.Error || Io.Dir.OpenError;

pub fn readConfiguration(
    allocator: std.mem.Allocator,
    io: Io,
    path: ?[]const u8,
) ReadError!updater.files.Bytes {
    const selected = path orelse {
        const empty = try allocator.alloc(u8, 0);
        return .{ .buffer = empty, .value = empty };
    };
    return readFile(allocator, io, selected, 64 * 1024);
}

pub fn readFile(
    allocator: std.mem.Allocator,
    io: Io,
    selected: []const u8,
    maximum: usize,
) ReadError!updater.files.Bytes {
    const parent_path = std.fs.path.dirname(selected) orelse ".";
    const parent = try Io.Dir.cwd().openDir(io, parent_path, .{ .follow_symlinks = false });
    defer parent.close(io);
    const reader: updater.files.Reader = .{
        .allocator = allocator,
        .io = io,
        .directory = parent,
        .name_capacity = 255,
    };
    return reader.read(std.fs.path.basename(selected), .{ .maximum = maximum });
}

pub fn write(io: Io, path: []const u8, source: *const updater.Prepared) !void {
    if (path.len == 0 or std.mem.indexOfScalar(u8, "/\\", path[path.len - 1]) != null)
        return error.InvalidCandidateName;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const name = std.fs.path.basename(path);
    const parent = try Io.Dir.cwd().openDir(io, parent_path, .{ .follow_symlinks = false });
    defer parent.close(io);
    const seconds = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    if (seconds < 0 or seconds > std.math.maxInt(u64)) return error.InvalidClock;
    const package = source.package orelse return error.PreparedPackageTransferred;
    const manifest = try crs.artifact_manifest.Manifest.create(package, .{
        .revision = 1,
        .activation = .{ .mode = .off },
        .observation = .request_response,
    }, .{
        .previous_revision = 0,
        .signature_bytes = source.signature.value.len,
        .configuration_bytes = source.configuration.value.len,
    });
    try updater.candidate_directory.write(.{
        .io = io,
        .parent = parent,
        .name = name,
        .now = @intCast(seconds),
    }, manifest, source);
}

test "operator configuration accepts exact bounds and refuses directories and oversized files" {
    const t = std.testing;
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    const payload: [64 * 1024 + 1]u8 = @splat('#');
    try temporary.dir.writeFile(t.io, .{ .sub_path = "operator.conf", .data = payload[0..65536] });
    var root: [1024]u8 = undefined;
    // tmpDir exposes its name; no descriptor-to-path API is needed (OpenBSD
    // cannot resolve a directory descriptor through Zig's realPath backend).
    const directory_root = try std.fmt.bufPrint(
        &root,
        ".zig-cache/tmp/{s}",
        .{temporary.sub_path},
    );
    var bytes: [1200]u8 = undefined;
    const path = try std.fmt.bufPrint(&bytes, "{s}/operator.conf", .{directory_root});
    const source = try readConfiguration(t.allocator, t.io, path);
    defer t.allocator.free(source.buffer);
    try t.expectEqual(@as(usize, 65536), source.value.len);
    try temporary.dir.writeFile(t.io, .{ .sub_path = "operator.conf", .data = &payload });
    try t.expectError(error.ArtifactFileLimit, readConfiguration(t.failing_allocator, t.io, path));
    try temporary.dir.createDir(t.io, "directory", .default_dir);
    const directory = try std.fmt.bufPrint(&bytes, "{s}/directory", .{directory_root});
    const refused = readConfiguration(t.failing_allocator, t.io, directory);
    try t.expectError(error.ArtifactFileKind, refused);
}

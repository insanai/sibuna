const std = @import("std");
const files = @import("artifact_files.zig");
const artifact = @import("artifact.zig");
const t = std.testing;

test "artifact reads reject size and kind before allocating their bounded buffer" {
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(t.io, .{ .sub_path = "data", .data = "abc" });
    try temporary.dir.createDir(t.io, "directory", .default_dir);
    const refused: files.Reader = .{
        .allocator = t.failing_allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    try t.expectError(error.ArtifactFileLength, refused.read("data", .{ .exact = 2 }));
    try t.expectError(error.ArtifactFileLimit, refused.read("data", .{ .maximum = 2 }));
    try t.expectError(error.ArtifactFileKind, refused.read("directory", .{ .maximum = 512 }));
    try t.expectError(error.ArtifactFileLimit, refused.read("data", .{ .exact = 8388609 }));
    try t.expectError(error.ArtifactFileName, refused.read("../data", .{ .exact = 3 }));
    var reader = refused;
    reader.allocator = t.allocator;
    const bytes = try reader.read("data", .{ .exact = 3 });
    defer t.allocator.free(bytes.buffer);
    try t.expectEqualStrings("abc", bytes.value);
    try t.expectEqual(@as(usize, 4), bytes.buffer.len);
    const bounded = try reader.read("data", .{ .maximum = 3 });
    defer t.allocator.free(bounded.buffer);
    try t.expectEqualStrings("abc", bounded.value);
    try temporary.dir.writeFile(t.io, .{ .sub_path = "empty", .data = "" });
    const empty = try reader.read("empty", .{ .exact = 0 });
    defer t.allocator.free(empty.buffer);
    try t.expectEqual(@as(usize, 0), empty.value.len);
}

test "artifact reader refuses symbolic links instead of loading another directory's bytes" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(t.io, .{ .sub_path = "real", .data = "abc" });
    try temporary.dir.symLink(t.io, "real", "linked", .{});
    const reader: files.Reader = .{
        .allocator = t.failing_allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    try t.expectError(error.ArtifactFileKind, reader.read("linked", .{ .exact = 3 }));
}

test "restart preparation refuses invalid manifest framing before looking for artifact files" {
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(t.io, .{ .sub_path = "manifest.bin", .data = "unverified" });
    try t.expectError(error.InvalidManifest, artifact.load(.{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
        .now = 1791049738,
        .observation = .request_response,
    }));
}

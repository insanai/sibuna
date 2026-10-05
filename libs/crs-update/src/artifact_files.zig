//! Fixed artifact names and bounded regular-file reads in an operator-owned directory.
const std = @import("std");
const ownership = @import("prepared.zig");
const Io = std.Io;
pub const Error = Io.Dir.StatFileError || Io.File.OpenError || Io.File.StatError ||
    Io.File.ReadPositionalError || std.mem.Allocator.Error || error{
    ArtifactFileKind,
    ArtifactFileLength,
    ArtifactFileLimit,
    ArtifactFileName,
};
pub const Bytes = ownership.Bytes;
pub const Limit = union(enum) { exact: usize, maximum: usize };
const maximum_file = 8 * 1024 * 1024;
pub const Reader = struct {
    allocator: std.mem.Allocator,
    io: Io,
    directory: Io.Dir,
    name_capacity: usize = 64,

    pub fn read(self: Reader, name: []const u8, limit: Limit) Error!ownership.Bytes {
        const maximum = switch (limit) {
            .exact, .maximum => |value| value,
        };
        if (maximum > maximum_file) return error.ArtifactFileLimit;
        const file = try self.open(name);
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        switch (limit) {
            .exact => if (size != maximum) return error.ArtifactFileLength,
            .maximum => if (size > maximum) return error.ArtifactFileLimit,
        }
        const expected: usize = @intCast(size);
        // The extra byte detects growth after stat, without an unbounded EOF read.
        const buffer = try self.allocator.alloc(u8, expected + 1);
        errdefer self.allocator.free(buffer);
        const received = try file.readPositionalAll(self.io, buffer, 0);
        if (received != expected) return error.ArtifactFileLength;
        return .{ .buffer = buffer, .value = buffer[0..expected] };
    }

    fn open(self: Reader, name: []const u8) Error!Io.File {
        std.debug.assert(self.name_capacity > 0 and self.name_capacity <= 255);
        if (name.len == 0 or name.len > self.name_capacity or std.mem.eql(u8, name, ".") or
            std.mem.eql(u8, name, "..") or std.mem.indexOfAny(u8, name, "/\\:\x00") != null)
            return error.ArtifactFileName;
        const before = try self.directory.statFile(self.io, name, .{ .follow_symlinks = false });
        if (before.kind != .file) return error.ArtifactFileKind;
        const file = try self.directory.openFile(self.io, name, .{
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        errdefer file.close(self.io);
        if ((try file.stat(self.io)).kind != .file) return error.ArtifactFileKind;
        return file;
    }
};

test {
    _ = @import("artifact_files_test.zig");
}

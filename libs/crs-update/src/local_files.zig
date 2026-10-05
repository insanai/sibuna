//! Shared local filesystem barriers and record ownership. The store must live on
//! a local filesystem with atomic replacement and working advisory file locks.
const std = @import("std");
const Io = std.Io;
const records = @import("local_records.zig");
const files = @import("artifact_files.zig");
pub const Error = files.Error || Io.Dir.CreateFileAtomicError || Io.File.Writer.Error ||
    Io.File.SyncError || Io.File.Atomic.ReplaceError || Io.File.OpenError ||
    std.json.ParseError(std.json.Scanner) || records.Error || error{WriteFailed};

pub fn read(
    comptime T: type,
    allocator: std.mem.Allocator,
    io: Io,
    directory: Io.Dir,
    name: []const u8,
) Error!T {
    const reader: files.Reader = .{ .allocator = allocator, .io = io, .directory = directory };
    const bytes = try reader.read(name, .{ .maximum = records.capacity });
    defer allocator.free(bytes.buffer);
    var memory: [32 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try std.json.parseFromSlice(T, fixed.allocator(), bytes.value, .{});
    defer parsed.deinit();
    try parsed.value.validate();
    return parsed.value;
}

pub fn write(io: Io, directory: Io.Dir, name: []const u8, value: anytype) Error!void {
    try value.validate();
    var bytes: [records.capacity]u8 = undefined;
    var writer: Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(value, .{}, &writer);
    var atomic = try directory.createFileAtomic(io, name, .{
        .replace = true,
        .permissions = if (@import("builtin").os.tag == .windows)
            .default_file
        else
            @fromBackingInt(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, writer.buffered());
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncName(io, directory, name);
}

/// POSIX flushes the containing directory after rename. NTFS commits namespace
/// changes through its volume log when the resulting file is flushed; opening a
/// writable handle after replacement supplies that barrier. Unsupported mounts
/// return an error, so an uncertain selector installation needs a status query.
pub fn syncName(io: Io, directory: Io.Dir, name: []const u8) Error!void {
    if (@import("builtin").os.tag == .windows) {
        const file = try directory.openFile(io, name, .{
            .mode = .read_write,
            .follow_symlinks = false,
            .allow_directory = false,
        });
        defer file.close(io);
        return file.sync(io);
    }
    const file: Io.File = .{ .handle = directory.handle, .flags = .{ .nonblocking = false } };
    return file.sync(io);
}

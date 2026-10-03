//! Configuration boundary shared by the CLI and embedding hosts.
//!
//! Secrets are accepted only through provider paths, never as literal command
//! line values. This module owns file parsing and validation so transport code
//! receives already validated bytes and never performs filesystem I/O.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const minimum_secret_bytes = 32;
pub const maximum_secret_file_bytes = 4096;
pub const maximum_config_file_bytes = 1024 * 1024;

pub const File = struct {
    data: ?[]const u8 = null,
    connect: ?[]const u8 = null,
    node: ?u32 = null,
    role: ?[]const u8 = null,
    listen: ?[]const u8 = null,
    peers: []const []const u8 = &.{},
    cluster_id: ?[]const u8 = null,
    auth_file: ?[]const u8 = null,
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    tls_ca: ?[]const u8 = null,
    enrollment_ca_key: ?[]const u8 = null,
    revocation_file: ?[]const u8 = null,
    /// Administrator names allowed to run privileged membership
    /// operations; matched against `zaxon-admin-<name>` certificates.
    admins: []const []const u8 = &.{},
    sync: ?[]const u8 = null,
};

pub const Loaded = struct {
    parsed: std.json.Parsed(File),

    pub fn deinit(self: *Loaded) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn value(self: *const Loaded) *const File {
        return &self.parsed.value;
    }
};

pub fn loadFile(
    gpa: std.mem.Allocator,
    io: Io,
    path: []const u8,
) !Loaded {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(maximum_config_file_bytes),
    );
    defer gpa.free(bytes);
    return .{ .parsed = try std.json.parseFromSlice(File, gpa, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) };
}

pub const Secret = struct {
    allocation: []u8,
    bytes: []const u8,

    pub fn deinit(self: *Secret, gpa: std.mem.Allocator) void {
        @memset(self.allocation, 0);
        gpa.free(self.allocation);
        self.* = undefined;
    }
};

/// Loads a PSK provider file. One conventional trailing line ending is not
/// part of the key; all other bytes, including spaces, are significant.
pub fn loadSecret(
    gpa: std.mem.Allocator,
    io: Io,
    path: []const u8,
) !Secret {
    try validatePrivateFile(io, path);
    const allocation = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(maximum_secret_file_bytes),
    );
    errdefer {
        @memset(allocation, 0);
        gpa.free(allocation);
    }
    var length = allocation.len;
    if (length > 0 and allocation[length - 1] == '\n') length -= 1;
    if (length > 0 and allocation[length - 1] == '\r') length -= 1;
    if (length < minimum_secret_bytes) return error.SecretTooShort;
    return .{ .allocation = allocation, .bytes = allocation[0..length] };
}

/// Private transport material must be a regular file reached without
/// following a symlink. POSIX hosts also require owner-only mode bits.
/// Windows has no equivalent mode-bit boundary; its ACL remains an operator
/// responsibility and is inherited when zaxonlite creates local files.
pub fn validatePrivateFile(io: Io, path: []const u8) !void {
    const stat = try Io.Dir.cwd().statFile(io, path, .{
        .follow_symlinks = false,
    });
    if (stat.kind != .file) return error.UnsafePrivateFile;
    if (builtin.os.tag != .windows and
        @backingInt(stat.permissions) & 0o077 != 0)
    {
        return error.UnsafePrivateFile;
    }
}

test "secret provider removes only its final line ending" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const value = "0123456789abcdef0123456789abcdef space\r\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "secret", .data = value });
    try tmp.dir.setFilePermissions(
        io,
        "secret",
        @fromBackingInt(@intCast(0o600)),
        .{},
    );
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try tmp.dir.realPath(io, &path_buffer);
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/secret",
        .{path_buffer[0..path_length]},
    );
    defer std.testing.allocator.free(path);
    var secret = try loadSecret(std.testing.allocator, io, path);
    defer secret.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef space",
        secret.bytes,
    );
}

test "private provider refuses broad permissions and symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "secret", .data = &@as([32]u8, @splat(120)) });
    try tmp.dir.setFilePermissions(
        io,
        "secret",
        @fromBackingInt(@intCast(0o644)),
        .{},
    );
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try tmp.dir.realPath(io, &path_buffer);
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/secret",
        .{path_buffer[0..path_length]},
    );
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.UnsafePrivateFile, validatePrivateFile(io, path));
}

test "configuration file owns parsed values" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{
        .sub_path = "config.json",
        .data =
        \\{"data":"node","node":2,"peers":["1@a:1","3@c:3"]}
        ,
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try tmp.dir.realPath(io, &path_buffer);
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/config.json",
        .{path_buffer[0..path_length]},
    );
    defer std.testing.allocator.free(path);
    var loaded = try loadFile(std.testing.allocator, io, path);
    defer loaded.deinit();
    try std.testing.expectEqualStrings("node", loaded.value().data.?);
    try std.testing.expectEqual(@as(u32, 2), loaded.value().node.?);
    try std.testing.expectEqual(@as(usize, 2), loaded.value().peers.len);
}

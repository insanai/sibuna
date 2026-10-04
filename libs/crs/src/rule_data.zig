//! Off-path resolution within the verified artifact, never the host filesystem.
const std = @import("std");
const model = @import("model.zig");
pub const File = struct { path: []const u8, bytes: []const u8 };
pub const Error = error{ InvalidDataPath, DuplicateData, DataLimit, MissingData };

pub fn validate(files: []const File, byte_limit: usize) Error!void {
    if (files.len > 256) return error.DataLimit;
    var total: usize = 0;
    for (files, 0..) |file, index| {
        try validatePath(file.path);
        if (file.bytes.len > byte_limit - total) return error.DataLimit;
        total += file.bytes.len;
        for (files[0..index]) |previous| {
            if (std.mem.eql(u8, file.path, previous.path)) return error.DuplicateData;
        }
    }
}

/// References are relative to their source file. Resolve only exact, canonical
/// artifact paths: a missing table is an error, not a match against an empty set.
pub fn resolve(
    source: *const model.Condition,
    files: []const File,
    output: [][]const u8,
) Error![]const []const u8 {
    const expression = source.expression orelse return &.{};
    if (expression.kind != .pm_from_file) return &.{};
    try validatePath(source.site.path);
    const slash = std.mem.lastIndexOfScalar(u8, source.site.path, '/');
    const parent = source.site.path[0..if (slash) |index| index + 1 else 0];
    var references = std.mem.tokenizeAny(u8, expression.argument, " \t\r\n");
    var used: usize = 0;
    var resolved: [4096]u8 = undefined;
    while (references.next()) |name| {
        try validatePath(name);
        if (used == output.len) return error.DataLimit;
        if (parent.len > resolved.len or name.len > resolved.len - parent.len)
            return error.InvalidDataPath;
        @memcpy(resolved[0..parent.len], parent);
        @memcpy(resolved[parent.len..][0..name.len], name);
        const wanted = resolved[0 .. parent.len + name.len];
        var found: ?[]const u8 = null;
        for (files) |file| {
            if (std.mem.eql(u8, wanted, file.path)) {
                found = file.bytes;
                break;
            }
        }
        output[used] = found orelse return error.MissingData;
        used += 1;
    }
    if (used == 0) return error.MissingData;
    return output[0..used];
}

pub fn validatePath(value: []const u8) Error!void {
    if (value.len == 0 or value.len > 4096 or value[0] == '/' or
        std.mem.indexOfAny(u8, value, "\\:\x00\r\n") != null) return error.InvalidDataPath;
    var segments = std.mem.splitScalar(u8, value, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or
            std.mem.eql(u8, segment, "..")) return error.InvalidDataPath;
    }
}

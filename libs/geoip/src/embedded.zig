//! A build may embed one validated snapshot. Empty bytes mean no snapshot was embedded.
const std = @import("std");
const database = @import("database.zig");
const snapshot = @import("snapshot.zig");

pub fn load(allocator: std.mem.Allocator, bytes: []const u8) !?database.Database {
    if (bytes.len == 0) return null;
    return try snapshot.decode(allocator, bytes);
}

test "empty embedded bytes mean no generation" {
    try std.testing.expect((try load(std.testing.allocator, "")) == null);
    try std.testing.expectError(error.InvalidSnapshot, load(std.testing.allocator, "junk"));
}

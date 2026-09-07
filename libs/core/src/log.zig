//! Sibuna Core Logging
//!
//! Structured, zero-allocation logging utilities writing formatted
//! messages to stderr without dynamic heap allocations.

const std = @import("std");

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn prefix(self: Level) []const u8 {
        return switch (self) {
            .debug => "[DEBUG]",
            .info => "[INFO ]",
            .warn => "[WARN ]",
            .err => "[ERROR]",
        };
    }
};

pub fn log(comptime level: Level, comptime format: []const u8, args: anytype) void {
    const stderr = std.io.getStdErr().writer();
    stderr.print("{s} " ++ format ++ "\n", .{level.prefix()} ++ args) catch {};
}

pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, format, args);
}

pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, format, args);
}

pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, format, args);
}

test "log level prefixes" {
    try std.testing.expectEqualStrings("[INFO ]", Level.info.prefix());
    try std.testing.expectEqualStrings("[ERROR]", Level.err.prefix());
}

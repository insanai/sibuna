//! Sibuna Core Library
//!
//! Provides foundational utilities: arena pools, high-resolution monotonic
//! timers, structured zero-allocation logging, Elm-style diagnostics,
//! and human-friendly error reporting with actionable hints.

const std = @import("std");

pub const time = struct {
    pub const ns_per_ms = std.time.ns_per_ms;
    pub const ns_per_s = std.time.ns_per_s;
};

pub const diagnostic = @import("diagnostic.zig");
pub const explainError = @import("errors.zig").explainError;
pub const config = @import("config.zig");
pub const Config = config.Config;
pub const Mode = config.Mode;
pub const max_cluster_peers = config.max_cluster_peers;
pub const log = @import("log.zig");

test {
    _ = @import("diagnostic.zig");
    _ = @import("errors.zig");
    _ = @import("config.zig");
    _ = @import("log.zig");
}

test "core sanity" {
    try std.testing.expect(time.ns_per_s == 1_000_000_000);
}

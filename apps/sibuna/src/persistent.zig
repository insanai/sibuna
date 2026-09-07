//! Placeholder; replaced by the Zaxonlite-backed implementation.
const std = @import("std");
pub const Persistent = struct {
    pub fn start(_: std.mem.Allocator, _: std.Io, _: anytype, _: anytype, _: anytype) error{StorageDisabled}!*Persistent {
        return error.StorageDisabled;
    }
    pub fn stop(_: *Persistent) void {}
};

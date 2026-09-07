//! Persistent storage facade (SID 0005).
//!
//! Compiled against Zaxonlite when the build enables storage; otherwise a
//! stub that refuses `--data-dir` so the daemon stays a single static
//! binary with no libc dependency.

const std = @import("std");
const build_options = @import("build_options");

pub const Persistent = if (build_options.storage)
    @import("persistent.zig").Persistent
else
    struct {
        pub fn start(
            _: std.mem.Allocator,
            _: std.Io,
            _: anytype,
            _: anytype,
            _: anytype,
        ) error{StorageDisabled}!*Persistent {
            return error.StorageDisabled;
        }
        pub fn stop(_: *Persistent) void {}
    };

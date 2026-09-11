//! Thread stack sizes that survive static thread-local storage. glibc carves a thread's
//! static TLS out of the stack it is given, and Zig's standard library keeps the per-thread
//! alternative signal stack (`std.options.signal_stack_size`, 256 KiB by default) in TLS, so
//! a thread asked for exactly N bytes cannot hold its own TLS and glibc refuses it with
//! EINVAL. Every service thread therefore reserves its usable size plus that TLS. Darwin
//! allocates TLS separately; there the extra reservation is virtual address space only.
const std = @import("std");

pub fn bytes(usable: usize) usize {
    return usable + (std.options.signal_stack_size orelse 0);
}

test "a usable stack request grows by the thread-local signal stack" {
    try std.testing.expect(bytes(256 * 1024) >= 256 * 1024);
    try std.testing.expectEqual(
        bytes(0),
        @as(usize, @intCast(std.options.signal_stack_size orelse 0)),
    );
}

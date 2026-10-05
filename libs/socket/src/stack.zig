//! Thread stack sizes include static TLS and unoptimised frame depth. glibc
//! carves static TLS out of the supplied stack, including Zig's alternate signal
//! stack. Reserving it separately keeps the requested usable service capacity.
const std = @import("std");
const builtin = @import("builtin");
pub const debug_scale: usize = if (builtin.mode == .debug) 4 else 1;

pub fn bytes(usable: usize) usize {
    return usable * debug_scale + (std.options.signal_stack_size orelse 0);
}

test "a usable stack request grows by the thread-local signal stack" {
    try std.testing.expect(bytes(256 * 1024) >= 256 * 1024);
    try std.testing.expectEqual(
        bytes(0),
        @as(usize, @intCast(std.options.signal_stack_size orelse 0)),
    );
}

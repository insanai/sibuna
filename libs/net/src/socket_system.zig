//! Raw socket calls for the relay and overload drain. Linux without libc exposes
//! recvfrom/sendto rather than the libc recv/send shorthands; connected streams
//! need no address buffer. Keep that distinction below application code.
const std = @import("std");
const builtin = @import("builtin");

pub const system = if (builtin.os.tag == .windows)
    @import("windows_socket.zig").system
else if (builtin.os.tag == .linux and !builtin.link_libc)
    Linux
else
    std.posix.system;

const Linux = struct {
    pub const poll = std.os.linux.poll;

    pub fn recv(fd: std.posix.socket_t, bytes: [*]u8, len: usize, flags: u32) usize {
        return std.os.linux.recvfrom(fd, bytes, len, flags, null, null);
    }

    pub fn send(fd: std.posix.socket_t, bytes: [*]const u8, len: usize, flags: u32) usize {
        return std.os.linux.sendto(fd, bytes, len, flags, null, 0);
    }
};

//! Bounded AFD operations on the native handles used by Zig 0.16's Windows Io backend.
//! These are not Winsock SOCKETs. Each operation owns its completion event and drains a
//! canceled request before returning, so the kernel never retains stack or caller buffers.
const std = @import("std");
const w = std.os.windows;
const Io = std.Io;
pub const Error = error{ ConnectionFailed, TimedOut };
pub const socket_t = Io.net.Socket.Handle;
pub const invalid_socket: socket_t = @ptrFromInt(std.math.maxInt(usize));
pub const pollfd = struct { fd: socket_t, events: i16, revents: i16 = 0 };
pub const POLL = struct {
    pub const IN: i16 = 1;
    pub const OUT: i16 = 4;
    pub const ERR: i16 = 8;
    pub const HUP: i16 = 16;
    pub const NVAL: i16 = 32;
};
pub const MSG = struct {
    pub const DONTWAIT: u32 = 0;
    pub const NOSIGNAL: u32 = 0;
};
pub const E = enum { SUCCESS, AGAIN, INTR, FAILED };

pub fn errno(result: isize) E {
    return if (result >= 0) .SUCCESS else if (result == -2) .AGAIN else .FAILED;
}

/// Relative waits use the awake clock. Cancellation is followed by an unbounded completion
/// join, not an abandoned timeout: buffers cannot be released before the driver releases them.
pub fn control(
    handle: socket_t,
    code: w.CTL_CODE,
    input: []const u8,
    output: []u8,
    timeout_ns: u64,
) Error!usize {
    var event: w.HANDLE = undefined;
    if (w.ntdll.NtCreateEvent(&event, .{
        .STANDARD = .{ .SYNCHRONIZE = true },
        .SPECIFIC = .{ .EVENT = .{ .MODIFY_STATE = true } },
    }, null, .Notification, .FALSE) != .SUCCESS) return error.ConnectionFailed;
    defer w.CloseHandle(event);
    var status: w.IO_STATUS_BLOCK = .{ .u = .{ .Status = .PENDING }, .Information = 0 };
    const result = w.ntdll.NtDeviceIoControlFile(
        handle,
        event,
        null,
        null,
        &status,
        code,
        if (input.len == 0) null else input.ptr,
        @intCast(input.len),
        if (output.len == 0) null else output.ptr,
        @intCast(output.len),
    );
    if (result == .PENDING) {
        const timeout: i64 = -@as(i64, @intCast(@max(1, timeout_ns / 100)));
        const waited = w.ntdll.NtWaitForSingleObject(event, .FALSE, &timeout);
        if (waited != .SUCCESS) {
            var cancellation: w.IO_STATUS_BLOCK = undefined;
            _ = w.ntdll.NtCancelIoFileEx(handle, &status, &cancellation);
            // This join also covers completion racing with the cancellation request.
            _ = w.ntdll.NtWaitForSingleObject(event, .FALSE, null);
            if (status.u.Status != .SUCCESS) return error.TimedOut;
        }
    } else if (result != .SUCCESS) return error.ConnectionFailed;
    if (status.u.Status != .SUCCESS) return error.ConnectionFailed;
    return status.Information;
}

fn remaining(io: Io, deadline: i96) Error!u64 {
    const delta = deadline - Io.Clock.awake.now(io).nanoseconds;
    if (delta <= 0) return error.TimedOut;
    return @intCast(@min(delta, std.math.maxInt(i64)));
}

pub fn connect(io: Io, address: Io.net.IpAddress, deadline: i96) Error!Io.net.Stream {
    const local: Io.net.IpAddress = switch (address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = local.bind(io, .{ .mode = .stream }) catch return error.ConnectionFailed;
    errdefer socket.close(io);
    const Storage = extern struct {
        reserved: [3]usize = @splat(0),
        address: Io.Threaded.PosixAddress,
    };
    var storage: Storage = .{ .address = undefined };
    const length = Io.Threaded.addressToPosix(&address, &storage.address);
    const bytes = std.mem.asBytes(&storage)[0 .. @offsetOf(Storage, "address") + length];
    _ = try control(socket.handle, w.IOCTL.AFD.CONNECT, bytes, &.{}, try remaining(io, deadline));
    return .{ .socket = socket };
}

pub fn noDelay(stream: Io.net.Stream) void {
    const one: c_int = 1;
    const option: w.AFD.SOCKOPT_INFO = .{
        .mode = .set,
        .level = w.ws2_32.IPPROTO.TCP,
        .optname = w.ws2_32.TCP.NODELAY,
        .optval = &one,
        .optlen = @sizeOf(c_int),
    };
    _ = control(
        stream.socket.handle,
        w.IOCTL.AFD.SOCKOPT,
        std.mem.asBytes(&option),
        &.{},
        100 * std.time.ns_per_ms,
    ) catch {};
}

pub fn receive(handle: socket_t, buffer: []u8, timeout: u64) Error!usize {
    const vector: w.AFD.WSABUF(.@"var") = .{ .buf = buffer.ptr, .len = @intCast(buffer.len) };
    const request: w.AFD.RECV_INFO = .{
        .BufferArray = @ptrCast(&vector),
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };
    return control(handle, w.IOCTL.AFD.RECEIVE, std.mem.asBytes(&request), &.{}, timeout);
}

pub fn send(handle: socket_t, buffer: []const u8, timeout: u64) Error!usize {
    const vector: w.AFD.WSABUF(.@"const") = .{ .buf = buffer.ptr, .len = @intCast(buffer.len) };
    const request: w.AFD.SEND_INFO = .{
        .BufferArray = @ptrCast(&vector),
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{},
    };
    return control(handle, w.IOCTL.AFD.SEND, std.mem.asBytes(&request), &.{}, timeout);
}

pub fn writeBounded(io: Io, stream: Io.net.Stream, bytes: []const u8, deadline: i96) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try send(stream.socket.handle, bytes[offset..], try remaining(io, deadline));
        if (count == 0) return error.ConnectionFailed;
        offset += count;
    }
}

pub fn readBounded(io: Io, stream: Io.net.Stream, buffer: []u8, deadline: i96) !usize {
    var length: usize = 0;
    while (length < buffer.len) {
        const count = try receive(
            stream.socket.handle,
            buffer[length..],
            try remaining(io, deadline),
        );
        if (count == 0) break;
        length += count;
    }
    return length;
}

const PollEntry = extern struct { handle: socket_t, events: u32, status: w.NTSTATUS };
const Poll = extern struct {
    timeout: i64,
    count: u32,
    exclusive: u32 = 0,
    entries: [2]PollEntry,
};

pub const system = struct {
    pub fn recv(handle: socket_t, bytes: [*]u8, length: usize, _: u32) isize {
        const count = receive(handle, bytes[0..length], std.time.ns_per_ms) catch |err|
            return if (err == error.TimedOut) -2 else -1;
        return @intCast(count);
    }

    pub fn send(handle: socket_t, bytes: [*]const u8, length: usize, _: u32) isize {
        const count = @This().sendBytes(handle, bytes[0..length]) catch return -1;
        return @intCast(count);
    }

    fn sendBytes(handle: socket_t, bytes: []const u8) Error!usize {
        // A send canceled midway may have transferred bytes; never retry an unknown prefix.
        return @import("windows_socket.zig").send(handle, bytes, 100 * std.time.ns_per_ms);
    }

    pub fn poll(descriptors: [*]pollfd, length: usize, timeout_ms: c_int) isize {
        std.debug.assert(length <= 2);
        var request: Poll = .{
            .timeout = -@as(i64, @intCast(@max(1, timeout_ms))) * 10_000,
            .count = 0,
            .entries = undefined,
        };
        for (descriptors[0..length]) |*descriptor| {
            descriptor.revents = 0;
            if (descriptor.fd == invalid_socket) continue;
            request.entries[request.count] = .{
                .handle = descriptor.fd,
                .events = 8 | 16 | 32 | 256 |
                    @as(u32, if (descriptor.events & POLL.IN != 0) 1 else 0) |
                    @as(u32, if (descriptor.events & POLL.OUT != 0) 4 else 0),
                .status = .SUCCESS,
            };
            request.count += 1;
        }
        if (request.count == 0) return 0;
        const size = @offsetOf(Poll, "entries") + request.count * @sizeOf(PollEntry);
        const bytes = std.mem.asBytes(&request)[0..size];
        _ = control(
            request.entries[0].handle,
            w.IOCTL.AFD.POLL,
            bytes,
            bytes,
            @as(u64, @intCast(@max(1, timeout_ms) + 100)) * std.time.ns_per_ms,
        ) catch return -1;
        var ready: isize = 0;
        for (descriptors[0..length]) |*descriptor| {
            for (request.entries[0..request.count]) |entry| {
                if (descriptor.fd != entry.handle) continue;
                if (entry.events & 1 != 0) descriptor.revents |= POLL.IN;
                if (entry.events & 4 != 0) descriptor.revents |= POLL.OUT;
                if (entry.events & 8 != 0) descriptor.revents |= POLL.HUP;
                if (entry.events & (16 | 32 | 256) != 0 or entry.status != .SUCCESS)
                    descriptor.revents |= POLL.ERR;
                if (descriptor.revents != 0) ready += 1;
            }
        }
        return ready;
    }
};

#!/usr/bin/env python3
"""Apply labeled counts-only logging to exact-tag tunnel teardown; no behavior changes."""
from pathlib import Path


def replace(path, old, new):
    p = Path(path)
    text = p.read_text()
    assert text.count(old) == 1, (path, text.count(old))
    p.write_text(text.replace(old, new))


replace('libs/net/src/duplex.zig', '    var last_activity = nowMs(io);',
        '    var last_activity = nowMs(io);\n    var diagnostic_at = last_activity;')
replace('libs/net/src/duplex.zig', '        const now = nowMs(io);', '''        const now = nowMs(io);
        if (now -| diagnostic_at >= 5000) {
            diagnostic_at = now;
            diagnostic(io, &directions, &descriptors, options.idle_timeout_seconds);
        }''')
replace('libs/net/src/duplex.zig', 'fn interests(', '''fn diagnostic(io: Io, dirs: *const [2]Direction, fds: *const [2]posix.pollfd, idle: u32) void {
    for (dirs, fds, 0..) |d, fd, i| {
        var buffer: [512]u8 = undefined;
        const message = std.fmt.bufPrint(
            &buffer,
            "TUNNEL-DIAGNOSTIC side={d} fd={d} events={d} revents={d} " ++
                "prefix={d} begin={d} end={d} eof={} closed={} idle={d}\\n",
            .{ i, fd.fd, fd.events, fd.revents, d.prefix.len, d.begin, d.end, d.eof, d.closed, idle },
        ) catch return;
        @import("socket").diagnostic(io, message);
    }
}

fn interests(''')
replace('libs/socket/src/root.zig', '    stream.shutdown(io, .both) catch |err| switch (err) {',
        '''    diagnosticSocket(io, "interrupt", stream.socket.handle);
    stream.shutdown(io, .both) catch |err| switch (err) {''')
replace('libs/socket/src/root.zig', '        error.SocketUnconnected => {},',
        '''        error.SocketUnconnected => diagnosticSocket(io, "unconnected", stream.socket.handle),''')
replace('libs/socket/src/root.zig', '    };\n}\n\ntest', '''    };
    diagnosticSocket(io, "completed", stream.socket.handle);
}

var diagnostic_mutex: std.Io.Mutex = .init;

pub fn diagnostic(io: std.Io, message: []const u8) void {
    diagnostic_mutex.lockUncancelable(io);
    defer diagnostic_mutex.unlock(io);
    var buffer: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, ".zig-cache/tunnel-diagnostic-{d}.log", .{
        std.c.getpid(),
    }) catch return;
    const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch return;
    defer file.close(io);
    const stat = file.stat(io) catch return;
    if (stat.size >= 256 * 1024) return;
    file.writePositionalAll(io, message, stat.size) catch return;
}

fn diagnosticSocket(io: std.Io, event: []const u8, fd: std.Io.net.Socket.Handle) void {
    var buffer: [128]u8 = undefined;
    const message = std.fmt.bufPrint(&buffer, "SOCKET-DIAGNOSTIC {s} fd={d}\\n", .{
        event, fd,
    }) catch return;
    diagnostic(io, message);
}

test''')

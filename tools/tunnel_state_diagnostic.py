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
replace('libs/net/src/duplex.zig', '        const now = nowMs(io);', """        const now = nowMs(io);
        if (now -| diagnostic_at >= 5000) {
            diagnostic_at = now;
            diagnostic(&directions, &descriptors, options.idle_timeout_seconds);
        }""")
replace('libs/net/src/duplex.zig', 'fn interests(', """fn diagnostic(dirs: *const [2]Direction, fds: *const [2]posix.pollfd, idle: u32) void {
    for (dirs, fds, 0..) |d, fd, i| {
        std.debug.print("TUNNEL-DIAGNOSTIC side={d} fd={d} events={d} revents={d} " ++
            "prefix={d} begin={d} end={d} eof={} closed={} idle={d}\\n", .{
            i, fd.fd, fd.events, fd.revents, d.prefix.len, d.begin, d.end, d.eof, d.closed, idle,
        });
    }
}

fn interests(""")
replace('libs/socket/src/root.zig', '    stream.shutdown(io, .both) catch |err| switch (err) {',
        '''    std.debug.print("SOCKET-DIAGNOSTIC interrupt fd={d}\\n", .{stream.socket.handle});
    stream.shutdown(io, .both) catch |err| switch (err) {''')
replace('libs/socket/src/root.zig', '        error.SocketUnconnected => {},',
        '''        error.SocketUnconnected => {
            std.debug.print("SOCKET-DIAGNOSTIC unconnected fd={d}\\n", .{stream.socket.handle});
        },''')
replace('libs/socket/src/root.zig', '    };\n}\n\ntest',
        '''    };
    std.debug.print("SOCKET-DIAGNOSTIC completed fd={d}\\n", .{stream.socket.handle});
}

test''')

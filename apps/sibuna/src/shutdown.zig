//! Signal handlers only set a lock-free flag. A normal thread wakes acceptors; all
//! descriptor operations, joins and storage flushes run outside the signal handler.
const std = @import("std");
const server = @import("server.zig");
const Io = std.Io;
var requested: std.atomic.Value(bool) = .init(false);

fn signal(_: std.posix.SIG) callconv(.c) void {
    requested.store(true, .release);
}

/// Install before storage or management listeners start, and restore only after they stop.
/// A termination observed during startup must survive until the accept loop is ready.
pub const Signals = if (@import("builtin").os.tag == .windows) WindowsSignals else PosixSignals;

const PosixSignals = struct {
    previous_term: std.posix.Sigaction,
    previous_int: std.posix.Sigaction,

    pub fn init() !PosixSignals {
        requested.store(false, .release);
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = signal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        var saved: PosixSignals = undefined;
        std.posix.sigaction(.TERM, &action, &saved.previous_term);
        std.posix.sigaction(.INT, &action, &saved.previous_int);
        return saved;
    }

    pub fn deinit(self: *const PosixSignals) void {
        std.posix.sigaction(.TERM, &self.previous_term, null);
        std.posix.sigaction(.INT, &self.previous_int, null);
    }
};

const WindowsSignals = struct {
    extern "kernel32" fn SetConsoleCtrlHandler(
        handler: ?*const fn (u32) callconv(.winapi) i32,
        add: i32,
    ) callconv(.winapi) i32;

    fn control(kind: u32) callconv(.winapi) i32 {
        // CTRL_C, CTRL_BREAK and close: the monitor performs the same ordered shutdown.
        if (kind > 2) return 0;
        requested.store(true, .release);
        return 1;
    }

    pub fn init() !WindowsSignals {
        requested.store(false, .release);
        if (SetConsoleCtrlHandler(control, 1) == 0) return error.SignalHandlerUnavailable;
        return .{};
    }

    pub fn deinit(_: *const WindowsSignals) void {
        _ = SetConsoleCtrlHandler(control, 0);
    }
};

pub fn wasRequested() bool {
    return requested.load(.acquire);
}

pub fn run(listener: *Io.net.Server, io: Io, state: *server.AppState) !void {
    var monitor: Monitor = .{ .listener = listener, .io = io, .state = state };
    const thread = try std.Thread.spawn(.{}, Monitor.watch, .{&monitor});
    defer {
        monitor.finished.store(true, .release);
        thread.join();
    }
    try server.runServer(listener, io, state);
}

const Monitor = struct {
    listener: *Io.net.Server,
    io: Io,
    state: *server.AppState,
    finished: std.atomic.Value(bool) = .init(false),

    fn watch(self: *Monitor) void {
        while (!self.finished.load(.acquire)) {
            if (requested.load(.acquire)) {
                server.requestStop(self.listener, self.io, self.state);
                return;
            }
            Io.sleep(self.io, Io.Duration.fromMilliseconds(100), .awake) catch return;
        }
    }
};

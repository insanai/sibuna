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
pub const Signals = struct {
    previous_term: std.posix.Sigaction,
    previous_int: std.posix.Sigaction,

    pub fn init() Signals {
        requested.store(false, .release);
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = signal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        var saved: Signals = undefined;
        std.posix.sigaction(.TERM, &action, &saved.previous_term);
        std.posix.sigaction(.INT, &action, &saved.previous_int);
        return saved;
    }

    pub fn deinit(self: *const Signals) void {
        std.posix.sigaction(.TERM, &self.previous_term, null);
        std.posix.sigaction(.INT, &self.previous_int, null);
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
    server.runServer(listener, io, state);
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

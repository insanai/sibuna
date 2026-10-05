//! One monotonic wait budget shared by bounded native management workflows.
const std = @import("std");
const Error = @import("console_session.zig").Error;
pub const Budget = struct {
    started: i96,
    seconds: u32,

    pub fn remaining(self: Budget, io: std.Io) Error!u64 {
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - self.started;
        const limit = @as(i96, self.seconds) * std.time.ns_per_s;
        if (elapsed >= limit) return error.Deadline;
        return @intCast(limit - @max(0, elapsed));
    }

    pub fn wait(self: Budget, io: std.Io) Error!void {
        const remaining_ns = try self.remaining(io);
        std.Io.sleep(io, .fromNanoseconds(@min(remaining_ns, std.time.ns_per_s)), .awake) catch
            return error.Canceled;
    }
};

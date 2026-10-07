//! Election transients may interrupt a durable CRS read after storage startup.
//! Retry only observation/application before listeners; source adoption is never replayed.
const std = @import("std");

pub const Retry = struct {
    deadline: std.Io.Timestamp,

    pub fn init(io: std.Io) Retry {
        return .{ .deadline = std.Io.Clock.awake.now(io).addDuration(.fromSeconds(30)) };
    }

    pub fn wait(self: Retry, io: std.Io, stopping: bool, err: anyerror) !void {
        if (stopping) return error.Canceled;
        const now = std.Io.Clock.awake.now(io);
        if (!self.allowed(now, stopping, err)) return err;
        // Start no new attempt after thirty seconds. An admitted attempt retains
        // existing per-query deadlines, signed-source bounds and compilation limits.
        const remaining = self.deadline.nanoseconds - now.nanoseconds;
        try std.Io.sleep(io, .fromNanoseconds(@min(remaining, 100 * std.time.ns_per_ms)), .awake);
        if (std.Io.Clock.awake.now(io).compare(.gte, self.deadline)) return err;
    }

    fn allowed(self: Retry, now: std.Io.Timestamp, stopping: bool, err: anyerror) bool {
        if (stopping or now.compare(.gte, self.deadline)) return false;
        return switch (err) {
            error.StorageUnavailable, error.StorageTimeout => true,
            error.Full, error.CrsSelectionChanged => true,
            else => false,
        };
    }
};

test "startup retries only transient observations within the awake deadline" {
    const t = std.testing;
    const retry: Retry = .{ .deadline = .{ .nanoseconds = 30 * std.time.ns_per_s } };
    const before: std.Io.Timestamp = .{ .nanoseconds = 29 * std.time.ns_per_s };
    try t.expect(retry.allowed(before, false, error.StorageUnavailable));
    try t.expect(retry.allowed(before, false, error.StorageTimeout));
    try t.expect(retry.allowed(before, false, error.CrsSelectionChanged));
    try t.expect(!retry.allowed(retry.deadline, false, error.StorageUnavailable));
    try t.expect(!retry.allowed(before, true, error.StorageUnavailable));
    const fatal = [_]anyerror{
        error.Canceled,            error.CrsStartupConflict, error.InvalidCrsSource,
        error.InvalidCrsSelection, error.SignatureInvalid,   error.OutOfMemory,
    };
    for (fatal) |err| try t.expect(!retry.allowed(before, false, err));
}

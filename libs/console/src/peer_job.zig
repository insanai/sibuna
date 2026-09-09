//! Each configured peer has one outgoing worker; cancellation joins every borrowed scope.
const std = @import("std");
const client = @import("peer_client.zig");
const Store = @import("peer_store.zig").Store;
const max_peers = @import("peer_config.zig").max_peers;
const Result = union(enum) { connection: anyerror!void, deadline: anyerror!void };
pub const Job = struct {
    store: *Store = undefined,
    gpa: std.mem.Allocator = undefined,
    stopping: std.atomic.Value(bool) = .init(false),
    threads: [max_peers]?std.Thread = @splat(null),

    pub fn start(self: *Job, store: *Store, gpa: std.mem.Allocator) !void {
        self.store = store;
        self.gpa = gpa;
        errdefer self.stop();
        for (0..store.config.count) |index| {
            self.threads[index] = try std.Thread.spawn(
                .{ .stack_size = 256 * 1024 },
                run,
                .{ self, @as(u8, @intCast(index)) },
            );
        }
    }

    pub fn stop(self: *Job) void {
        self.stopping.store(true, .release);
        for (&self.threads) |*thread| {
            if (thread.*) |task| task.join();
            thread.* = null;
        }
    }

    fn run(self: *Job, index: u8) void {
        var backoff: u64 = 1;
        while (!self.stopping.load(.acquire)) {
            const started = client.monotonic(self.store.io);
            var rejected = false;
            self.attempt(index) catch |err| {
                rejected = err == error.InvalidProof or err == error.InvalidRequest;
            };
            self.store.failed(index, rejected);
            if (client.monotonic(self.store.io) - started >= 10) backoff = 1;
            var jitter: [1]u8 = undefined;
            self.store.io.random(&jitter);
            const ticks = backoff * 10 + jitter[0] % 10;
            for (0..ticks) |_| {
                if (self.stopping.load(.acquire)) return;
                std.Io.sleep(self.store.io, .fromMilliseconds(100), .awake) catch return;
            }
            backoff = @min(30, backoff * 2);
        }
    }

    fn attempt(self: *Job, index: u8) !void {
        var progress: std.atomic.Value(i64) = .init(client.monotonic(self.store.io));
        var buffer: [2]Result = undefined;
        var select: std.Io.Select(Result) = .init(self.store.io, &buffer);
        defer select.cancelDiscard();
        try select.concurrent(.deadline, deadline, .{ self, &progress });
        try select.concurrent(.connection, client.run, .{client.Input{
            .store = self.store,
            .index = index,
            .gpa = self.gpa,
            .progress = &progress,
        }});
        switch (try select.await()) {
            .connection => |result| try result,
            .deadline => return error.PeerDeadline,
        }
    }

    fn deadline(self: *Job, progress: *std.atomic.Value(i64)) anyerror!void {
        const started = client.monotonic(self.store.io);
        while (!self.stopping.load(.acquire)) {
            const now = client.monotonic(self.store.io);
            if (now - progress.load(.acquire) >= 10 or now - started >= 3600) return;
            try std.Io.sleep(self.store.io, .fromMilliseconds(100), .awake);
        }
    }
};

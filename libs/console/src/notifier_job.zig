//! One cluster notifier at a time: the lease holder claims queued events and delivers
//! them; standby nodes only enqueue. Delivery runs on this thread, never in the collector
//! or a request handler, and every outcome is recorded under the database fence.
const std = @import("std");
const p = @import("console_protocol");
const n = p.notifications;
const App = @import("app.zig").App;
const events = @import("notify_events.zig");
pub const poll_ms = 5000;
pub const max_attempts = 3;

pub const Job = struct {
    app: *App = undefined,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    holder: p.retention.Holder = .{ .node = 0, .boot = @splat(0) },
    lease: ?p.retention.Lease = null,
    renew_at: u64 = 0,
    ring: events.Ring = .{},
    ring_mutex: std.Io.Mutex = .init,
    sequence: u64 = 0,
    enqueued: std.atomic.Value(u64) = .init(0),
    delivered: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(u64) = .init(0),

    pub fn start(self: *Job) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, run, .{self});
    }

    pub fn stop(self: *Job) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
    }

    /// Called by the collector and the probe thread; bounded by the ring.
    pub fn raise(self: *Job, event: events.Event, now: u64, detail: []const u8) void {
        self.ring_mutex.lockUncancelable(self.app.io);
        defer self.ring_mutex.unlock(self.app.io);
        self.ring.offer(event, now, detail);
    }

    fn run(self: *Job) void {
        while (!self.stopping.load(.acquire)) {
            self.flush();
            self.deliver() catch |err| {
                std.log.warn("console notifier: {t}", .{err});
                self.lease = null;
            };
            var waited: u64 = 0;
            while (!self.stopping.load(.acquire) and waited < poll_ms) : (waited += 100) {
                std.Io.sleep(self.app.io, std.Io.Duration.fromMilliseconds(100), .awake) catch
                    return;
            }
        }
    }

    /// Moves locally raised events into the replicated queue with this node's identity.
    fn flush(self: *Job) void {
        for (0..events.capacity) |_| {
            self.ring_mutex.lockUncancelable(self.app.io);
            const raised = self.ring.take();
            self.ring_mutex.unlock(self.app.io);
            const item = raised orelse return;
            const result = self.app.background(.{ .notifications_enqueue = .{
                .node = self.holder.node,
                .boot = self.holder.boot,
                .sequence = item.sequence,
                .event = @enumFromInt(@intFromEnum(item.event)),
                .raised_at = item.raised_at,
                .detail = p.Bytes(n.max_detail).init(item.text()) catch .{},
            } }) catch return;
            if (result == .command_recorded) _ = self.enqueued.fetchAdd(1, .monotonic);
        }
    }

    fn deliver(self: *Job) !void {
        const now = self.app.now();
        if (self.lease == null or now >= self.renew_at) {
            const result = try self.app.background(.{ .notifier_acquire = self.holder });
            if (result != .notifier_lease) {
                self.lease = null;
                return;
            }
            self.lease = result.notifier_lease;
            self.renew_at = now + 10;
        }
        const lease = self.lease.?;
        const claimed = try self.app.background(.{ .notifications_claim = .{ .lease = lease } });
        if (claimed != .notification_batch) return error.ClaimRejected;
        const batch = claimed.notification_batch;
        for (batch.events[0..batch.count]) |event| try self.fanOut(lease, event);
    }

    fn fanOut(self: *Job, lease: p.retention.Lease, event: n.Pending) !void {
        var after: u64 = 0;
        var remaining: u32 = 0;
        var attempted: u32 = 0;
        while (true) {
            const page = try self.app.background(.{ .notifications_query = .{
                .auth = .{ .session_digest = @splat(0) },
                .after = after,
                .lease = lease,
            } });
            if (page != .notifications_page) return error.PageRejected;
            for (page.notifications_page.rows[0..page.notifications_page.count]) |destination| {
                if (!destination.enabled or destination.events & event.event.bit() == 0) continue;
                if (destination.last_attempt_at) |last| {
                    if (self.app.now() -| last < destination.cooldown_seconds) {
                        remaining += 1;
                        continue;
                    }
                }
                attempted += 1;
                try self.send(lease, event, destination);
            }
            after = page.notifications_page.next orelse break;
        }
        if (remaining == 0) try self.finish(lease, event, attempted == 0);
    }

    fn send(self: *Job, lease: p.retention.Lease, event: n.Pending, dest: n.Destination) !void {
        const delivery = @import("notify_delivery.zig");
        var detail: p.Bytes(n.max_detail) = .{};
        var delivered = false;
        var attempt: u32 = 0;
        while (attempt < max_attempts and !delivered) : (attempt += 1) {
            if (attempt != 0) {
                const backoff: i64 = @as(i64, 1) << @intCast(2 * attempt - 1);
                std.Io.sleep(self.app.io, .fromSeconds(backoff), .awake) catch return;
            }
            delivered = delivery.deliver(self.app, dest, event, &detail, .{
                .auth = .{ .session_digest = @splat(0) },
                .id = dest.id,
                .lease = lease,
            });
        }
        _ = (if (delivered) &self.delivered else &self.failed).fetchAdd(1, .monotonic);
        const result = try self.app.background(.{ .notifications_record = .{
            .lease = lease,
            .event_id = event.id,
            .destination = dest.id,
            .delivered = delivered,
            .detail = detail,
            .finished = false,
        } });
        if (result != .command_recorded) return error.RecordRejected;
    }

    fn finish(self: *Job, lease: p.retention.Lease, event: n.Pending, silent: bool) !void {
        _ = silent;
        const result = try self.app.background(.{ .notifications_record = .{
            .lease = lease,
            .event_id = event.id,
            .destination = 0,
            .delivered = true,
            .detail = .{},
            .finished = true,
        } });
        if (result != .command_recorded) return error.RecordRejected;
    }
};

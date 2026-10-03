//! One cluster notifier at a time: the lease holder claims queued events and delivers
//! them; standby nodes only enqueue. Delivery runs on this thread, never in the collector
//! or a request handler, and every outcome is recorded under the database fence.
const std = @import("std");
const p = @import("console_protocol");
const n = p.notifications;
const App = @import("app.zig").App;
const events = @import("notify_events.zig");
pub const poll_ms = 1000;

pub const Job = struct {
    app: *App = undefined,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    holder: p.retention.Holder = .{ .node = 0, .boot = @splat(0) },
    lease: ?p.retention.Lease = null,
    pending: ?events.Raised = null,
    reported_drops: u64 = 0,
    ring: events.Ring = .{},
    ring_mutex: std.Io.Mutex = .init,
    sequence: u64 = 0,
    enqueued: std.atomic.Value(u64) = .init(0),
    delivered: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(u64) = .init(0),

    pub fn start(self: *Job) !void {
        self.thread = try std.Thread.spawn(
            .{ .stack_size = @import("serve").stack.bytes(512 * 1024) },
            run,
            .{self},
        );
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
            if (self.pending == null) self.pending = self.ring.take();
            const drops = self.ring.dropped;
            self.ring_mutex.unlock(self.app.io);
            if (drops != self.reported_drops) {
                std.log.warn("console notifier: {d} local events lost to capacity", .{drops});
                self.reported_drops = drops;
            }
            const item = self.pending orelse return;
            const result = self.app.background(.{ .notifications_enqueue = .{
                .node = self.holder.node,
                .boot = self.holder.boot,
                .sequence = item.sequence,
                .event = @fromBackingInt(@intCast(@backingInt(item.event))),
                .raised_at = item.raised_at,
                .detail = p.Bytes(n.max_detail).init(
                    item.text()[0..@min(item.detail_len, n.max_detail)],
                ) catch unreachable,
            } }) catch return;
            if (result != .command_recorded) return;
            self.pending = null;
            _ = self.enqueued.fetchAdd(1, .monotonic);
        }
    }

    fn deliver(self: *Job) !void {
        // One lease refresh per attempt, never a batch of network retries under an old grant.
        for (0..n.capacity) |_| {
            if (self.stopping.load(.acquire)) return;
            const started = std.Io.Clock.awake.now(self.app.io).nanoseconds;
            const acquired = try self.app.background(.{ .notifier_acquire = self.holder });
            if (acquired != .notifier_lease) {
                self.lease = null;
                return;
            }
            const lease = acquired.notifier_lease;
            self.lease = lease;
            // Budget from before storage submission: a delayed reply cannot extend authority.
            const not_after = started + 20 * std.time.ns_per_s;
            if (!self.fresh(lease, not_after)) return;
            const result = try self.app.background(.{
                .notifications_claim = .{ .lease = lease },
            });
            if (result != .notification_claimed) return error.ClaimRejected;
            const claimed = result.notification_claimed orelse return;
            if (!self.fresh(lease, not_after)) return;
            try self.send(lease, claimed, not_after);
        }
    }

    fn fresh(self: *Job, lease: p.retention.Lease, not_after: i96) bool {
        return !self.stopping.load(.acquire) and
            lease.expires -| self.app.now() >= n.claim_margin_seconds and
            std.Io.Clock.awake.now(self.app.io).nanoseconds < not_after;
    }

    fn send(self: *Job, lease: p.retention.Lease, claimed: n.Claimed, not_after: i96) !void {
        const outcome = @import("notify_delivery.zig").deliver(self.app, .{
            .destination = claimed.destination,
            .event = claimed.event,
            .not_after = not_after,
            .read = .{
                .auth = .{ .session_digest = @splat(0) },
                .id = claimed.destination.id,
                .revision = claimed.destination.revision,
                .lease = lease,
            },
        });
        _ = (if (outcome.delivered) &self.delivered else &self.failed).fetchAdd(1, .monotonic);
        const result = try self.app.background(.{ .notifications_record = .{
            .lease = lease,
            .delivery_id = claimed.delivery_id,
            .attempt = claimed.event.attempts,
            .delivered = outcome.delivered,
            .detail = outcome.detail,
        } });
        if (result != .command_recorded) return error.RecordRejected;
    }
};

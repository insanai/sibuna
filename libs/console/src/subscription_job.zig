//! One feeder polls bounded owner operations and publishes outside request processing.
//! Every pending ticket owns its inputs, and shutdown abandons it only after joining us.
const std = @import("std");
const p = @import("console_protocol");
const s = p.subscriptions;
const f = p.subscription_feed;
const Mailbox = @import("mailbox.zig").Mailbox;
const App = @import("app.zig").App;
const Slot = struct {
    ticket: ?Mailbox.Ticket = null,
    started_ms: u64 = 0,
    next_ms: u64 = 0,
    cursor: f.Request = .{ .kind = .events },
};
const nodes_slot = p.nodes.max_members;
const policy_slot = nodes_slot + 1;
const audit_slot = nodes_slot + 2;
pub const Job = struct {
    app: *App = undefined,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    slots: [p.nodes.max_members + 3]Slot = @splat(.{}),
    node_count: u8 = 1,
    buffer: []u8 = &.{},
    next_fanout_ms: u64 = 0,

    pub fn start(self: *Job, app: *App) !void {
        self.app = app;
        self.slots[0].cursor.node = app.config.node_id;
        self.slots[audit_slot].cursor = .{ .kind = .audit };
        self.buffer = try app.gpa.alloc(u8, s.snapshot_bytes);
        errdefer app.gpa.free(self.buffer);
        self.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, run, .{self});
    }

    pub fn stop(self: *Job) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
        for (&self.slots) |*slot| if (slot.ticket) |ticket| {
            self.app.mailbox.abandon(self.app.io, ticket) catch @panic("feed ticket ownership");
            slot.ticket = null;
        };
        self.app.gpa.free(self.buffer);
        self.buffer = &.{};
    }

    fn run(self: *Job) void {
        while (!self.stopping.load(.acquire)) {
            const ms: u64 = @intCast(@max(0, @divTrunc(
                std.Io.Clock.awake.now(self.app.io).nanoseconds,
                std.time.ns_per_ms,
            )));
            self.tick(ms);
            std.Io.sleep(self.app.io, .fromMilliseconds(100), .awake) catch return;
        }
    }

    fn tick(self: *Job, ms: u64) void {
        const wanted = self.app.hub.wanted();
        for (&self.slots, 0..) |*slot, index| {
            if (slot.ticket) |ticket| {
                const result = self.app.mailbox.poll(self.app.io, ticket) catch
                    @panic("feed ticket ownership");
                if (result) |done| {
                    slot.ticket = null;
                    slot.next_ms = ms +| 1000;
                    defer p.releaseResult(done, self.app.gpa);
                    self.complete(index, done, ms) catch |err| {
                        std.log.warn("console subscription source failed: {t}", .{err});
                    };
                } else if (ms -| slot.started_ms >= 10000) {
                    self.app.mailbox.abandon(self.app.io, ticket) catch
                        @panic("feed cancellation ownership");
                    slot.ticket = null;
                    slot.next_ms = ms +| 1000;
                }
            }
            if (slot.ticket != null or ms < slot.next_ms or !self.needed(index, wanted)) continue;
            const request: p.StorageRequest = switch (index) {
                nodes_slot => .subscription_nodes,
                policy_slot => .subscription_policy,
                else => .{ .subscription_read = slot.cursor },
            };
            slot.ticket = self.app.mailbox.submit(self.app.io, request, .background) catch {
                slot.next_ms = ms +| 1000;
                continue;
            };
            slot.started_ms = ms;
        }
        if (ms < self.next_fanout_ms) return;
        self.next_fanout_ms = ms +| 1000;
        self.local(wanted) catch |err| {
            std.log.warn("console subscription statistics failed: {t}", .{err});
        };
        self.app.hub.fanout();
    }

    fn needed(self: *const Job, index: usize, wanted: [s.topic_count]bool) bool {
        return switch (index) {
            nodes_slot => wanted[@intFromEnum(p.Topic.nodes)] or
                wanted[@intFromEnum(p.Topic.events)],
            policy_slot => wanted[@intFromEnum(p.Topic.policy)],
            audit_slot => wanted[@intFromEnum(p.Topic.audit)],
            else => index < self.node_count and wanted[@intFromEnum(p.Topic.events)],
        };
    }

    fn complete(self: *Job, index: usize, result: p.StorageResult, ms: u64) !void {
        if (result == .failed) return;
        switch (index) {
            nodes_slot => {
                if (result != .nodes_page) return error.InvalidSource;
                for (result.nodes_page.members[0..result.nodes_page.count]) |member|
                    try self.addMember(member.node);
                var probes: [p.nodes.max_probes]p.nodes.Probe = undefined;
                const count = self.app.cluster.snapshot(&probes);
                try self.state(.nodes, .{
                    .page = result.nodes_page,
                    .probes = probes[0..count],
                    .observed_at = p.Counter{ .value = self.app.now() },
                });
            },
            policy_slot => {
                if (result != .revision) return error.InvalidSource;
                try self.state(.policy, .{
                    .node = self.app.config.node_id,
                    .committed = p.Counter{ .value = result.revision.committed },
                    .applied = p.Counter{ .value = result.revision.applied },
                    .observed_at = p.Counter{ .value = self.app.now() },
                });
            },
            else => {
                if (result != .subscription_page) return error.InvalidSource;
                const page = &result.subscription_page;
                const topic: p.Topic = if (page.kind == .events) .events else .audit;
                const store = self.app.hub.stores[@intFromEnum(topic)];
                for (page.rows[0..page.count]) |row| try store.row(self.app.io, row);
                try store.advance(self.app.io, page);
                const slot = &self.slots[index];
                slot.cursor.after = page.next;
                slot.cursor.through = if (page.more) page.through else null;
                if (page.more) slot.next_ms = ms;
            },
        }
    }

    fn addMember(self: *Job, node: u32) !void {
        if (node == 0 or node >= (1 << 23)) return error.InvalidSource;
        for (self.slots[0..self.node_count]) |slot| if (slot.cursor.node == node) return;
        if (self.node_count == p.nodes.max_members) return error.TooManySources;
        self.slots[self.node_count].cursor.node = node;
        self.node_count += 1;
        self.app.hub.stores[@intFromEnum(p.Topic.events)].expected_sources = self.node_count;
    }

    fn local(self: *Job, wanted: [s.topic_count]bool) !void {
        const app = self.app;
        if (wanted[@intFromEnum(p.Topic.stats)]) try self.state(.stats, app.stats.snapshot(
            app.io,
            app.telemetry,
            app.metrics,
            app.now(),
        ));
        if (wanted[@intFromEnum(p.Topic.challenges)]) try self.state(
            .challenges,
            @import("challenge_routes.zig").snapshot(
                &app.telemetry.challenges,
                app.challenge_defaults,
                @import("challenge_routes.zig").configuredBin(app.challenge_defaults),
                app.now(),
            ),
        );
    }

    fn state(self: *Job, topic: p.Topic, value: anytype) !void {
        var writer: std.Io.Writer = .fixed(self.buffer);
        try std.json.Stringify.value(value, .{}, &writer);
        var arena = std.heap.FixedBufferAllocator.init(self.app.hub.arena_bytes);
        try self.app.hub.stores[@intFromEnum(topic)].state(
            self.app.io,
            arena.allocator(),
            writer.buffered(),
            self.app.hub.scratch,
        );
    }
};

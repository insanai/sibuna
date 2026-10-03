//! One hub-owned subscriber. The handler supplies commands and consumes copied frames;
//! no socket write occurs while the hub mutex is held.
const std = @import("std");
const p = @import("console_protocol");
const s = p.subscriptions;
const topics = @import("topic_store.zig");
const queue = @import("subscription_queue.zig");
pub const Context = struct {
    io: std.Io,
    boot: [32]u8,
    stores: *[s.topic_count]*topics.Store,
    arena: std.mem.Allocator,
    scratch: []u8,
    dashboard: ?*const @import("dashboard_stats.zig").Frame = null,
};
const Phase = enum { off, waiting, streaming, live, paused };
const State = struct {
    phase: Phase = .off,
    args: s.Args = .{},
    epoch: u64 = 0,
    sequence: u64 = 0,
    cursor: u64 = 1,
};
const Pending = struct {
    topic: p.Topic,
    snapshot: bool,
    phase: enum { begin, chunks, end },
    watermark: u64,
    offset: usize = 0,
    part: u16 = 0,
    parts: u16 = 0,
};
const Message = struct {
    op: enum { snapshot_begin, snapshot_chunk, snapshot_end, delta },
    topic: p.Topic,
    epoch: []const u8,
    seq: p.Counter,
    snapshot: bool,
    watermark: p.Counter,
    data: ?[]const u8 = null,
    part: u16 = 0,
    parts: u16 = 0,
    update: p.Counter = .{ .value = 0 },
    kind: enum { patch, row } = .patch,
};
pub const Subscriber = struct {
    outbox: queue.Queue(s.queue_capacity) = .{},
    states: [s.topic_count]State = @splat(.{}),
    payload: p.Bytes(s.snapshot_bytes) = .{},
    node_view: p.Bytes(16384) = .{},
    stats_view: p.Bytes(16384) = .{},
    pending: ?Pending = null,
    next_topic: usize = 0,

    pub fn command(self: *Subscriber, input: s.Command, epoch: u64) void {
        const topic = input.topic orelse return;
        self.outbox.reset(topic);
        if (self.pending != null and self.pending.?.topic == topic) self.pending = null;
        self.states[@backingInt(topic)] = .{
            .phase = if (input.op == .unsub) .off else .waiting,
            .args = input.args,
            .epoch = epoch,
        };
    }

    /// A fixed scan and delivery allowance bounds filtering work as well as wire traffic.
    pub fn pump(self: *Subscriber, context: Context) !void {
        var sent: usize = 0;
        for (0..s.messages_per_second * s.topic_count) |_| {
            if (sent == s.messages_per_second) break;
            const topic: p.Topic = @fromBackingInt(@intCast(self.next_topic));
            self.next_topic = (self.next_topic + 1) % s.topic_count;
            const state = &self.states[@backingInt(topic)];
            const store = context.stores[@backingInt(topic)];
            if (state.phase == .waiting and self.pending == null)
                try self.snapshot(context, topic, store);
            if (self.pending != null and self.pending.?.topic == topic) {
                try self.fragment(context);
                sent += 1;
            } else if (state.phase == .live) {
                if (try self.delta(context, topic, store)) sent += 1;
            }
        }
    }

    fn snapshot(self: *Subscriber, context: Context, topic: p.Topic, store: *topics.Store) !void {
        const state = &self.states[@backingInt(topic)];
        var writer: std.Io.Writer = .fixed(&self.payload.data);
        try snapshotView(context, topic, store, &state.args, &writer);
        self.payload.len = writer.buffered().len;
        if (self.filteredView(context, topic)) |view| try view.set(self.payload.slice());
        state.cursor = store.ring.watermark() + 1;
        state.phase = .streaming;
        self.pending = .{
            .topic = topic,
            .snapshot = true,
            .phase = .begin,
            .watermark = state.cursor - 1,
            .parts = parts(self.payload.slice()),
        };
    }

    fn fragment(self: *Subscriber, context: Context) !void {
        var pending = self.pending.?;
        var message = self.envelope(pending.topic);
        var epoch: [64]u8 = undefined;
        message.epoch = try self.formatEpoch(pending.topic, context.boot, &epoch);
        message.watermark.value = pending.watermark;
        message.snapshot = pending.snapshot;
        message.parts = pending.parts;
        message.part = pending.part;
        message.update.value = pending.watermark;
        switch (pending.phase) {
            .begin => {
                message.op = .snapshot_begin;
                pending.phase = .chunks;
            },
            .chunks => {
                const remaining = self.payload.slice()[pending.offset..];
                const length = s.fragmentLength(remaining);
                message.op = if (pending.snapshot) .snapshot_chunk else .delta;
                message.data = remaining[0..length];
                pending.offset += length;
                pending.part += 1;
                if (pending.offset == self.payload.len) pending.phase = .end;
            },
            .end => message.op = .snapshot_end,
        }
        const complete = message.op == .snapshot_end or
            (!pending.snapshot and pending.phase == .end);
        self.pending = if (complete) null else pending;
        if (complete) self.states[@backingInt(pending.topic)].phase = .live;
        try self.offer(message);
    }

    fn delta(self: *Subscriber, context: Context, topic: p.Topic, store: *topics.Store) !bool {
        const state = &self.states[@backingInt(topic)];
        var record: topics.Journal.Record = undefined;
        switch (store.ring.read(context.io, state.cursor, &record)) {
            .busy, .empty => return false,
            .gap => |gap| {
                self.pause(topic, gap.dropped);
                return false;
            },
            .record => {},
        }
        if (record.metadata.kind == .gap) {
            self.pause(topic, 1);
            return false;
        }
        if (self.filteredView(context, topic) != null) {
            if (self.pending == null) try self.filteredState(context, topic, store);
            return false;
        }
        state.cursor += 1;
        if (record.metadata.kind == .row and !record.metadata.matches(&state.args)) return false;
        var message = self.envelope(topic);
        var epoch: [64]u8 = undefined;
        message.epoch = try self.formatEpoch(topic, context.boot, &epoch);
        message.op = .delta;
        message.snapshot = false;
        message.watermark.value = state.cursor - 1;
        message.update.value = record.metadata.update;
        message.part = record.metadata.part;
        message.parts = record.metadata.parts;
        message.kind = if (record.metadata.kind == .row) .row else .patch;
        message.data = record.payload();
        try self.offer(message);
        return true;
    }

    fn filteredView(self: *Subscriber, context: Context, topic: p.Topic) ?*p.Bytes(16384) {
        if (topic == .stats and context.dashboard != null) return &self.stats_view;
        if (topic == .nodes and self.states[@backingInt(topic)].args.node != null)
            return &self.node_view;
        return null;
    }

    fn filteredState(
        self: *Subscriber,
        context: Context,
        topic: p.Topic,
        store: *topics.Store,
    ) !void {
        const state = &self.states[@backingInt(topic)];
        const previous = self.filteredView(context, topic).?;
        var view: std.Io.Writer = .fixed(context.scratch);
        try snapshotView(context, topic, store, &state.args, &view);
        var writer: std.Io.Writer = .fixed(&self.payload.data);
        const changed = try p.json_delta.write(
            context.arena,
            previous.slice(),
            view.buffered(),
            &writer,
        );
        try previous.set(view.buffered());
        state.cursor = store.ring.watermark() + 1;
        if (!changed) return;
        self.payload.len = writer.buffered().len;
        state.phase = .streaming;
        self.pending = .{
            .topic = topic,
            .snapshot = false,
            .phase = .chunks,
            .watermark = state.cursor - 1,
            .parts = parts(self.payload.slice()),
        };
    }

    fn envelope(self: *Subscriber, topic: p.Topic) Message {
        return .{
            .op = .delta,
            .topic = topic,
            .epoch = "",
            .seq = .{ .value = self.states[@backingInt(topic)].sequence },
            .snapshot = false,
            .watermark = .{ .value = 0 },
        };
    }

    fn formatEpoch(self: *Subscriber, topic: p.Topic, boot: [32]u8, buffer: []u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{s}:{d}", .{
            boot, self.states[@backingInt(topic)].epoch,
        });
    }

    fn offer(self: *Subscriber, message_value: Message) !void {
        const state = &self.states[@backingInt(message_value.topic)];
        var frame: queue.Frame = .{
            .topic = message_value.topic,
            .epoch = state.epoch,
            .bytes = .{},
        };
        var writer: std.Io.Writer = .fixed(&frame.bytes.data);
        try std.json.Stringify.value(message_value, .{}, &writer);
        frame.bytes.len = writer.buffered().len;
        if (self.outbox.offer(frame)) |topic| {
            self.states[@backingInt(topic)].phase = .paused;
            if (self.pending != null and self.pending.?.topic == topic) self.pending = null;
        }
        state.sequence += 1;
    }

    fn pause(self: *Subscriber, topic: p.Topic, dropped: u64) void {
        const state = &self.states[@backingInt(topic)];
        self.outbox.invalidate(topic, state.epoch, dropped);
        state.phase = .paused;
        if (self.pending != null and self.pending.?.topic == topic) self.pending = null;
    }
};

fn parts(bytes: []const u8) u16 {
    var count: u16 = 0;
    var position: usize = 0;
    while (position < bytes.len) : (count += 1) position += s.fragmentLength(bytes[position..]);
    return count;
}

// The feeder owns both the copied dashboard frame and stores throughout a pump. A pending
// fragmented message owns its serialized bytes, so later ticks cannot change its contents.
fn snapshotView(
    context: Context,
    topic: p.Topic,
    store: *topics.Store,
    args: *const s.Args,
    writer: *std.Io.Writer,
) !void {
    if (topic == .stats) if (context.dashboard) |dashboard|
        return std.json.Stringify.value(dashboard.view(args.node), .{}, writer);
    return store.snapshot(topic, args, context.arena, writer);
}

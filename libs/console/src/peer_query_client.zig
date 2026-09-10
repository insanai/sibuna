//! One in-flight query per TLS connection; the remaining eight slots are bounded admission.
//! Replies are fenced by the authenticated boot and connection generation. Reconnects fail
//! pending work instead of replaying a cursor against a different issuer boot.
const std = @import("std");
const q = @import("peer_query.zig");
const peers = @import("peer_store.zig");
pub const Session = struct {
    store: *peers.Store,
    handle: peers.Handle,
    pending: ?q.Mailbox.Work = null,
    sent_at: i96 = 0,

    pub fn deinit(self: *Session) void {
        if (self.pending != null) self.finish(.{ .failed = .unavailable }) catch |err| {
            std.log.err("peer query completion: {t}", .{err});
        };
    }

    pub fn next(self: *Session, writer: *std.Io.Writer) !bool {
        const now = std.Io.Clock.awake.now(self.store.io).nanoseconds;
        if (self.pending != null) {
            if (now - self.sent_at >= 5 * std.time.ns_per_s) return error.PeerQueryTimeout;
            return false;
        }
        const queue = self.store.queries[self.handle.index] orelse return false;
        const work = queue.take(self.store.io) orelse return false;
        self.pending = work;
        self.sent_at = now;
        if (work.request.generation != self.handle.generation or
            !std.mem.eql(u8, &work.request.boot, &self.handle.boot))
        {
            try self.finish(.{ .failed = .unavailable });
            return false;
        }
        try std.json.Stringify.value(q.Wire{
            .op = .peer_query,
            .id = work.ticket.id,
            .kind = work.request.kind,
            .cursor = work.request.cursor,
        }, .{}, writer);
        return true;
    }

    pub fn receive(self: *Session, value: std.json.Value, gpa: std.mem.Allocator) !bool {
        if (!q.operation(value, "peer_result")) return false;
        const work = self.pending orelse return error.UnexpectedPeerReply;
        const reply = try std.json.parseFromValue(struct {
            op: enum { peer_result },
            id: u64,
            node: u32,
            boot: [16]u8,
            status: q.Status,
            data: std.json.Value,
        }, gpa, value, .{});
        defer reply.deinit();
        const r = reply.value;
        const node = self.store.config.targets[self.handle.index].node;
        if (r.id != work.ticket.id or r.node != node or
            !std.mem.eql(u8, &r.boot, &self.handle.boot)) return error.InvalidPeerReply;
        if (r.status != .ok) {
            if (r.data != .null) return error.InvalidPeerReply;
            try self.finish(.{ .failed = r.status });
            return true;
        }
        try validate(work.request.kind, r.data, gpa, r.node, r.boot);
        var result: q.Result = .{ .page = .{} };
        var writer: std.Io.Writer = .fixed(&result.page.data);
        try std.json.Stringify.value(r.data, .{}, &writer);
        result.page.len = writer.buffered().len;
        try self.finish(result);
        return true;
    }

    fn finish(self: *Session, result: q.Result) !void {
        const work = self.pending orelse return error.UnexpectedPeerReply;
        const queue = self.store.queries[self.handle.index] orelse unreachable;
        try queue.complete(self.store.io, work.ticket, result);
        self.pending = null;
    }
};

fn validate(
    kind: q.Kind,
    value: std.json.Value,
    gpa: std.mem.Allocator,
    node: u32,
    boot: [16]u8,
) !void {
    const p = @import("console_protocol");
    switch (kind) {
        .timeline => {
            const parsed = try std.json.parseFromValue(p.timeline.Page, gpa, value, .{});
            defer parsed.deinit();
            const page = parsed.value;
            if (page.version != 1 or page.node != node or page.rows.len > 8 or
                !std.mem.eql(u8, page.boot, &std.fmt.bytesToHex(boot, .lower)))
                return error.InvalidPeerReply;
        },
        .rankings => {
            const parsed = try std.json.parseFromValue(p.rankings.Page, gpa, value, .{});
            defer parsed.deinit();
            const page = parsed.value;
            if (page.node != node or page.rows.len > 8 or
                !std.mem.eql(u8, &page.boot, &boot) or
                !std.mem.eql(u8, page.kind, "path_prefix") or
                !std.mem.eql(u8, page.sampling_probability, "1/64"))
                return error.InvalidPeerReply;
            for (page.rows) |row| if (row.key.len >
                @as(usize, if (row.encoding == .hex) 256 else 128) or
                row.error_bound > row.estimate) return error.InvalidPeerReply;
        },
    }
}

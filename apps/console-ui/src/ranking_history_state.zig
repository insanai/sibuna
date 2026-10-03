//! A retained population is published only after complete-archive validation and merge.
const std = @import("std");
const p = @import("console_protocol");
const wire = p.ranking_history;
pub const Reply = struct {
    version: u8,
    metadata: struct {
        from_minute: u64,
        until_minute: u64,
        retention_days: u16,
        observed_at: u64,
        cursor: ?wire.Cursor,
        next: ?wire.Cursor,
    },
    archive: []const u8,
};
pub const Window = struct {
    query: wire.Request = .{ .from_minute = 0, .until_minute = 0 },
    summary: p.space_saving.Summary = .{},
    referrers: p.ranking_storage.Referrers = .{},
    families: p.ranking_storage.Families = .{},
    /// Archives that carried referrers and families; older archives count only paths.
    extended: u32 = 0,
    archives: u32 = 0,
    truncated: u64 = 0,
    rejected: u64 = 0,
    reported_loss: bool = false,
    finished: bool = false,
    earliest: ?u64 = null,
    latest: ?u64 = null,
    retention_days: ?u16 = null,
    retention_clipped: bool = false,

    pub fn accept(self: *Window, reply: Reply, work: *Workspace) !void {
        if (self.finished or reply.version != 1 or
            reply.metadata.until_minute != self.query.until_minute or
            reply.metadata.from_minute < self.query.from_minute or
            reply.metadata.until_minute >= reply.metadata.observed_at / 60 or
            reply.metadata.retention_days == 0 or reply.metadata.retention_days > 90)
            return error.InvalidResponse;
        if (self.retention_days) |days| if (days != reply.metadata.retention_days)
            return error.InvalidResponse;
        work.candidate = self.*;
        const candidate = &work.candidate;
        if (reply.metadata.cursor) |cursor| {
            try candidate.merge(self, reply, cursor, work);
        } else if (reply.archive.len != 0 or reply.metadata.next != null)
            return error.InvalidResponse;
        candidate.query.before = reply.metadata.next;
        candidate.finished = reply.metadata.next == null;
        candidate.retention_days = reply.metadata.retention_days;
        candidate.retention_clipped = candidate.retention_clipped or
            reply.metadata.from_minute > self.query.from_minute;
        self.* = candidate.*;
    }

    fn merge(
        self: *Window,
        previous: *const Window,
        reply: Reply,
        cursor: wire.Cursor,
        work: *Workspace,
    ) !void {
        if (cursor.minute < reply.metadata.from_minute or
            cursor.minute > self.query.until_minute or
            cursor.digest.len != 64 or reply.archive.len > p.ranking_storage.max_bytes * 2)
            return error.InvalidResponse;
        if (self.query.before) |before| if (!wire.precedes(cursor, before))
            return error.InvalidResponse;
        if (reply.metadata.next) |next| if (!std.meta.eql(next, cursor))
            return error.InvalidResponse;
        const decoded = try std.fmt.hexToBytes(&work.bytes, reply.archive);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(decoded, &digest, .{});
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), cursor.digest.slice()))
            return error.InvalidResponse;
        try p.rankings_archive.decodeInto(&work.archive, decoded);
        const archive = &work.archive;
        if (archive.minute.minute != cursor.minute or (self.query.node != null and
            archive.identity.node != self.query.node.?)) return error.InvalidResponse;
        try p.space_saving.Summary.mergeInto(
            &self.summary,
            &previous.summary,
            &archive.minute.paths,
            &work.candidates,
        );
        try p.ranking_storage.Referrers.mergeInto(
            &self.referrers,
            &previous.referrers,
            &archive.minute.referrers,
            &work.referrer_candidates,
        );
        if (archive.minute.extended) {
            self.extended = try std.math.add(u32, self.extended, 1);
            inline for (.{ "os", "browser", "status" }) |name| {
                const totals = &@field(self.families, name);
                for (totals, @field(archive.minute.families, name)) |*total, count|
                    total.* = try std.math.add(u64, total.*, count);
            }
        }
        self.truncated = try std.math.add(u64, self.truncated, archive.minute.truncated_records);
        self.rejected = try std.math.add(u64, self.rejected, archive.minute.rejected_records);
        self.archives = try std.math.add(u32, self.archives, 1);
        self.reported_loss = self.reported_loss or archive.identity.queue_loss_end != 0;
        self.earliest = cursor.minute;
        if (self.latest == null) self.latest = cursor.minute;
    }
};
/// A single browser event owns this scratch; no archive or candidate survives publication.
pub const Workspace = struct {
    candidate: Window,
    archive: p.rankings_archive.Archive,
    bytes: [p.ranking_storage.max_bytes]u8,
    candidates: [512]p.space_saving.Summary.Counter,
    referrer_candidates: [512]p.ranking_storage.Referrers.Counter,
};
pub const Inputs = struct {
    mode: enum { previous, yesterday, node } = .previous,
    minutes: u32 = 60,
    offset: u32 = 0,
    node: u32 = 0,
    other_node: u32 = 0,
};
pub const Model = struct {
    inputs: Inputs = .{},
    open: bool = false,
    started: bool = false,
    windows: [2]Window = @splat(.{}),
    ticket: u64 = 0,
    side: usize = 0,
    busy: bool = false,
    remaining: u8 = 0,
    message: p.Bytes(192) = .{},

    pub fn clear(self: *Model) void {
        const metadata = @typeInfo(Model).@"struct";
        inline for (metadata.field_names, 0..) |field_name, index| {
            const FieldType = @FieldType(Model, field_name);
            if (comptime std.mem.eql(u8, field_name, "windows")) {
                for (&self.windows) |*window| window.* = .{};
            } else {
                const attrs = metadata.field_attrs[index];
                @field(self, field_name) = attrs.defaultValue(FieldType).?;
            }
        }
    }
};

test "archive pagination merges all counters and rejects replay without partial publication" {
    const t = std.testing;
    var window: Window = .{ .query = .{ .from_minute = 1, .until_minute = 2, .node = 7 } };
    var source: p.rankings_archive.Archive = .{
        .identity = .{ .node = 7, .boot = @splat(1) },
        .minute = .{ .minute = 2, .first_second = 120, .last_second = 120 },
    };
    for (0..256) |i| {
        var key: [8]u8 = undefined;
        try source.minute.paths.add(try std.fmt.bufPrint(&key, "/{d}", .{i}));
    }
    var encoded: [p.ranking_storage.max_bytes]u8 = undefined;
    const bytes = try p.rankings_archive.encode(&source, &encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const cursor: wire.Cursor = .{
        .minute = 2,
        .digest = try p.Bytes(64).init(&std.fmt.bytesToHex(digest, .lower)),
    };
    const hex = std.fmt.bytesToHex(encoded, .lower);
    const reply: Reply = .{ .version = 1, .archive = hex[0 .. bytes.len * 2], .metadata = .{
        .from_minute = 1,
        .until_minute = 2,
        .retention_days = 7,
        .observed_at = 240,
        .cursor = cursor,
        .next = cursor,
    } };
    var work: Workspace = undefined;
    try window.accept(reply, &work);
    try t.expectEqual(@as(usize, 256), window.summary.len);
    const saved = window;
    try t.expectError(error.InvalidResponse, window.accept(reply, &work));
    try t.expectEqualDeep(saved, window);
}

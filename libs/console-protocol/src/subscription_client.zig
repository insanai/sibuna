//! Browser-independent, transactional chunk reassembly. A gap preserves the last good
//! view and forbids further deltas until a new subscription epoch supplies a snapshot.
const std = @import("std");
const p = @import("root.zig");
const s = p.subscriptions;
pub const Event = union(enum) { none, unauthorized, gap: p.Topic, changed: p.Topic };
pub const Error = error{ InvalidMessage, TooLarge, WriteFailed, OutOfMemory };
const Slot = struct {
    epoch: p.Bytes(64) = .{},
    sequence: u64 = 0,
    watermark: u64 = 0,
    update: u64 = 0,
    part: u16 = 0,
    parts: u16 = 0,
    pending: bool = false,
    snapshot: bool = false,
    row: bool = false,
    blocked: bool = true,
    current: p.Bytes(s.snapshot_bytes) = .{},
    incoming: p.Bytes(s.snapshot_bytes) = .{},
};
pub const Client = struct {
    slots: [s.topic_count]Slot = @splat(.{}),
    scratch: [s.snapshot_bytes]u8 = undefined,

    pub fn reset(self: *Client) void {
        for (&self.slots) |*slot| {
            std.crypto.secureZero(u8, std.mem.asBytes(slot));
            slot.blocked = true;
        }
        std.crypto.secureZero(u8, &self.scratch);
    }

    pub fn view(self: *const Client, topic: p.Topic) []const u8 {
        return self.slots[@intFromEnum(topic)].current.slice();
    }

    pub const Position = struct { sequence: u64, watermark: u64 };

    /// Only completed, gap-free views have a position that consumers may acknowledge.
    pub fn position(self: *const Client, topic: p.Topic) ?Position {
        const slot = &self.slots[@intFromEnum(topic)];
        if (slot.pending or slot.blocked) return null;
        return .{ .sequence = slot.sequence, .watermark = slot.watermark };
    }

    pub fn receive(
        self: *Client,
        value: std.json.Value,
        allocator: std.mem.Allocator,
    ) Error!Event {
        if (value != .object) return error.InvalidMessage;
        if (value.object.contains("error")) {
            if (!std.mem.eql(u8, try text(value, "error"), "unauthorized"))
                return error.InvalidMessage;
            return .unauthorized;
        }
        const op = try text(value, "op");
        if (std.mem.eql(u8, op, "pong")) return .none;
        const topic = std.meta.stringToEnum(p.Topic, try text(value, "topic")) orelse
            return error.InvalidMessage;
        const slot = &self.slots[@intFromEnum(topic)];
        const epoch = try text(value, "epoch");
        if (std.mem.eql(u8, op, "snapshot_begin")) {
            try begin(slot, value, epoch);
            return .none;
        }
        if (!std.mem.eql(u8, epoch, slot.epoch.slice())) return error.InvalidMessage;
        if (std.mem.eql(u8, op, "gap")) {
            _ = try number(value, "dropped");
            slot.blocked = true;
            slot.pending = false;
            try slot.incoming.set("");
            return .{ .gap = topic };
        }
        if (slot.blocked) return error.InvalidMessage;
        const sequence = try number(value, "seq");
        if (slot.sequence == std.math.maxInt(u64) or sequence != slot.sequence + 1)
            return error.InvalidMessage;
        if (std.mem.eql(u8, op, "snapshot_end")) {
            try snapshotFlag(value, true);
            if (!slot.pending or !slot.snapshot or slot.part != slot.parts or
                try number(value, "watermark") != slot.watermark) return error.InvalidMessage;
            try self.commit(slot, allocator);
        } else {
            const snapshot = std.mem.eql(u8, op, "snapshot_chunk");
            if (!snapshot and !std.mem.eql(u8, op, "delta")) return error.InvalidMessage;
            try append(slot, value, snapshot);
            if (snapshot or slot.part != slot.parts) {
                slot.sequence = sequence;
                return .none;
            }
            try self.commit(slot, allocator);
        }
        slot.sequence = sequence;
        return .{ .changed = topic };
    }

    fn commit(self: *Client, slot: *Slot, allocator: std.mem.Allocator) Error!void {
        const incoming = try parse(allocator, slot.incoming.slice());
        defer incoming.deinit();
        if (slot.snapshot) {
            try slot.current.set(slot.incoming.slice());
        } else {
            var old = try parse(allocator, slot.current.slice());
            defer old.deinit();
            if (slot.row) {
                try addRow(&old.value, incoming.value);
            } else {
                p.json_delta.apply(old.arena.allocator(), &old.value, incoming.value) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.InvalidMessage;
                };
            }
            var writer: std.Io.Writer = .fixed(&self.scratch);
            try std.json.Stringify.value(old.value, .{}, &writer);
            try slot.current.set(writer.buffered());
        }
        slot.pending = false;
        try slot.incoming.set("");
    }
};

fn begin(slot: *Slot, value: std.json.Value, epoch: []const u8) Error!void {
    try snapshotFlag(value, true);
    if (epoch.len < 34 or epoch.len > 64 or epoch[32] != ':' or
        std.mem.eql(u8, epoch, slot.epoch.slice()) or try number(value, "seq") != 0)
        return error.InvalidMessage;
    for (epoch[0..32]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidMessage;
    _ = std.fmt.parseInt(u64, epoch[33..], 10) catch return error.InvalidMessage;
    const parts = try number(value, "parts");
    if (parts == 0 or parts > s.snapshot_bytes / (s.fragment_bytes - 3) + 1)
        return error.InvalidMessage;
    try slot.epoch.set(epoch);
    try slot.incoming.set("");
    slot.sequence = 0;
    slot.watermark = try number(value, "watermark");
    slot.parts = @intCast(parts);
    slot.part = 0;
    slot.snapshot = true;
    slot.pending = true;
    slot.blocked = false;
}

fn append(slot: *Slot, value: std.json.Value, snapshot: bool) Error!void {
    try snapshotFlag(value, snapshot);
    const part = try number(value, "part");
    const parts = try number(value, "parts");
    const watermark = try number(value, "watermark");
    if (parts == 0 or parts > s.snapshot_bytes / (s.fragment_bytes - 3) + 1)
        return error.InvalidMessage;
    if (!snapshot and part == 0) {
        if (slot.pending or watermark < slot.watermark) return error.InvalidMessage;
        slot.update = try number(value, "update");
        slot.watermark = watermark;
        slot.part = 0;
        slot.parts = @intCast(parts);
        slot.snapshot = false;
        slot.pending = true;
        const kind = try text(value, "kind");
        slot.row = std.mem.eql(u8, kind, "row");
        if (!slot.row and !std.mem.eql(u8, kind, "patch")) return error.InvalidMessage;
        try slot.incoming.set("");
    }
    if (!slot.pending or slot.snapshot != snapshot or part != slot.part or
        parts != slot.parts or part >= parts) return error.InvalidMessage;
    if (snapshot) {
        if (watermark != slot.watermark) return error.InvalidMessage;
    } else {
        if (try number(value, "update") != slot.update or watermark < slot.watermark)
            return error.InvalidMessage;
        slot.watermark = watermark;
    }
    const data = try text(value, "data");
    if (data.len == 0 or data.len > s.fragment_bytes or
        data.len > s.snapshot_bytes - slot.incoming.len) return error.TooLarge;
    @memcpy(slot.incoming.data[slot.incoming.len..][0..data.len], data);
    slot.incoming.len += data.len;
    slot.part += 1;
}

fn addRow(state: *std.json.Value, row: std.json.Value) Error!void {
    const rows = state.object.getPtr("rows") orelse return error.InvalidMessage;
    if (rows.* != .array or rows.array.items.len > 64) return error.InvalidMessage;
    const id = try number(row, "id");
    for (rows.array.items) |item| if (try number(item, "id") == id) return error.InvalidMessage;
    try rows.array.ensureTotalCapacity(64);
    if (rows.array.items.len < 64) rows.array.items.len += 1;
    std.mem.copyBackwards(
        std.json.Value,
        rows.array.items[1..],
        rows.array.items[0 .. rows.array.items.len - 1],
    );
    rows.array.items[0] = row;
}

fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!std.json.Parsed(std.json.Value) {
    const result = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidMessage;
    if (result.value != .object) {
        result.deinit();
        return error.InvalidMessage;
    }
    return result;
}

fn text(value: std.json.Value, key: []const u8) Error![]const u8 {
    if (value != .object) return error.InvalidMessage;
    const item = value.object.get(key) orelse return error.InvalidMessage;
    return if (item == .string) item.string else error.InvalidMessage;
}

fn number(value: std.json.Value, key: []const u8) Error!u64 {
    if (value != .object) return error.InvalidMessage;
    const item = value.object.get(key) orelse return error.InvalidMessage;
    if (item == .integer and item.integer >= 0) return @intCast(item.integer);
    if (item == .string) {
        if (item.string.len == 0 or item.string.len > 20) return error.InvalidMessage;
        for (item.string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidMessage;
        return std.fmt.parseInt(u64, item.string, 10) catch error.InvalidMessage;
    }
    return error.InvalidMessage;
}

fn snapshotFlag(value: std.json.Value, expected: bool) Error!void {
    const flag = value.object.get("snapshot") orelse return error.InvalidMessage;
    if (flag != .bool or flag.bool != expected) return error.InvalidMessage;
}

const TestFrame = struct {
    op: []const u8,
    topic: []const u8 = "stats",
    epoch: []const u8 = "a" ** 32 ++ ":1",
    seq: u64 = 0,
    snapshot: bool = true,
    watermark: u64 = 0,
    parts: u16 = 1,
    part: u16 = 0,
    update: u64 = 1,
    kind: []const u8 = "patch",
    data: ?[]const u8 = null,
};

fn testFrame(client: *Client, frame: TestFrame) !Event {
    var bytes: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(frame, .{}, &writer);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    return client.receive(parsed.value, std.testing.allocator);
}

test "client commits complete snapshots and patches without losing its last good view" {
    const t = std.testing;
    const client = try t.allocator.create(Client);
    defer t.allocator.destroy(client);
    client.* = .{};
    _ = try testFrame(client, .{ .op = "snapshot_begin" });
    _ = try testFrame(client, .{
        .op = "snapshot_chunk",
        .seq = 1,
        .data = "{\"requests\":1}",
    });
    try t.expectEqualStrings("", client.view(.stats));
    try t.expectEqual(p.Topic.stats, (try testFrame(client, .{
        .op = "snapshot_end",
        .seq = 2,
    })).changed);
    _ = try testFrame(client, .{
        .op = "delta",
        .snapshot = false,
        .seq = 3,
        .watermark = 1,
        .data = "{\"set\":{\"requests\":\"9007199254740993\"},\"remove\":[]}",
    });
    try t.expectEqualStrings("{\"requests\":\"9007199254740993\"}", client.view(.stats));
    try t.expectError(error.InvalidMessage, testFrame(client, .{
        .op = "delta",
        .snapshot = false,
        .seq = 4,
        .watermark = 2,
        .data = "{\"set\":{\"requests\":2},\"remove\":[\"requests\"]}",
    }));
    try t.expectEqualStrings("{\"requests\":\"9007199254740993\"}", client.view(.stats));
    _ = try testFrame(client, .{ .op = "snapshot_begin", .epoch = "b" ** 32 ++ ":2", .parts = 2 });
    _ = try testFrame(client, .{
        .op = "snapshot_chunk",
        .epoch = "b" ** 32 ++ ":2",
        .parts = 2,
        .seq = 1,
        .data = "{\"requests\":",
    });
    try t.expectError(error.InvalidMessage, testFrame(client, .{
        .op = "snapshot_end",
        .epoch = "b" ** 32 ++ ":2",
        .seq = 2,
        .parts = 2,
    }));
    try t.expectEqualStrings("{\"requests\":\"9007199254740993\"}", client.view(.stats));
    client.reset();
    try t.expectEqualStrings("", client.view(.stats));
    try t.expect(std.mem.allEqual(u8, &client.slots[0].current.data, 0));
}

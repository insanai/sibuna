//! Managed-policy workflows that ride the manager's request plumbing: ordering, replay of
//! retained events against the draft, and the chunked replace-all import with its review.
const std = @import("std");
const p = @import("console_protocol");
const Controller = @import("managed_controller.zig").Controller;
const string = @import("events_state.zig").string;
const field = @import("events_state.zig").field;
const equal = std.mem.eql;
pub const Stage = enum { idle, review, sending, committing };
pub const Import = struct {
    stage: Stage = .idle,
    count: u16 = 0,
    sent: u16 = 0,
    digest: [64]u8 = @splat(0),
    expected: p.Bytes(20) = .{},
};
/// Staged documents live outside the state struct: a 64 KiB set is not data-segment zeros.
var documents: [64 * 1024]u8 = undefined;
var offsets: [129]u32 = undefined;
var arena_bytes: [384 * 1024]u8 = undefined;
var replay_bytes: [2048]u8 = undefined;
var replay_len: u16 = 0;

pub fn replay() []const u8 {
    return replay_bytes[0..replay_len];
}

pub fn clearReplay() void {
    replay_len = 0;
}

pub fn action(self: Controller, name: []const u8, fields: std.json.Value) !bool {
    const manager = &self.state.policies.manager;
    const up = std.mem.startsWith(u8, name, "managed-up:");
    if (up or std.mem.startsWith(u8, name, "managed-down:")) {
        if (!self.state.allows(.manage_policy) or manager.committed.len == 0) return true;
        try self.post("order", .{
            .id = name[if (up) "managed-up:".len else "managed-down:".len..],
            .expected_revision = manager.committed.slice(),
            .direction = if (up) "up" else "down",
        });
        return true;
    }
    if (equal(u8, name, "managed-replay")) {
        var document: p.Bytes(4096) = .{};
        if (!try self.captureDocument(fields, &document)) return true;
        try self.post("replay", .{
            .rule = manager.form.name.slice(),
            .hours = @as(u16, 24),
            .draft = document.slice(),
            .committed = manager.committed.slice(),
        });
        return true;
    }
    if (equal(u8, name, "managed-import-all")) return review(self, string(fields, "documents"));
    if (equal(u8, name, "managed-import-cancel")) {
        manager.import_all = .{};
        return true;
    }
    if (equal(u8, name, "managed-import-confirm") and manager.import_all.stage == .review) {
        manager.import_all.stage = .sending;
        manager.import_all.sent = 0;
        try sendChunk(self);
        return true;
    }
    return false;
}

/// Parses the pasted set, stores compact documents and shows the digest and count to
/// confirm. Nothing is sent until the operator confirms.
fn review(self: Controller, text: []const u8) !bool {
    const manager = &self.state.policies.manager;
    if (!self.state.allows(.manage_policy) or manager.committed.len == 0) return true;
    var arena = std.heap.FixedBufferAllocator.init(&arena_bytes);
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), text, .{}) catch {
        self.message("The policy set must be a JSON array of rule documents.");
        return true;
    };
    if (root != .array or root.array.items.len == 0 or root.array.items.len > 128) {
        self.message("The policy set must hold between 1 and 128 rule documents.");
        return true;
    }
    // The key only groups chunks; the storage owner hashes the staged set at commit.
    var key: [32]u8 = undefined;
    var used: usize = 0;
    for (root.array.items, 0..) |item, index| {
        if (item != .object) {
            self.message("Every entry of the policy set must be a rule document.");
            return true;
        }
        var writer: std.Io.Writer = .fixed(documents[used..]);
        std.json.Stringify.value(item, .{}, &writer) catch {
            self.message("The policy set exceeds 64 KiB of compact documents.");
            return true;
        };
        const bytes = writer.buffered();
        if (bytes.len > 4096) {
            self.message("One rule document exceeds 4 KiB.");
            return true;
        }
        offsets[index] = @intCast(used);
        used += bytes.len;
        offsets[index + 1] = @intCast(used);
    }
    // Session-unique staging key: this session's CSRF text, the time, the size and count.
    const csrf = self.state.csrf.slice();
    for (&key, 0..) |*byte, index| byte.* = if (index < csrf.len) csrf[index] else 0;
    std.mem.writeInt(u64, key[0..8], self.state.browser_time, .little);
    std.mem.writeInt(u32, key[8..12], @intCast(used), .little);
    key[12] = @intCast(root.array.items.len);
    manager.import_all = .{
        .stage = .review,
        .count = @intCast(root.array.items.len),
        .digest = std.fmt.bytesToHex(key, .lower),
        .expected = manager.committed,
    };
    return true;
}

fn sendChunk(self: Controller) !void {
    const import_all = &self.state.policies.manager.import_all;
    const index = import_all.sent;
    try self.post("import-chunk", .{
        .digest = @as([]const u8, &import_all.digest),
        .ordinal = index,
        .document = documents[offsets[index]..offsets[index + 1]],
    });
}

/// True when the response belonged to a workflow ticket and has been consumed.
pub fn response(self: Controller, id: []const u8, body: std.json.Value) !bool {
    const state = self.state;
    const manager = &state.policies.manager;
    if (std.mem.startsWith(u8, id, "managed-order-")) {
        try manager.committed.set(string(body, "committed"));
        manager.snapshot = .{};
        manager.next = .{};
        state.message_success = true;
        self.message("Rule moved. The data plane applies the order after its next rebuild.");
        try self.post("catalog", .{ .kind = "catalog" });
        return true;
    }
    if (std.mem.startsWith(u8, id, "managed-replay-")) {
        var writer: std.Io.Writer = .fixed(&replay_bytes);
        try std.json.Stringify.value(body, .{}, &writer);
        replay_len = @intCast(writer.buffered().len);
        try self.out.emit(.{ .op = "focus", .selector = "#policy-replay" });
        return true;
    }
    if (std.mem.startsWith(u8, id, "managed-import-chunk-")) {
        manager.import_all.sent += 1;
        if (manager.import_all.sent < manager.import_all.count) {
            try sendChunk(self);
            return true;
        }
        manager.import_all.stage = .committing;
        try self.post("import-commit", .{
            .digest = @as([]const u8, &manager.import_all.digest),
            .count = manager.import_all.count,
            .expected_revision = manager.import_all.expected.slice(),
        });
        return true;
    }
    if (std.mem.startsWith(u8, id, "managed-import-commit-")) {
        try manager.committed.set(string(body, "committed"));
        manager.import_all = .{};
        manager.view = .catalog;
        manager.snapshot = .{};
        manager.next = .{};
        state.message_success = true;
        self.message("Policy set replaced. The data plane applies it after its next rebuild.");
        try self.post("catalog", .{ .kind = "catalog" });
        return true;
    }
    return false;
}

/// A failed chunk or commit leaves the staged set for review again.
pub fn failed(self: Controller, id: []const u8) void {
    if (!std.mem.startsWith(u8, id, "managed-import-")) return;
    const import_all = &self.state.policies.manager.import_all;
    if (import_all.stage == .sending or import_all.stage == .committing)
        import_all.stage = .review;
}

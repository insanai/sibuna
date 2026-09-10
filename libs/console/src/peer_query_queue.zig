//! Reader-to-writer handoff contains only owned protocol values. Slow replies cannot stop
//! the reader from consuming ping, close or subscription messages.
const std = @import("std");
const q = @import("peer_query.zig");
pub const Queue = struct {
    mutex: std.Io.Mutex = .init,
    items: [8]q.Wire = undefined,
    head: usize = 0,
    count: usize = 0,

    pub fn accept(self: *Queue, io: std.Io, payload: []const u8) !bool {
        var memory: [8192]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&memory);
        const json = try std.json.parseFromSlice(std.json.Value, fixed.allocator(), payload, .{});
        defer json.deinit();
        if (!q.operation(json.value, "peer_query")) return false;
        const parsed = try std.json.parseFromValue(q.Wire, fixed.allocator(), json.value, .{});
        defer parsed.deinit();
        const request = parsed.value;
        if (request.id == 0 or request.cursor.limit == 0 or request.cursor.limit > 8)
            return error.InvalidRequest;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.count == self.items.len) return error.Full;
        self.items[(self.head + self.count) % self.items.len] = request;
        self.count += 1;
        return true;
    }

    pub fn take(self: *Queue, io: std.Io) ?q.Wire {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.count == 0) return null;
        const request = self.items[self.head];
        self.head = (self.head + 1) % self.items.len;
        self.count -= 1;
        return request;
    }
};

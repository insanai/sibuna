//! Immutable generations have one owner. Readers hold the registry lock only for lookup;
//! a rejected staging attempt never mutates or frees the active generation.
const std = @import("std");
const geo = @import("geoip.zig");
pub const max_csv_bytes = 128 * 1024 * 1024;
pub const max_ranges = 1024 * 1024;
pub const Generation = struct {
    allocator: std.mem.Allocator,
    ranges: []const geo.Range,
    digest: [32]u8,

    pub fn fromCsv(allocator: std.mem.Allocator, csv: []const u8) !Generation {
        if (csv.len == 0 or csv.len > max_csv_bytes) return error.Capacity;
        var lines = std.mem.splitScalar(u8, csv, '\n');
        var count: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0 and lines.peek() == null) break;
            if (line.len > 128) return error.InvalidRow;
            count += 1;
            if (count > max_ranges) return error.Capacity;
        }
        const storage = try allocator.alloc(geo.Range, count);
        errdefer allocator.free(storage);
        var builder: geo.Builder = .{ .storage = storage };
        lines.reset();
        while (lines.next()) |line| {
            if (line.len == 0 and lines.peek() == null) break;
            try builder.append(line);
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(csv, &digest, .{});
        return .{
            .allocator = allocator,
            .ranges = try builder.finish(),
            .digest = digest,
        };
    }

    pub fn deinit(self: *Generation) void {
        self.allocator.free(self.ranges);
        self.* = undefined;
    }
};

pub const Registry = struct {
    mutex: std.Io.Mutex = .init,
    importing: std.atomic.Value(bool) = .init(false),
    active: ?Generation = null,
    revision: u64 = 0,

    pub fn begin(self: *Registry) error{Busy}!void {
        if (self.importing.cmpxchgStrong(false, true, .acquire, .monotonic) != null)
            return error.Busy;
    }

    pub fn end(self: *Registry) void {
        std.debug.assert(self.importing.load(.monotonic));
        self.importing.store(false, .release);
    }

    /// Caller retains staged ownership on conflict; ownership transfers only on success.
    /// Publish only after the storage owner has durably committed the matching generation.
    pub fn activate(
        self: *Registry,
        io: std.Io,
        staged: Generation,
        expected_revision: u64,
    ) error{Conflict}!void {
        std.debug.assert(self.importing.load(.acquire));
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.revision != expected_revision) return error.Conflict;
        var old = self.active;
        self.active = staged;
        self.revision += 1;
        if (old) |*generation| generation.deinit();
    }

    pub fn lookup(self: *Registry, io: std.Io, address: [16]u8) ?[2]u8 {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const active = self.active orelse return null;
        return geo.lookup(active.ranges, address);
    }

    /// The composing service joins both collectors and importers before destruction.
    pub fn deinit(self: *Registry) void {
        std.debug.assert(!self.importing.load(.acquire));
        if (self.active) |*active| active.deinit();
        self.* = undefined;
    }
};

test "failed import and revision conflict retain the previous immutable generation" {
    const t = std.testing;
    var registry: Registry = .{};
    defer registry.deinit();
    try registry.begin();
    defer registry.end();
    try t.expectError(error.Busy, registry.begin());
    const first = try Generation.fromCsv(t.allocator, "8.8.8.0,8.8.8.255,US\n");
    try registry.activate(t.io, first, 0);
    try t.expectError(error.Overlap, Generation.fromCsv(
        t.allocator,
        "8.8.8.0,8.8.8.255,US\n8.8.8.255,8.8.9.0,DE",
    ));
    var second = try Generation.fromCsv(t.allocator, "8.8.8.0,8.8.8.255,DE\n");
    try t.expectError(error.Conflict, registry.activate(t.io, second, 0));
    try t.expectEqualStrings("US", &(registry.lookup(t.io, try geo.address("8.8.8.8")).?));
    second.deinit();
    const third = try Generation.fromCsv(t.allocator, "8.8.8.0,8.8.8.255,DE");
    try registry.activate(t.io, third, 1);
    try t.expectEqualStrings("DE", &(registry.lookup(t.io, try geo.address("8.8.8.8")).?));
}

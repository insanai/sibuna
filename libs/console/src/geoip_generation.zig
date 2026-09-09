//! Immutable generations have one owner. Readers hold the registry lock only for lookup;
//! a rejected staging attempt never mutates or frees the active generation.
const std = @import("std");
const geoip = @import("geoip");
pub const max_csv_bytes = geoip.max_csv_bytes;
pub const max_ranges = geoip.max_ranges;

pub const Registry = struct {
    mutex: std.Io.Mutex = .init,
    loaded: std.atomic.Value(bool) = .init(false),
    importing: std.atomic.Value(bool) = .init(false),
    active: ?geoip.Database = null,
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
        staged: geoip.Database,
        expected_revision: u64,
    ) error{Conflict}!void {
        std.debug.assert(self.importing.load(.acquire));
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.revision != expected_revision) return error.Conflict;
        var old = self.active;
        self.active = staged;
        self.revision += 1;
        self.loaded.store(true, .release);
        if (old) |*generation| generation.deinit();
    }

    pub fn lookup(self: *Registry, io: std.Io, address: [16]u8) ?[2]u8 {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const active = self.active orelse return null;
        return active.lookup(address);
    }

    /// Whether the active provider's licence requires attribution in the interface.
    pub fn attributionRequired(self: *Registry, io: std.Io) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const active = self.active orelse return false;
        return active.provider.attribution() != null;
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
    const first = try geoip.fromCsv(t.allocator, .dbip, "2026-09", "8.8.8.0,8.8.8.255,US\n");
    try registry.activate(t.io, first, 0);
    try t.expectError(error.Overlap, geoip.fromCsv(
        t.allocator,
        .dbip,
        "2026-09",
        "8.8.8.0,8.8.8.255,US\n8.8.8.255,8.8.9.0,DE",
    ));
    const csv = "8.8.8.0,8.8.8.255,DE\n";
    var second = try geoip.fromCsv(t.allocator, .user_country, "2026-09-09", csv);
    try t.expectError(error.Conflict, registry.activate(t.io, second, 0));
    const ip = try geoip.parseAddress("8.8.8.8");
    try t.expectEqualStrings("US", &(registry.lookup(t.io, ip).?));
    try t.expect(registry.attributionRequired(t.io));
    second.deinit();
    const third = try geoip.fromCsv(t.allocator, .user_country, "2026-09-09", csv);
    try registry.activate(t.io, third, 1);
    try t.expectEqualStrings("DE", &(registry.lookup(t.io, ip).?));
    try t.expect(!registry.attributionRequired(t.io));
}

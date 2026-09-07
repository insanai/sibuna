const std = @import("std");

/// Capacity accounting is a reservation estimate, not measured process RSS. Database/cache
/// memory and allocator overhead must be measured separately by the impact harness.
pub const Budget = struct {
    slots: u16 = 80,
    http_reserved: u16 = 16,
    subscribers: u16 = 64,
    peers: u16 = 16,
    stack_bytes: u32 = 256 * 1024,
    auth_verifiers: u8 = 1,
    geoip_generation_bytes: u32 = @import("geoip_generation.zig").max_ranges *
        @sizeOf(@import("geoip.zig").Range),

    pub const Error = error{InvalidBudget};
    pub const socket_buffer_bytes = 16 * 1024;
    pub const body_bytes = 1024 * 1024;
    pub const import_bytes = 16 * 1024 * 1024 + 40 * 1024;
    pub const auth_bytes = @import("password.zig").Password.workspace_bytes;
    pub const topic_bytes = 10 * 1024 * 1024;
    pub const traffic_bytes = @sizeOf(@import("store").ConsoleTelemetry);
    // Incremental evidence metadata in the existing 512-slot incident queue and 32-row batch.
    // Include alignment slack without importing daemon record or ownership types.
    pub const evidence_bytes = 544 * (@sizeOf(@import("core").IncidentEvidence) +
        @alignOf(@import("core").IncidentEvidence));
    pub const query_bytes = @sizeOf(@import("query_budget.zig").Budget);

    pub fn validate(self: Budget) Error!void {
        if (self.slots < 16 or self.slots > 256) return error.InvalidBudget;
        if (self.http_reserved < 16 or self.http_reserved > self.slots)
            return error.InvalidBudget;
        if (self.subscribers > self.slots - self.http_reserved)
            return error.InvalidBudget;
        if (self.subscribers > 64 or self.peers > 64) return error.InvalidBudget;
        if (self.auth_verifiers != 1) return error.InvalidBudget;
        if (self.stack_bytes < 64 * 1024 or self.stack_bytes > 8 * 1024 * 1024)
            return error.InvalidBudget;
    }

    pub fn reservedBytes(self: Budget) Error!u64 {
        try self.validate();
        const connections: u64 = @as(u64, self.slots) + self.peers;
        // Every streaming connection reserves both a reader and a writer task stack.
        const stacks = (connections + self.subscribers + self.peers + 3) * self.stack_bytes;
        return stacks + connections * 2 * socket_buffer_bytes +
            @as(u64, self.slots) * body_bytes + import_bytes + auth_bytes +
            topic_bytes + traffic_bytes + query_bytes + evidence_bytes +
            2 * @as(u64, self.geoip_generation_bytes);
    }
};

test "budget preserves HTTP headroom and accounts for both GeoIP generations" {
    const t = std.testing;
    try t.expectError(error.InvalidBudget, (Budget{ .slots = 79 }).validate());
    try t.expectError(error.InvalidBudget, (Budget{ .auth_verifiers = 2 }).validate());
    const base = try (Budget{ .geoip_generation_bytes = 0 }).reservedBytes();
    const loaded = try (Budget{ .geoip_generation_bytes = 1000 }).reservedBytes();
    try t.expectEqual(base + 2000, loaded);
}

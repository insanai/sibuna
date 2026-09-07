const p = @import("console_protocol");
pub const Phase = enum { loading, setup, login, password, dashboard };
pub const State = struct {
    phase: Phase = .loading,
    message: p.Bytes(256) = .{},
    username: p.Bytes(64) = .{},
    csrf: p.Bytes(64) = .{},
    role: p.Bytes(16) = .{},
    busy: bool = false,
    must_change: bool = false,
    stats_busy: bool = false,
    epoch: p.Bytes(32) = .{},
    sequence: u64 = 0,
    reconnect_ms: u32 = 1000,
    paused: bool = false,
    stale: bool = false,
    dark: bool = false,
    stats: ?p.StatsSnapshot = null,
    points: [60]struct { second: u64 = 0, count: u64 = 0 } = @splat(.{}),
};

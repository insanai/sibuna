//! Boot-local challenge flow and one bounded timing partition, shared with Wasm.
pub const Algorithm = enum { hashcash, posw };
pub const Defaults = struct {
    algorithm: Algorithm = .hashcash,
    difficulty: u32 = 16,
    parameter: u8 = 16,
    openings: u8 = 0,
};
pub const Snapshot = struct {
    timestamp: u64 = 0,
    configured: Defaults = .{},
    last_issued: ?Defaults = null,
    issued: u64 = 0,
    submitted: u64 = 0,
    accepted: u64 = 0,
    rejected: u64 = 0,
    causes: [13]u64 = @splat(0),
    selected: u8 = 0,
    bin_accepted: [256]u64 = @splat(0),
    buckets: [16]u64 = @splat(0),
    missing: u64 = 0,
    invalid: u64 = 0,
    wasm: u64 = 0,
    javascript: u64 = 0,
    unknown_solver: u64 = 0,
};

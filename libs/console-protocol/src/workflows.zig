//! Policy workflow contracts: rule ordering, replay of retained events, reputation prefixes,
//! country blocks and atomic set import. Every mutation names an expected revision; pages
//! and summaries stay inside the fixed storage envelope.
const std = @import("std");
const p = @import("root.zig");
pub const max_prefix = 48;
pub const max_note = 128;
pub const max_source = 32;
pub const page_rows = 8;
pub const chunk_prefixes = 32;
pub const max_country_prefixes = 1024;
pub const replay_rows = 8;
pub const replay_scan = 64;
pub const max_replay_hours = 24 * 7;
pub const stage_seconds = 600;

pub const Direction = enum { up, down };
pub const Order = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    id: p.Bytes(128),
    direction: Direction,
};

pub const Replay = struct {
    auth: p.users.Auth,
    committed: ?u64 = null,
    draft: ?p.Bytes(4096) = null,
    /// Rule name to look for; empty means any non-allow decision.
    rule: p.Bytes(128) = .{},
    hours: u16 = 24,
};
pub const ReplayRow = struct {
    id: u64 = 0,
    ip: p.Bytes(max_prefix) = .{},
    path: p.Bytes(128) = .{},
    action: p.Bytes(16) = .{},
    rule: p.Bytes(64) = .{},
    conclusive: bool = false,
    matched: bool = false,
};
pub const ReplaySummary = struct {
    total: u32 = 0,
    matched: u32 = 0,
    inconclusive: u32 = 0,
    applied: u64 = 0,
    committed: u64 = 0,
    preview: bool = false,
    rows: [replay_rows]ReplayRow = @splat(.{}),
    count: u8 = 0,
};

pub const ReputationAction = enum { deny, allow };
pub const ReputationQuery = struct { auth: p.users.Auth, after: p.Bytes(max_prefix) = .{} };
pub const ReputationRow = struct {
    prefix: p.Bytes(max_prefix) = .{},
    score: i32 = 0,
    banned_until: ?u64 = null,
    trigger: p.Bytes(64) = .{},
    source: p.Bytes(max_source) = .{},
    note: p.Bytes(max_note) = .{},
    hits: u64 = 0,
    last_seen: u64 = 0,
};
pub const ReputationPage = struct {
    rows: [page_rows]ReputationRow = @splat(.{}),
    count: u8 = 0,
    next: ?p.Bytes(max_prefix) = null,
    committed: u64 = 0,
    nodes: u16 = 0,
};
pub const ReputationEdit = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    prefix: p.Bytes(max_prefix),
    action: ReputationAction,
    until: ?u64 = null,
    note: p.Bytes(max_note) = .{},
};
pub const ReputationRemove = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    prefix: p.Bytes(max_prefix),
};

pub const CountryChunk = struct {
    digest: [32]u8,
    ordinal: u16,
    prefixes: [chunk_prefixes]p.Bytes(max_prefix) = @splat(.{}),
    count: u8 = 0,
};
pub const CountryPreflight = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    digest: [32]u8,
    count: u16,
};
pub const CountryApply = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    digest: [32]u8,
    count: u16,
    country: [2]u8,
    action: ReputationAction,
    until: ?u64 = null,
    geo_generation: p.Bytes(64),
};
pub const CountrySummary = struct {
    prefixes: u16 = 0,
    nodes_before: u16 = 0,
    nodes_after: u16 = 0,
    overlaps: u16 = 0,
    sample: [8]p.Bytes(max_prefix) = @splat(.{}),
    sample_count: u8 = 0,
};

pub const ImportChunk = struct {
    digest: [32]u8,
    ordinal: u16,
    document: p.Bytes(4096),
};
pub const ImportCommit = struct {
    auth: p.users.Auth,
    expected_revision: u64,
    digest: [32]u8,
    count: u16,
};

pub fn validateOrder(input: Order) error{InvalidLimit}!void {
    if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.id.len == 0) return error.InvalidLimit;
}

pub fn validateReplay(input: Replay) error{InvalidLimit}!void {
    if ((input.draft != null) != (input.committed != null)) return error.InvalidLimit;
    if ((input.committed orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.hours == 0 or input.hours > max_replay_hours) return error.InvalidLimit;
    if (input.draft) |draft| if (draft.len == 0) return error.InvalidLimit;
}

pub fn validateReputationEdit(input: ReputationEdit) error{InvalidLimit}!void {
    if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.prefix.len == 0) return error.InvalidLimit;
    if ((input.until orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
}

pub fn validateCountry(count: u16, revision: u64) error{InvalidLimit}!void {
    if (count == 0 or count > max_country_prefixes) return error.InvalidLimit;
    if (revision >= std.math.maxInt(i64)) return error.InvalidLimit;
}

pub fn validateImportCommit(input: ImportCommit) error{InvalidLimit}!void {
    if (input.count == 0 or input.count > 128) return error.InvalidLimit;
    if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
}

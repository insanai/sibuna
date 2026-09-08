const p = @import("root.zig");
pub const Authorization = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    require_totp: bool = false,
};
pub const Metadata = struct {
    revision: u64 = 0,
    digest: p.Bytes(64) = .{},
    source_version: p.Bytes(7) = .{},
    ranges: u32 = 0,
    loaded_at: u64 = 0,
};
pub const Begin = struct {
    auth: Authorization,
    expected_revision: u64,
    digest: p.Bytes(64),
    source_version: p.Bytes(7),
    ranges: u32,
};
pub const Batch = struct {
    auth: Authorization,
    digest: p.Bytes(64),
    ordinal: u32,
    // Each range is two normalized 16-byte addresses plus a two-byte country code.
    bytes: p.Bytes(3400),
};
pub const Activate = struct {
    auth: Authorization,
    expected_revision: u64,
    digest: p.Bytes(64),
};
pub const Read = struct { digest: p.Bytes(64), ordinal: u32 };

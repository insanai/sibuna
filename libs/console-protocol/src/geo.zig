const p = @import("root.zig");
pub const Authorization = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    require_totp: bool = false,
};
pub const max_provider = 12;
pub const max_version = 10;
/// One or two lowercase hex digests separated by a colon: "hex" or "hex:hex".
pub const max_source_digests = 129;
pub const Metadata = struct {
    revision: u64 = 0,
    digest: p.Bytes(64) = .{},
    provider: p.Bytes(max_provider) = .{},
    source_version: p.Bytes(max_version) = .{},
    source_digests: p.Bytes(max_source_digests) = .{},
    ranges: u32 = 0,
    loaded_at: u64 = 0,
};
pub const Begin = struct {
    auth: Authorization,
    expected_revision: u64,
    digest: p.Bytes(64),
    provider: p.Bytes(max_provider),
    source_version: p.Bytes(max_version),
    source_digests: p.Bytes(max_source_digests) = .{},
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

pub fn validSourceDigests(text: []const u8) bool {
    if (text.len != 0 and text.len != 64 and text.len != max_source_digests) return false;
    for (text, 0..) |byte, index| {
        if (index == 64) {
            if (byte != ':') return false;
        } else if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    }
    return true;
}
const std = @import("std");

test "source digests are one or two lowercase hex values" {
    const t = std.testing;
    const hex = "a" ** 64;
    try t.expect(validSourceDigests(""));
    try t.expect(validSourceDigests(hex));
    try t.expect(validSourceDigests(hex ++ ":" ++ hex));
    try t.expect(!validSourceDigests(hex ++ " " ++ hex));
    try t.expect(!validSourceDigests("A" ** 64));
    try t.expect(!validSourceDigests(hex[0..63]));
}

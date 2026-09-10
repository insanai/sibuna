//! Internal owned requests. No HTTP route accepts archive writes from a browser.
const Bytes = @import("root.zig").Bytes;
pub const chunk_bytes = 2048;
pub const max_bytes = 37468;
pub const quota_bytes = 512 * 1024 * 1024;
pub const Begin = struct { digest: [32]u8, total_bytes: u32, now: u64 };
pub const Chunk = struct { digest: [32]u8, ordinal: u8, bytes: Bytes(chunk_bytes) };
pub const Finish = struct { digest: [32]u8, now: u64 };

/// Conservative charged retention bytes include room for chunk keys and indexes.
/// This bounds retained archive reservations, not the shared database's physical file size.
pub fn charge(bytes: u32) u64 {
    return ((@as(u64, bytes) + chunk_bytes - 1) / chunk_bytes) * 8192 + 1024;
}

const Summary = @import("space_saving.zig").Summary;
pub const Minute = struct {
    minute: ?u64 = null,
    first_second: u64 = 0,
    last_second: u64 = 0,
    truncated_records: u64 = 0,
    rejected_records: u64 = 0,
    paths: Summary = .{},
};

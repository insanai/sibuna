//! Wall-display sessions: an operator mints a one-time code; the display exchanges it once
//! for a read-only cookie session scoped to statistics. Codes never travel in URLs.
const p = @import("root.zig");
pub const use_seconds = 600;
pub const lifetime_seconds = 43200;
pub const max_label = 64;
pub const Grant = struct {
    auth: p.users.Auth,
    code_digest: [32]u8,
    label: p.Bytes(max_label) = .{},
};
pub const Exchange = struct {
    code_digest: [32]u8,
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    client: p.Bytes(48) = .{},
};
pub const Granted = struct { use_by: u64, expires: u64 };
pub const Session = struct { expires: u64 };

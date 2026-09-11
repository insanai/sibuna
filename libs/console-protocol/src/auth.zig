//! Owned authentication data crossing the storage mailbox. Secrets are never serialized
//! into ordinary user/session responses. Factor consumption belongs to session creation.
const p = @import("root.zig");
pub const Authorization = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8,
};
pub const Totp = struct {
    user: u64,
    revision: u64,
    envelope: [60]u8,
    key_id: [32]u8,
    enabled: bool,
    expires: u64,
    last_step: ?u64,
    recovery_digests: [10][32]u8 = @splat(@splat(0)),
    recovery_used: u16,
};
pub const Enrollment = struct {
    auth: Authorization,
    expected_revision: u64,
    envelope: [60]u8,
    key_id: [32]u8,
};
pub const Confirmation = struct {
    auth: Authorization,
    expected_revision: u64,
    step: u64,
    recovery_digests: [10][32]u8,
};
pub const Factor = union(enum) {
    none,
    totp: struct { revision: u64, step: u64 },
    recovery: struct { revision: u64, slot: u8, digest: [32]u8 },
};

// Deadlines are absolute bounds, not authorization clocks. Persistent stamps execution.
pub const Bootstrap = struct {
    username: p.Bytes(64),
    password_hash: p.Bytes(255),
    must_change: bool = false,
    password_expires: u64 = 0,
};
pub const Session = struct {
    factor: Factor = .none,
    user: u64,
    revision: u64,
    digest: [32]u8,
    csrf_digest: [32]u8,
    expires: u64,
    /// Transport peer, or the forwarded client behind a trusted proxy; empty when unknown.
    client: p.Bytes(48) = .{},
    /// SHA-256 of the User-Agent header as hex; empty when the header was absent.
    agent_digest: p.Bytes(64) = .{},
};
/// A refused sign-in: the attempted name and where it came from, never the credential.
pub const Denied = struct {
    username: p.Bytes(64),
    client: p.Bytes(48) = .{},
};
pub const Logout = struct {
    digest: [32]u8,
    /// Address presenting the credential for this sign-out, not its original sign-in.
    client: p.Bytes(48) = .{},
};
pub const PasswordChange = struct {
    expected_revision: u64,
    replacement_digest: [32]u8,
    replacement_csrf: [32]u8,
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    password_hash: p.Bytes(255),
};

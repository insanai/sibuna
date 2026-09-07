//! Owned authentication data crossing the storage mailbox. Secrets are never serialized
//! into ordinary user/session responses. Factor consumption belongs to session creation.
pub const Authorization = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    now: u64,
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

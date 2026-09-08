//! Policy and inspection edits share one authorization contract. The conditional mutation
//! rechecks the owner clock after candidate construction; no queued caller time is trusted.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const util = @import("console_store.zig");

pub const predicate =
    "s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>? " ++
    "AND u.disabled=0 AND u.must_change=0 AND u.role IN ('operator','admin') " ++
    "AND u.revision=s.revision AND (?=0 OR u.role!='admin' OR " ++
    "EXISTS(SELECT 1 FROM console_totp t WHERE t.user_id=u.id AND t.enabled=1)) ";

pub const Credentials = struct {
    digest: [64]u8,
    csrf: [64]u8,
    now: u64,
    require_totp: bool,

    pub fn init(input: p.policies.Edit, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .now = now,
            .require_totp = input.require_totp,
        };
    }

    // Bindings borrow the synchronous commit's owned credential buffers.
    pub fn values(self: *const Credentials) [4]zx.Value {
        return .{
            util.text(&self.digest),
            util.text(&self.csrf),
            util.integer(self.now),
            util.integer(@intFromBool(self.require_totp)),
        };
    }
};

pub fn check(owner: *Persistent, input: p.policies.Edit) !?p.Failure {
    const identity = try util.authorize(owner, input.session_digest, owner.nowSeconds());
    if (identity != .authorized or identity.authorized.must_change) return .unauthorized;
    const actor = identity.authorized;
    if (!actor.role.allows(.manage_policy)) return .forbidden;
    const account_role = actor.account_role orelse actor.role;
    if (input.require_totp and account_role == .admin and !actor.totp_enabled) return .forbidden;
    if (!std.crypto.timing_safe.eql([32]u8, input.csrf_digest, actor.csrf_digest))
        return .forbidden;
    return null;
}

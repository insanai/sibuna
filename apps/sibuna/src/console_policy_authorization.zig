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
    "EXISTS(SELECT 1 FROM console_totp t WHERE t.user_id=u.id AND t.enabled=1)) " ++
    "AND (s.token_id IS NULL OR EXISTS(SELECT 1 FROM console_tokens t WHERE t.id=s.token_id " ++
    "AND t.disabled=0 AND t.role IN ('operator','admin') AND (t.scopes & " ++
    std.fmt.comptimePrint("{d}", .{p.tokens.Scope.policy_write.bit()}) ++ ")!=0)) ";

// Capture the effective credential role, including token attenuation, at the commit itself.
pub const role = "CASE WHEN s.token_id IS NULL THEN u.role ELSE " ++
    "(SELECT role FROM console_tokens WHERE id=s.token_id) END";

pub const Credentials = struct {
    digest: [64]u8,
    csrf: [64]u8,
    now: u64,
    require_totp: bool,
    client: p.Bytes(48),

    pub fn init(input: p.policies.Edit, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .now = now,
            .require_totp = input.require_totp,
            .client = input.client,
        };
    }

    pub fn fromAuth(input: p.users.Auth, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .now = now,
            .require_totp = input.require_totp,
            .client = input.client,
        };
    }

    /// The presenting address for the staged row, NULL when the request carried none.
    pub fn address(self: *const Credentials) zx.Value {
        return util.address(&self.client);
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
    return checkAuth(owner, .{
        .session_digest = input.session_digest,
        .csrf_digest = input.csrf_digest,
        .require_totp = input.require_totp,
    });
}

/// The same contract for every policy-writing workflow: an operator or administrator
/// session (or a policy-write token) with a matching CSRF digest and the proxy TOTP rule.
pub fn checkAuth(owner: *Persistent, input: p.users.Auth) !?p.Failure {
    const identity = try util.authorize(owner, input.session_digest, owner.nowSeconds());
    if (identity != .authorized or identity.authorized.must_change) return .unauthorized;
    const actor = identity.authorized;
    if (!actor.role.allows(.manage_policy) or
        actor.scopes & p.tokens.Scope.policy_write.bit() == 0) return .forbidden;
    const account_role = actor.account_role orelse actor.role;
    if (input.require_totp and account_role == .admin and !actor.totp_enabled) return .forbidden;
    if (!std.crypto.timing_safe.eql([32]u8, input.csrf_digest, actor.csrf_digest))
        return .forbidden;
    return null;
}

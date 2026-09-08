//! Read services recheck current authority before work and before releasing results.
//! The clock is sampled on each check, including after a bounded replicated query.
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;

pub fn check(
    owner: *Persistent,
    digest: [32]u8,
    require_totp: bool,
    scope: p.tokens.Scope,
) !?p.Failure {
    const result = try @import("console_store.zig").authorize(owner, digest, owner.nowSeconds());
    if (result != .authorized or result.authorized.must_change) return .unauthorized;
    const actor = result.authorized;
    const account_role = actor.account_role orelse actor.role;
    if (require_totp and account_role == .admin and !actor.totp_enabled) return .forbidden;
    if (!actor.role.allows(scope.action()) or actor.scopes & scope.bit() == 0) return .forbidden;
    return null;
}

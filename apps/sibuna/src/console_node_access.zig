const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;

pub fn check(owner: *Persistent, input: p.users.Auth, manage: bool) !?p.Failure {
    const result = try @import("console_store.zig").authorize(
        owner,
        input.session_digest,
        owner.nowSeconds(),
    );
    if (result != .authorized or result.authorized.must_change) return .unauthorized;
    const actor = result.authorized;
    if (actor.token_id != null or
        (input.require_totp and actor.role == .admin and !actor.totp_enabled)) return .forbidden;
    if (manage and (!actor.role.allows(.control_node) or
        !std.crypto.timing_safe.eql([32]u8, actor.csrf_digest, input.csrf_digest)))
        return .forbidden;
    return null;
}

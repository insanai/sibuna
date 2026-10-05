//! Borrowed prepared-query arguments live through a synchronous owner call.
//! The predicate rechecks the administrator cookie, CSRF, revision and factor
//! inside the mutation that also commits its audit trigger.
const std = @import("std");
const p = @import("console").protocol;
const zx = @import("zaxonlite");
const util = @import("console_store.zig");
const Persistent = @import("persistent.zig").Persistent;
pub const sql = @import("console_store_tokens.zig").authority;
pub const Credentials = struct {
    digest: [64]u8,
    csrf: [64]u8,
    now: u64,
    require_totp: bool,

    pub fn init(input: p.users.Auth, now: u64) Credentials {
        return .{
            .digest = std.fmt.bytesToHex(input.session_digest, .lower),
            .csrf = std.fmt.bytesToHex(input.csrf_digest, .lower),
            .now = now,
            .require_totp = input.require_totp,
        };
    }

    pub fn values(self: *const Credentials) [4]zx.Value {
        return .{
            util.text(&self.digest),
            util.text(&self.csrf),
            util.integer(self.now),
            util.integer(@intFromBool(self.require_totp)),
        };
    }
};

pub fn mutation(owner: *Persistent, auth: p.users.Auth) !?u64 {
    return @import("console_store_settings.zig").admin(owner, auth, owner.nowSeconds());
}

pub fn read(owner: *Persistent, auth: p.users.Auth) !?p.Failure {
    return @import("console_node_access.zig").check(owner, auth, false);
}

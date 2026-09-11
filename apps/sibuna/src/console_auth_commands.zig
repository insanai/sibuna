//! Authentication mailbox commands take time exclusively from the storage owner.
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const auth = @import("console_store_auth.zig");
const factor = @import("console_store_totp.zig");

pub fn execute(owner: *Persistent, request: p.StorageRequest) !p.StorageResult {
    const now = owner.nowSeconds();
    return switch (request) {
        .bootstrap => |input| auth.bootstrap(owner, input, now),
        .auth_user => |username| auth.user(owner, username.slice()),
        .login_denied => |input| auth.denied(owner, input, now),
        .session_create => |input| @import("console_store_session.zig").create(owner, input, now),
        .password_change => |input| auth.password(owner, input, now),
        .logout => |input| auth.logout(owner, input, now),
        .totp_read => |user| factor.read(owner, user),
        .totp_begin => |input| factor.begin(owner, input, now),
        .totp_confirm => |input| factor.confirm(owner, input, now),
        .authorize => |input| authorize(owner, input, now),
        else => unreachable,
    };
}

fn authorize(owner: *Persistent, input: p.AuthorizationCheck, now: u64) !p.StorageResult {
    if (input.touch and input.kind == .session) try auth.touch(owner, input.session_digest, now);
    return @import("console_store_identity.zig").authorize(
        owner,
        input.session_digest,
        now,
        input.kind,
    );
}

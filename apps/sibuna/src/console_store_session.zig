//! Session insertion and factor consumption share one replicated transaction. The
//! preverified factor is checked again against current user/factor revisions and replay state.
const std = @import("std");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;
const nil: zx.Value = .null_value;

pub fn create(owner: *Persistent, input: anytype) !p.StorageResult {
    if (input.expires <= input.now or input.expires - input.now > 43200)
        return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    var revision: zx.Value = nil;
    var step: zx.Value = nil;
    var slot: zx.Value = nil;
    var recovery: zx.Value = nil;
    var recovery_hex: [64]u8 = undefined;
    switch (input.factor) {
        .none => {},
        .totp => |factor| {
            revision = integer(factor.revision);
            step = integer(factor.step);
        },
        .recovery => |factor| {
            if (factor.slot >= 10) return .{ .failed = .invalid_input };
            revision = integer(factor.revision);
            slot = integer(factor.slot);
            recovery_hex = std.fmt.bytesToHex(factor.digest, .lower);
            recovery = text(&recovery_hex);
        },
    }
    const changes = try db.exec(owner.db, owner.gpa, sql, &.{
        text(&digest),       text(&csrf),             integer(input.now), integer(input.expires),
        integer(input.user), integer(input.revision), revision,           step,
        slot,                recovery,
    });
    return if (changes == 0) .{ .failed = .conflict } else .command_recorded;
}

const sql =
    "WITH i AS (SELECT ? digest,? csrf,? now,? expires,? uid,? revision," ++
    "? factor_revision,? step,? slot,? recovery) " ++
    "INSERT INTO console_sessions(digest,user_id,revision,csrf_digest,created_at,expires," ++
    "idle_expires,mfa_step,recovery_slot) SELECT i.digest,u.id,u.revision,i.csrf,i.now," ++
    "i.expires,MIN(i.expires,i.now+1800),i.step,i.slot FROM i JOIN console_users u " ++
    "ON u.id=i.uid LEFT JOIN console_totp m ON m.user_id=u.id AND m.enabled=1 " ++
    "WHERE u.revision=i.revision AND u.disabled=0 " ++
    "AND (u.password_expires=0 OR u.password_expires>i.now) " ++
    "AND (SELECT COUNT(*) FROM console_sessions WHERE MIN(expires,idle_expires)>i.now)<4096 " ++
    "AND ((m.user_id IS NULL AND i.factor_revision IS NULL AND i.step IS NULL " ++
    "AND i.slot IS NULL) OR (m.revision=i.factor_revision AND " ++
    "((i.step>COALESCE(m.last_step,-1) AND i.slot IS NULL AND " ++
    "i.step BETWEEN MAX(0,CAST(i.now/30 AS INTEGER)-1) AND CAST(i.now/30 AS INTEGER)+1) " ++
    "OR (i.slot BETWEEN 0 AND 9 AND i.step IS NULL AND (m.recovery_used & (1 << i.slot))=0 " ++
    "AND substr(m.recovery_digests,i.slot*64+1,64)=i.recovery))))";

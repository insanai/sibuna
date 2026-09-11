//! Factor state is read and consumed only through Persistent's authoritative database.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;
const number = store.number;
const authorized =
    "SELECT u.id FROM console_sessions s JOIN console_users u ON u.id=s.user_id " ++
    "WHERE s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>? " ++
    "AND s.revision=u.revision AND u.disabled=0";

pub fn read(owner: *Persistent, user: u64) !p.StorageResult {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT revision,envelope,key_id,enabled,expires,last_step,recovery_digests," ++
            "recovery_used FROM console_totp WHERE user_id=? LIMIT 1",
        &.{integer(user)},
    );
    defer result.deinit();
    if (result.rows.len != 1) return .{ .failed = .unavailable };
    const row = result.rows[0];
    var output: p.auth.Totp = .{
        .user = user,
        .revision = try number(row[0]),
        .envelope = undefined,
        .key_id = undefined,
        .enabled = try number(row[3]) != 0,
        .expires = try number(row[4]),
        .last_step = if (row[5] != null) try number(row[5]) else null,
        .recovery_used = @intCast(try number(row[7])),
    };
    _ = try std.fmt.hexToBytes(&output.envelope, row[1].?);
    _ = try std.fmt.hexToBytes(&output.key_id, row[2].?);
    const digests = row[6].?;
    if (output.enabled and digests.len != 640) return error.InvalidStoredValue;
    if (digests.len == 640) {
        for (&output.recovery_digests, 0..) |*digest, index| {
            _ = try std.fmt.hexToBytes(digest, digests[index * 64 ..][0..64]);
        }
    }
    return .{ .totp = output };
}

pub fn begin(owner: *Persistent, input: p.auth.Enrollment, now: u64) !p.StorageResult {
    const session = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    const envelope = std.fmt.bytesToHex(input.envelope, .lower);
    const key = std.fmt.bytesToHex(input.key_id, .lower);
    // Replacing an unconfirmed enrollment needs its revision. An enabled factor can
    // never be silently replaced by someone possessing only an existing session.
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_totp(user_id,envelope,key_id,revision,expires,modified_at," ++
            "client_ip) SELECT u.id,?,?,1,?,?,? FROM (" ++ authorized ++ ") u " ++
            "WHERE ?=COALESCE((SELECT revision FROM console_totp WHERE user_id=u.id),0) " ++
            "ON CONFLICT(user_id) DO UPDATE SET envelope=excluded.envelope," ++
            "key_id=excluded.key_id,revision=console_totp.revision+1," ++
            "expires=excluded.expires,modified_at=excluded.modified_at," ++
            "client_ip=excluded.client_ip " ++
            "WHERE console_totp.enabled=0 AND console_totp.revision=?",
        &.{
            text(&envelope),
            text(&key),
            integer(now + 600),
            integer(now),
            store.address(&input.auth.client),
            text(&session),
            text(&csrf),
            integer(now),
            integer(input.expected_revision),
            integer(input.expected_revision),
        },
    );
    return if (changes == 0) .{ .failed = .conflict } else .command_recorded;
}

pub fn confirm(owner: *Persistent, input: p.auth.Confirmation, now: u64) !p.StorageResult {
    const current = now / 30;
    if (input.step < current -| 1 or input.step > current + 1)
        return .{ .failed = .invalid_input };
    const session = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    var digests: [640]u8 = undefined;
    for (input.recovery_digests, 0..) |digest, index| {
        @memcpy(digests[index * 64 ..][0..64], &std.fmt.bytesToHex(digest, .lower));
    }
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_totp SET enabled=1,last_step=?,recovery_digests=?,modified_at=?," ++
            "client_ip=? " ++
            "WHERE user_id IN (" ++ authorized ++ ") AND enabled=0 AND expires>? " ++
            "AND revision=?",
        &.{
            integer(input.step),
            text(&digests),
            integer(now),
            store.address(&input.auth.client),
            text(&session),
            text(&csrf),
            integer(now),
            integer(now),
            integer(input.expected_revision),
        },
    );
    // Enabling increments the authorization revision and revokes every prior session
    // through triggers in the same commit. A lost response cannot leave partial codes.
    return if (changes == 0) .{ .failed = .conflict } else .command_recorded;
}

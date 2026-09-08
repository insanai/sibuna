//! Every entry executes only on Persistent's owner thread. Generation chunks are bounded
//! and immutable. Neither incomplete chunks nor a stale authorization may publish data.
//! Authorization uses the owner clock at execution, never the caller submission timestamp.
const std = @import("std");
const p = @import("console").protocol;
const zx = @import("zaxonlite");
const db = @import("console_database.zig");
const Persistent = @import("persistent.zig").Persistent;
const util = @import("console_store.zig");
const authorized =
    "SELECT u.id FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
    "WHERE s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>? " ++
    "AND s.revision=u.revision " ++
    "AND u.disabled=0 AND u.must_change=0 AND u.role='admin' " ++
    "AND (?=0 OR EXISTS(SELECT 1 FROM console_totp t WHERE t.user_id=u.id AND t.enabled=1))";

fn text(value: []const u8) zx.Value {
    return .{ .text = value };
}
fn integer(value: u64) zx.Value {
    return .{ .integer = @intCast(value) };
}
fn validDigest(digest: p.Bytes(64)) bool {
    if (digest.len != 64) return false;
    for (digest.slice()) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

pub fn metadata(owner: *Persistent) !p.StorageResult {
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT a.revision,a.digest,a.loaded_at,g.source_version,g.ranges " ++
            "FROM console_geo_active a LEFT JOIN console_geo_generations g " ++
            "ON g.digest=a.digest WHERE a.id=1 LIMIT 1",
        &.{},
    );
    defer result.deinit();
    if (result.rows.len != 1) return error.InvalidRow;
    const row = result.rows[0];
    return .{ .geo_metadata = .{
        .revision = try util.number(row[0]),
        .digest = try p.Bytes(64).init(row[1] orelse return error.InvalidRow),
        .loaded_at = try util.number(row[2]),
        .source_version = if (row[3]) |version| try p.Bytes(7).init(version) else .{},
        .ranges = if (row[4] == null) 0 else @intCast(try util.number(row[4])),
    } };
}

pub fn begin(owner: *Persistent, input: p.geo.Begin, now: u64) !p.StorageResult {
    if (!validDigest(input.digest) or input.ranges == 0 or input.ranges > 1024 * 1024)
        return .{ .failed = .invalid_input };
    if (input.source_version.len > 7) return .{ .failed = .invalid_input };
    const date = input.source_version.slice();
    if (date.len != 7 or date[4] != '-') return .{ .failed = .invalid_input };
    const year = std.fmt.parseInt(u16, date[0..4], 10) catch return .{ .failed = .invalid_input };
    const month = std.fmt.parseInt(u8, date[5..7], 10) catch return .{ .failed = .invalid_input };
    if (year < 2000 or month == 0 or month > 12) return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_geo_generations(digest,source_version,ranges,actor,created_at) " ++
            "SELECT ?,?,?,u.id,? FROM (" ++ authorized ++ ") u " ++
            "WHERE (SELECT revision FROM console_geo_active WHERE id=1)=? " ++
            "AND (SELECT count(*) FROM console_geo_generations)<2 " ++
            "ON CONFLICT(digest) DO NOTHING",
        &.{
            text(input.digest.slice()),
            text(date),
            integer(input.ranges),
            integer(now),
            text(&digest),
            text(&csrf),
            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
            integer(input.expected_revision),
        },
    );
    if (changed > 0) return .command_recorded;
    return replayBegin(owner, input, now);
}

pub fn batch(owner: *Persistent, input: p.geo.Batch, now: u64) !p.StorageResult {
    if (!validDigest(input.digest) or input.bytes.len == 0 or input.bytes.len > 3400 or
        input.bytes.len % 34 != 0 or input.ordinal >= 10486) return .{ .failed = .invalid_input };
    if (!validBatch(input.bytes.slice())) return .{ .failed = .invalid_input };
    if (!try orderedBatch(owner, input)) return .{ .failed = .invalid_input };
    // Address/country validation is repeated by the loader before activation. This layer
    // admits only a full chunk at the next ordinal and never changes already stored bytes.
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    var encoded: [6800]u8 = undefined;
    const hex = std.fmt.bytesToHex(input.bytes.data, .lower);
    @memcpy(encoded[0 .. input.bytes.len * 2], hex[0 .. input.bytes.len * 2]);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_geo_chunks(digest,ordinal,payload) SELECT ?,?,? " ++
            "FROM console_geo_generations g WHERE g.digest=? AND g.actor IN (" ++ authorized ++
            ") AND g.digest<>(SELECT digest FROM console_geo_active WHERE id=1) " ++
            "AND ?=(SELECT count(*) FROM console_geo_chunks WHERE digest=g.digest) " ++
            "AND ?*100<?",
        &.{
            text(input.digest.slice()),
            integer(input.ordinal),
            text(encoded[0 .. input.bytes.len * 2]),
            text(input.digest.slice()),
            text(&digest),
            text(&csrf),
            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
            integer(input.ordinal),
            integer(input.ordinal),
            integer(1024 * 1024),
        },
    );
    if (changed > 0) return .command_recorded;
    return replayBatch(owner, input, encoded[0 .. input.bytes.len * 2], now);
}

pub fn activate(owner: *Persistent, input: p.geo.Activate, now: u64) !p.StorageResult {
    if (!validDigest(input.digest)) return .{ .failed = .invalid_input };
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_geo_active SET digest=?,revision=revision+1,loaded_at=?," ++
            "actor=(" ++ authorized ++ ") WHERE id=1 AND revision=? " ++
            "AND EXISTS(SELECT 1 FROM console_geo_generations g WHERE g.digest=? AND g.actor=(" ++
            authorized ++ ") AND g.ranges=(SELECT sum(length(payload)/68) " ++
            "FROM console_geo_chunks WHERE digest=g.digest))",
        &.{
            text(input.digest.slice()),
            integer(now),
            text(&digest),
            text(&csrf),
            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
            integer(input.expected_revision),
            text(input.digest.slice()),
            text(&digest),
            text(&csrf),
            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
        },
    );
    return if (changed > 0) .{ .geo_activated = now } else .{ .failed = .conflict };
}

pub fn read(owner: *Persistent, input: p.geo.Read) !p.StorageResult {
    if (!validDigest(input.digest)) return .{ .failed = .invalid_input };
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT payload FROM console_geo_chunks WHERE digest=? AND ordinal=? LIMIT 1",
        &.{ text(input.digest.slice()), integer(input.ordinal) },
    );
    defer result.deinit();
    if (result.rows.len == 0) return .{ .geo_bytes = .{} };
    const hex = result.rows[0][0] orelse return error.InvalidRow;
    if (hex.len > 6800 or hex.len % 68 != 0) return error.InvalidRow;
    var bytes: p.Bytes(3400) = .{ .len = hex.len / 2 };
    _ = std.fmt.hexToBytes(bytes.data[0..bytes.len], hex) catch return error.InvalidRow;
    return .{ .geo_bytes = bytes };
}

fn validBatch(bytes: []const u8) bool {
    const geo = @import("console").geoip;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += 34) {
        const first = bytes[offset..][0..16];
        const last = bytes[offset + 16 ..][0..16];
        if (std.mem.order(u8, first, last) == .gt) return false;
        if (!geo.countryValid(bytes[offset + 32 ..][0..2])) return false;
        if (offset != 0 and std.mem.order(u8, first, bytes[offset - 18 ..][0..16]) != .gt)
            return false;
    }
    return true;
}

fn orderedBatch(owner: *Persistent, input: p.geo.Batch) !bool {
    if (input.ordinal == 0) return true;
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT substr(payload,-68) FROM console_geo_chunks WHERE digest=? AND ordinal=? LIMIT 1",
        &.{ text(input.digest.slice()), integer(input.ordinal - 1) },
    );
    defer result.deinit();
    if (result.rows.len != 1) return false;
    const hex = result.rows[0][0] orelse return error.InvalidRow;
    if (hex.len != 68) return error.InvalidRow;
    var previous: [34]u8 = undefined;
    _ = try std.fmt.hexToBytes(&previous, hex);
    return std.mem.order(u8, input.bytes.data[0..16], previous[16..32]) == .gt;
}

/// Two bounded deletes per maintenance tick reclaim retired generations and abandoned
/// staging work. Never delete an active generation, including after a clock rollback.
pub fn prune(owner: *Persistent, now: u64) !p.StorageResult {
    const eligible =
        "SELECT g.digest FROM console_geo_generations g,console_geo_active a " ++
        "WHERE a.id=1 AND g.digest<>a.digest AND " ++
        "(g.created_at<a.loaded_at OR g.created_at<?)";
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_geo_chunks WHERE rowid IN (SELECT rowid " ++
            "FROM console_geo_chunks WHERE digest IN (" ++ eligible ++ ") LIMIT 20)",
        &.{integer(now -| 3600)},
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_geo_generations WHERE digest IN (" ++ eligible ++ ") " ++
            "AND NOT EXISTS(SELECT 1 FROM console_geo_chunks c " ++
            "WHERE c.digest=console_geo_generations.digest)",
        &.{integer(now -| 3600)},
    );
    return .command_recorded;
}

fn replayBegin(owner: *Persistent, input: p.geo.Begin, now: u64) !p.StorageResult {
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT g.digest FROM console_geo_generations g,console_geo_active a WHERE a.id=1 " ++
            "AND g.digest=? AND g.source_version=? AND g.ranges=? AND a.revision=? " ++
            "AND g.digest<>a.digest AND g.actor IN (" ++ authorized ++ ") LIMIT 1",
        &.{
            text(input.digest.slice()),
            text(input.source_version.slice()),
            integer(input.ranges),
            integer(input.expected_revision),
            text(&digest),
            text(&csrf),
            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
        },
    );
    defer result.deinit();
    return if (result.rows.len == 1) .command_recorded else .{ .failed = .conflict };
}

/// After restart a validated same-digest import may replay immutable chunks. Accept only an
/// exact byte match under fresh authorization; a conflicting retry never overwrites a chunk.
fn replayBatch(
    owner: *Persistent,
    input: p.geo.Batch,
    encoded: []const u8,
    now: u64,
) !p.StorageResult {
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    var result = try db.query(
        owner.db,
        owner.gpa,
        "SELECT c.ordinal FROM console_geo_chunks c JOIN console_geo_generations g " ++
            "ON c.digest=g.digest WHERE c.digest=? AND c.ordinal=? AND c.payload=? " ++
            "AND g.digest<>(SELECT digest FROM console_geo_active WHERE id=1) " ++
            "AND g.actor IN (" ++ authorized ++ ") LIMIT 1",
        &.{
            text(input.digest.slice()),                     integer(input.ordinal), text(encoded),
            text(&digest),                                  text(&csrf),            integer(now),
            integer(@intFromBool(input.auth.require_totp)),
        },
    );
    defer result.deinit();
    return if (result.rows.len == 1) .command_recorded else .{ .failed = .conflict };
}

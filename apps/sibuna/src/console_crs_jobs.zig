//! The storage owner records candidate intent and immutable source chunks. The
//! native preparation service alone may submit a verification witness; an HTTP
//! caller cannot turn submitted manifest bytes into verified protection.
const std = @import("std");
const p = @import("console").protocol;
const m = p.crs_management;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_crs_access.zig");
const reads = @import("console_crs_jobs_read.zig");

pub fn execute(owner: *Persistent, input: m.Request) !p.StorageResult {
    try m.validate(input);
    return switch (input) {
        .status => |auth| reads.status(owner, auth),
        .job => |value| reads.job(owner, value),
        .jobs => |auth| reads.jobs(owner, auth),
        .begin => |value| begin(owner, value),
        .chunk => |value| chunk(owner, value),
        .verify => |value| verify(owner, value),
        .select => |value| @import("console_crs_selection.zig").select(owner, value),
        .discard => |value| discard(owner, value),
        .selected => reads.selected(owner),
        .source => |value| reads.source(owner, value),
        .failed => |value| failed(owner, value),
        .applied => |value| @import("console_crs_selection.zig").applied(owner, value),
        .nodes => |auth| reads.nodes(owner, auth),
    };
}

pub fn begin(owner: *Persistent, input: m.Begin) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const now = owner.nowSeconds();
    const credentials = access.Credentials.init(input.auth, now);
    var previous = try db.query(
        owner.db,
        owner.gpa,
        access.sql ++
            "SELECT id FROM console_crs_jobs WHERE id=? AND kind=? AND expected_revision=? " ++
            "AND expires=? AND clone IS ? AND actor=(SELECT id FROM a)",
        &(credentials.values() ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.text(@tagName(input.kind)),
            util.integer(input.expected_revision),
            util.integer(input.expires),
            if (input.clone) |id| util.text(id.slice()) else .null_value,
        }),
    );
    defer previous.deinit();
    if (previous.rows.len == 1) return .{ .crs_job = try reads.load(owner, input.id) };
    if (input.expires <= now or input.expires - now > m.preparation_seconds)
        return .{ .failed = .invalid_input };
    try prune(owner, now);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "INSERT INTO console_crs_jobs(id,actor,client_ip,kind,expected_revision," ++
            "state,created_at,expires,clone) SELECT ?,a.id,?,?,?,'preparing',?,?,? FROM a " ++
            "WHERE (SELECT revision FROM console_crs_selection WHERE id=1)=? " ++
            "AND (SELECT COUNT(*) FROM console_crs_jobs WHERE state IN " ++
            "('preparing','verified','selected'))<4 AND (SELECT COUNT(*) FROM " ++
            "console_crs_jobs)<128 " ++
            "AND (? IS NULL OR EXISTS(SELECT 1 FROM console_crs_jobs j WHERE j.id=? " ++
            "AND j.state='selected' AND j.id IN (SELECT job FROM console_crs_selection " ++
            "UNION SELECT previous FROM console_crs_selection))) " ++
            "AND NOT EXISTS(SELECT 1 FROM console_crs_jobs WHERE id=?)",
        &(credentials.values() ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.address(&input.auth.client),
            util.text(@tagName(input.kind)),
            util.integer(input.expected_revision),
            util.integer(now),
            util.integer(input.expires),
            if (input.clone) |id| util.text(id.slice()) else .null_value,
            util.integer(input.expected_revision),
            if (input.clone) |id| util.text(id.slice()) else .null_value,
            if (input.clone) |id| util.text(id.slice()) else .null_value,
            util.text(input.id.slice()),
        }),
    );
    if (changed != 0) return .{ .crs_job = try reads.load(owner, input.id) };
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const selection = (try reads.selected(owner)).crs_selection;
    if (selection.revision != input.expected_revision or
        try reads.load(owner, input.id) != null) return .{ .failed = .conflict };
    return beginFailure(owner);
}

pub fn chunk(owner: *Persistent, input: m.Chunk) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const credentials = access.Credentials.init(input.auth, owner.nowSeconds());
    var encoded: [m.chunk_bytes * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    var writer: std.Io.Writer = .fixed(&encoded);
    try writer.print("{x}", .{input.bytes.slice()});
    const file = @tagName(input.file);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "INSERT INTO console_crs_chunks(job,file,ordinal,bytes) SELECT ?,?,?,? FROM a " ++
            "WHERE EXISTS(SELECT 1 FROM console_crs_jobs WHERE id=? AND actor=a.id " ++
            "AND state='preparing' AND clone IS NULL AND expires>?) " ++
            "AND (SELECT COUNT(*) FROM console_crs_chunks WHERE job=? AND file=?)=? " ++
            "AND NOT EXISTS(SELECT 1 FROM console_crs_chunks WHERE job=? AND file=? " ++
            "AND length(bytes)!=4096) ON CONFLICT DO NOTHING",
        &(credentials.values() ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.text(file),
            util.integer(input.ordinal),
            util.text(writer.buffered()),
            util.text(input.id.slice()),
            util.integer(credentials.now),
            util.text(input.id.slice()),
            util.text(file),
            util.integer(input.ordinal),
            util.text(input.id.slice()),
            util.text(file),
        }),
    );
    if (changed != 0) return .command_recorded;
    var repeated = try db.query(
        owner.db,
        owner.gpa,
        access.sql ++
            "SELECT c.bytes FROM console_crs_chunks c JOIN console_crs_jobs j ON j.id=c.job " ++
            "WHERE c.job=? AND c.file=? AND c.ordinal=? AND c.bytes=? AND " ++
            "j.actor=(SELECT id FROM a) " ++
            "AND j.state='preparing' AND j.expires>? LIMIT 1",
        &(credentials.values() ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.text(file),
            util.integer(input.ordinal),
            util.text(writer.buffered()),
            util.integer(credentials.now),
        }),
    );
    defer repeated.deinit();
    if (repeated.rows.len == 1) return .command_recorded;
    return mutationFailure(owner, input.auth);
}

pub fn verify(owner: *Persistent, input: m.Verify) !p.StorageResult {
    const manifest = @import("crs").artifact_manifest.decode(input.manifest.slice()) catch
        return .{ .failed = .invalid_input };
    const observation = if (owner.cfg.mode == .forward_auth)
        @import("crs").config.Observation.request_metadata
    else
        @import("crs").config.Observation.request_response;
    _ = manifest.options(observation) catch return .{ .failed = .invalid_input };
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const now = owner.nowSeconds();
    if (!try complete(owner, input.id, manifest)) return .{ .failed = .invalid_input };
    const credentials = access.Credentials.init(input.auth, now);
    var encoded: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try writer.print("{x}", .{input.manifest.slice()});
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "UPDATE console_crs_jobs SET state='verified',manifest=?,verified_at=?,expires=? " ++
            "WHERE id=? AND actor=(SELECT id FROM a) AND state='preparing' AND expires>? " ++
            "AND expected_revision=?",
        &(credentials.values() ++ [_]zx.Value{
            util.text(writer.buffered()),
            util.integer(now),
            util.integer(now + m.review_seconds),
            util.text(input.id.slice()),
            util.integer(now),
            util.integer(manifest.previous_revision),
        }),
    );
    if (changed != 0) return .{ .crs_job = try reads.load(owner, input.id) };
    const previous = try reads.load(owner, input.id);
    if (previous) |job| if (job.state == .verified and
        std.mem.eql(u8, job.manifest.slice(), input.manifest.slice()) and
        try access.mutation(owner, input.auth) != null) return .{ .crs_job = job };
    return mutationFailure(owner, input.auth);
}

fn complete(
    owner: *Persistent,
    id: m.Id,
    manifest: @import("crs").artifact_manifest.Manifest,
) !bool {
    const sizes = [_]usize{
        manifest.archive_bytes, manifest.signature_bytes, manifest.configuration_bytes,
    };
    inline for (@typeInfo(m.File).@"enum".field_names, 0..) |name, index| {
        var rows = try db.query(
            owner.db,
            owner.gpa,
            "SELECT COUNT(*),COALESCE(SUM(length(bytes)/2),0) FROM console_crs_chunks " ++
                "WHERE job=? AND file=?",
            &.{ util.text(id.slice()), util.text(name) },
        );
        defer rows.deinit();
        const chunks = std.math.divCeil(usize, sizes[index], m.chunk_bytes) catch unreachable;
        if (try util.number(rows.rows[0][0]) != chunks or
            try util.number(rows.rows[0][1]) != sizes[index]) return false;
    }
    return true;
}

pub fn discard(owner: *Persistent, input: m.Read) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const credentials = access.Credentials.init(input.auth, owner.nowSeconds());
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "UPDATE console_crs_jobs SET state='canceled',reason='canceled',completed_at=? " ++
            "WHERE id=? AND state IN ('preparing','verified') AND EXISTS(SELECT 1 FROM a)",
        &(credentials.values() ++ [_]zx.Value{
            util.integer(credentials.now),
            util.text(input.id.slice()),
        }),
    );
    if (changed == 0) return mutationFailure(owner, input.auth);
    try prune(owner, credentials.now);
    return .{ .crs_job = try reads.load(owner, input.id) };
}

pub fn failed(owner: *Persistent, input: m.Failed) !p.StorageResult {
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_crs_jobs SET state='failed',reason=?,completed_at=? " ++
            "WHERE id=? AND state='preparing'",
        &.{
            util.text(@tagName(input.reason)), util.integer(owner.nowSeconds()),
            util.text(input.id.slice()),
        },
    );
    return .{ .crs_job = try reads.load(owner, input.id) };
}

fn prune(owner: *Persistent, now: u64) !void {
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_crs_jobs SET state='failed',reason='canceled',completed_at=? " ++
            "WHERE state IN ('preparing','verified') AND expires<=?",
        &.{
            util.integer(now), util.integer(now),
        },
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_crs_jobs SET state='retired' WHERE state='selected' AND id NOT IN " ++
            "(SELECT job FROM console_crs_selection WHERE job IS NOT NULL UNION " ++
            "SELECT previous FROM console_crs_selection WHERE previous IS NOT NULL)",
        &.{},
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_crs_chunks WHERE job IN (SELECT id FROM console_crs_jobs " ++
            "WHERE state IN ('failed','canceled','retired'))",
        &.{},
    );
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_crs_jobs WHERE id IN (SELECT id FROM console_crs_jobs " ++
            "WHERE state IN ('failed','canceled','retired') AND created_at<? " ++
            "ORDER BY created_at,id LIMIT 16)",
        &.{util.integer(now -| m.review_seconds)},
    );
}

pub fn mutationFailure(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.mutation(owner, auth) == null) return .{ .failed = .forbidden };
    return .{ .failed = .conflict };
}

fn beginFailure(owner: *Persistent) !p.StorageResult {
    var count = try db.query(
        owner.db,
        owner.gpa,
        "SELECT COUNT(*),SUM(state IN ('preparing','verified','selected')) " ++
            "FROM console_crs_jobs",
        &.{},
    );
    defer count.deinit();
    const row = count.rows[0];
    return .{ .failed = if (try util.number(row[0]) >= 128 or
        (if (row[1] == null) @as(u64, 0) else try util.number(row[1])) >= m.candidate_capacity)
        .capacity
    else
        .conflict };
}

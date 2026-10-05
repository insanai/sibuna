//! Scalar reads copy their complete envelope before database result teardown.
//! Internal source reads are not HTTP endpoints; only the joined CRS service
//! consumes signed source, including the private operator configuration.
const std = @import("std");
const p = @import("console").protocol;
const m = p.crs_management;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_crs_access.zig");

pub fn load(owner: *Persistent, id: m.Id) !?m.Job {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,kind,state,expected_revision,created_at,expires,verified_at," ++
            "completed_at,manifest,reason FROM console_crs_jobs WHERE id=? LIMIT 1",
        &.{util.text(id.slice())},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    const row = rows.rows[0];
    var value: m.Job = .{
        .id = try m.Id.init(row[0].?),
        .kind = try enumeration(m.Kind, row[1]),
        .state = try enumeration(m.State, row[2]),
        .expected_revision = try util.number(row[3]),
        .created_at = try util.number(row[4]),
        .expires = try util.number(row[5]),
        .verified_at = if (row[6]) |_| try util.number(row[6]) else null,
        .completed_at = if (row[7]) |_| try util.number(row[7]) else null,
        .reason = try enumeration(m.Reason, row[9]),
    };
    if (!m.validId(value.id)) return error.InvalidStoredValue;
    if (row[8]) |hex| {
        if (hex.len > value.manifest.data.len * 2 or hex.len % 2 != 0)
            return error.InvalidStoredValue;
        value.manifest.len = hex.len / 2;
        _ = std.fmt.hexToBytes(value.manifest.data[0..value.manifest.len], hex) catch
            return error.InvalidStoredValue;
        _ = try @import("crs").artifact_manifest.decode(value.manifest.slice());
    }
    return value;
}

pub fn selected(owner: *Persistent) !p.StorageResult {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT revision,selected_at,job,previous FROM console_crs_selection WHERE id=1",
        &.{},
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return error.InvalidStoredValue;
    const row = rows.rows[0];
    var value: m.Selection = .{
        .revision = try util.number(row[0]),
        .selected_at = try util.number(row[1]),
    };
    if (row[2]) |id| value.current = try load(owner, try m.Id.init(id)) orelse
        return error.InvalidStoredValue;
    if (row[3]) |id| value.previous = try load(owner, try m.Id.init(id)) orelse
        return error.InvalidStoredValue;
    if ((value.current == null) != (value.revision == 0)) return error.InvalidStoredValue;
    if (value.current) |current| {
        const manifest = try @import("crs").artifact_manifest.decode(current.manifest.slice());
        if (manifest.revision != value.revision) return error.InvalidStoredValue;
    }
    return .{ .crs_selection = value };
}

pub fn status(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.read(owner, auth)) |failure| return .{ .failed = failure };
    const result = try selected(owner);
    if (try access.read(owner, auth)) |failure| return .{ .failed = failure };
    return result;
}

pub fn job(owner: *Persistent, input: m.Read) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const value = try load(owner, input.id);
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    return .{ .crs_job = value };
}

pub fn jobs(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.mutation(owner, auth) == null) return .{ .failed = .forbidden };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id FROM console_crs_jobs ORDER BY " ++
            "state IN ('preparing','verified','selected') DESC,created_at DESC,id DESC LIMIT 4",
        &.{},
    );
    defer rows.deinit();
    var result: m.Jobs = .{};
    for (rows.rows) |row| {
        result.rows[result.count] = try load(owner, try m.Id.init(row[0].?)) orelse
            return error.InvalidStoredValue;
        result.count += 1;
    }
    if (try access.mutation(owner, auth) == null) return .{ .failed = .forbidden };
    return .{ .crs_jobs = result };
}

pub fn source(owner: *Persistent, input: m.Source) !p.StorageResult {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT c.bytes FROM console_crs_chunks c JOIN console_crs_jobs j ON j.id=c.job " ++
            "WHERE c.job=? AND c.file=? AND c.ordinal=? " ++
            "AND (j.state IN ('verified','selected') OR " ++
            "(j.state='preparing' AND j.clone IS NOT NULL)) LIMIT 1",
        &.{
            util.text(input.id.slice()),
            util.text(@tagName(input.file)),
            util.integer(input.ordinal),
        },
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return .{ .failed = .conflict };
    const hex = rows.rows[0][0] orelse return error.InvalidStoredValue;
    var bytes: p.Bytes(m.chunk_bytes) = .{};
    if (hex.len > bytes.data.len * 2 or hex.len % 2 != 0) return error.InvalidStoredValue;
    bytes.len = hex.len / 2;
    _ = std.fmt.hexToBytes(bytes.data[0..bytes.len], hex) catch return error.InvalidStoredValue;
    return .{ .crs_source = bytes };
}

pub fn nodes(owner: *Persistent, auth: p.users.Auth) !p.StorageResult {
    if (try access.read(owner, auth)) |failure| return .{ .failed = failure };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT r.node,r.boot,r.revision,r.applied,r.reason,r.observed_at " ++
            "FROM console_crs_applied r JOIN console_nodes n " ++
            "ON n.node=r.node AND n.boot=r.boot " ++
            "ORDER BY r.node LIMIT 9",
        &.{},
    );
    defer rows.deinit();
    var page: m.Nodes = .{};
    for (rows.rows) |row| {
        page.rows[page.count] = .{
            .node = std.math.cast(u32, try util.number(row[0])) orelse
                return error.InvalidStoredValue,
            .boot = try m.Id.init(row[1].?),
            .revision = try util.number(row[2]),
            .applied = try util.number(row[3]) == 1,
            .reason = try enumeration(m.Reason, row[4]),
            .observed_at = try util.number(row[5]),
        };
        page.count += 1;
    }
    if (try access.read(owner, auth)) |failure| return .{ .failed = failure };
    return .{ .crs_nodes = page };
}

fn enumeration(comptime T: type, input: ?[]const u8) !T {
    return std.meta.stringToEnum(T, input orelse return error.InvalidStoredValue) orelse
        error.InvalidStoredValue;
}

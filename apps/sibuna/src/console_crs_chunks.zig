//! One append contract for authenticated jobs and filesystem startup adoption.
//! Ordinals and exact retries have identical ownership and bounds in both paths.
const std = @import("std");
const p = @import("console").protocol;
const m = p.crs_management;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_crs_access.zig");
pub const Authority = union(enum) { admin: p.users.Auth, startup };
const startup = "WITH a AS(SELECT 0 AS id WHERE " ++
    "(SELECT revision FROM console_crs_selection WHERE id=1)=0) ";

pub fn append(owner: *Persistent, authority: Authority, input: m.SourceWrite) !p.StorageResult {
    if (authority == .startup) return appendAs(owner, input, startup, [_]zx.Value{});
    const auth = authority.admin;
    if (try access.mutation(owner, auth) == null) return .{ .failed = .forbidden };
    const credentials = access.Credentials.init(auth, owner.nowSeconds());
    const result = try appendAs(owner, input, access.sql, credentials.values());
    if (try access.mutation(owner, auth) == null) return .{ .failed = .forbidden };
    return result;
}

fn appendAs(
    owner: *Persistent,
    input: m.SourceWrite,
    comptime authority: []const u8,
    credentials: anytype,
) !p.StorageResult {
    var encoded: [m.chunk_bytes * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    var writer: std.Io.Writer = .fixed(&encoded);
    try writer.print("{x}", .{input.bytes.slice()});
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        authority ++ "INSERT INTO console_crs_chunks(job,file,ordinal,bytes) " ++
            "SELECT ?,?,?,? FROM a WHERE EXISTS(SELECT 1 FROM console_crs_jobs " ++
            "WHERE id=? AND actor=a.id AND state='preparing' AND clone IS NULL " ++
            "AND expires>?) AND (SELECT COUNT(*) FROM console_crs_chunks " ++
            "WHERE job=? AND file=?)=? AND NOT EXISTS(SELECT 1 FROM console_crs_chunks " ++
            "WHERE job=? AND file=? AND length(bytes)!=4096) ON CONFLICT DO NOTHING",
        &(credentials ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.text(@tagName(input.file)),
            util.integer(input.ordinal),
            util.text(writer.buffered()),
            util.text(input.id.slice()),
            util.integer(owner.nowSeconds()),
            util.text(input.id.slice()),
            util.text(@tagName(input.file)),
            util.integer(input.ordinal),
            util.text(input.id.slice()),
            util.text(@tagName(input.file)),
        }),
    );
    if (changed != 0) return .command_recorded;
    return repeated(owner, input, writer.buffered(), authority, credentials);
}

fn repeated(
    owner: *Persistent,
    input: m.SourceWrite,
    encoded: []const u8,
    comptime authority: []const u8,
    credentials: anytype,
) !p.StorageResult {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        authority ++ "SELECT c.bytes FROM console_crs_chunks c " ++
            "JOIN console_crs_jobs j ON j.id=c.job WHERE c.job=? AND c.file=? " ++
            "AND c.ordinal=? AND c.bytes=? AND j.actor=(SELECT id FROM a) " ++
            "AND j.state='preparing' AND j.expires>? LIMIT 1",
        &(credentials ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.text(@tagName(input.file)),
            util.integer(input.ordinal),
            util.text(encoded),
            util.integer(owner.nowSeconds()),
        }),
    );
    defer rows.deinit();
    if (rows.rows.len == 1) return .command_recorded;
    return .{ .failed = .conflict };
}

//! Adopt an already authenticated filesystem generation before listeners start.
//! These internal operations cannot select new protection: the manifest must
//! describe the actual published generation, and durable selection must be empty.
const std = @import("std");
const crs = @import("crs");
const p = @import("console").protocol;
const m = p.crs_management;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const jobs = @import("console_crs_jobs.zig");
const reads = @import("console_crs_jobs_read.zig");

pub fn execute(owner: *Persistent, request: m.Request) !p.StorageResult {
    return switch (request) {
        .startup_begin => |input| begin(owner, input),
        .startup_chunk => |input| chunk(owner, input),
        .startup_commit => |id| commit(owner, id),
        else => unreachable,
    };
}

fn begin(owner: *Persistent, input: m.Startup) !p.StorageResult {
    const manifest = crs.artifact_manifest.decode(input.manifest.slice()) catch
        return .{ .failed = .invalid_input };
    if (!matches(owner, manifest)) return .{ .failed = .conflict };
    try jobs.prune(owner, owner.nowSeconds());
    var encoded: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try writer.print("{x}", .{input.manifest.slice()});
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_crs_jobs(id,actor,kind,expected_revision,state,created_at," ++
            "expires,manifest) SELECT ?,0,'update',0,'preparing',?,?,? " ++
            "WHERE (SELECT revision FROM console_crs_selection WHERE id=1)=0 " ++
            "AND (SELECT COUNT(*) FROM console_crs_jobs)<128 AND " ++
            "(SELECT COUNT(*) FROM console_crs_jobs " ++
            "WHERE state IN ('preparing','verified','selected'))<4 " ++
            "ON CONFLICT DO NOTHING",
        &.{
            util.text(input.id.slice()),
            util.integer(owner.nowSeconds()),
            util.integer(owner.nowSeconds() + m.preparation_seconds),
            util.text(writer.buffered()),
        },
    );
    return if (changed != 0) .command_recorded else .{ .failed = .conflict };
}

fn chunk(owner: *Persistent, input: m.SourceWrite) !p.StorageResult {
    return @import("console_crs_chunks.zig").append(owner, .startup, input);
}

fn commit(owner: *Persistent, id: m.Id) !p.StorageResult {
    const job = try reads.load(owner, id) orelse return .{ .failed = .conflict };
    const manifest = crs.artifact_manifest.decode(job.manifest.slice()) catch
        return .{ .failed = .invalid_input };
    if (!matches(owner, manifest) or !try jobs.complete(owner, id, manifest))
        return .{ .failed = .conflict };
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_crs_selection SET revision=?,job=?,selected_at=?,actor=0 " ++
            "WHERE id=1 AND revision=0 AND EXISTS(SELECT 1 FROM console_crs_jobs j " ++
            "WHERE j.id=? AND j.actor=0 AND j.state='preparing' AND j.expires>?)",
        &.{
            util.integer(manifest.revision),
            util.text(id.slice()),
            util.integer(owner.nowSeconds()),
            util.text(id.slice()),
            util.integer(owner.nowSeconds()),
        },
    );
    const result = try reads.selected(owner);
    if (result.crs_selection.current) |current| {
        if (std.mem.eql(u8, current.id.slice(), id.slice())) return result;
    }
    return .{ .failed = .conflict };
}

fn matches(owner: *Persistent, manifest: crs.artifact_manifest.Manifest) bool {
    const publisher = owner.state.crs orelse return false;
    const current = publisher.snapshot() catch return false;
    return manifest.matchesCurrent(current);
}

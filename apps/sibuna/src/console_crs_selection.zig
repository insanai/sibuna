//! One durable CAS selects immutable signed source. Publication follows on the
//! node's service thread; receipts report effects without rewriting that intent.
const std = @import("std");
const p = @import("console").protocol;
const m = p.crs_management;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_crs_access.zig");
const reads = @import("console_crs_jobs_read.zig");

pub fn select(owner: *Persistent, input: m.Select) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const job = try reads.load(owner, input.id) orelse return .{ .failed = .conflict };
    const manifest = @import("crs").artifact_manifest.decode(job.manifest.slice()) catch
        return .{ .failed = .invalid_input };
    if (manifest.previous_revision != input.expected_revision or
        manifest.revision != input.expected_revision + 1) return .{ .failed = .conflict };
    const credentials = access.Credentials.init(input.auth, owner.nowSeconds());
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "UPDATE console_crs_selection SET revision=revision+1,previous=job,job=?," ++
            "selected_at=?,actor=(SELECT id FROM a),client_ip=? WHERE id=1 AND revision=? " ++
            "AND EXISTS(SELECT 1 FROM a) AND EXISTS(SELECT 1 FROM console_crs_jobs j " ++
            "WHERE j.id=? AND j.state='verified' AND j.expires>? AND j.expected_revision=?)",
        &(credentials.values() ++ [_]zx.Value{
            util.text(input.id.slice()),
            util.integer(credentials.now),
            util.address(&input.auth.client),
            util.integer(input.expected_revision),
            util.text(input.id.slice()),
            util.integer(credentials.now),
            util.integer(input.expected_revision),
        }),
    );
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const result = try reads.selected(owner);
    // A lost reply can be retried, but a different intervening selection cannot
    // be mistaken for this operation's completion.
    if (changed != 0) return result;
    const selected = result.crs_selection;
    if (selected.revision == manifest.revision and selected.current != null and
        std.mem.eql(u8, selected.current.?.id.slice(), input.id.slice())) return result;
    return .{ .failed = .conflict };
}

pub fn applied(owner: *Persistent, input: m.Applied) !p.StorageResult {
    if (input.applied) {
        const publisher = owner.state.crs orelse return .{ .failed = .conflict };
        const snapshot = publisher.snapshot() catch return .{ .failed = .conflict };
        if (snapshot.revision != input.revision) return .{ .failed = .conflict };
    }
    const boot = std.fmt.bytesToHex(owner.console_node.boot, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_crs_applied(node,boot,revision,applied,reason,observed_at) " ++
            "SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM console_crs_selection " ++
            "WHERE id=1 AND revision=?) ON CONFLICT(node) DO UPDATE SET " ++
            "boot=excluded.boot,revision=excluded.revision,applied=excluded.applied," ++
            "reason=excluded.reason,observed_at=excluded.observed_at " ++
            "WHERE boot!=excluded.boot OR revision<excluded.revision OR " ++
            "(revision=excluded.revision AND excluded.applied>=applied AND " ++
            "(applied!=excluded.applied OR reason!=excluded.reason))",
        &.{
            util.integer(owner.node_id),
            util.text(&boot),
            util.integer(input.revision),
            util.integer(@intFromBool(input.applied)),
            util.text(@tagName(input.reason)),
            util.integer(owner.nowSeconds()),
            util.integer(input.revision),
        },
    );
    const selection = (try reads.selected(owner)).crs_selection;
    if (selection.revision != input.revision) return .{ .failed = .conflict };
    return .command_recorded;
}

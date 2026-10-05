//! Authorization, expected revision, retained source and a redacted test intent
//! are checked in the same statement. Private samples never enter storage.
const p = @import("console").protocol;
const m = p.crs_management;
const Persistent = @import("persistent.zig").Persistent;
const access = @import("console_crs_access.zig");
const reads = @import("console_crs_jobs_read.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const zx = @import("zaxonlite");

pub fn begin(owner: *Persistent, input: m.Select) !p.StorageResult {
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    const credentials = access.Credentials.init(input.auth, owner.nowSeconds());
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        access.sql ++
            "INSERT INTO console_audit(actor,actor_role,action,subject,target," ++
            "recorded_at,client_ip) SELECT a.id,'admin','crs.test',?,?,?,? FROM a " ++
            "WHERE (SELECT revision FROM console_crs_selection WHERE id=1)=? " ++
            "AND EXISTS(SELECT 1 FROM console_crs_jobs j WHERE j.id=? AND " ++
            "((j.state='verified' AND j.expires>?) OR (j.state='selected' AND j.id IN " ++
            "(SELECT job FROM console_crs_selection UNION " ++
            "SELECT previous FROM console_crs_selection))))",
        &(credentials.values() ++ [_]zx.Value{
            util.integer(input.expected_revision),
            util.text(input.id.slice()),
            util.integer(credentials.now),
            util.address(&input.auth.client),
            util.integer(input.expected_revision),
            util.text(input.id.slice()),
            util.integer(credentials.now),
        }),
    );
    if (try access.mutation(owner, input.auth) == null) return .{ .failed = .forbidden };
    if (changed == 0) return .{ .failed = .conflict };
    return .{ .crs_job = try reads.load(owner, input.id) };
}

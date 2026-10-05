//! Every expensive review or test starts with atomic redacted audit intent and
//! finishes with fresh authority, source retention and saved-revision checks.
const p = @import("console_protocol");
const App = @import("app.zig").App;
const m = p.crs_management;

pub fn begin(app: *App, auth: p.users.Auth, result: *const p.crs_tasks.Status) !m.Job {
    const input: m.Select = .{
        .auth = auth,
        .id = result.source,
        .expected_revision = result.expected_revision,
    };
    const operation: m.Request = if (result.kind == .sample)
        .{ .test_begin = input }
    else
        .{ .review_begin = input };
    const authorized = try app.request(.{ .crs_management = operation });
    if (authorized == .failed and authorized.failed == .forbidden)
        return error.CrsPreparationForbidden;
    if (authorized != .crs_job or authorized.crs_job == null) return error.CrsSelectionConflict;
    return authorized.crs_job.?;
}

pub fn recheck(app: *App, auth: p.users.Auth, result: *const p.crs_tasks.Status) !void {
    if (app.stopping.load(.acquire)) return error.Canceled;
    const selected = try app.request(.{ .crs_management = .{ .status = auth } });
    if (selected != .crs_selection or selected.crs_selection.revision != result.expected_revision)
        return error.CrsSelectionConflict;
    const retained = try app.request(.{ .crs_management = .{ .job = .{
        .auth = auth,
        .id = result.source,
    } } });
    if (retained != .crs_job or retained.crs_job == null or
        (retained.crs_job.?.state != .verified and retained.crs_job.?.state != .selected))
        return error.CrsPreparationForbidden;
    if (retained.crs_job.?.state == .verified and retained.crs_job.?.expires <= app.now())
        return error.CrsPreparationForbidden;
}

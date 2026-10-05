//! Only fresh administrator sessions can prepare or select CRS protection. Native
//! verification witnesses and raw signed source never have public HTTP routes.
const std = @import("std");
const p = @import("console_protocol");
const m = p.crs_management;
const App = @import("app.zig").App;
const http = @import("http.zig");
const view = @import("crs_views.zig");
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, route: Handler) !void {
    // Capture every borrowed head field before consuming a possibly large body.
    const auth = try @import("origin.zig").authority(app, context, principal);
    if (!app.query_budget.allow(app.io, auth.session_digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    dispatch(app, context, auth, route) catch |err| {
        return http.fail(context, switch (err) {
            error.CrsPreparationForbidden => .forbidden,
            error.CrsSelectionConflict, error.CrsPreparationRejected => .conflict,
            error.Busy, error.CrsPreparationCapacity => .too_many_requests,
            error.InvalidRequest,
            error.InvalidLimit,
            error.UnobservableProfile,
            error.InvalidReleaseVersion,
            error.InvalidMode,
            error.TooLarge,
            => .bad_request,
            else => .service_unavailable,
        }, "CONSOLECRS");
    };
}

fn dispatch(app: *App, context: *http.Context, auth: p.users.Auth, route: Handler) !void {
    switch (route) {
        .crs_test, .crs_test_read, .crs_review, .crs_review_read => {
            return @import("crs_test_routes.zig").handle(app, context, auth, route);
        },
        .crs_exclusions => return @import("crs_exclusion_routes.zig").read(app, context, auth),
        .crs_status => return status(app, context, auth),
        .crs_prepare => return @import("crs_prepare_routes.zig").prepare(app, context, auth),
        .crs_configuration => return @import("crs_prepare_routes.zig").configuration(
            app,
            context,
            auth,
        ),
        .crs_select, .crs_discard => return edit(app, context, auth, route),
        else => unreachable,
    }
}

fn selection(app: *App, auth: p.users.Auth) !m.Selection {
    const result = try app.request(.{ .crs_management = .{ .status = auth } });
    if (result != .crs_selection) return error.CrsSelectionConflict;
    return result.crs_selection;
}

pub fn administrator(app: *App, auth: p.users.Auth) !m.Jobs {
    const result = try app.request(.{ .crs_management = .{ .jobs = auth } });
    if (result == .failed and result.failed == .forbidden) return error.CrsPreparationForbidden;
    if (result != .crs_jobs) return error.StorageUnavailable;
    return result.crs_jobs;
}

fn status(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    const jobs = try administrator(app, auth);
    const selected = try selection(app, auth);
    const nodes = try app.request(.{ .crs_management = .{ .nodes = auth } });
    const local = try app.request(.{ .node_status = auth });
    if (nodes != .crs_nodes or local != .node_status) return error.StorageUnavailable;
    const progress = app.crs_job.snapshot();
    var output: p.crs_api.Status = .{
        .available = app.crs_job.publisher != null,
        .next_id = @import("crs_job.zig").identifier(app.io),
        .revision = selected.revision,
        .selected_at = selected.selected_at,
        .current = if (selected.current) |job| try view.candidate(job) else null,
        .previous = if (selected.previous) |job| try view.candidate(job) else null,
        .local = local.node_status.crs orelse .{},
        .job = progress.id,
        .stage = progress.stage,
        .reason = progress.reason,
        .count = jobs.count,
        .node_count = nodes.crs_nodes.count,
    };
    for (jobs.rows[0..jobs.count], 0..) |job, i| output.candidates[i] = try view.candidate(job.?);
    for (nodes.crs_nodes.rows[0..nodes.crs_nodes.count], 0..) |node, i| output.nodes[i] = node;
    // A concurrent selection is a retryable view, never a mixed reviewed state.
    if ((try selection(app, auth)).revision != selected.revision) {
        return error.CrsSelectionConflict;
    }
    _ = try administrator(app, auth);
    return http.json(context, output, &.{});
}

fn edit(app: *App, context: *http.Context, auth: p.users.Auth, route: Handler) !void {
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(
        struct { id: []const u8, expected_revision: []const u8 },
        context,
        &body,
        arena.allocator(),
    );
    defer parsed.deinit();
    const id = try identifier(parsed.value.id);
    const revision = try revisionValue(parsed.value.expected_revision);
    const result = try app.request(.{ .crs_management = if (route == .crs_select) .{ .select = .{
        .auth = auth,
        .id = id,
        .expected_revision = revision,
    } } else .{ .discard = .{ .auth = auth, .id = id } } });
    if (result == .failed) return storageFailure(context, result.failed);
    if (result == .crs_selection) return http.json(context, .{
        .committed = true,
        .revision = result.crs_selection.revision,
        .application = "unconfirmed",
    }, &.{});
    if (result == .crs_job) return http.json(context, .{ .discarded = true }, &.{});
    return error.StorageUnavailable;
}

pub fn identifier(text: []const u8) !m.Id {
    const id = try m.Id.init(text);
    if (!m.validId(id)) return error.InvalidRequest;
    return id;
}

pub fn revisionValue(text: []const u8) !u64 {
    if (text.len == 0) return error.InvalidRequest;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
    const revision = std.fmt.parseInt(u64, text, 10) catch return error.InvalidRequest;
    if (revision >= std.math.maxInt(i64)) return error.InvalidRequest;
    return revision;
}

fn storageFailure(context: *http.Context, reason: p.Failure) !void {
    return http.fail(context, switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        .conflict => .conflict,
        .capacity => .too_many_requests,
        else => .service_unavailable,
    }, "CONSOLECRS");
}

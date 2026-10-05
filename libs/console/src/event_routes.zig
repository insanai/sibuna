const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const origin = @import("origin.zig");

pub fn query(app: *App, context: *http.Context, export_page: bool) !void {
    const digest = try http.session(context);
    const kind: @import("query_budget.zig").Kind = if (export_page) .export_page else .query;
    if (!app.query_budget.allow(app.io, digest, app.now(), kind))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    const seen = origin.Origin.capture(app, context);
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct {
        view: enum { raw, source } = .raw,
        format: enum { json, csv } = .json,
        before: ?struct { time: u64, id: []const u8 } = null,
        limit: u16 = 10,
        from: u64 = 0,
        until: ?u64 = null,
        node: u32 = 0,
        campaign: []const u8 = "",
        incident: []const u8 = "",
        category: []const u8 = "",
        module: ?p.security.Module = null,
        country: []const u8 = "",
        ip: []const u8 = "",
        path_prefix: []const u8 = "",
    }, context, &body, fixed.allocator());
    defer input.deinit();
    const fields = input.value;
    var request: p.events.Query = .{
        .session_digest = digest,
        .grouped = fields.view == .source,
        .export_page = export_page,
        .require_totp = app.config.behind_proxy,
        .client = seen.client,
        .limit = fields.limit,
        .from = fields.from,
        .until = fields.until orelse std.math.maxInt(i64),
        .node = fields.node,
        .campaign = try campaignId(fields.campaign),
        .incident = try campaignId(fields.incident),
        .module = fields.module,
        .category = try p.Bytes(32).init(fields.category),
        .country = try p.events.country.Filter.init(fields.country),
        .ip = try p.Bytes(48).init(fields.ip),
        .path_prefix = try p.Bytes(256).init(fields.path_prefix),
    };
    if (fields.before) |cursor| request.before = .{
        .time = cursor.time,
        .id = std.fmt.parseInt(u64, cursor.id, 10) catch return error.InvalidRequest,
    };
    const result = try app.request(.{ .events_query = request });
    return reply(context, result, export_page, fields.format == .csv);
}

fn reply(
    context: *http.Context,
    result: p.StorageResult,
    export_page: bool,
    csv_format: bool,
) !void {
    if (result == .page) {
        if (export_page and csv_format) {
            var output: [4096]u8 = undefined;
            const csv = try @import("event_export.zig").csv(result.page.slice(), &output);
            return context.respond(.ok, "text/csv; charset=utf-8", csv, &.{.{
                .name = "Content-Disposition",
                .value = "attachment; filename=\"sibuna-events.csv\"",
            }});
        }
        const headers: []const std.http.Header = if (export_page) &.{.{
            .name = "Content-Disposition",
            .value = "attachment; filename=\"sibuna-events.json\"",
        }} else &.{};
        return context.respond(.ok, "application/json", result.page.slice(), headers);
    }
    const status: std.http.Status = switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    };
    return http.fail(context, status, "CONSOLEEVENTS");
}

fn campaignId(value: []const u8) error{InvalidRequest}!u64 {
    if (value.len == 0) return 0;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidRequest;
}

/// Redacted heads for one incident; absent rows read as not recorded, never as empty.
pub fn heads(app: *App, context: *http.Context) !void {
    return readDetail(app, context, .heads);
}

pub fn handle(app: *App, context: *http.Context, handler: @import("routes.zig").Handler) !void {
    return switch (handler) {
        .events => query(app, context, false),
        .events_export => query(app, context, true),
        .events_heads => heads(app, context),
        .events_crs => crs(app, context),
        else => unreachable,
    };
}

pub fn crs(app: *App, context: *http.Context) !void {
    return readDetail(app, context, .crs);
}

fn readDetail(app: *App, context: *http.Context, kind: enum { heads, crs }) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [256]u8 = undefined;
    var arena: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct { id: []const u8 }, context, &body, fixed.allocator());
    defer input.deinit();
    const id = std.fmt.parseInt(u64, input.value.id, 10) catch return error.InvalidRequest;
    const request: p.incident_heads.Read = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .id = id,
    };
    const result = try app.request(switch (kind) {
        .heads => .{ .incident_heads_read = request },
        .crs => .{ .incident_crs_read = request },
    });
    defer p.releaseResult(result, app.gpa);
    if (result == .incident_heads) return http.json(context, result.incident_heads.*, &.{});
    if (result == .incident_crs) return http.json(context, result.incident_crs.*, &.{});
    return http.fail(context, switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    }, "CONSOLEEVENTS");
}

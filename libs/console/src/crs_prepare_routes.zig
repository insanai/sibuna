//! Operator text is bounded and owned before the HTTP connection can disappear.
//! Preparation does not select protection, even after successful verification.
const std = @import("std");
const crs = @import("crs");
const p = @import("console_protocol");
const m = p.crs_management;
const App = @import("app.zig").App;
const http = @import("http.zig");
const api = @import("crs_routes.zig");
const job = @import("crs_job.zig");
const sources = @import("crs_sources.zig");
const candidate = @import("crs_candidate.zig");
const Input = struct {
    id: []const u8,
    kind: m.Kind,
    expected_revision: []const u8,
    version: ?[]const u8 = null,
    settings: ?m.Settings = null,
    configuration: ?[]const u8 = null,
};
// JSON can escape each editor byte into six bytes. Body + parser + transferred
// text stay below the console's 1 MiB per-request allowance, off the stream stack.
const body_capacity = p.crs_api.body_bytes;
const parser_capacity = 512 * 1024;

pub fn prepare(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    _ = try api.administrator(app, auth);
    const body = try app.gpa.alloc(u8, body_capacity);
    defer app.gpa.free(body);
    defer std.crypto.secureZero(u8, body);
    const memory = try app.gpa.alloc(u8, parser_capacity);
    defer app.gpa.free(memory);
    defer std.crypto.secureZero(u8, memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const parsed = try http.parse(Input, context, body, arena.allocator());
    defer parsed.deinit();
    const selected = try selection(app, auth);
    const input = try command(app, auth, parsed.value, selected);
    var transferred = false;
    defer if (!transferred) {
        var owned = input;
        owned.deinit(app.gpa);
    };
    _ = try api.administrator(app, auth);
    const id = try app.crs_job.enqueue(input);
    transferred = true;
    return http.json(context, .{ .accepted = true, .id = id.slice() }, &.{});
}

fn command(app: *App, auth: p.users.Auth, input: Input, selected: m.Selection) !job.Input {
    const revision = try api.revisionValue(input.expected_revision);
    if (revision != selected.revision) return error.CrsSelectionConflict;
    const clone = switch (input.kind) {
        .mode => selected.current orelse return error.CrsSelectionConflict,
        .rollback => selected.previous orelse return error.CrsSelectionConflict,
        else => null,
    };
    if (clone != null and (input.version != null or input.configuration != null))
        return error.InvalidRequest;
    if (input.kind == .rollback and input.settings != null) return error.InvalidRequest;
    var defaults: m.Settings = .{};
    if (clone orelse selected.current) |existing| {
        defaults = @import("crs_views.zig").settings(
            try crs.artifact_manifest.decode(existing.manifest.slice()),
        );
    } else if (app.config.proxy_mode == .forward_auth) defaults.profile = .headers;
    return .{
        .auth = auth,
        .id = try api.identifier(input.id),
        .kind = input.kind,
        .expected_revision = revision,
        .clone = clone,
        .version = try version(input.version),
        .settings = input.settings orelse defaults,
        .configuration = if (clone != null) null else try editor(app, input, selected),
    };
}

fn editor(app: *App, input: Input, selected: m.Selection) !*candidate.Configuration {
    const output = try app.gpa.create(candidate.Configuration);
    errdefer app.gpa.destroy(output);
    @memset(&output.data, 0);
    output.len = 0;
    if (input.configuration) |text| {
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidRequest;
        try output.set(text);
    } else if (selected.current) |current| {
        const text = try sources.readConfiguration(app, current);
        defer app.gpa.free(text);
        defer std.crypto.secureZero(u8, text);
        try output.set(text);
    }
    return output;
}

fn selection(app: *App, auth: p.users.Auth) !m.Selection {
    const result = try app.request(.{ .crs_management = .{ .status = auth } });
    if (result != .crs_selection) return error.CrsSelectionConflict;
    return result.crs_selection;
}

pub fn configuration(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    _ = try api.administrator(app, auth);
    const selected = try selection(app, auth);
    const current = selected.current orelse return http.json(context, .{
        .revision = selected.revision,
        .configuration = "",
    }, &.{});
    const text = try sources.readConfiguration(app, current);
    defer app.gpa.free(text);
    defer std.crypto.secureZero(u8, text);
    _ = try api.administrator(app, auth);
    if ((try selection(app, auth)).revision != selected.revision) {
        return error.CrsSelectionConflict;
    }
    const buffer = try app.gpa.alloc(u8, body_capacity);
    defer app.gpa.free(buffer);
    defer std.crypto.secureZero(u8, buffer);
    var writer: std.Io.Writer = .fixed(buffer);
    try std.json.Stringify.value(.{
        .revision = selected.revision,
        .configuration = text,
    }, .{}, &writer);
    return context.respond(.ok, "application/json", writer.buffered(), &.{});
}

fn version(text: ?[]const u8) !?crs.release_version.Version {
    return if (text) |value| try crs.release_version.Version.parse(value) else null;
}

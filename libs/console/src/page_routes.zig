//! Template editing for administrators. Drafts are previewed through a separate GET that
//! answers under a sandbox policy in an opaque origin, so operator markup never runs inside
//! the console's own origin. Edits and resets are revision checked and audited by digest.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");
const policy = @import("policy");
const page_template = policy.page_template;
pub const max_drafts = 16;
pub const Draft = struct {
    session: [32]u8 = @splat(0),
    kind: p.pages.Kind = .denied,
    html: [p.pages.max_bytes]u8 = undefined,
    len: u16 = 0,
    stored_at: u64 = 0,
};
pub const Drafts = struct {
    mutex: std.Io.Mutex = .init,
    slots: [max_drafts]Draft = @splat(.{}),

    fn store(
        self: *Drafts,
        io: std.Io,
        session: [32]u8,
        kind: p.pages.Kind,
        html: []const u8,
        now: u64,
    ) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var oldest: usize = 0;
        for (&self.slots, 0..) |*slot, index| {
            if (std.mem.eql(u8, &slot.session, &session)) {
                oldest = index;
                break;
            }
            if (slot.stored_at < self.slots[oldest].stored_at) oldest = index;
        }
        const slot = &self.slots[oldest];
        slot.session = session;
        slot.kind = kind;
        @memcpy(slot.html[0..html.len], html);
        slot.len = @intCast(html.len);
        slot.stored_at = now;
    }

    fn take(
        self: *Drafts,
        io: std.Io,
        session: [32]u8,
        kind: p.pages.Kind,
        out: *[p.pages.max_bytes]u8,
    ) ?usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        for (&self.slots) |*slot| {
            if (slot.len == 0 or slot.kind != kind) continue;
            if (!std.mem.eql(u8, &slot.session, &session)) continue;
            @memcpy(out[0..slot.len], slot.html[0..slot.len]);
            return slot.len;
        }
        return null;
    }
};

fn auth(app: *App, context: *http.Context, principal: p.Principal) !p.users.Auth {
    return .{
        .session_digest = try http.session(context),
        .csrf_digest = principal.csrf_digest,
        .require_totp = app.config.behind_proxy,
    };
}

pub fn handle(
    app: *App,
    context: *http.Context,
    principal: p.Principal,
    route: @import("routes.zig").Route,
) !void {
    return switch (route.handler) {
        .pages_read => read(app, context, principal),
        .pages_edit => edit(app, context, principal),
        .pages_preview => preview(app, context, principal),
        .pages_preview_get => render(app, context, principal, std.meta.stringToEnum(
            p.pages.Kind,
            route.path["/console/api/pages/preview/".len..],
        ) orelse return error.InvalidRequest),
        else => unreachable,
    };
}

fn read(app: *App, context: *http.Context, principal: p.Principal) !void {
    // Headers are read before the body consumes the request buffer.
    const authority = try auth(app, context, principal);
    var body: [256]u8 = undefined;
    var memory: [512]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(
        struct { kind: p.pages.Kind },
        context,
        &body,
        arena.allocator(),
    );
    defer parsed.deinit();
    const result = try app.request(.{ .page_read = .{
        .auth = authority,
        .kind = parsed.value.kind,
    } });
    defer p.releaseResult(result, app.gpa);
    return reply(context, result);
}

fn reply(context: *http.Context, result: p.StorageResult) !void {
    switch (result) {
        .page_document => |document| return http.json(context, .{
            .kind = @tagName(document.kind),
            .revision = p.Counter{ .value = document.revision },
            .customized = document.customized,
            .sha256 = document.sha256.slice(),
            .html = document.html.slice(),
        }, &.{}),
        .command_recorded => return http.json(context, .{ .ok = true }, &.{}),
        .failed => |reason| return http.fail(context, switch (reason) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            .conflict => .conflict,
            .invalid_input => .bad_request,
            else => .service_unavailable,
        }, if (reason == .invalid_input) "CONSOLEPAGE" else "CONSOLESETTINGS"),
        else => return error.StorageUnavailable,
    }
}

const Form = struct {
    kind: p.pages.Kind,
    expected_revision: u64,
    reset: bool = false,
    html: []const u8 = "",
};

fn edit(app: *App, context: *http.Context, principal: p.Principal) !void {
    const authority = try auth(app, context, principal);
    const body = try app.gpa.alloc(u8, 20 * 1024);
    defer app.gpa.free(body);
    const memory = try app.gpa.alloc(u8, 40 * 1024);
    defer app.gpa.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const parsed = try http.parse(Form, context, body, arena.allocator());
    defer parsed.deinit();
    const form = parsed.value;
    if (form.html.len > p.pages.max_bytes) return http.fail(context, .bad_request, "CONSOLEPAGE");
    if (form.reset != (form.html.len == 0)) return http.fail(context, .bad_request, "CONSOLEPAGE");
    // The block belongs to the request from here on; `App.request` frees it on refusal
    // and the mailbox frees it once the owner has executed or discarded the edit.
    const html: ?*p.pages.Html = if (form.reset) null else try app.gpa.create(p.pages.Html);
    if (html) |block| block.set(form.html) catch unreachable;
    return reply(context, try app.request(.{ .page_edit = .{
        .auth = authority,
        .kind = form.kind,
        .expected_revision = form.expected_revision,
        .reset = form.reset,
        .html = html,
    } }));
}

/// Stores a draft for this session; the GET preview renders it in a sandboxed reply.
fn preview(app: *App, context: *http.Context, principal: p.Principal) !void {
    _ = principal;
    const session = try http.session(context);
    const body = try app.gpa.alloc(u8, 20 * 1024);
    defer app.gpa.free(body);
    const memory = try app.gpa.alloc(u8, 40 * 1024);
    defer app.gpa.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const parsed = try http.parse(
        struct { kind: p.pages.Kind, html: []const u8 },
        context,
        body,
        arena.allocator(),
    );
    defer parsed.deinit();
    if (parsed.value.html.len == 0 or parsed.value.html.len > p.pages.max_bytes)
        return http.fail(context, .bad_request, "CONSOLEPAGE");
    const scratch = try app.gpa.create(page_template.Template);
    defer app.gpa.destroy(scratch);
    const kind: page_template.Kind = @enumFromInt(@intFromEnum(parsed.value.kind));
    page_template.compile(kind, parsed.value.html, scratch) catch |err| {
        return http.json(context, .{ .accepted = false, .diagnostic = @errorName(err) }, &.{});
    };
    app.drafts.store(app.io, session, parsed.value.kind, parsed.value.html, app.now());
    return http.json(context, .{ .accepted = true, .path = previewPath(parsed.value.kind) }, &.{});
}

pub fn previewPath(kind: p.pages.Kind) []const u8 {
    return switch (kind) {
        .challenge => "/console/api/pages/preview/challenge",
        .denied => "/console/api/pages/preview/denied",
        .rate_limited => "/console/api/pages/preview/rate_limited",
        .banned => "/console/api/pages/preview/banned",
        .overloaded => "/console/api/pages/preview/overloaded",
    };
}

/// Renders the session's draft (or the stored page) with sample values under a sandbox
/// policy that forbids scripts, network and framing; the reply is its own opaque origin.
fn render(app: *App, context: *http.Context, principal: p.Principal, kind: p.pages.Kind) !void {
    const session = try http.session(context);
    const html = try app.gpa.alloc(u8, p.pages.max_bytes);
    defer app.gpa.free(html);
    var length = app.drafts.take(app.io, session, kind, html[0..p.pages.max_bytes]);
    if (length == null) {
        const result = try app.request(.{ .page_read = .{
            .auth = try auth(app, context, principal),
            .kind = kind,
        } });
        defer p.releaseResult(result, app.gpa);
        if (result != .page_document) return reply(context, result);
        @memcpy(html[0..result.page_document.html.len], result.page_document.html.slice());
        length = result.page_document.html.len;
    }
    const template = try app.gpa.create(page_template.Template);
    defer app.gpa.destroy(template);
    const template_kind: page_template.Kind = @enumFromInt(@intFromEnum(kind));
    page_template.compile(template_kind, html[0..length.?], template) catch
        return http.fail(context, .bad_request, "CONSOLEPAGE");
    const output = try app.gpa.alloc(u8, p.pages.max_bytes + 4096);
    defer app.gpa.free(output);
    var writer: std.Io.Writer = .fixed(output);
    try page_template.write(template, &writer, .{
        .status = 403,
        .reason = "sample: blocked by rule example",
        .retry_after = 30,
        .request_id = "0123456789abcdef",
        .node = app.config.node_id,
        .challenge = "<p><em>Solver block appears here.</em></p>",
    });
    return context.respondIsolated(.ok, "text/html; charset=utf-8", writer.buffered());
}

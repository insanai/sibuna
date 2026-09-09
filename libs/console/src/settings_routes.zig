//! Administrator settings and notification destinations. Cookie sessions only: a bearer
//! credential never manages destinations. Secrets are sealed on this thread under the
//! console key before storage and are never echoed back.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");
const n = p.notifications;
const Handler = @import("routes.zig").Handler;
const target = @import("notify_target.zig");
const secrets = @import("auth_secrets.zig");

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, kind: Handler) !void {
    std.debug.assert(principal.token_id == null);
    const auth: p.users.Auth = .{
        .session_digest = try http.session(context),
        .csrf_digest = principal.csrf_digest,
        .require_totp = app.config.behind_proxy,
    };
    return switch (kind) {
        .settings_query => reply(context, try app.request(.{ .settings_query = auth })),
        .settings_change => changeSetting(app, context, auth),
        .notifications_query => queryDestinations(app, context, auth),
        .notifications_save => saveDestination(app, context, auth),
        .notifications_remove => removeDestination(app, context, auth),
        .notifications_test => testDestination(app, context, auth),
        else => unreachable,
    };
}

fn reply(context: *http.Context, result: p.StorageResult) !void {
    switch (result) {
        .settings_page => |page| return http.json(context, page, &.{}),
        .notifications_page => |page| return http.json(context, page, &.{}),
        .notification_saved => |id| return http.json(
            context,
            .{ .id = p.Counter{ .value = id } },
            &.{},
        ),
        .command_recorded => return http.json(context, .{ .ok = true }, &.{}),
        .failed => |reason| return http.fail(context, switch (reason) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            .conflict => .conflict,
            .invalid_input => .bad_request,
            .capacity => .service_unavailable,
            else => .service_unavailable,
        }, if (reason == .capacity) "CONSOLENOTIFYFULL" else "CONSOLESETTINGS"),
        else => return error.StorageUnavailable,
    }
}

fn changeSetting(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [2048]u8 = undefined;
    var memory: [4096]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        key: []const u8,
        value: []const u8,
        expected_revision: u64,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    const input = parsed.value;
    if (!n.knownSetting(input.key) or !validNumber(input.value))
        return http.fail(context, .bad_request, "CONSOLESETTINGS");
    return reply(context, try app.request(.{ .settings_change = .{
        .auth = auth,
        .key = try p.Bytes(n.max_setting_key).init(input.key),
        .value = try p.Bytes(n.max_setting_value).init(input.value),
        .expected_revision = input.expected_revision,
    } }));
}

/// The two known settings are small positive integers.
fn validNumber(text: []const u8) bool {
    const value = std.fmt.parseInt(u32, text, 10) catch return false;
    return value >= 1 and value <= 1_000_000;
}

fn queryDestinations(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [256]u8 = undefined;
    var memory: [512]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct { after: u64 = 0 }, context, &body, arena.allocator());
    defer parsed.deinit();
    return reply(context, try app.request(.{ .notifications_query = .{
        .auth = auth,
        .after = parsed.value.after,
    } }));
}

const Form = struct {
    id: ?u64 = null,
    expected_revision: u64 = 0,
    kind: n.Kind,
    transport: n.Transport = .udp,
    label: []const u8,
    target: []const u8,
    secret: []const u8 = "",
    clear_secret: bool = false,
    events: u8,
    cooldown_seconds: u32,
    enabled: bool = true,
};

fn saveDestination(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [4096]u8 = undefined;
    var memory: [8192]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(Form, context, &body, arena.allocator());
    defer parsed.deinit();
    const form = parsed.value;
    const host = validTarget(form.kind, form.target) orelse
        return http.fail(context, .bad_request, "CONSOLENOTIFYTARGET");
    var envelope: ?p.Bytes(n.max_envelope) = null;
    if (form.secret.len != 0) {
        if (form.secret.len > n.max_secret)
            return http.fail(context, .bad_request, "CONSOLESETTINGS");
        const key = app.totp_key orelse
            return http.fail(context, .bad_request, "CONSOLEKEYREQUIRED");
        // A new destination has no id yet; the envelope is bound to its target instead.
        const subject = target.envelopeSubject(form.target);
        const sealed = try secrets.sealBytes(app.io, form.secret, key, subject);
        envelope = try p.Bytes(n.max_envelope).init(&sealed);
    }
    return reply(context, try app.request(.{ .notifications_save = .{
        .auth = auth,
        .id = form.id,
        .expected_revision = form.expected_revision,
        .kind = form.kind,
        .transport = form.transport,
        .label = p.Bytes(n.max_label).init(form.label) catch
            return http.fail(context, .bad_request, "CONSOLESETTINGS"),
        .target = p.Bytes(n.max_target).init(form.target) catch
            return http.fail(context, .bad_request, "CONSOLESETTINGS"),
        .target_host = p.Bytes(n.max_host).init(host.slice()) catch
            return http.fail(context, .bad_request, "CONSOLESETTINGS"),
        .secret_envelope = envelope,
        .clear_secret = form.clear_secret,
        .events = form.events,
        .cooldown_seconds = form.cooldown_seconds,
        .enabled = form.enabled,
    } }));
}

fn validTarget(kind: n.Kind, text: []const u8) ?@import("net").outbound.Host {
    return switch (kind) {
        .webhook => (target.validateWebhook(text) catch return null).host,
        .syslog => @import("net").outbound.Host.init(
            (target.validateSyslog(text) catch return null).host,
        ) catch return null,
    };
}

fn removeDestination(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [256]u8 = undefined;
    var memory: [512]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(
        struct { id: u64, expected_revision: u64 },
        context,
        &body,
        arena.allocator(),
    );
    defer parsed.deinit();
    return reply(context, try app.request(.{ .notifications_remove = .{
        .auth = auth,
        .id = parsed.value.id,
        .expected_revision = parsed.value.expected_revision,
    } }));
}

/// Record intent before the external request, then report completion separately.
fn testDestination(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [256]u8 = undefined;
    var memory: [512]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct { id: u64 }, context, &body, arena.allocator());
    defer parsed.deinit();
    const page = try app.request(.{ .notifications_query = .{
        .auth = auth,
        .after = parsed.value.id -| 1,
    } });
    if (page != .notifications_page) return reply(context, page);
    const rows = page.notifications_page.rows[0..page.notifications_page.count];
    const destination = for (rows) |row| {
        if (row.id == parsed.value.id) break row;
    } else return http.fail(context, .not_found, "CONSOLESETTINGS");
    var audit: n.TestAudit = .{
        .auth = auth,
        .destination = destination.id,
        .revision = destination.revision,
        .operation = undefined,
    };
    app.io.random(&audit.operation);
    const intent = try app.request(.{ .notifications_test_audit = audit });
    if (intent != .command_recorded) return reply(context, intent);
    const outcome = @import("notify_delivery.zig").deliver(app, .{
        .destination = destination,
        .event = .{
            .id = 0,
            .node = app.config.node_id,
            .event = .denial_spike,
            .raised_at = app.now(),
            .detail = try p.Bytes(n.max_detail).init("test delivery from the console"),
            .attempts = 0,
        },
        .read = .{ .auth = auth, .id = parsed.value.id, .revision = destination.revision },
    });
    audit.outcome = if (outcome.delivered) .delivered else .failed;
    audit.detail = outcome.detail;
    const completion: ?p.StorageResult =
        app.request(.{ .notifications_test_audit = audit }) catch null;
    return http.json(context, .{
        .delivered = outcome.delivered,
        .detail = outcome.detail.slice(),
        .audit_recorded = completion != null and completion.? == .command_recorded,
    }, &.{});
}

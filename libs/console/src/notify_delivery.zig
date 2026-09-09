//! Outbound delivery for one event to one destination: an HTTPS webhook POST with an HMAC
//! signature, or an RFC 5424 syslog line over UDP or framed TCP. Targets are re-validated
//! and their resolved addresses re-checked immediately before each attempt; the outcome
//! detail never contains the secret. Runs only on the notifier thread.
const std = @import("std");
const App = @import("app.zig").App;
const p = @import("console_protocol");
const n = p.notifications;
const target = @import("notify_target.zig");
const syslog = @import("notify_syslog.zig");
const secrets = @import("auth_secrets.zig");
const net = @import("net");
pub const deadline_ns = 10 * std.time.ns_per_s;
const Result = union(enum) { delivery: anyerror!u16, deadline: anyerror!void };

pub fn deliver(
    app: *App,
    dest: n.Destination,
    event: n.Pending,
    detail: *p.Bytes(n.max_detail),
    read: n.Read,
) bool {
    const outcome = attempt(app, dest, event, read) catch |err| {
        detail.set(@errorName(err)) catch {};
        return false;
    };
    var text: [n.max_detail]u8 = undefined;
    const written = std.fmt.bufPrint(&text, "status {d}", .{outcome}) catch "status";
    detail.set(written) catch {};
    return outcome >= 200 and outcome < 300;
}

fn attempt(app: *App, dest: n.Destination, event: n.Pending, read: n.Read) !u16 {
    // The secret is opened under the storage bound before the network deadline starts.
    const secret: ?Secret = if (dest.kind == .webhook and dest.secret_set)
        try openSecret(app, read)
    else
        null;
    var results: [2]Result = undefined;
    var select: std.Io.Select(Result) = .init(app.io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.deadline, deadline, .{app});
    try select.concurrent(.delivery, send, .{ app, dest, event, secret });
    return switch (try select.await()) {
        .delivery => |status| try status,
        .deadline => error.DeliveryDeadline,
    };
}

fn deadline(app: *App) anyerror!void {
    const start = std.Io.Clock.awake.now(app.io).nanoseconds;
    while (!app.stopping.load(.acquire)) {
        if (std.Io.Clock.awake.now(app.io).nanoseconds - start >= deadline_ns) return;
        try std.Io.sleep(app.io, std.Io.Duration.fromMilliseconds(50), .awake);
    }
}

fn send(app: *App, dest: n.Destination, event: n.Pending, secret: ?Secret) anyerror!u16 {
    return switch (dest.kind) {
        .webhook => webhook(app, dest, event, secret),
        .syslog => sysLog(app, dest, event),
    };
}

fn body(out: *[1024]u8, app: *App, event: n.Pending) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try std.json.Stringify.value(.{
        .event = @tagName(event.event),
        .node = event.node,
        .at = event.raised_at,
        .detail = event.detail.slice(),
        .console = app.config.origin.slice(),
    }, .{}, &writer);
    return writer.buffered();
}

fn webhook(app: *App, dest: n.Destination, event: n.Pending, secret: ?Secret) anyerror!u16 {
    const parsed = try target.validateWebhook(dest.target.slice());
    const policy: net.outbound.Policy = if (parsed.scheme == .http)
        .loopback_allowed
    else
        .public_only;
    const addresses = try net.outbound.resolve(app.io, parsed.host.slice(), parsed.port, policy);
    var payload: [1024]u8 = undefined;
    const json = try body(&payload, app, event);
    var signature: [80]u8 = undefined;
    var headers: [2]std.http.Header = undefined;
    var count: usize = 1;
    headers[0] = .{ .name = "X-Sibuna-Event", .value = @tagName(event.event) };
    if (secret) |shared| {
        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, json, shared.slice());
        const hex = std.fmt.bytesToHex(mac, .lower);
        const value = try std.fmt.bufPrint(&signature, "sha256={s}", .{hex});
        headers[count] = .{ .name = "X-Sibuna-Signature", .value = value };
        count += 1;
    }
    return net.outbound.post(app.io, app.gpa, .{
        .pinned = .{
            .address = addresses.items[0],
            .host = parsed.host,
            .secure = parsed.scheme == .https,
            .policy = policy,
        },
        .url = dest.target.slice(),
        .payload = json,
        .headers = headers[0..count],
    });
}

const Secret = struct {
    bytes: [n.max_secret]u8 = @splat(0),
    len: u8 = 0,
    fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn openSecret(app: *App, read: n.Read) !Secret {
    const key = app.totp_key orelse return error.ConsoleKeyRequired;
    const result = try app.background(.{ .notifications_read = read });
    if (result != .notification_secret) return error.SecretUnavailable;
    const stored = result.notification_secret;
    const envelope = stored.envelope orelse return error.SecretUnavailable;
    const subject = target.envelopeSubject(stored.target.slice());
    var secret: Secret = .{};
    secret.len = try secrets.openBytes(envelope.slice(), key, subject, &secret.bytes);
    return secret;
}

fn sysLog(app: *App, dest: n.Destination, event: n.Pending) anyerror!u16 {
    const endpoint = try target.validateSyslog(dest.target.slice());
    const addresses = try net.outbound.resolve(
        app.io,
        endpoint.host,
        endpoint.port,
        .loopback_allowed,
    );
    const address = addresses.items[0];
    var line: [syslog.max_message]u8 = undefined;
    var host: [64]u8 = undefined;
    const origin = std.fmt.bufPrint(&host, "node-{d}", .{event.node}) catch "node";
    const message = syslog.format(
        &line,
        .warning,
        event.raised_at,
        origin,
        @tagName(event.event),
        event.detail.slice(),
    );
    if (std.mem.endsWith(u8, dest.label.slice(), "tcp")) {
        const started = std.Io.Clock.awake.now(app.io).nanoseconds;
        const stream = try net.connect.boundedDeadline(app.io, address, started + deadline_ns);
        defer stream.close(app.io);
        var frame: [syslog.max_message + 8]u8 = undefined;
        const framed = syslog.framed(&frame, message);
        try net.connect.writeBounded(app.io, stream, framed, started + deadline_ns);
        return 200;
    }
    const local: std.Io.net.IpAddress = switch (address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = try local.bind(app.io, .{ .mode = .dgram });
    defer socket.close(app.io);
    try socket.send(app.io, &address, message);
    return 200;
}

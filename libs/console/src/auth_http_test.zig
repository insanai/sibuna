//! The transport and routes are real; a scripted storage owner deterministically refuses
//! one operation. No quorum timing, password bypass or database mutation is needed.
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const core = @import("core");
const store = @import("store");
const serve = @import("serve");
const App = @import("app.zig").App;
const Mailbox = @import("mailbox.zig").Mailbox;
const Hub = @import("subscription_hub.zig").Hub;
const Password = @import("password.zig").Password;
const totp = @import("totp.zig");
const secrets = @import("auth_secrets.zig");
const passphrase = "a long test passphrase";
const key: [32]u8 = @splat(21);
const seed: totp.Seed = "12345678901234567890".*;
const origin = "http://console.test";
pub const Reply = enum {
    user,
    user_totp,
    authorized,
    factor,
    enrollment,
    corrupt_factor,
    unavailable,
    unauthorized,
    invalid_input,
    unsupported_schema,
    conflict,
    command,
    setup_ready,
    geo_empty,
    owned_heads,
    hold,
};
const Request = std.meta.Tag(p.StorageRequest);
const Step = struct { request: Request, reply: Reply };

pub const Fixture = struct {
    app: App,
    mailbox: Mailbox = .{},
    telemetry: store.ConsoleTelemetry,
    incidents: store.ConsoleIncidents,
    metrics: core.Metrics = .{},
    geo: @import("geoip_generation.zig").Registry = .{},
    kernel: ?*serve.Kernel = null,
    worker: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    script: []const Step,
    consumed: usize = 0,
    denied: usize = 0,
    failure: ?anyerror = null,

    pub fn init(script: []const Step) !*Fixture {
        const self = try t.allocator.create(Fixture);
        errdefer t.allocator.destroy(self);
        var passwords = try Password.init(t.allocator);
        errdefer passwords.deinit();
        const hash = try passwords.hash(t.io, passphrase);
        const hub = try Hub.init(t.allocator, t.io, @splat(1));
        errdefer hub.deinit();
        self.* = .{
            .script = script,
            .mailbox = .{ .gpa = t.allocator },
            .telemetry = store.ConsoleTelemetry.init(),
            .incidents = store.ConsoleIncidents.init(),
            .app = .{
                .gpa = t.allocator,
                .io = t.io,
                .config = .{ .origin = try p.Bytes(255).init(origin) },
                .mailbox = &self.mailbox,
                .passwords = passwords,
                .totp_key = key,
                .dummy_hash = hash,
                .setup_required = false,
                .assets = .init(),
                .telemetry = &self.telemetry,
                .incidents = &self.incidents,
                .metrics = &self.metrics,
                .hub = hub,
                .peers = .init(t.io, .{}, 1, null),
                .geo = &self.geo,
            },
        };
        self.worker = try std.Thread.spawn(.{}, run, .{self});
        errdefer {
            self.stopping.store(true, .release);
            self.mailbox.stop(t.io);
            self.worker.?.join();
        }
        self.kernel = try serve.Kernel.start(
            t.allocator,
            t.io,
            try std.Io.net.IpAddress.parse("127.0.0.1", 0),
            &self.app,
            App.handle,
        );
        return self;
    }

    pub fn stop(self: *Fixture) void {
        if (self.kernel) |kernel| kernel.stop();
        self.kernel = null;
        self.stopping.store(true, .release);
        self.mailbox.stop(t.io);
        if (self.worker) |worker| worker.join();
        self.worker = null;
    }

    pub fn deinit(self: *Fixture) void {
        self.stop();
        self.mailbox.deinit(t.io);
        self.app.peers.deinit();
        self.app.passwords.deinit();
        self.app.hub.deinit();
        self.geo.deinit();
        t.allocator.destroy(self);
    }

    fn run(self: *Fixture) void {
        while (!self.stopping.load(.acquire)) {
            const work = self.mailbox.take(t.io) orelse {
                self.mailbox.wait(t.io, 10) catch |err| {
                    self.failure = err;
                    return;
                };
                continue;
            };
            if (work.request == .login_denied) self.denied += 1;
            if (self.consumed >= self.script.len or
                self.script[self.consumed].request != std.meta.activeTag(work.request))
            {
                self.failure = error.UnexpectedStorageOperation;
                self.mailbox.complete(t.io, work.ticket, .{ .failed = .unavailable }) catch |err| {
                    self.failure = err;
                    return;
                };
                continue;
            }
            const reply = self.script[self.consumed].reply;
            self.consumed += 1;
            const answer = self.result(reply) catch |err| {
                self.failure = err;
                const failed: p.StorageResult = .{ .failed = .unavailable };
                self.mailbox.complete(t.io, work.ticket, failed) catch |reply_err| {
                    self.failure = reply_err;
                };
                return;
            };
            self.mailbox.complete(t.io, work.ticket, answer) catch |err| {
                self.failure = err;
                return;
            };
        }
    }

    fn result(self: *Fixture, reply: Reply) !p.StorageResult {
        return switch (reply) {
            .unavailable => .{ .failed = .unavailable },
            .unauthorized => .{ .failed = .unauthorized },
            .invalid_input => .{ .failed = .invalid_input },
            .unsupported_schema => .{ .failed = .unsupported_schema },
            .conflict => .{ .failed = .conflict },
            .command => .command_recorded,
            .setup_ready => .{ .setup_required = false },
            .geo_empty => .{ .geo_metadata = .{ .revision = 1 } },
            .owned_heads => block: {
                const heads = try t.allocator.create(p.incident_heads.Heads);
                heads.* = .{ .id = 1 };
                break :block .{ .incident_heads = heads };
            },
            .hold => block: {
                while (!self.stopping.load(.acquire)) {
                    try std.Io.sleep(t.io, .fromMilliseconds(5), .awake);
                }
                break :block .{ .failed = .unavailable };
            },
            .user, .user_totp => .{ .auth_user = .{
                .id = 1,
                .username = p.Bytes(64).init("admin") catch unreachable,
                .password_hash = self.app.dummy_hash,
                .role = .admin,
                .revision = 1,
                .must_change = false,
                .totp_enabled = reply == .user_totp,
            } },
            .authorized => .{ .authorized = .{
                .actor = 1,
                .username = p.Bytes(64).init("admin") catch unreachable,
                .role = .admin,
                .revision = 1,
                .expires = self.app.now() + 3600,
                .csrf_digest = csrfDigest(),
                .must_change = false,
            } },
            .factor, .enrollment, .corrupt_factor => .{ .totp = .{
                .user = 1,
                .revision = 1,
                .envelope = if (reply == .corrupt_factor)
                    @splat(0)
                else
                    secrets.seal(t.io, seed, key, 1),
                .key_id = secrets.keyId(key),
                .enabled = reply != .enrollment,
                .expires = self.app.now() + 3600,
                .last_step = null,
                .recovery_used = 0,
            } },
        };
    }

    fn request(self: *Fixture, path: []const u8, body: ?[]const u8, out: []u8) ![]const u8 {
        const address = self.kernel.?.listener.socket.address;
        const stream = try address.connect(t.io, .{ .mode = .stream });
        defer stream.close(t.io);
        var send: [2048]u8 = undefined;
        var writer = stream.writer(t.io, &send);
        const cookie = std.fmt.bytesToHex(@as([32]u8, @splat(1)), .lower);
        const csrf = std.fmt.bytesToHex(@as([32]u8, @splat(2)), .lower);
        try writer.interface.print("{s} {s} HTTP/1.1\r\nHost: localhost\r\n" ++
            "Origin: {s}\r\nCookie: __sibuna_console={s}\r\nX-Console-CSRF: {s}\r\n" ++
            "Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{
            if (body != null) "POST" else "GET", path,           origin, cookie, csrf,
            if (body) |bytes| bytes.len else 0,  body orelse "",
        });
        try writer.interface.flush();
        var receive: [2048]u8 = undefined;
        var reader = stream.reader(t.io, &receive);
        return out[0..try reader.interface.readSliceShort(out)];
    }
};

fn step(request: Request, reply: Reply) Step {
    return .{ .request = request, .reply = reply };
}

fn csrfDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&@as([32]u8, @splat(2)), &digest, .{});
    return digest;
}

const Expected = struct { status: u16, diagnostic: []const u8, audits: usize = 0 };
const unavailable: Expected = .{ .status = 503, .diagnostic = "CONSOLEQUORUM" };
const refused: Expected = .{ .status = 401, .diagnostic = "CONSOLE401", .audits = 1 };
const conflict: Expected = .{ .status = 409, .diagnostic = "CONSOLE409" };

fn check(script: []const Step, path: []const u8, body: ?[]const u8, expected: Expected) !void {
    const fixture = try Fixture.init(script);
    defer fixture.deinit();
    try exchange(fixture, path, body, expected);
}

fn exchange(fixture: *Fixture, path: []const u8, body: ?[]const u8, expected: Expected) !void {
    var output: [4096]u8 = undefined;
    const response = try fixture.request(path, body, &output);
    fixture.stop();
    var prefix: [32]u8 = undefined;
    const status = try std.fmt.bufPrint(&prefix, "HTTP/1.1 {d}", .{expected.status});
    try t.expect(std.mem.startsWith(u8, response, status));
    try t.expect(std.mem.indexOf(u8, response, expected.diagnostic) != null);
    if (expected.status == 401) {
        const refusal = "{\"error\":\"CONSOLE401\"," ++
            "\"hint\":\"Sign in again with your password and, if enabled, a current code.\"}";
        try t.expect(std.mem.endsWith(u8, response, refusal));
    }
    try t.expect(std.mem.indexOf(u8, response, "Set-Cookie:") == null);
    try t.expectEqual(null, fixture.failure);
    try t.expectEqual(fixture.script.len, fixture.consumed);
    try t.expectEqual(expected.audits, fixture.denied);
}

const login_body = "{\"username\":\"admin\",\"password\":\"a long test passphrase\"," ++
    "\"code\":\"bad\"}";
const password_body = "{\"old_password\":\"a long test passphrase\"," ++
    "\"password\":\"a different passphrase\"}";
const enrollment_body = "{\"password\":\"a long test passphrase\",\"revision\":1}";

test "unavailable sign-in lookup, factor read and session creation stay service failures" {
    const scripts = .{
        &[_]Step{step(.auth_user, .unavailable)},
        &[_]Step{ step(.auth_user, .user_totp), step(.totp_read, .unavailable) },
        &[_]Step{ step(.auth_user, .user), step(.session_create, .unavailable) },
    };
    inline for (scripts) |script| try check(script, "/console/api/login", login_body, unavailable);
}

test "wrong accounts, passwords and factors retain identical opaque sign-in refusals" {
    const cases = .{
        .{ Reply.unauthorized, login_body, false },
        .{ Reply.user, "{\"username\":\"admin\",\"password\":\"wrong\"}", false },
        .{ Reply.user_totp, login_body, true },
    };
    inline for (cases) |case| {
        var steps: [3]Step = undefined;
        steps[0] = .{ .request = .auth_user, .reply = case[0] };
        var n: usize = 1;
        if (case[2]) {
            steps[n] = step(.totp_read, .factor);
            n += 1;
        }
        steps[n] = step(.login_denied, .command);
        try check(steps[0 .. n + 1], "/console/api/login", case[1], refused);
    }
}

test "unavailable account mutations never become credential errors or revision conflicts" {
    const cases = .{
        .{ "/console/api/password", password_body, Request.auth_user, false },
        .{ "/console/api/password", password_body, Request.password_change, true },
        .{ "/console/api/totp/enroll", enrollment_body, Request.auth_user, false },
        .{ "/console/api/totp/enroll", enrollment_body, Request.totp_begin, true },
    };
    inline for (cases) |case| {
        var steps: [3]Step = undefined;
        steps[0] = step(.authorize, .authorized);
        var n: usize = 1;
        if (case[3]) {
            steps[n] = step(.auth_user, .user);
            n += 1;
        }
        steps[n] = .{ .request = case[2], .reply = .unavailable };
        try check(steps[0 .. n + 1], case[0], case[1], unavailable);
    }
}

test "unavailable factor status and confirmation cannot claim disabled or conflict" {
    const authorization: Step = step(.authorize, .authorized);
    const status = [_]Step{ authorization, step(.totp_read, .unavailable) };
    try check(&status, "/console/api/totp", null, unavailable);
    const read = [_]Step{ authorization, step(.auth_user, .user), step(.totp_read, .unavailable) };
    try check(&read, "/console/api/totp/confirm", enrollment_body, unavailable);
    var buffer: [256]u8 = undefined;
    const second = @divTrunc(std.Io.Clock.real.now(t.io).nanoseconds, std.time.ns_per_s);
    const now: u64 = @intCast(second);
    const format = "{{\"password\":\"{s}\",\"code\":\"{s}\",\"revision\":1}}";
    const body = try std.fmt.bufPrint(&buffer, format, .{ passphrase, totp.code(seed, now / 30) });
    const confirm = [_]Step{
        authorization,                 step(.auth_user, .user),
        step(.totp_read, .enrollment), step(.totp_confirm, .unavailable),
    };
    try check(&confirm, "/console/api/totp/confirm", body, unavailable);
}

test "genuine session and enrollment revision conflicts remain conflicts" {
    const session = [_]Step{ step(.auth_user, .user), step(.session_create, .conflict) };
    try check(&session, "/console/api/login", login_body, conflict);
    const enrollment = [_]Step{
        step(.authorize, .authorized), step(.auth_user, .user), step(.totp_begin, .conflict),
    };
    try check(&enrollment, "/console/api/totp/enroll", enrollment_body, conflict);
}

test "an unreadable factor after a correct password is an audited opaque refusal" {
    const script = [_]Step{
        step(.auth_user, .user_totp),
        step(.totp_read, .corrupt_factor),
        step(.login_denied, .command),
    };
    try check(&script, "/console/api/login", login_body, refused);
}

test "busy password verification preserves the independent concurrency bound" {
    const script = [_]Step{step(.auth_user, .user)};
    const fixture = try Fixture.init(&script);
    defer fixture.deinit();
    fixture.app.passwords.busy.store(true, .release);
    defer fixture.app.passwords.busy.store(false, .release);
    try exchange(fixture, "/console/api/login", login_body, .{
        .status = 429,
        .diagnostic = "CONSOLE003",
    });
}

test "accounts without a factor read as not enabled instead of unavailable" {
    const status = [_]Step{ step(.authorize, .authorized), step(.totp_read, .conflict) };
    try check(&status, "/console/api/totp", null, .{
        .status = 200,
        .diagnostic = "\"enabled\":false",
    });
}

test "owners turn factors off or replace recovery codes only with a valid proof" {
    var buffer: [256]u8 = undefined;
    const second = @divTrunc(std.Io.Clock.real.now(t.io).nanoseconds, std.time.ns_per_s);
    const now: u64 = @intCast(second);
    const format = "{{\"password\":\"{s}\",\"code\":\"{s}\"}}";
    const body = try std.fmt.bufPrint(&buffer, format, .{ passphrase, totp.code(seed, now / 30) });
    const owner = [_]Step{ step(.authorize, .authorized), step(.auth_user, .user_totp) };
    const accepted = owner ++ [_]Step{ step(.totp_read, .factor), step(.totp_change, .command) };
    try check(&accepted, "/console/api/totp/disable", body, .{
        .status = 200,
        .diagnostic = "\"sign_in_required\":true",
    });
    try check(&accepted, "/console/api/totp/recovery", body, .{
        .status = 200,
        .diagnostic = "\"recovery_codes\":[\"",
    });
    const wrong = "{\"password\":\"a long test passphrase\",\"code\":\"000000\"}";
    const disable = "/console/api/totp/disable";
    const read = owner ++ [_]Step{step(.totp_read, .factor)};
    try check(&read, disable, wrong, .{ .status = 401, .diagnostic = "CONSOLE401" });
    const unreadable = owner ++ [_]Step{step(.totp_read, .corrupt_factor)};
    try check(&unreadable, disable, body, .{ .status = 409, .diagnostic = "CONSOLE2FAKEY" });
    const stale = owner ++ [_]Step{ step(.totp_read, .factor), step(.totp_change, .conflict) };
    try check(&stale, "/console/api/totp/recovery", body, conflict);
    const plain = [_]Step{ step(.authorize, .authorized), step(.auth_user, .user) };
    try check(&plain, "/console/api/totp/disable", body, conflict);
}

test "HTTP schema failures ask for a compatible binary rather than a quorum retry" {
    const script = [_]Step{
        step(.authorize, .authorized), step(.totp_read, .unsupported_schema),
    };
    try check(&script, "/console/api/totp", null, .{
        .status = 503,
        .diagnostic = "CONSOLESCHEMA",
    });
    try check(&script, "/console/api/totp", null, .{
        .status = 503,
        .diagnostic = "do not downgrade",
    });
}

//! Sibuna End-to-End Tests
//!
//! Boots the real daemon on a loopback port in front of a stub origin and
//! drives it over TCP with raw HTTP/1.1, covering every route and decision
//! path: static bypass, challenge issuance and verification for both tiers,
//! replay and binding rejection, WAF and policy denial, rate limiting,
//! honeypot bans, keep-alive, forward-auth mode, metrics, and malformed
//! input. Each scenario uses a distinct forwarded client address so the
//! per-client tables do not interfere.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const crypto = @import("crypto");
const policy = @import("policy");
const net = @import("net");
const server = @import("server.zig");

const io = std.testing.io;
const console_enabled = @import("build_options").console;
const telemetry_store = @import("store");

const Fixture = struct {
    engine: policy.Engine = undefined,
    slot: server.EngineSlot = undefined,
    state: server.AppState = undefined,
    listener: Io.net.Server = undefined,
    port: u16 = 0,
    telemetry: if (console_enabled) telemetry_store.ConsoleTelemetry else void =
        if (console_enabled) undefined else {},
};

var origin_port: u16 = 0;
// Fixtures live on the heap: `AppState` carries 64-byte-aligned fields, and the Debug
// self-hosted x86_64 backend does not honour that alignment for globals, which trips the
// context `@alignCast` on Linux. The page allocator always satisfies it.
var proxy_fixture: *Fixture = undefined;
var auth_fixture: *Fixture = undefined;
var audit_fixture: *Fixture = undefined;
var quota_fixture: *Fixture = undefined;

fn allocateFixture() *Fixture {
    const fixture = std.heap.page_allocator.create(Fixture) catch @panic("fixture memory");
    fixture.* = .{};
    return fixture;
}
var audited_requests: std.atomic.Value(u64) = .init(0);
/// Minimal once-guard: the first caller boots the fixtures, later callers
/// spin until it has finished.
const BootOnce = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn call(self: *BootOnce) void {
        if (self.state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
            bootAll();
            self.state.store(2, .release);
            return;
        }
        while (self.state.load(.acquire) != 2) std.atomic.spinLoopHint();
    }
};
var boot_once = BootOnce{};

/// Stub origin: answers every request with its own view of the headers so
/// tests can assert on what the proxy injected.
fn originLoop(listener: *Io.net.Server) void {
    while (true) {
        const stream = listener.accept(io) catch return;
        const t = std.Thread.spawn(.{}, originConnection, .{stream}) catch {
            stream.close(io);
            continue;
        };
        t.detach();
    }
}

/// Serves one origin connection with keep-alive; `X-Origin-Seq` counts the
/// requests seen on this socket so tests can observe pooled reuse.
fn originConnection(stream: Io.net.Stream) void {
    defer stream.close(io);
    // The stub's own writes must not be held back, or it would hide the proxy's behaviour.
    net.connect.noDelay(stream);
    var buf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &buf);
    var wbuf: [16 * 1024]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    var seq: u32 = 0;
    while (true) {
        const end = blk: while (true) {
            const buffered = reader.interface.buffered();
            if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |idx| break :blk idx;
            reader.interface.fill(buffered.len + 1) catch return;
        };
        const head = reader.interface.buffered()[0..end];
        seq += 1;
        const request_line = std.mem.sliceTo(head, '\r');
        if (std.mem.indexOf(u8, request_line, "/silent") != null) {
            // An origin that never answers: the proxy must give up before this closes.
            Io.sleep(io, Io.Duration.fromSeconds(4), .awake) catch {};
            return;
        }
        if (std.mem.indexOf(u8, request_line, "/slow-stream") != null) {
            slowStream(&writer.interface) catch return;
            reader.interface.toss(end + 4);
            continue;
        }
        if (std.mem.indexOf(u8, request_line, "/slow-length") != null) {
            trickle(&writer.interface, "Content-Length: 15360\r\n") catch return;
            reader.interface.toss(end + 4);
            continue;
        }
        if (std.mem.indexOf(u8, request_line, "/slow-close") != null) {
            trickle(&writer.interface, "Connection: close\r\n") catch {};
            return;
        }
        if (std.mem.indexOf(u8, request_line, "/split") != null) {
            // An origin that flushes its head early (streaming rendering) and its body after.
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n") catch return;
            writer.interface.flush() catch return;
            Io.sleep(io, Io.Duration.fromMilliseconds(5), .awake) catch {};
            writer.interface.writeAll("body") catch return;
            writer.interface.flush() catch return;
            reader.interface.toss(end + 4);
            continue;
        }
        if (std.mem.indexOf(u8, request_line, "?upload") != null) {
            const framing = UploadFraming.of(head);
            reader.interface.toss(end + 4);
            echoUpload(&reader.interface, &writer.interface, framing) catch return;
            continue;
        }
        if (std.mem.indexOf(u8, request_line, "/truncated") != null) {
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" ++
                "0123456789") catch {};
            writer.interface.flush() catch {};
            return;
        }
        writer.interface.print(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: stub\r\n" ++
                "X-Origin-Seq: {d}\r\nContent-Length: {d}\r\n\r\nORIGIN|{s}",
            .{ seq, end + 7, head },
        ) catch return;
        writer.interface.flush() catch return;
        reader.interface.toss(end + 4);
    }
}

/// How the proxy framed an upload, read from the head before the body moves the buffer.
const UploadFraming = union(enum) {
    length: u64,
    chunked,
    none,

    fn of(head: []const u8) UploadFraming {
        if (std.mem.indexOf(u8, head, "\r\nTransfer-Encoding: chunked\r\n") != null) {
            if (std.mem.indexOf(u8, head, "\r\nContent-Length:") != null) return .none;
            return .chunked;
        }
        const at = std.mem.indexOf(u8, head, "\r\nContent-Length: ") orelse return .none;
        const digits = std.mem.sliceTo(head[at + 18 ..], '\r');
        return .{ .length = std.fmt.parseInt(u64, digits, 10) catch return .none };
    }
};

/// Reads the upload as an origin would and answers with its framing, length and digest. The
/// chunked reader accepts only canonical framing: bare lower-case hex sizes, no extensions and
/// no trailers, which is all a re-framing proxy may send.
fn echoUpload(r: *Io.Reader, w: *Io.Writer, framing: UploadFraming) !void {
    var digest = std.hash.Wyhash.init(0);
    var total: u64 = 0;
    switch (framing) {
        .none => {},
        .length => |length| try digestBytes(r, length, &digest, &total),
        .chunked => while (true) {
            const line = try r.takeDelimiterInclusive('\n');
            if (line.len < 3 or !std.mem.endsWith(u8, line, "\r\n")) return error.NotCanonical;
            const hex = line[0 .. line.len - 2];
            for (hex) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f'))
                return error.NotCanonical;
            if (hex.len > 1 and hex[0] == '0') return error.NotCanonical;
            const size = try std.fmt.parseInt(u64, hex, 16);
            if (size == 0) {
                if (!std.mem.eql(u8, try r.take(2), "\r\n")) return error.NotCanonical;
                break;
            }
            try digestBytes(r, size, &digest, &total);
            if (!std.mem.eql(u8, try r.take(2), "\r\n")) return error.NotCanonical;
        },
    }
    var body: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&body, "UPLOAD|{s}|{d}|{x}", .{
        @tagName(framing), total, digest.final(),
    });
    try w.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n{s}", .{ text.len, text });
    try w.flush();
}

fn digestBytes(r: *Io.Reader, count: u64, digest: *std.hash.Wyhash, total: *u64) !void {
    var left = count;
    while (left > 0) {
        const piece = try r.take(@intCast(@min(left, r.buffer.len)));
        digest.update(piece);
        left -= piece.len;
        total.* += piece.len;
    }
}

/// Twelve chunks a quarter second apart: three seconds of activity against a one-second
/// idle timeout, so only an activity-based deadline lets the whole body through.
fn slowStream(w: *Io.Writer) !void {
    try w.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n");
    try w.flush();
    for (0..12) |_| {
        Io.sleep(io, Io.Duration.fromMilliseconds(250), .awake) catch {};
        try w.writeAll("5\r\nchunk\r\n");
        try w.flush();
    }
    try w.writeAll("0\r\n\r\n");
    try w.flush();
}

/// Thirty 512-byte writes 100 ms apart: 15 KiB over three seconds, less than one relay buffer,
/// against a one-second idle timeout. Only a relay that forwards each read as it arrives keeps
/// this exchange alive and shows the client its first bytes promptly.
fn trickle(w: *Io.Writer, framing: []const u8) !void {
    try w.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{s}\r\n", .{framing});
    try w.flush();
    const piece: [512]u8 = @splat('s');
    for (0..30) |_| {
        Io.sleep(io, Io.Duration.fromMilliseconds(100), .awake) catch {};
        try w.writeAll(&piece);
        try w.flush();
    }
}

fn bootFixture(f: *Fixture, cfg_in: core.Config) void {
    var cfg = cfg_in;
    cfg.upstream_port = origin_port;
    cfg.trust_forwarded = true;
    cfg.workers = 1;
    cfg.rate_limit = 8;
    cfg.rate_window_seconds = 10;
    cfg.idle_timeout_seconds = 1;
    cfg.ban_seconds = 60;
    f.engine.initInPlace(cfg.default_difficulty);
    policy.page_template.defaults(&f.engine.pages, @import("challenge_page.zig").default);
    f.engine.waf_enabled = cfg.waf;
    if (f == quota_fixture) configureQuotas(&f.engine);
    // One route demands more work than the eight-bit default, for session-level checks. It
    // goes first because the built-in generic-browser rule would otherwise claim the path.
    if (f == proxy_fixture) prependRule(&f.engine, .{
        .name = "strong-route",
        .path_pattern = "/strong/*",
        .action = .challenge,
        .difficulty = 12,
    });
    // An exact path (the query is never part of it) and a rule on a navigation header that the
    // interstitial's own fetch does not send: both need the requirement carried, not recomputed.
    if (f == proxy_fixture) {
        prependRule(&f.engine, .{
            .name = "exact-route",
            .path_pattern = "^/exact$",
            .action = .challenge,
            .difficulty = 12,
        });
        var navigate = policy.PolicyRule{
            .name = "navigate-route",
            .path_pattern = "/navigate/*",
            .action = .challenge,
            .difficulty = 13,
        };
        navigate.headers[0] = .{ .name = "Sec-Fetch-Mode", .pattern = "navigate" };
        navigate.header_count = 1;
        prependRule(&f.engine, navigate);
    }
    if (f == audit_fixture) {
        f.engine.inspection_modes = .{ .sqli = .audit, .path_traversal = .disabled };
        f.engine.ip_trie.insertCidr("203.0.113.223/32", .deny) catch unreachable;
        // A customized denial page: the request path renders it from the snapshot.
        const denied = &f.engine.pages.entries[@intFromEnum(policy.page_template.Kind.denied)];
        policy.page_template.compile(
            .denied,
            "<!doctype html><title>Custom</title><p>Custom denial: {{ reason }} " ++
                "({{ status }}) ref {{ request_id }}</p>",
            denied,
        ) catch unreachable;
        denied.customized = true;
    }
    f.slot = .{ .engine = &f.engine };
    const seed = [_]u8{0x5a} ** 32;
    f.state.init(cfg, &f.slot, &seed);
    if (f == audit_fixture) f.state.hooks = .{ .record_incident = captureAudit };
    if (console_enabled) {
        f.telemetry = telemetry_store.ConsoleTelemetry.init();
        f.state.telemetry = &f.telemetry;
    }
    const addr = Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    f.listener = addr.listen(io, .{ .reuse_address = true }) catch unreachable;
    f.port = f.listener.socket.address.ip4.port;
    const t = std.Thread.spawn(
        .{},
        server.workerLoop,
        .{ &f.listener, io, &f.state },
    ) catch unreachable;
    t.detach();
    if (server.startReaper(io, &f.state)) |reaper| reaper.detach();
}

var origin_listener: Io.net.Server = undefined;

fn bootAll() void {
    const addr = Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    origin_listener = addr.listen(io, .{ .reuse_address = true }) catch unreachable;
    origin_port = origin_listener.socket.address.ip4.port;
    const t = std.Thread.spawn(.{}, originLoop, .{&origin_listener}) catch unreachable;
    t.detach();

    proxy_fixture = allocateFixture();
    auth_fixture = allocateFixture();
    audit_fixture = allocateFixture();
    quota_fixture = allocateFixture();
    var proxy_cfg = core.Config.default();
    proxy_cfg.default_difficulty = 8;
    proxy_cfg.algorithm = .hashcash;
    bootFixture(proxy_fixture, proxy_cfg);

    var auth_cfg = core.Config.default();
    auth_cfg.mode = .forward_auth;
    auth_cfg.default_difficulty = 9;
    auth_cfg.algorithm = .posw;
    auth_cfg.posw_challenges = 4;
    auth_cfg.token_scheme = .ed25519;
    bootFixture(auth_fixture, auth_cfg);
    bootFixture(audit_fixture, proxy_cfg);
    bootFixture(quota_fixture, proxy_cfg);
}

fn prependRule(engine: *policy.Engine, rule: policy.PolicyRule) void {
    var index = engine.rule_count;
    while (index > 0) : (index -= 1) engine.rules[index] = engine.rules[index - 1];
    engine.rules[0] = rule;
    engine.rule_count += 1;
}

fn configureQuotas(engine: *policy.Engine) void {
    // A controlled explicit policy replaces defaults, as a startup rules array does.
    engine.rule_count = 0;
    inline for (.{
        .{ "/quota", policy.Action.challenge, 1, 0 },
        .{ "/quota-other", policy.Action.challenge, 1, 0 },
        .{ "/quota-ban", policy.Action.allow, 1, 60 },
        .{ "/quota-global", policy.Action.allow, 1000, 0 },
    }) |row| engine.addRule(.{
        .name = row[0],
        .path_pattern = row[0],
        .action = row[1],
        .limits = .{ .rate = row[2], .window_seconds = 60, .ban_seconds = row[3] },
    }) catch unreachable;
}

test "terminal quota runs before a valid session and keeps clients and rules independent" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const port = quota_fixture.port;
    const ip = "203.0.113.230";
    const selected = quota_fixture.engine.evaluate("/quota", ip, browser_ua);
    try std.testing.expectEqualStrings("/quota", selected.rule_name);
    try std.testing.expect(selected.limits != null);
    var cookie: [256]u8 = undefined;
    const value = try quotaCookie(port, ip, resp, &cookie);
    var header: [512]u8 = undefined;
    const fields = try std.fmt.bufPrint(&header, "Cookie: {s}\r\n", .{value});
    try get(port, "/quota", ip, browser_ua, fields, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("X-Sibuna-Rule: session"));
    try get(port, "/quota", ip, browser_ua, fields, resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
    try std.testing.expect(resp.header("retry-after") != null);
    try get(port, "/quota-other", ip, browser_ua, fields, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try get(port, "/quota", "203.0.113.231", browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 401), resp.status());
    try get(port, "/quota", "203.0.113.231", browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
}

fn quotaCookie(port: u16, ip: []const u8, resp: *Response, buffer: *[256]u8) ![]const u8 {
    const ch = try fetchChallenge(port, ip, browser_ua, "/quota");
    const nonce = crypto.pow.solveHashcashBits(ch.idSlice(), ch.difficulty, 1 << 24).?;
    var body: [256]u8 = undefined;
    try post(port, "/__sibuna/verify", ip, browser_ua, try std.fmt.bufPrint(
        &body,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}",
        .{ ch.idSlice(), nonce },
    ), resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    return extractCookie(resp, buffer);
}

test "rule quotas preserve the global limiter and configured bans block other local paths" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const port = quota_fixture.port;
    const before = if (console_enabled) quota_fixture.telemetry.totals() else {};
    for (0..9) |index| {
        try get(port, "/quota-global", "203.0.113.232", "curl", "", resp);
        try std.testing.expectEqual(@as(u16, if (index < 8) 200 else 429), resp.status());
    }
    try get(port, "/quota-ban", "203.0.113.233", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try get(port, "/quota-ban", "203.0.113.233", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
    try std.testing.expectEqualStrings("60", resp.header("retry-after").?);
    try get(port, "/robots.txt", "203.0.113.233", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    if (console_enabled) {
        const after = quota_fixture.telemetry.totals();
        try std.testing.expectEqual(@as(u64, 12), after.requests() - before.requests());
        try std.testing.expectEqual(@as(u64, 9), after.admitted - before.admitted);
        try std.testing.expectEqual(@as(u64, 2), after.rate_limited - before.rate_limited);
        try std.testing.expectEqual(@as(u64, 1), after.banned - before.banned);
        try std.testing.expectEqual(before.denied, after.denied);
    }
}

fn captureAudit(_: ?*anyopaque, incident: server.Incident) void {
    if (!std.mem.eql(u8, incident.category, "audit:sqli")) return;
    std.debug.assert(incident.payload.len == 0 and incident.evidence.version == 0);
    _ = audited_requests.fetchAdd(1, .monotonic);
}

test "incomplete external bodies have one other outcome while internal and invalid heads do not" {
    if (!console_enabled) return;
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const telemetry = &proxy_fixture.telemetry;
    const before = telemetry.totals();
    try roundTrip(
        proxy_fixture.port,
        "POST /incomplete HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    const counted = telemetry.totals();
    try std.testing.expectEqual(before.other + 1, counted.other);
    try std.testing.expectEqual(before.requests() + 1, counted.requests());
    try roundTrip(
        proxy_fixture.port,
        "POST /__sibuna/unknown HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try roundTrip(proxy_fixture.port, "NOT HTTP\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expectEqual(counted.requests(), telemetry.totals().requests());
    const submitted = telemetry.challenges.submitted.load(.monotonic);
    const cause = @intFromEnum(telemetry_store.challenge_metrics.Cause.malformed_solution);
    const rejected = telemetry.challenges.causes[cause].load(.monotonic);
    try roundTrip(
        proxy_fixture.port,
        "POST /__sibuna/verify HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expectEqual(submitted + 1, telemetry.challenges.submitted.load(.monotonic));
    try std.testing.expectEqual(rejected + 1, telemetry.challenges.causes[cause].load(.monotonic));
    try std.testing.expectEqual(counted.requests(), telemetry.totals().requests());
}

test "audit inspection records findings while other inspection, rules and reputation still deny" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const port = audit_fixture.port;
    try get(port, "/robots.txt?q=union%20select", "203.0.113.220", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try get(
        port,
        "/robots.txt?q=union%20select%20%3Cscript%3E",
        "203.0.113.221",
        "curl",
        "",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try get(port, "/?q=union%20select", "203.0.113.222", "Amazonbot", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try get(port, "/robots.txt?q=union%20select", "203.0.113.223", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try get(port, "/../../etc/passwd", "203.0.113.224", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 401), resp.status());
    try std.testing.expectEqual(@as(u64, 4), audited_requests.load(.monotonic));
}

test "snapshot templates render for browsers while other clients keep plain text" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const port = audit_fixture.port;
    try get(port, "/pages", "203.0.113.223", "curl", "Accept: text/html\r\n", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try std.testing.expectEqualStrings("text/html; charset=utf-8", resp.header("content-type").?);
    const body = resp.body();
    try std.testing.expect(std.mem.startsWith(u8, body, "<!doctype html><title>Custom</title>"));
    const marker = "Custom denial: ip/cidr-trie (403) ref ";
    try std.testing.expect(std.mem.indexOf(u8, body, marker) != null);
    const length = try std.fmt.parseInt(usize, resp.header("content-length").?, 10);
    try std.testing.expectEqual(body.len, length);
    try get(port, "/pages", "203.0.113.223", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try std.testing.expectEqualStrings("text/plain; charset=utf-8", resp.header("content-type").?);
    try std.testing.expectEqualStrings("Forbidden: blocked by Sibuna policy", resp.body());
    // The library default for rate limiting keeps Retry-After and answers as HTML.
    const quota = quota_fixture.port;
    try get(quota, "/quota-ban", "203.0.113.240", "curl", "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try get(quota, "/quota-ban", "203.0.113.240", "curl", "Accept: text/html\r\n", resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
    try std.testing.expectEqualStrings("60", resp.header("retry-after").?);
    try std.testing.expect(std.mem.indexOf(u8, resp.body(), "Retry after 60 seconds") != null);
}

const Response = struct {
    buf: [128 * 1024]u8 = undefined,
    len: usize = 0,

    fn text(self: *const Response) []const u8 {
        return self.buf[0..self.len];
    }

    fn status(self: *const Response) u16 {
        const t = self.text();
        if (t.len < 12) return 0;
        return std.fmt.parseInt(u16, t[9..12], 10) catch 0;
    }

    fn header(self: *const Response, name: []const u8) ?[]const u8 {
        var it = std.mem.splitSequence(u8, self.text(), "\r\n");
        _ = it.first();
        while (it.next()) |line| {
            if (line.len == 0) return null;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..colon], name)) {
                return std.mem.trim(u8, line[colon + 1 ..], " ");
            }
        }
        return null;
    }

    fn body(self: *const Response) []const u8 {
        const t = self.text();
        const idx = std.mem.indexOf(u8, t, "\r\n\r\n") orelse return "";
        return t[idx + 4 ..];
    }

    fn contains(self: *const Response, needle: []const u8) bool {
        return std.mem.indexOf(u8, self.text(), needle) != null;
    }
};

/// Sends one raw request and reads until the peer closes.
fn roundTrip(port: u16, raw: []const u8, out: *Response) !void {
    const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    // Admission rejection is sent before reading a request. An empty input reads that
    // response without racing a write/shutdown against the server's immediate close.
    if (raw.len != 0) {
        var wbuf: [4096]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        try writer.interface.writeAll(raw);
        try writer.interface.flush();
        try stream.shutdown(io, .send);
    }
    var rbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    out.len = 0;
    while (true) {
        const n = reader.interface.readSliceShort(out.buf[out.len..]) catch break;
        if (n == 0) break;
        out.len += n;
        if (out.len == out.buf.len) break;
    }
}

fn get(
    port: u16,
    path: []const u8,
    ip: []const u8,
    ua: []const u8,
    extra: []const u8,
    out: *Response,
) !void {
    var buf: [4096]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &buf,
        "GET {s} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {s}\r\nUser-Agent: {s}\r\n{s}\r\n",
        .{ path, ip, ua, extra },
    );
    try roundTrip(port, raw, out);
}

fn post(
    port: u16,
    path: []const u8,
    ip: []const u8,
    ua: []const u8,
    body: []const u8,
    out: *Response,
) !void {
    var buf: [64 * 1024]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &buf,
        "POST {s} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {s}\r\nUser-Agent: {s}\r\n" ++
            "Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ path, ip, ua, body.len, body },
    );
    try roundTrip(port, raw, out);
}

const browser_ua = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/128.0 Safari/537.36";
const browser_accept = "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n" ++
    "Accept-Language: en\r\n";

const Challenge = struct {
    id: [128]u8,
    id_len: usize,
    algorithm: [16]u8,
    alg_len: usize,
    difficulty: u32,
    challenges: u8,

    fn idSlice(self: *const Challenge) []const u8 {
        return self.id[0..self.id_len];
    }
};

fn fetchChallenge(port: u16, ip: []const u8, ua: []const u8, path: []const u8) !Challenge {
    var query: [256]u8 = undefined;
    return issue(port, ip, ua, try std.fmt.bufPrint(&query, "path={s}", .{path}));
}

/// Requests a challenge with an explicit issuance query (a reported path, a ticket or both).
fn issue(port: u16, ip: []const u8, ua: []const u8, query: []const u8) !Challenge {
    var resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var url: [512]u8 = undefined;
    const target = try std.fmt.bufPrint(&url, "/__sibuna/challenge.json?{s}", .{query});
    try get(port, target, ip, ua, "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    const body = resp.body();
    var ch: Challenge = undefined;
    const id = server.extractJsonString(body, "id") orelse return error.MissingId;
    @memcpy(ch.id[0..id.len], id);
    ch.id_len = id.len;
    const alg = server.extractJsonString(body, "algorithm") orelse return error.MissingAlgorithm;
    @memcpy(ch.algorithm[0..alg.len], alg);
    ch.alg_len = alg.len;
    ch.difficulty = try std.fmt.parseInt(u32, server.extractJsonString(body, "difficulty").?, 10);
    ch.challenges = try std.fmt.parseInt(u8, server.extractJsonString(body, "challenges").?, 10);
    return ch;
}

fn extractCookie(resp: *const Response, out: *[256]u8) ![]const u8 {
    const set_cookie = resp.header("set-cookie") orelse return error.NoCookie;
    const semi = std.mem.indexOfScalar(u8, set_cookie, ';') orelse set_cookie.len;
    const pair = set_cookie[0..semi];
    @memcpy(out[0..pair.len], pair);
    return out[0..pair.len];
}

test "browser navigation without a session gets the interstitial, static paths pass through" {
    boot_once.call();
    const p = proxy_fixture.port;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    try get(p, "/blog/post-1", "203.0.113.10", browser_ua, browser_accept, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expectEqualStrings("CHALLENGE", resp.header("x-sibuna-status").?);
    try std.testing.expect(resp.contains("Weighing Connection"));

    try get(p, "/api/data", "203.0.113.10", browser_ua, "Accept: application/json\r\n", resp);
    try std.testing.expectEqual(@as(u16, 401), resp.status());
    try std.testing.expect(resp.contains("challenge_required"));

    try get(p, "/robots.txt", "203.0.113.10", "GPTBot/1.0", "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /robots.txt HTTP/1.1"));
    try std.testing.expect(resp.contains("X-Sibuna-Status: PASS"));
    try std.testing.expect(resp.contains("X-Sibuna-Rule: robots-txt"));
    try std.testing.expect(resp.contains("X-Forwarded-For: 203.0.113.10"));
}

test "hashcash flow: challenge, solve, verify, cookie, proxied, replay and binding rejected" {
    boot_once.call();
    const p = proxy_fixture.port;
    const ip = "203.0.113.11";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    const ch = try fetchChallenge(p, ip, browser_ua, "/blog/post-1");
    try std.testing.expectEqualStrings("hashcash", ch.algorithm[0..ch.alg_len]);
    try std.testing.expectEqual(@as(u32, 8), ch.difficulty);
    const nonce = crypto.pow.solveHashcashBits(ch.idSlice(), ch.difficulty, 1 << 24).?;

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}",
        .{ ch.idSlice(), nonce },
    );
    try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    var cookie_buf: [256]u8 = undefined;
    const cookie = try extractCookie(resp, &cookie_buf);
    try std.testing.expect(std.mem.startsWith(u8, cookie, "__sibuna_token="));

    var hdr: [512]u8 = undefined;
    const cookie_hdr = try std.fmt.bufPrint(
        &hdr,
        "Cookie: {s}\r\n{s}",
        .{ cookie, browser_accept },
    );
    try get(p, "/blog/post-1", ip, browser_ua, cookie_hdr, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /blog/post-1"));
    try std.testing.expect(resp.contains("X-Sibuna-Rule: session"));
    try std.testing.expect(
        !resp.contains("Cookie: __sibuna_token") or resp.contains("Cookie: __sibuna_token"),
    );

    try get(p, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", ip, browser_ua, cookie_hdr, resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    var deny_hdr: [600]u8 = undefined;
    const denied = try std.fmt.bufPrint(&deny_hdr, "{s}CF-Worker: worker\r\n", .{cookie_hdr});
    try get(p, "/blog/post-1", ip, browser_ua, denied, resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());

    // Replay of the same solution is a double spend.
    try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("DOUBLE SPEND"));

    // The cookie is bound to the client identity.
    try get(p, "/blog/post-1", "203.0.113.99", browser_ua, cookie_hdr, resp);
    try std.testing.expect(resp.contains("Weighing Connection"));

    // A solution from a different client identity is rejected before hashing.
    const ch2 = try fetchChallenge(p, ip, browser_ua, "/");
    const nonce2 = crypto.pow.solveHashcashBits(ch2.idSlice(), ch2.difficulty, 1 << 24).?;
    const body2 = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}",
        .{ ch2.idSlice(), nonce2 },
    );
    try post(p, "/__sibuna/verify", "203.0.113.98", browser_ua, body2, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("FINGERPRINT MISMATCH"));
    // A wrong nonce fails the difficulty check.
    const body3 = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}",
        .{ ch2.idSlice(), nonce2 + 1 },
    );
    try post(p, "/__sibuna/verify", ip, browser_ua, body3, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
}

/// Fetches, solves and verifies a hashcash challenge for `path`, returning the cookie header.
fn hashcashSession(port: u16, ip: []const u8, path: []const u8, out: *[512]u8) ![]const u8 {
    return solveSession(port, ip, try fetchChallenge(port, ip, browser_ua, path), out);
}

/// Solves and verifies an issued hashcash challenge, returning the cookie header.
fn solveSession(port: u16, ip: []const u8, ch: Challenge, out: *[512]u8) ![]const u8 {
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const nonce = crypto.pow.solveHashcashBits(ch.idSlice(), ch.difficulty, 1 << 26).?;
    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}",
        .{ ch.idSlice(), nonce },
    );
    try post(port, "/__sibuna/verify", ip, browser_ua, body, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    var cookie_buf: [256]u8 = undefined;
    const cookie = try extractCookie(resp, &cookie_buf);
    return std.fmt.bufPrint(out, "Cookie: {s}\r\n{s}", .{ cookie, browser_accept });
}

test "a session earned on a cheaper route does not admit a route that demands more work" {
    boot_once.call();
    const p = proxy_fixture.port;
    const ip = "203.0.113.12";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var weak_buf: [512]u8 = undefined;
    const weak = try hashcashSession(p, ip, "/blog/post-1", &weak_buf);
    try get(p, "/blog/post-1", ip, browser_ua, weak, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("X-Sibuna-Rule: session"));
    // Eight paid bits do not cover a twelve-bit route: the interstitial returns, not the origin.
    try get(p, "/strong/data", ip, browser_ua, weak, resp);
    try std.testing.expectEqualStrings("CHALLENGE", resp.header("x-sibuna-status").?);
    try std.testing.expect(!resp.contains("ORIGIN|"));
    const strong_challenge = try fetchChallenge(p, ip, browser_ua, "/strong/data");
    try std.testing.expectEqual(@as(u32, 12), strong_challenge.difficulty);
    var strong_buf: [512]u8 = undefined;
    const strong = try hashcashSession(p, ip, "/strong/data", &strong_buf);
    try get(p, "/strong/data", ip, browser_ua, strong, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /strong/data"));
    try std.testing.expect(resp.contains("X-Sibuna-Rule: session"));
    // The stronger session covers the cheaper route as well; levels are ordered, not named.
    try get(p, "/blog/post-1", ip, browser_ua, strong, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /blog/post-1"));
    // Neither session clears a WAF denial.
    try get(p, "/search?q=1%27%20union%20select%20null--", ip, browser_ua, strong, resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
}

/// The requirement an interstitial carries, copied out as the solver script reads it.
fn ticketOf(resp: *const Response, out: *[128]u8) ![]const u8 {
    const marker = "data-ticket=\"";
    const text = resp.text();
    const start = (std.mem.indexOf(u8, text, marker) orelse return error.NoTicket) + marker.len;
    const end = std.mem.indexOfScalarPos(u8, text, start, '"') orelse return error.NoTicket;
    @memcpy(out[0 .. end - start], text[start..end]);
    return out[0 .. end - start];
}

test "issuance honours the requirement the challenged request was given" {
    boot_once.call();
    const p = proxy_fixture.port;
    const ip = "203.0.113.14";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var ticket_buf: [128]u8 = undefined;
    var query_buf: [256]u8 = undefined;
    var cookie_buf: [512]u8 = undefined;
    // An exact-path rule behind a query string: admission evaluates the path alone.
    try get(p, "/exact?view=1", ip, browser_ua, browser_accept, resp);
    try std.testing.expectEqualStrings("CHALLENGE", resp.header("x-sibuna-status").?);
    const ticket = try ticketOf(resp, &ticket_buf);
    const carried = try std.fmt.bufPrint(&query_buf, "path=%2Fexact%3Fview%3D1&need={s}", .{
        ticket,
    });
    const ch = try issue(p, ip, browser_ua, carried);
    try std.testing.expectEqual(@as(u32, 12), ch.difficulty);
    // Without a ticket the reported URL is split exactly as the request line is.
    const reported = try issue(p, ip, browser_ua, "path=%2Fexact%3Fview%3D1");
    try std.testing.expectEqual(@as(u32, 12), reported.difficulty);
    const cookie = try solveSession(p, ip, ch, &cookie_buf);
    try get(p, "/exact?view=1", ip, browser_ua, cookie, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /exact?view=1"));
    // Non-browser clients receive an issuance URL that already carries the requirement.
    try get(p, "/exact?view=1", ip, browser_ua, "Accept: application/json\r\n", resp);
    try std.testing.expectEqual(@as(u16, 401), resp.status());
    try std.testing.expect(resp.contains("/__sibuna/challenge.json?need="));
}

test "a requirement decided on navigation headers survives the interstitial's own fetch" {
    boot_once.call();
    const p = proxy_fixture.port;
    const ip = "203.0.113.15";
    const navigate = "Sec-Fetch-Mode: navigate\r\n" ++ browser_accept;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var ticket_buf: [128]u8 = undefined;
    var query_buf: [256]u8 = undefined;
    var cookie_buf: [512]u8 = undefined;
    try get(p, "/navigate/home", ip, browser_ua, navigate, resp);
    const ticket = try ticketOf(resp, &ticket_buf);
    const carried = try std.fmt.bufPrint(&query_buf, "path=%2Fnavigate%2Fhome&need={s}", .{
        ticket,
    });
    // The fetch carries no navigation header; the ticket still asks for the decided work.
    const ch = try issue(p, ip, browser_ua, carried);
    try std.testing.expectEqual(@as(u32, 13), ch.difficulty);
    const session = try solveSession(p, ip, ch, &cookie_buf);
    var header_buf: [640]u8 = undefined;
    const headers = try std.fmt.bufPrint(&header_buf, "{s}Sec-Fetch-Mode: navigate\r\n", .{
        session,
    });
    try get(p, "/navigate/home", ip, browser_ua, headers, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /navigate/home"));
    // A ticket is bound to its client: another address falls back to evaluating the URL.
    const elsewhere = try issue(p, "203.0.113.16", browser_ua, carried);
    try std.testing.expectEqual(@as(u32, 8), elsewhere.difficulty);
}

test "an ingress error page carries the requirement of the original target" {
    boot_once.call();
    const p = auth_fixture.port;
    const ip = "203.0.113.17";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var ticket_buf: [128]u8 = undefined;
    var query_buf: [256]u8 = undefined;
    const original = "X-Original-URI: /private?view=1\r\n" ++ browser_accept;
    try get(p, "/__sibuna/challenge", ip, browser_ua, original, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    const ticket = try ticketOf(resp, &ticket_buf);
    const ch = try issue(p, ip, browser_ua, try std.fmt.bufPrint(&query_buf, "need={s}", .{
        ticket,
    }));
    try std.testing.expectEqualStrings("posw", ch.algorithm[0..ch.alg_len]);
    try std.testing.expectEqual(@as(u32, 6), ch.difficulty);
    // Without the original URI the page renders with no requirement and issuance falls back.
    try get(p, "/__sibuna/challenge", ip, browser_ua, browser_accept, resp);
    try std.testing.expectError(error.NoTicket, ticketOf(resp, &ticket_buf));
    try std.testing.expect(resp.contains("/__sibuna/challenge.json"));
}

test "posw flow through forward-auth mode with ed25519 tokens" {
    boot_once.call();
    const p = auth_fixture.port;
    const ip = "203.0.113.20";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    try get(p, "/private", ip, browser_ua, browser_accept, resp);
    try std.testing.expectEqual(@as(u16, 401), resp.status());
    try std.testing.expectEqualStrings("CHALLENGE", resp.header("x-sibuna-status").?);
    try std.testing.expect(std.mem.startsWith(u8, resp.header("content-type").?, "text/html"));
    try std.testing.expect(std.mem.indexOf(u8, resp.body(), "new Worker(") != null);

    const ch = try fetchChallenge(p, ip, browser_ua, "/private");
    try std.testing.expectEqualStrings("posw", ch.algorithm[0..ch.alg_len]);
    try std.testing.expectEqual(@as(u32, 6), ch.difficulty);
    try std.testing.expectEqual(@as(u8, 4), ch.challenges);

    const ws = try std.testing.allocator.create(crypto.posw.Workspace);
    defer std.testing.allocator.destroy(ws);
    const params = crypto.posw.Params{ .depth = @intCast(
        ch.difficulty,
    ), .challenges = ch.challenges };
    const proof = try crypto.posw.solve(ch.idSlice(), params, ws);
    var b64: [crypto.posw.max_proof_size * 2]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&b64, proof);

    var body_buf: [crypto.posw.max_proof_size * 2 + 256]u8 = undefined;
    const body = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"proof\":\"{s}\"}}",
        .{ ch.idSlice(), encoded },
    );
    try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    var cookie_buf: [256]u8 = undefined;
    const cookie = try extractCookie(resp, &cookie_buf);
    try std.testing.expectEqual("__sibuna_token=".len + crypto.Token.encoded_size, cookie.len);

    var hdr: [512]u8 = undefined;
    const cookie_hdr = try std.fmt.bufPrint(&hdr, "Cookie: {s}\r\n", .{cookie});
    try get(p, "/private", ip, browser_ua, cookie_hdr, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expectEqualStrings("PASS", resp.header("x-sibuna-status").?);
    try std.testing.expectEqualStrings("session", resp.header("x-sibuna-rule").?);

    // A nonce for a PoSW challenge is the wrong solution type.
    const ch2 = try fetchChallenge(p, ip, browser_ua, "/");
    const bad = try std.fmt.bufPrint(
        &body_buf,
        "{{\"challenge_id\":\"{s}\",\"nonce\":\"1\"}}",
        .{ch2.idSlice()},
    );
    try post(p, "/__sibuna/verify", ip, browser_ua, bad, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("WRONG SOLUTION TYPE"));
}

test "policy and WAF denials, honeypot bans, and rate limiting" {
    boot_once.call();
    const p = proxy_fixture.port;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    try get(p, "/", "203.0.113.30", "Mozilla/5.0 Amazonbot/0.1", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());

    try get(p, "/", "203.0.113.30", "curl/8", "CF-Worker: x.workers.dev\r\n", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());

    try get(p, "/static/../../etc/passwd", "203.0.113.31", browser_ua, browser_accept, resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());

    try get(
        p,
        "/search?q=1%27%20union%20select%20null--",
        "203.0.113.31",
        browser_ua,
        browser_accept,
        resp,
    );
    try std.testing.expectEqual(@as(u16, 403), resp.status());

    try get(p, "/__sibuna/honeypot", "203.0.113.32", "Scrapy/2.0", "", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try get(p, "/robots.txt", "203.0.113.32", browser_ua, browser_accept, resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
    try std.testing.expect(resp.contains("banned"));

    var limited: u32 = 0;
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        try get(p, "/robots.txt", "203.0.113.33", browser_ua, "", resp);
        if (resp.status() == 429) {
            limited += 1;
            try std.testing.expect(resp.header("retry-after") != null);
        }
    }
    try std.testing.expectEqual(@as(u32, 4), limited);
}

test "challenge issuance and verification spend a budget of their own" {
    boot_once.call();
    const p = proxy_fixture.port;
    const st = &proxy_fixture.state;
    const saved = st.config.challenge_rate_limit;
    st.config.challenge_rate_limit = 2;
    defer st.config.challenge_rate_limit = saved;
    const ip = "203.0.113.13";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    _ = try fetchChallenge(p, ip, browser_ua, "/a");
    _ = try fetchChallenge(p, ip, browser_ua, "/b");
    try get(p, "/__sibuna/challenge.json?path=/c", ip, browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
    try std.testing.expect(resp.header("retry-after") != null);
    try post(p, "/__sibuna/verify", ip, browser_ua, "{\"nonce\":\"1\"}", resp);
    try std.testing.expectEqual(@as(u16, 429), resp.status());
    // Pages, assets and health answer as before: the budget covers only the work routes.
    try get(p, "/__sibuna/health", ip, browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try get(p, "/robots.txt", ip, browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
}

test "keep-alive serves multiple internal requests on one connection" {
    boot_once.call();
    const raw = "GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /__sibuna/metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try roundTrip(proxy_fixture.port, raw, resp);
    try std.testing.expect(resp.contains("\"status\":\"ok\""));
    try std.testing.expect(resp.contains("sibuna_requests_total"));
    try std.testing.expect(resp.contains("Connection: keep-alive"));
    try std.testing.expect(resp.contains("Connection: close"));
}

test "proxied responses keep the client connection open for the next request" {
    boot_once.call();
    const raw = "GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n\r\n" ++
        "GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n" ++
        "Connection: close\r\n\r\n";
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try roundTrip(proxy_fixture.port, raw, resp);
    const t = resp.text();
    const first = std.mem.indexOf(u8, t, "ORIGIN|GET /robots.txt").?;
    try std.testing.expect(std.mem.indexOfPos(u8, t, first + 1, "ORIGIN|GET /robots.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "Connection: keep-alive") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "Connection: close") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "X-Origin: stub") != null);
    // The second request reused the pooled origin socket: its sequence is
    // exactly one more than the first response's.
    const a = std.mem.indexOf(u8, t, "X-Origin-Seq: ").?;
    const b = std.mem.indexOfPos(u8, t, a + 1, "X-Origin-Seq: ").?;
    const seq_a = try std.fmt.parseInt(u32, std.mem.sliceTo(t[a + 14 ..], '\r'), 10);
    const seq_b = try std.fmt.parseInt(u32, std.mem.sliceTo(t[b + 14 ..], '\r'), 10);
    try std.testing.expectEqual(seq_a + 1, seq_b);
}

test "connections beyond the configured limit are answered 503 and closed" {
    boot_once.call();
    const st = &proxy_fixture.state;
    const saved = st.config.max_connections;
    st.config.max_connections = 0;
    defer st.config.max_connections = saved;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try roundTrip(proxy_fixture.port, "", resp);
    try std.testing.expectEqual(@as(u16, 503), resp.status());
    try std.testing.expect(resp.contains("connection limit"));
    // A client that has already sent its request receives the same answer, not a reset.
    try roundTrip(proxy_fixture.port, "GET / HTTP/1.1\r\nHost: t\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 503), resp.status());
    try std.testing.expect(resp.contains("connection limit"));
    st.config.max_connections = saved;
    try roundTrip(proxy_fixture.port, "GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(std.mem.indexOf(u8, resp.text(), "sibuna_overloaded_total") == null);
}

test "malformed, smuggled, oversized, and unknown requests are rejected cleanly" {
    boot_once.call();
    const p = proxy_fixture.port;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    try roundTrip(p, "GARBAGE\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());

    try roundTrip(
        p,
        "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 400), resp.status());

    const big = try std.testing.allocator.alloc(u8, 20 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'a');
    var head: [32 * 1024]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &head,
        "GET / HTTP/1.1\r\nHost: t\r\nX-Big: {s}\r\n\r\n",
        .{big},
    );
    try roundTrip(p, raw, resp);
    try std.testing.expectEqual(@as(u16, 431), resp.status());

    try get(p, "/__sibuna/nope", "203.0.113.40", browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 404), resp.status());

    try post(p, "/__sibuna/verify", "203.0.113.40", browser_ua, "{\"nonce\":\"1\"}", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try post(
        p,
        "/__sibuna/verify",
        "203.0.113.40",
        browser_ua,
        "{\"challenge_id\":\"zzz\",\"nonce\":\"1\"}",
        resp,
    );
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("MALFORMED CHALLENGE"));
}

/// The expected origin answer for an upload of `body` framed as `framing`.
fn uploadEcho(out: []u8, framing: []const u8, body: []const u8) ![]const u8 {
    return std.fmt.bufPrint(out, "UPLOAD|{s}|{d}|{x}", .{
        framing, body.len, std.hash.Wyhash.hash(0, body),
    });
}

const upload_head = "POST /robots.txt?upload HTTP/1.1\r\nHost: t\r\n" ++
    "Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n";

test "chunked uploads reach the origin framed by Sibuna, never by the client" {
    boot_once.call();
    const p = proxy_fixture.port;
    const allocator = std.testing.allocator;
    const resp = try allocator.create(Response);
    defer allocator.destroy(resp);
    var expected: [64]u8 = undefined;

    // A body that ends within the buffer reaches the origin with a length; extensions and the
    // trailer stay behind, and the pipelined request after it is served on the same connection.
    try roundTrip(p, upload_head ++ "X-Forwarded-For: 203.0.113.81\r\n\r\n" ++
        "5;sig=\"a;b\"\r\nhello\r\n1\r\n \r\n00D\r\nchunked world\r\n" ++
        "0\r\nX-Checksum: 1\r\n\r\n" ++
        "GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.81\r\n\r\n", resp);
    const short = try uploadEcho(&expected, "length", "hello chunked world");
    try std.testing.expect(resp.contains(short));
    try std.testing.expect(resp.contains("ORIGIN|GET /robots.txt"));
    try std.testing.expect(!resp.contains("X-Checksum"));

    // A body longer than the buffer streams as canonical chunks, one per read, whatever sizes
    // the client chose; the origin's digest matches the body byte for byte.
    const body = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(body);
    for (body, 0..) |*b, i| b.* = "abcdefghijklmnopqrstuvwxyz0123456789"[i % 36];
    var raw: std.Io.Writer.Allocating = .init(allocator);
    defer raw.deinit();
    try raw.writer.writeAll(upload_head ++ "X-Forwarded-For: 203.0.113.82\r\n\r\n");
    var at: usize = 0;
    var size: usize = 1;
    while (at < body.len) : (size = size * 7 % 9001 + 1) {
        const n = @min(size, body.len - at);
        try raw.writer.print("{X};n={d}\r\n{s}\r\n", .{ n, at, body[at..][0..n] });
        at += n;
    }
    try raw.writer.writeAll("0\r\n\r\n");
    try roundTrip(p, raw.written(), resp);
    try std.testing.expect(resp.contains(try uploadEcho(&expected, "chunked", body)));
}

test "chunk boundaries cannot hide a payload from inspection" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try roundTrip(proxy_fixture.port, "POST /robots.txt?upload HTTP/1.1\r\nHost: t\r\n" ++
        "X-Forwarded-For: 203.0.113.83\r\nTransfer-Encoding: chunked\r\n" ++
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n" ++
        "8\r\nq=1' uni\r\n6\r\non sel\r\nA\r\nect null--\r\n0\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 403), resp.status());
}

test "ambiguous chunked framing is refused before and after forwarding begins" {
    boot_once.call();
    const p = proxy_fixture.port;
    const allocator = std.testing.allocator;
    const resp = try allocator.create(Response);
    defer allocator.destroy(resp);
    const from = "X-Forwarded-For: 203.0.113.84\r\n\r\n";
    // A lone LF ends this size line for lenient parsers: refused before the origin sees it.
    try roundTrip(p, upload_head ++ from ++ "5\nhello\r\n0\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("Malformed chunked request body"));
    const coded = "POST /robots.txt HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    try roundTrip(p, coded, resp);
    try std.testing.expectEqual(@as(u16, 501), resp.status());
    try roundTrip(p, "POST /robots.txt HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());

    // Past the buffer the body is already streaming: the origin gets no terminal chunk and
    // the client still gets one 400.
    const filler = try allocator.alloc(u8, 80 * 1024);
    defer allocator.free(filler);
    @memset(filler, 'f');
    const raw = try std.fmt.allocPrint(allocator, upload_head ++ "X-Forwarded-For: " ++
        "203.0.113.85\r\n\r\n{X}\r\n{s}\r\n5 \r\nhello\r\n0\r\n\r\n", .{ filler.len, filler });
    defer allocator.free(raw);
    try roundTrip(p, raw, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("Malformed chunked request body"));
    try std.testing.expect(!resp.contains("UPLOAD|"));
}

test "assets are served with caching and the wasm module is the embedded solver" {
    boot_once.call();
    const p = proxy_fixture.port;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try get(p, "/__sibuna/wasm/sibuna-pow.wasm", "203.0.113.50", browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expectEqualStrings("application/wasm", resp.header("content-type").?);
    try std.testing.expect(std.mem.startsWith(u8, resp.body(), "\x00asm"));
    try std.testing.expectEqual(server.wasm_bytes.len, resp.body().len);
    try get(p, "/__sibuna/worker.js", "203.0.113.50", browser_ua, "", resp);
    try std.testing.expect(resp.contains("solvePoswJs"));
}

test "a streaming origin response outlives the idle timeout while bytes keep flowing" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const started = Io.Clock.awake.now(io);
    try get(proxy_fixture.port, "/.well-known/slow-stream", "203.0.113.70", browser_ua, "", resp);
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(@divTrunc(elapsed, 1_000_000) >= 2500);
    try std.testing.expectEqual(@as(usize, 12), std.mem.count(u8, resp.body(), "chunk"));
    try std.testing.expect(std.mem.endsWith(u8, resp.body(), "0\r\n\r\n"));
}

const Timed = struct { first_body_ms: i64, total_ms: i64, body: usize };

/// Reads one response read by read, noting when the first body byte arrived, until the peer
/// closes or `want` body bytes are in.
fn timedGet(port: u16, path: []const u8, ip: []const u8, want: usize, out: *Response) !Timed {
    const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [512]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    try writer.interface.print("GET {s} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {s}\r\n" ++
        "User-Agent: curl/8\r\n\r\n", .{ path, ip });
    try writer.interface.flush();
    const started = Io.Clock.awake.now(io);
    var result: Timed = .{ .first_body_ms = -1, .total_ms = 0, .body = 0 };
    var rbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    out.len = 0;
    while (result.body < want) {
        reader.interface.fillMore() catch break;
        const bytes = reader.interface.buffered();
        const room = @min(bytes.len, out.buf.len - out.len);
        @memcpy(out.buf[out.len..][0..room], bytes[0..room]);
        out.len += room;
        reader.interface.toss(bytes.len);
        const ms = @divTrunc(started.durationTo(Io.Clock.awake.now(io)).nanoseconds, 1_000_000);
        const head = std.mem.indexOf(u8, out.text(), "\r\n\r\n") orelse continue;
        result.body = out.len - head - 4;
        if (result.body != 0 and result.first_body_ms < 0) result.first_body_ms = @intCast(ms);
        result.total_ms = @intCast(ms);
    }
    return result;
}

test "small origin writes reach the client as produced and keep the exchange alive" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    // Framed by length, then delimited by close: both copies forward each read on arrival.
    const cases = [_][]const u8{ "/.well-known/slow-length", "/.well-known/slow-close" };
    const ips = [_][]const u8{ "203.0.113.73", "203.0.113.74" };
    for (cases, ips) |path, ip| {
        const timed = try timedGet(proxy_fixture.port, path, ip, 15360, resp);
        try std.testing.expectEqual(@as(u16, 200), resp.status());
        try std.testing.expectEqual(@as(usize, 15360), timed.body);
        // The first 512 bytes appear after one origin write, not after a full buffer.
        try std.testing.expect(timed.first_body_ms >= 0 and timed.first_body_ms < 800);
        // Three seconds of activity outlive the one-second idle timeout.
        try std.testing.expect(timed.total_ms >= 2500);
    }
}

test "a body sent after an early-flushed head is not held back by the kernel" {
    boot_once.call();
    const addr = try Io.net.IpAddress.parse("127.0.0.1", proxy_fixture.port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [512]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    var rbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    // Delayed acknowledgement starts after the first exchanges of a connection, so several
    // requests share one: with Nagle each body waits for the head's ACK, about 40 ms on Linux.
    const requests = 8;
    const started = Io.Clock.awake.now(io);
    for (0..requests) |_| {
        try writer.interface.writeAll("GET /.well-known/split HTTP/1.1\r\nHost: t\r\n" ++
            "X-Forwarded-For: 203.0.113.86\r\nUser-Agent: curl/8\r\n\r\n");
        try writer.interface.flush();
        while (std.mem.indexOf(u8, reader.interface.buffered(), "\r\n\r\nbody") == null)
            try reader.interface.fillMore();
        const reply = reader.interface.buffered();
        try std.testing.expect(std.mem.startsWith(u8, reply, "HTTP/1.1 200"));
        reader.interface.toss(std.mem.indexOf(u8, reply, "\r\n\r\nbody").? + 8);
    }
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    // Each exchange costs the origin's 5 ms pause; a held-back body would cost ~40 ms more.
    try std.testing.expect(elapsed < requests * 25 * std.time.ns_per_ms);
}

test "an origin that fails after its head aborts the connection without a second response" {
    boot_once.call();
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    try get(proxy_fixture.port, "/.well-known/truncated", "203.0.113.75", "curl/8", "", resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expectEqualStrings("0123456789", resp.body());
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, resp.text(), "HTTP/1.1 "));
    try std.testing.expect(!resp.contains("Bad Gateway"));
}

test "a silent origin is cut at the idle timeout and releases its connection slot" {
    boot_once.call();
    const st = &proxy_fixture.state;
    const saved = st.config.max_connections;
    st.config.max_connections = 1;
    defer st.config.max_connections = saved;
    const addr = try Io.net.IpAddress.parse("127.0.0.1", proxy_fixture.port);
    const held = try addr.connect(io, .{ .mode = .stream });
    defer held.close(io);
    var wbuf: [512]u8 = undefined;
    var writer = held.writer(io, &wbuf);
    try writer.interface.writeAll("GET /.well-known/silent HTTP/1.1\r\nHost: t\r\n" ++
        "X-Forwarded-For: 203.0.113.71\r\nUser-Agent: curl/8\r\n\r\n");
    try writer.interface.flush();
    Io.sleep(io, Io.Duration.fromMilliseconds(200), .awake) catch {};
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    // The stalled exchange occupies the only slot.
    try roundTrip(proxy_fixture.port, "", resp);
    try std.testing.expectEqual(@as(u16, 503), resp.status());
    // Nothing moves on either socket, so the reaper cuts the exchange well before the
    // origin's own four-second silence ends, and the worker releases the slot.
    const started = Io.Clock.awake.now(io);
    var rbuf: [4096]u8 = undefined;
    var reader = held.reader(io, &rbuf);
    var scratch: [4096]u8 = undefined;
    while (true) {
        const n = reader.interface.readSliceShort(&scratch) catch 0;
        if (n == 0) break;
    }
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    try std.testing.expect(@divTrunc(elapsed, 1_000_000) < 3500);
    // The worker may still be unwinding its retry when the client sees the cut; the slot
    // must come back well before the origin's silence ends.
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        const health = "GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n";
        try roundTrip(proxy_fixture.port, health, resp);
        if (resp.status() == 200) break;
        try std.testing.expect(resp.status() == 503 or resp.len == 0);
        Io.sleep(io, Io.Duration.fromMilliseconds(100), .awake) catch {};
    }
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    const total = started.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    try std.testing.expect(@divTrunc(total, 1_000_000) < 3500);
}

test "an idle connection is closed after the socket timeout" {
    boot_once.call();
    const addr = try Io.net.IpAddress.parse("127.0.0.1", proxy_fixture.port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const started = Io.Clock.awake.now(io);
    var rbuf: [256]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var scratch: [64]u8 = undefined;
    const n = reader.interface.readSliceShort(&scratch) catch 0;
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    const elapsed_ms = @divTrunc(elapsed, 1_000_000);
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expect(elapsed_ms >= 900 and elapsed_ms < 5000);
}

test {
    _ = @import("storage.zig");
    if (console_enabled) _ = @import("console_command.zig");
}

test "accepted client timing is observational and rejection causes cover parsed submissions" {
    if (!console_enabled) return;
    boot_once.call();
    const p = proxy_fixture.port;
    const ip = "203.0.113.181";
    const metrics = &proxy_fixture.telemetry.challenges;
    const cm = telemetry_store.challenge_metrics;
    const bin = &metrics.bins[cm.index(.hashcash, 8, 0)];
    const submitted = metrics.submitted.load(.monotonic);
    const accepted = bin.accepted.load(.monotonic);
    const missing = bin.missing.load(.monotonic);
    const invalid = bin.invalid.load(.monotonic);
    const bucket = bin.buckets[4].load(.monotonic);
    const replay = metrics.causes[@intFromEnum(cm.Cause.replay)].load(.monotonic);
    const missing_id = metrics.causes[@intFromEnum(cm.Cause.missing_id)].load(.monotonic);
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    const metadata = [_][]const u8{
        ",\"elapsed_ms\":8,\"solver\":\"wasm\"",
        ",\"elapsed_ms\":-1",
        "",
    };
    for (metadata, 0..) |extra, i| {
        var path_buf: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/timing/{d}", .{i});
        const ch = try fetchChallenge(p, ip, browser_ua, path);
        const nonce = crypto.pow.solveHashcashBits(ch.idSlice(), ch.difficulty, 1 << 24).?;
        var body_buf: [512]u8 = undefined;
        const body = try std.fmt.bufPrint(
            &body_buf,
            "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"{s}}}",
            .{ ch.idSlice(), nonce, extra },
        );
        try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
        try std.testing.expectEqual(@as(u16, 200), resp.status());
        try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
        try std.testing.expectEqual(@as(u16, 400), resp.status());
    }
    try post(p, "/__sibuna/verify", ip, browser_ua, "{}", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expectEqual(submitted + 7, metrics.submitted.load(.monotonic));
    try std.testing.expectEqual(accepted + 3, bin.accepted.load(.monotonic));
    try std.testing.expectEqual(missing + 1, bin.missing.load(.monotonic));
    try std.testing.expectEqual(invalid + 1, bin.invalid.load(.monotonic));
    try std.testing.expectEqual(bucket + 1, bin.buckets[4].load(.monotonic));
    try std.testing.expectEqual(replay + 3, metrics.causes[@intFromEnum(cm.Cause.replay)].load(
        .monotonic,
    ));
    const missing_counter = &metrics.causes[@intFromEnum(cm.Cause.missing_id)];
    try std.testing.expectEqual(missing_id + 1, missing_counter.load(.monotonic));
}

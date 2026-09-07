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
const server = @import("server.zig");

const io = std.testing.io;

const Fixture = struct {
    engine: policy.Engine = undefined,
    state: server.AppState = undefined,
    listener: Io.net.Server = undefined,
    port: u16 = 0,
};

var origin_port: u16 = 0;
var proxy_fixture: Fixture = .{};
var auth_fixture: Fixture = .{};
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
        defer stream.close(io);
        var buf: [16 * 1024]u8 = undefined;
        var reader = stream.reader(io, &buf);
        const head = reader.interface.peekGreedy(1) catch continue;
        var wbuf: [16 * 1024]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        const end = std.mem.indexOf(u8, head, "\r\n\r\n") orelse head.len;
        writer.interface.print(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: stub\r\nContent-Length: {d}\r\nConnection: close\r\n\r\nORIGIN|{s}",
            .{ end + 7, head[0..end] },
        ) catch continue;
        writer.interface.flush() catch continue;
    }
}

fn bootFixture(f: *Fixture, cfg_in: core.Config) void {
    var cfg = cfg_in;
    cfg.upstream_port = origin_port;
    cfg.trust_forwarded = true;
    cfg.workers = 1;
    cfg.rate_limit = 8;
    cfg.rate_window_seconds = 10;
    cfg.ban_seconds = 60;
    f.engine.initInPlace(cfg.default_difficulty);
    f.engine.waf_enabled = cfg.waf;
    const seed = [_]u8{0x5a} ** 32;
    f.state.init(cfg, &f.engine, &seed);
    const addr = Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    f.listener = addr.listen(io, .{ .reuse_address = true }) catch unreachable;
    f.port = f.listener.socket.address.ip4.port;
    const t = std.Thread.spawn(.{}, server.workerLoop, .{ &f.listener, io, &f.state }) catch unreachable;
    t.detach();
}

var origin_listener: Io.net.Server = undefined;

fn bootAll() void {
    const addr = Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    origin_listener = addr.listen(io, .{ .reuse_address = true }) catch unreachable;
    origin_port = origin_listener.socket.address.ip4.port;
    const t = std.Thread.spawn(.{}, originLoop, .{&origin_listener}) catch unreachable;
    t.detach();

    var proxy_cfg = core.Config.default();
    proxy_cfg.default_difficulty = 8;
    proxy_cfg.algorithm = .hashcash;
    bootFixture(&proxy_fixture, proxy_cfg);

    var auth_cfg = core.Config.default();
    auth_cfg.mode = .forward_auth;
    auth_cfg.default_difficulty = 9;
    auth_cfg.algorithm = .posw;
    auth_cfg.posw_challenges = 4;
    auth_cfg.token_scheme = .ed25519;
    bootFixture(&auth_fixture, auth_cfg);
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
    var wbuf: [4096]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    try writer.interface.writeAll(raw);
    try writer.interface.flush();
    try stream.shutdown(io, .send);
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

fn get(port: u16, path: []const u8, ip: []const u8, ua: []const u8, extra: []const u8, out: *Response) !void {
    var buf: [4096]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &buf,
        "GET {s} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {s}\r\nUser-Agent: {s}\r\n{s}\r\n",
        .{ path, ip, ua, extra },
    );
    try roundTrip(port, raw, out);
}

fn post(port: u16, path: []const u8, ip: []const u8, ua: []const u8, body: []const u8, out: *Response) !void {
    var buf: [64 * 1024]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &buf,
        "POST {s} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {s}\r\nUser-Agent: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ path, ip, ua, body.len, body },
    );
    try roundTrip(port, raw, out);
}

const browser_ua = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/128.0 Safari/537.36";
const browser_accept = "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: en\r\n";

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
    var resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);
    var url: [256]u8 = undefined;
    const target = try std.fmt.bufPrint(&url, "/__sibuna/challenge.json?path={s}", .{path});
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
    const body = try std.fmt.bufPrint(&body_buf, "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}", .{ ch.idSlice(), nonce });
    try post(p, "/__sibuna/verify", ip, browser_ua, body, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    var cookie_buf: [256]u8 = undefined;
    const cookie = try extractCookie(resp, &cookie_buf);
    try std.testing.expect(std.mem.startsWith(u8, cookie, "__sibuna_token="));

    var hdr: [512]u8 = undefined;
    const cookie_hdr = try std.fmt.bufPrint(&hdr, "Cookie: {s}\r\n{s}", .{ cookie, browser_accept });
    try get(p, "/blog/post-1", ip, browser_ua, cookie_hdr, resp);
    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expect(resp.contains("ORIGIN|GET /blog/post-1"));
    try std.testing.expect(resp.contains("X-Sibuna-Rule: session"));
    try std.testing.expect(!resp.contains("Cookie: __sibuna_token") or resp.contains("Cookie: __sibuna_token"));

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
    const body2 = try std.fmt.bufPrint(&body_buf, "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}", .{ ch2.idSlice(), nonce2 });
    try post(p, "/__sibuna/verify", "203.0.113.98", browser_ua, body2, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("FINGERPRINT MISMATCH"));
    // A wrong nonce fails the difficulty check.
    const body3 = try std.fmt.bufPrint(&body_buf, "{{\"challenge_id\":\"{s}\",\"nonce\":\"{d}\"}}", .{ ch2.idSlice(), nonce2 + 1 });
    try post(p, "/__sibuna/verify", ip, browser_ua, body3, resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
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

    const ch = try fetchChallenge(p, ip, browser_ua, "/private");
    try std.testing.expectEqualStrings("posw", ch.algorithm[0..ch.alg_len]);
    try std.testing.expectEqual(@as(u32, 6), ch.difficulty);
    try std.testing.expectEqual(@as(u8, 4), ch.challenges);

    const ws = try std.testing.allocator.create(crypto.posw.Workspace);
    defer std.testing.allocator.destroy(ws);
    const params = crypto.posw.Params{ .depth = @intCast(ch.difficulty), .challenges = ch.challenges };
    const proof = try crypto.posw.solve(ch.idSlice(), params, ws);
    var b64: [crypto.posw.max_proof_size * 2]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&b64, proof);

    var body_buf: [crypto.posw.max_proof_size * 2 + 256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "{{\"challenge_id\":\"{s}\",\"proof\":\"{s}\"}}", .{ ch.idSlice(), encoded });
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
    const bad = try std.fmt.bufPrint(&body_buf, "{{\"challenge_id\":\"{s}\",\"nonce\":\"1\"}}", .{ch2.idSlice()});
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

    try get(p, "/search?q=1%27%20union%20select%20null--", "203.0.113.31", browser_ua, browser_accept, resp);
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

test "malformed, smuggled, oversized, and unknown requests are rejected cleanly" {
    boot_once.call();
    const p = proxy_fixture.port;
    const resp = try std.testing.allocator.create(Response);
    defer std.testing.allocator.destroy(resp);

    try roundTrip(p, "GARBAGE\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());

    try roundTrip(p, "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());

    const big = try std.testing.allocator.alloc(u8, 20 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'a');
    var head: [32 * 1024]u8 = undefined;
    const raw = try std.fmt.bufPrint(&head, "GET / HTTP/1.1\r\nHost: t\r\nX-Big: {s}\r\n\r\n", .{big});
    try roundTrip(p, raw, resp);
    try std.testing.expectEqual(@as(u16, 431), resp.status());

    try get(p, "/__sibuna/nope", "203.0.113.40", browser_ua, "", resp);
    try std.testing.expectEqual(@as(u16, 404), resp.status());

    try post(p, "/__sibuna/verify", "203.0.113.40", browser_ua, "{\"nonce\":\"1\"}", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try post(p, "/__sibuna/verify", "203.0.113.40", browser_ua, "{\"challenge_id\":\"zzz\",\"nonce\":\"1\"}", resp);
    try std.testing.expectEqual(@as(u16, 400), resp.status());
    try std.testing.expect(resp.contains("MALFORMED CHALLENGE"));
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

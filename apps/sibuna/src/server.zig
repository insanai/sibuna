//! Sibuna Request Server
//!
//! Owns the per-connection loop and every HTTP handler. A connection gets
//! one 64 KB stack buffer for the life of the socket; request heads,
//! bodies, cookies, and policy inputs are slices into that buffer, so a
//! full classification, challenge verification, or proxy hand-off runs
//! without a heap allocation.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const crypto = @import("crypto");
const net = @import("net");
const policy = @import("policy");
const challenge = @import("challenge");
const store = @import("store");

pub const wasm_bytes = @embedFile("wasm_solver");
pub const challenge_html = @embedFile("challenge_html");
pub const worker_js = @embedFile("worker_js");

pub const version = "0.2.0";
pub const max_request_bytes = 64 * 1024;
pub const max_head_bytes = 16 * 1024;
pub const max_requests_per_connection = 256;

pub const Metrics = struct {
    incidents_persisted: std.atomic.Value(u64) = .init(0),
    incidents_dropped: std.atomic.Value(u64) = .init(0),
    incident_write_failures: std.atomic.Value(u64) = .init(0),
    incident_batches: std.atomic.Value(u64) = .init(0),
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    allowed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    denied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    challenged: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    challenges_issued: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    solutions_accepted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    solutions_rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rate_limited: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    banned: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    proxied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    upstream_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    parse_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn bump(counter: *std.atomic.Value(u64)) void {
        _ = counter.fetchAdd(1, .monotonic);
    }

    pub fn writePrometheus(self: *const Metrics, w: *Io.Writer) !void {
        inline for (std.meta.fields(Metrics)) |field| {
            try w.print(
                "# TYPE sibuna_{s}_total counter\nsibuna_{s}_total {d}\n",
                .{ field.name, field.name, @field(self, field.name).load(.monotonic) },
            );
        }
    }
};

/// Hooks for the optional persistent layer (SID 0005). Null callbacks make
/// the daemon behave exactly like the in-memory build.
pub const Hooks = struct {
    context: ?*anyopaque = null,
    /// Called off the response path after a WAF denial or honeypot hit.
    record_incident: ?*const fn (ctx: ?*anyopaque, incident: Incident) void = null,
};

pub const Incident = struct {
    client_ip: []const u8,
    user_agent: []const u8,
    method: []const u8,
    path: []const u8,
    category: []const u8,
    payload: []const u8,
    now: u64,
};

/// A policy engine plus its reader count. The active slot is swapped by
/// the storage layer (read-copy-update): readers pin a slot for the
/// duration of one request, and a writer that has published a new slot
/// waits until the old slot's readers drain before rebuilding into it.
pub const EngineSlot = struct {
    engine: *policy.Engine,
    readers: std.atomic.Value(u32) align(64) = std.atomic.Value(u32).init(0),
};

pub const AppState = struct {
    config: core.Config,
    slot: std.atomic.Value(*EngineSlot),
    spent: store.ChallengeStore = .{},
    rate_limiter: store.RateLimiter = store.RateLimiter.init(),
    bans: store.BanList = .{},
    idle: IdleTable = .{},
    coordinator: challenge.Coordinator,
    metrics: Metrics = .{},
    hooks: Hooks = .{},

    pub fn init(self: *AppState, cfg: core.Config, slot: *EngineSlot, seed: *const [32]u8) void {
        self.* = .{
            .config = cfg,
            .slot = std.atomic.Value(*EngineSlot).init(slot),
            .coordinator = undefined,
        };
        self.coordinator = challenge.Coordinator.init(&self.spent, seed, .{
            .algorithm = switch (cfg.algorithm) {
                .hashcash => .hashcash,
                .posw => .posw,
            },
            .difficulty = cfg.default_difficulty,
            .posw_challenges = cfg.posw_challenges,
        }, @intCast(cfg.challenge_ttl_seconds), cfg.token_ttl_seconds);
        if (cfg.cluster_node != 0) self.coordinator.bindNode(cfg.cluster_node);
        self.coordinator.token_scheme = switch (cfg.token_scheme) {
            .mac => .mac,
            .ed25519 => .ed25519,
        };
    }

    /// Pins the active slot. The re-check after incrementing closes the
    /// window in which a writer could have swapped and observed zero
    /// readers between our load and our increment.
    pub fn acquireEngine(self: *AppState) *EngineSlot {
        while (true) {
            const slot = self.slot.load(.seq_cst);
            _ = slot.readers.fetchAdd(1, .seq_cst);
            if (self.slot.load(.seq_cst) == slot) return slot;
            _ = slot.readers.fetchSub(1, .seq_cst);
        }
    }

    pub fn releaseEngine(slot: *EngineSlot) void {
        _ = slot.readers.fetchSub(1, .seq_cst);
    }

    /// Publishes `fresh` and returns the previous slot once no request is
    /// still reading it, so the caller may rebuild into it safely.
    pub fn publishEngine(self: *AppState, fresh: *EngineSlot) *EngineSlot {
        const old = self.slot.swap(fresh, .seq_cst);
        while (old.readers.load(.seq_cst) != 0) std.atomic.spinLoopHint();
        return old;
    }
};

pub fn runServer(server: *Io.net.Server, io: Io, state: *AppState) void {
    startReaper(io, state);
    const cpu_count = std.Thread.getCpuCount() catch 1;
    const wanted: usize = if (state.config.workers == 0) cpu_count else state.config.workers;
    const extra = @min(wanted -| 1, 63);
    var workers: [63]std.Thread = undefined;
    var spawned: usize = 0;
    while (spawned < extra) : (spawned += 1) {
        workers[spawned] = std.Thread.spawn(.{}, workerLoop, .{ server, io, state }) catch break;
    }
    workerLoop(server, io, state);
}

pub fn workerLoop(server: *Io.net.Server, io: Io, state: *AppState) void {
    while (true) {
        const client_stream = server.accept(io) catch |err| switch (err) {
            error.Canceled, error.SocketNotListening => return,
            else => continue,
        };
        handleConnection(client_stream, io, state);
    }
}

const Connection = struct {
    stream: Io.net.Stream,
    io: Io,
    state: *AppState,
    reader: *Io.Reader,
    writer: *Io.Writer,
    peer_buf: [48]u8 = undefined,
    peer: []const u8 = "",

    fn formatPeer(self: *Connection) void {
        self.peer = switch (self.stream.socket.address) {
            .ip4 => |a| std.fmt.bufPrint(&self.peer_buf, "{d}.{d}.{d}.{d}", .{
                a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3],
            }) catch "0.0.0.0",
            .ip6 => |a| formatIpv6(&self.peer_buf, &a.bytes),
        };
    }
};

fn formatIpv6(buf: *[48]u8, bytes: *const [16]u8) []const u8 {
    var w = Io.Writer.fixed(buf);
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        const group = std.mem.readInt(u16, bytes[i..][0..2], .big);
        w.print("{x}{s}", .{ group, if (i < 14) ":" else "" }) catch return "::";
    }
    return w.buffered();
}

/// Registry of open connections for the idle reaper. Each slot pairs a
/// socket with its last-activity time under a tiny spinlock; the reaper
/// shuts a stale socket down while holding that lock, and a connection
/// unregisters under the same lock before it closes, so a reused
/// descriptor can never be shut down by mistake.
pub const IdleTable = struct {
    pub const capacity = 8192;

    const Slot = struct {
        lock: store.rate_limiter.SpinLock = .{},
        active: bool = false,
        stream: Io.net.Stream = undefined,
        last_active_ms: u64 = 0,
    };

    slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
    cursor: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn register(self: *IdleTable, stream: Io.net.Stream, now_ms: u64) ?u32 {
        const start = self.cursor.fetchAdd(1, .monotonic) % capacity;
        var probe: u32 = 0;
        while (probe < capacity) : (probe += 1) {
            const idx = (start + probe) % capacity;
            const slot = &self.slots[idx];
            slot.lock.lock();
            defer slot.lock.unlock();
            if (!slot.active) {
                slot.* = .{ .active = true, .stream = stream, .last_active_ms = now_ms };
                return idx;
            }
        }
        return null;
    }

    fn touch(self: *IdleTable, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        slot.lock.lock();
        defer slot.lock.unlock();
        slot.last_active_ms = now_ms;
    }

    fn unregister(self: *IdleTable, idx: u32) void {
        const slot = &self.slots[idx];
        slot.lock.lock();
        defer slot.lock.unlock();
        slot.active = false;
    }

    /// Shuts down every connection idle longer than `timeout_ms`; the
    /// blocked worker then sees end-of-stream and releases the thread.
    pub fn reap(self: *IdleTable, io: Io, now_ms: u64, timeout_ms: u64) u32 {
        var reaped: u32 = 0;
        for (&self.slots) |*slot| {
            slot.lock.lock();
            defer slot.lock.unlock();
            if (slot.active and now_ms > slot.last_active_ms + timeout_ms) {
                slot.stream.shutdown(io, .both) catch {};
                slot.active = false;
                reaped += 1;
            }
        }
        return reaped;
    }
};

fn nowMs(io: Io) u64 {
    return @intCast(@max(0, @divTrunc(Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms)));
}

fn reaperLoop(io: Io, state: *AppState) void {
    const timeout_ms = @as(u64, state.config.idle_timeout_seconds) * 1000;
    while (true) {
        const pause = Io.Duration.fromMilliseconds(@intCast(@max(200, timeout_ms / 4)));
        Io.sleep(io, pause, .awake) catch return;
        _ = state.idle.reap(io, nowMs(io), timeout_ms);
    }
}

/// Starts the idle reaper when a timeout is configured.
pub fn startReaper(io: Io, state: *AppState) void {
    if (state.config.idle_timeout_seconds == 0) return;
    const t = std.Thread.spawn(.{}, reaperLoop, .{ io, state }) catch return;
    t.detach();
}

pub fn handleConnection(stream: Io.net.Stream, io: Io, state: *AppState) void {
    defer stream.close(io);
    const idle_slot = state.idle.register(stream, nowMs(io));
    defer if (idle_slot) |idx| state.idle.unregister(idx);
    var conn_buf: [max_request_bytes]u8 = undefined;
    var reader = stream.reader(io, &conn_buf);
    var writer_buf: [16 * 1024]u8 = undefined;
    var writer = stream.writer(io, &writer_buf);
    var conn = Connection{
        .stream = stream,
        .io = io,
        .state = state,
        .reader = &reader.interface,
        .writer = &writer.interface,
    };
    conn.formatPeer();
    var served: u32 = 0;
    while (served < max_requests_per_connection) : (served += 1) {
        const keep = serveOne(&conn) catch break;
        if (!keep) break;
        if (idle_slot) |idx| state.idle.touch(idx, nowMs(io));
    }
}

const HeadError = error{ HeadTooLarge, Truncated, ReadFailed };

/// Buffers bytes until a complete head is present. Returns the head length
/// including the blank line, or null on a clean close between requests.
fn readHead(c: *Connection) HeadError!?usize {
    while (true) {
        const buf = c.reader.buffered();
        if (std.mem.indexOf(u8, buf, "\r\n\r\n")) |idx| {
            if (idx + 4 > max_head_bytes) return error.HeadTooLarge;
            return idx + 4;
        }
        if (buf.len >= max_head_bytes) return error.HeadTooLarge;
        c.reader.fill(buf.len + 1) catch |err| switch (err) {
            error.EndOfStream => return if (buf.len == 0) null else error.Truncated,
            else => return error.ReadFailed,
        };
    }
}

fn serveOne(c: *Connection) !bool {
    const head_len = (readHead(c) catch |err| {
        if (err == error.HeadTooLarge) {
            try net.response.writeText(
                c.writer,
                .headers_too_large,
                "Request head exceeds 16 KB",
                false,
            );
        }
        return false;
    }) orelse return false;

    var req = net.parseRequest(c.reader.buffered()[0..head_len]) catch {
        Metrics.bump(&c.state.metrics.parse_errors);
        try net.response.write400(c.writer, "Malformed HTTP request");
        return false;
    };
    const declared = req.contentLength() orelse 0;
    const fits = @min(declared, max_request_bytes - head_len);
    if (fits > 0) {
        c.reader.fill(head_len + fits) catch {
            try net.response.write400(c.writer, "Truncated request body");
            return false;
        };
    }
    const buffered = c.reader.buffered();
    const body_end = @min(buffered.len, head_len + fits);
    req.body = buffered[head_len..body_end];
    c.reader.toss(body_end);

    var ctx = RequestContext.init(c, &req, declared);
    return dispatch(&ctx);
}

const RequestContext = struct {
    c: *Connection,
    req: *net.Request,
    declared_body: usize,
    client_ip: []const u8,
    user_agent: []const u8,
    now: u64,
    now_ms: u64,
    keep_alive: bool,

    fn init(c: *Connection, req: *net.Request, declared_body: usize) RequestContext {
        const ts = Io.Clock.real.now(c.io);
        const now_ms: u64 = @intCast(@max(0, @divTrunc(ts.nanoseconds, std.time.ns_per_ms)));
        return .{
            .c = c,
            .req = req,
            .declared_body = declared_body,
            .client_ip = resolveClientIp(c, req),
            .user_agent = req.getHeader("user-agent") orelse "",
            .now = now_ms / 1000,
            .now_ms = now_ms,
            .keep_alive = req.wantsKeepAlive() and declared_body <= req.body.len,
        };
    }

    fn state(self: *RequestContext) *AppState {
        return self.c.state;
    }

    fn writer(self: *RequestContext) *Io.Writer {
        return self.c.writer;
    }
};

fn resolveClientIp(c: *Connection, req: *const net.Request) []const u8 {
    if (c.state.config.trustsForwarded()) {
        if (req.getHeader("x-forwarded-for")) |xff| {
            const first = std.mem.sliceTo(xff, ',');
            const trimmed = std.mem.trim(u8, first, " ");
            if (trimmed.len > 0) return trimmed;
        }
        if (req.getHeader("x-real-ip")) |real| {
            const trimmed = std.mem.trim(u8, real, " ");
            if (trimmed.len > 0) return trimmed;
        }
    }
    return c.peer;
}

fn dispatch(ctx: *RequestContext) !bool {
    const st = ctx.state();
    Metrics.bump(&st.metrics.requests);
    if (st.bans.isBanned(ctx.client_ip, ctx.now)) {
        Metrics.bump(&st.metrics.banned);
        try net.response.writeText(
            ctx.writer(),
            .forbidden,
            "Forbidden: address is banned",
            ctx.keep_alive,
        );
        return ctx.keep_alive;
    }
    if (std.mem.startsWith(u8, ctx.req.path, "/__sibuna/")) {
        try handleInternal(ctx);
        return ctx.keep_alive;
    }
    const limits = store.RateLimits{
        .rate = st.config.rate_limit,
        .window_ms = st.config.rate_window_seconds * 1000,
    };
    const rate = st.rate_limiter.check(ctx.client_ip, ctx.now_ms, limits);
    if (rate.limited) {
        Metrics.bump(&st.metrics.rate_limited);
        var hdr: [64]u8 = undefined;
        const retry = try std.fmt.bufPrint(
            &hdr,
            "Retry-After: {d}\r\n",
            .{(rate.retry_after_ms + 999) / 1000},
        );
        try net.response.write(
            ctx.writer(),
            .too_many_requests,
            "text/plain; charset=utf-8",
            "Rate limit exceeded",
            .{ .headers = retry, .keep_alive = ctx.keep_alive },
        );
        return ctx.keep_alive;
    }
    return applyPolicy(ctx);
}

fn policyHeaders(
    req: *const net.Request,
    out: *[net.MAX_HEADERS]policy.Header,
) []const policy.Header {
    for (req.headers[0..req.header_count], 0..) |h, idx| {
        out[idx] = .{ .name = h.name, .value = h.value };
    }
    return out[0..req.header_count];
}

/// Copy the only borrowed decision field needed by the response before
/// releasing the snapshot, so a slow origin cannot stall policy publication.
fn requestDecision(ctx: *RequestContext, name: *[policy.engine.MAX_RULE_NAME]u8) policy.Decision {
    const st = ctx.state();
    var hdr_buf: [net.MAX_HEADERS]policy.Header = undefined;
    const headers = policyHeaders(ctx.req, &hdr_buf);
    const slot = st.acquireEngine();
    defer AppState.releaseEngine(slot);
    var decision = slot.engine.evaluateRequest(.{
        .path = ctx.req.path,
        .query = ctx.req.query,
        .client_ip = ctx.client_ip,
        .user_agent = ctx.user_agent,
        .headers = headers,
        .body = ctx.req.body,
    });
    @memcpy(name[0..decision.rule_name.len], decision.rule_name);
    decision.rule_name = name[0..decision.rule_name.len];
    decision.algorithm = null; // Only challenge issuance uses the algorithm override.
    return decision;
}

fn applyPolicy(ctx: *RequestContext) !bool {
    const st = ctx.state();
    var name: [policy.engine.MAX_RULE_NAME]u8 = undefined;
    const decision = requestDecision(ctx, &name);
    // A session clears admission challenges, never WAF or explicit denials.
    if (decision.action != .deny) {
        if (ctx.req.getCookie(st.config.cookie_name)) |cookie| {
            if (st.coordinator.verifyCookie(cookie, ctx.client_ip, ctx.user_agent, ctx.now)) |t| {
                return forward(ctx, "PASS", "session", t.rule_hash);
            } else |_| {}
        }
    }
    switch (decision.action) {
        .allow => return forward(
            ctx,
            "PASS",
            decision.rule_name,
            crypto.ruleHash(decision.rule_name),
        ),
        .deny => {
            Metrics.bump(&st.metrics.denied);
            if (std.mem.startsWith(u8, decision.rule_name, "waf:")) recordIncident(
                ctx,
                decision.rule_name,
            );
            try net.response.writeText(
                ctx.writer(),
                .forbidden,
                "Forbidden: blocked by Sibuna policy",
                ctx.keep_alive,
            );
            return ctx.keep_alive;
        },
        .challenge, .weigh => {
            Metrics.bump(&st.metrics.challenged);
            try writeChallengeResponse(ctx);
            return ctx.keep_alive;
        },
    }
}

fn recordIncident(ctx: *RequestContext, category: []const u8) void {
    const st = ctx.state();
    const hook = st.hooks.record_incident orelse return;
    const payload = if (ctx.req.query.len > 0) ctx.req.query else ctx.req.body;
    hook(st.hooks.context, .{
        .client_ip = ctx.client_ip,
        .user_agent = ctx.user_agent,
        .method = @tagName(ctx.req.method),
        .path = ctx.req.path,
        .category = category,
        .payload = payload[0..@min(payload.len, 2048)],
        .now = ctx.now,
    });
}

fn writeChallengeResponse(ctx: *RequestContext) !void {
    const st = ctx.state();
    const extra = net.response.Extra{
        .headers = "X-Sibuna-Status: CHALLENGE\r\n",
        .keep_alive = ctx.keep_alive,
    };
    const w = ctx.writer();
    if (st.config.mode == .forward_auth) {
        const text = "Proof-of-work challenge required";
        try net.response.write(w, .unauthorized, "text/plain", text, extra);
        return;
    }
    if (ctx.req.acceptsHtml()) {
        try net.response.write(w, .ok, "text/html; charset=utf-8", challenge_html, extra);
        return;
    }
    const json = "{\"error\":\"challenge_required\",\"challenge\":\"/__sibuna/challenge.json\"}";
    try net.response.write(w, .unauthorized, "application/json", json, extra);
}

/// Hands an admitted request to the origin (reverse proxy) or answers the
/// ingress (forward auth). Proxied connections close afterwards because the
/// origin's framing is streamed through untouched.
fn forward(ctx: *RequestContext, status: []const u8, rule_name: []const u8, rule_hash: u64) !bool {
    const st = ctx.state();
    Metrics.bump(&st.metrics.allowed);
    if (st.config.mode == .forward_auth) {
        var hdr: [256]u8 = undefined;
        const headers = try std.fmt.bufPrint(
            &hdr,
            "X-Sibuna-Status: {s}\r\nX-Sibuna-Rule: {s}\r\nX-Sibuna-Rule-Hash: {x}\r\n",
            .{ status, rule_name, rule_hash },
        );
        try net.response.write(
            ctx.writer(),
            .ok,
            "text/plain; charset=utf-8",
            "OK",
            .{ .headers = headers, .keep_alive = ctx.keep_alive },
        );
        return ctx.keep_alive;
    }
    Metrics.bump(&st.metrics.proxied);
    const c = ctx.c;
    const cfg = st.config;
    const audit = net.ProxyAudit{
        .client_ip = ctx.client_ip,
        .status = status,
        .rule = rule_name,
    };
    const host = cfg.upstream_host;
    const port = cfg.upstream_port;
    net.proxy.streamProxy(c.stream, c.reader, c.io, host, port, ctx.req, audit) catch |err| {
        Metrics.bump(&st.metrics.upstream_errors);
        if (err == error.UpstreamUnreachable) {
            try net.response.write502(ctx.writer(), "Bad Gateway: upstream unreachable");
        }
    };
    return false;
}

fn handleInternal(ctx: *RequestContext) !void {
    const path = ctx.req.path;
    const st = ctx.state();
    const w = ctx.writer();
    const keep = ctx.keep_alive;
    if (std.mem.eql(u8, path, "/__sibuna/wasm/sibuna-pow.wasm")) {
        try net.response.write(
            w,
            .ok,
            "application/wasm",
            wasm_bytes,
            .{ .keep_alive = keep, .cache = true },
        );
    } else if (std.mem.eql(u8, path, "/__sibuna/worker.js")) {
        try net.response.write(
            w,
            .ok,
            "application/javascript",
            worker_js,
            .{ .keep_alive = keep, .cache = true },
        );
    } else if (std.mem.eql(u8, path, "/__sibuna/challenge")) {
        try net.response.write(
            w,
            .ok,
            "text/html; charset=utf-8",
            challenge_html,
            .{ .keep_alive = keep },
        );
    } else if (std.mem.eql(u8, path, "/__sibuna/challenge.json")) {
        try handleChallengeJson(ctx);
    } else if (std.mem.eql(u8, path, "/__sibuna/verify") and ctx.req.method == .POST) {
        try handleVerifySolution(ctx);
    } else if (std.mem.eql(u8, path, "/__sibuna/honeypot")) {
        Metrics.bump(&st.metrics.banned);
        st.bans.ban(ctx.client_ip, ctx.now + st.config.ban_seconds, ctx.now);
        recordIncident(ctx, "honeypot");
        try net.response.writeText(
            w,
            .forbidden,
            "Access Denied: automated scraper honeypot triggered",
            keep,
        );
    } else if (std.mem.eql(u8, path, "/__sibuna/health")) {
        var buf: [256]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &buf,
            "{{\"status\":\"ok\",\"engine\":\"sibuna\",\"version\":\"{s}\"," ++
                "\"mode\":\"{s}\",\"algorithm\":\"{s}\"}}",
            .{ version, st.config.mode.name(), st.config.algorithm.name() },
        );
        try net.response.write(w, .ok, "application/json", json, .{ .keep_alive = keep });
    } else if (std.mem.eql(u8, path, "/__sibuna/metrics")) {
        var buf: [4096]u8 = undefined;
        var mw = Io.Writer.fixed(&buf);
        try st.metrics.writePrometheus(&mw);
        try net.response.write(
            w,
            .ok,
            "text/plain; version=0.0.4",
            mw.buffered(),
            .{ .keep_alive = keep },
        );
    } else {
        try net.response.writeText(w, .not_found, "Not Found", keep);
    }
}

/// Query parameter lookup over the zero-copy query slice.
fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        var kv = std.mem.splitScalar(u8, pair, '=');
        const k = kv.first();
        if (std.mem.eql(u8, k, key)) return kv.rest();
    }
    return null;
}

fn handleChallengeJson(ctx: *RequestContext) !void {
    const st = ctx.state();
    // The interstitial reports the path it is protecting so the rule that
    // demanded the challenge decides the difficulty and algorithm.
    var path_buf: [1024]u8 = undefined;
    const raw_path = queryParam(ctx.req.query, "path") orelse "/";
    const target_path = policy.normalizer.percentDecode(raw_path, &path_buf);
    var hdr_buf: [net.MAX_HEADERS]policy.Header = undefined;
    const headers = policyHeaders(ctx.req, &hdr_buf);
    const slot = st.acquireEngine();
    const decision = slot.engine.evaluateWithHeaders(
        target_path,
        ctx.client_ip,
        ctx.user_agent,
        headers,
    );
    AppState.releaseEngine(slot);

    var spec = st.coordinator.default_spec;
    if (decision.difficulty > 0) spec.difficulty = decision.difficulty;
    if (decision.algorithm) |alg| {
        if (challenge.Algorithm.parse(alg)) |a| spec.algorithm = a;
    }
    const rule_hash = crypto.ruleHash(decision.rule_name);
    const ch = st.coordinator.createChallengeWithSpec(
        ctx.client_ip,
        ctx.user_agent,
        ctx.now,
        spec,
        rule_hash,
    );
    Metrics.bump(&st.metrics.challenges_issued);

    var json_buf: [320]u8 = undefined;
    const json = try std.fmt.bufPrint(
        &json_buf,
        "{{\"id\":\"{s}\",\"algorithm\":\"{s}\",\"difficulty\":{d}," ++
            "\"challenges\":{d},\"expires_at\":{d}}}",
        .{ ch.id, ch.algorithm.name(), ch.difficulty, ch.challenges, ch.expires_at },
    );
    try net.response.write(
        ctx.writer(),
        .ok,
        "application/json",
        json,
        .{ .keep_alive = ctx.keep_alive },
    );
}

const SolutionParse = union(enum) {
    ok: challenge.Solution,
    err: []const u8,
};

fn parseSolution(body: []const u8, proof_buf: []u8) SolutionParse {
    if (extractJsonString(body, "proof")) |proof_b64| {
        const decoded = decodeProof(proof_b64, proof_buf) orelse
            return .{ .err = "Malformed proof encoding" };
        return .{ .ok = .{ .proof = decoded } };
    }
    if (extractJsonString(body, "nonce")) |nonce_str| {
        const nonce = std.fmt.parseInt(u64, nonce_str, 10) catch
            return .{ .err = "Invalid numeric nonce" };
        return .{ .ok = .{ .nonce = nonce } };
    }
    return .{ .err = "Missing nonce or proof field" };
}

fn handleVerifySolution(ctx: *RequestContext) !void {
    const st = ctx.state();
    const w = ctx.writer();
    const body = ctx.req.body;
    if (body.len < ctx.declared_body) {
        const text = "Solution body exceeds 64 KB";
        try net.response.writeText(w, .payload_too_large, text, ctx.keep_alive);
        return;
    }
    const cid = extractJsonString(body, "challenge_id") orelse {
        try net.response.writeText(w, .bad_request, "Missing challenge_id field", ctx.keep_alive);
        return;
    };
    var proof_buf: [crypto.posw.max_proof_size]u8 = undefined;
    const solution = switch (parseSolution(body, &proof_buf)) {
        .ok => |s| s,
        .err => |message| {
            try net.response.writeText(w, .bad_request, message, ctx.keep_alive);
            return;
        },
    };
    const coord = &st.coordinator;
    const ip = ctx.client_ip;
    const res = coord.verifyAndMint(cid, solution, ip, ctx.user_agent, ctx.now) catch |err| {
        Metrics.bump(&st.metrics.solutions_rejected);
        try net.response.writeText(w, .bad_request, core.explainError(err), ctx.keep_alive);
        return;
    };
    Metrics.bump(&st.metrics.solutions_accepted);
    var cookie_buf: [512]u8 = undefined;
    const cookie = try net.response.cookieHeader(
        &cookie_buf,
        st.config.cookie_name,
        res.slice(),
        res.ttl_seconds,
        st.config.secure_cookie,
    );
    try net.response.write(w, .ok, "application/json", "{\"status\":\"ok\"}", .{
        .headers = cookie,
        .keep_alive = ctx.keep_alive,
    });
}

fn decodeProof(encoded: []const u8, out: []u8) ?[]const u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return null;
    if (size > out.len) return null;
    decoder.decode(out[0..size], encoded) catch return null;
    return out[0..size];
}

/// Minimal zero-copy lookup of a top-level JSON string or number value.
pub fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const search_key = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;
    const k_idx = std.mem.indexOf(u8, json, search_key) orelse return null;
    var rest = json[k_idx + search_key.len ..];
    const colon_idx = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    rest = rest[colon_idx + 1 ..];
    while (rest.len > 0 and (rest[0] == ' ' or rest[0] == '\t' or rest[0] == '"')) {
        rest = rest[1..];
    }
    var end_idx: usize = 0;
    while (end_idx < rest.len and rest[end_idx] != '"' and rest[end_idx] != ',' and
        rest[end_idx] != '}' and rest[end_idx] != ' ' and rest[end_idx] != '\r' and
        rest[end_idx] != '\n') : (end_idx += 1)
    {}
    return rest[0..end_idx];
}

test "extractJsonString handles various JSON formats" {
    const j1 = "{\"challenge_id\":\"cid123\",\"nonce\":\"456\"}";
    try std.testing.expectEqualStrings("cid123", extractJsonString(j1, "challenge_id").?);
    try std.testing.expectEqualStrings("456", extractJsonString(j1, "nonce").?);
    const j2 = "{\n  \"challenge_id\": \"cid456\" ,\n  \"nonce\": 789\n}";
    try std.testing.expectEqualStrings("cid456", extractJsonString(j2, "challenge_id").?);
    try std.testing.expectEqualStrings("789", extractJsonString(j2, "nonce").?);
    try std.testing.expect(extractJsonString(j2, "proof") == null);
}

test "query parameter lookup and ipv6 peer formatting" {
    try std.testing.expectEqualStrings("/a/b", queryParam("x=1&path=/a/b&y=2", "path").?);
    try std.testing.expect(queryParam("x=1", "path") == null);
    var buf: [48]u8 = undefined;
    const bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:1", formatIpv6(&buf, &bytes));
}

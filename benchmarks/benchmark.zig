//! Standalone primitive benchmarks: batch timing only, no daemon hooks.
//! Results are local measurements, not competitor estimates or HTTP throughput.

const std = @import("std");
const crypto = @import("crypto");
const policy = @import("policy");
const store = @import("store");
const net = @import("net");

pub const Run = struct {
    impl: []const u8,
    subsystem: []const u8,
    workload: []const u8,
    measured: bool,
    iterations: u64,
    ns_per_op_median: f64,
    ns_per_op_min: f64,
    ns_per_op_max: f64,
    ops_per_sec: u64,
    bytes_per_op: u64 = 0,
};

pub const Runs = struct {
    items: [40]Run = undefined,
    len: usize = 0,

    pub fn append(self: *Runs, run: Run) !void {
        if (self.len >= self.items.len) return error.BufferOverflow;
        self.items[self.len] = run;
        self.len += 1;
    }

    pub fn slice(self: *const Runs) []const Run {
        return self.items[0..self.len];
    }
};

const batches = 7;

const Timer = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    fn begin(io: std.Io) Timer {
        return .{ .io = io, .start = std.Io.Clock.awake.now(io) };
    }

    fn lap(self: Timer) u64 {
        const end = std.Io.Clock.awake.now(self.io);
        return @intCast(self.start.durationTo(end).nanoseconds);
    }
};

fn resetContext(ctx: anytype) void {
    if (@TypeOf(ctx) == *store.ChallengeStore) ctx.* = .{};
    if (@TypeOf(ctx) == *store.RateLimiter) ctx.* = store.RateLimiter.init();
}

/// Runs `body` seven times over `iters` operations and reduces the batch
/// timings to per-operation statistics. Percentiles over single operations
/// would require timing each call, which perturbs sub-100 ns work, so the
/// spread reported is across batches.
fn measure(io: std.Io, iters: u64, ctx: anytype, comptime body: fn (@TypeOf(ctx), u64) u64) Run {
    resetContext(ctx);
    std.mem.doNotOptimizeAway(body(ctx, @min(iters, 1000)));
    var samples: [batches]u64 = undefined;
    var sink: u64 = 0;
    for (&samples) |*s| {
        resetContext(ctx);
        const t = Timer.begin(io);
        sink +%= body(ctx, iters);
        s.* = t.lap();
    }
    std.mem.doNotOptimizeAway(sink);
    std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
    const f = @as(f64, @floatFromInt(iters));
    const median = @as(f64, @floatFromInt(samples[batches / 2])) / f;
    return .{
        .impl = "sibuna",
        .subsystem = "",
        .workload = "",
        .measured = true,
        .iterations = iters,
        .ns_per_op_median = median,
        .ns_per_op_min = @as(f64, @floatFromInt(samples[0])) / f,
        .ns_per_op_max = @as(f64, @floatFromInt(samples[batches - 1])) / f,
        .ops_per_sec = if (median > 0) @intFromFloat(1_000_000_000.0 / median) else 0,
    };
}

fn tag(run: Run, subsystem: []const u8, workload: []const u8) Run {
    var r = run;
    r.subsystem = subsystem;
    r.workload = workload;
    return r;
}

// ------------------------------------------------------------- proof of work

const PowCtx = struct { challenge: []const u8, nonce: u64 };

fn hashcashBody(ctx: PowCtx, iters: u64) u64 {
    var ok: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(&ctx);
        if (crypto.verifyHashcashBits(ctx.challenge, ctx.nonce, 16)) ok += 1;
    }
    return ok;
}

const PoswCtx = struct { challenge: []const u8, params: crypto.posw.Params, proof: []const u8 };

fn poswBody(ctx: PoswCtx, iters: u64) u64 {
    var ok: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(&ctx);
        if (crypto.posw.verify(ctx.challenge, ctx.params, ctx.proof)) ok += 1;
    }
    return ok;
}

fn benchProofOfWork(io: std.Io, gpa: std.mem.Allocator, runs: *Runs) !void {
    const challenge = "AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";
    const nonce = crypto.pow.solveHashcashBits(challenge, 16, 1 << 32) orelse
        return error.NoSolution;
    try runs.append(tag(
        measure(io, 200_000, PowCtx{ .challenge = challenge, .nonce = nonce }, hashcashBody),
        "pow_verify",
        "hashcash_16_bits",
    ));
    const ws = try gpa.create(crypto.posw.Workspace);
    defer gpa.destroy(ws);
    const params = crypto.posw.Params{ .depth = 13, .challenges = 16 };
    const proof = try crypto.posw.solve(challenge, params, ws);
    const ctx = PoswCtx{ .challenge = challenge, .params = params, .proof = proof };
    try runs.append(tag(measure(io, 20_000, ctx, poswBody), "pow_verify", "posw_depth13_t16"));
}

// ---------------------------------------------------------------- matching

const test_uas = [_][]const u8{
    "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "Mozilla/5.0 AppleWebKit/537.36 (compatible; ClaudeBot/1.0)",
    "Mozilla/5.0 (Linux; Android 10) Bytespider; spider-feedback@bytedance",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/604.1",
};

fn botBody(ac: *const policy.aho_corasick.BotMatcher, iters: u64) u64 {
    var hits: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(ac);
        hits += @intFromBool(ac.findFirst(test_uas[i % test_uas.len]) != null);
    }
    return hits;
}

fn naiveBody(_: void, iters: u64) u64 {
    var hits: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const ua = test_uas[i % test_uas.len];
        const found = blk: {
            for (policy.bot_signatures.AI_SCRAPERS ++
                policy.bot_signatures.SCRAPER_LIBRARIES ++
                policy.bot_signatures.SEARCH_CRAWLERS) |pattern|
            {
                if (std.ascii.indexOfIgnoreCase(ua, pattern) != null) break :blk true;
            }
            break :blk false;
        };
        hits += @intFromBool(found);
    }
    return hits;
}

fn benchBotMatcher(io: std.Io, gpa: std.mem.Allocator, runs: *Runs) !void {
    const ac = try gpa.create(policy.aho_corasick.BotMatcher);
    defer gpa.destroy(ac);
    ac.* = policy.aho_corasick.BotMatcher.init();
    for (policy.bot_signatures.AI_SCRAPERS) |bot| _ = try ac.addPattern(bot);
    for (policy.bot_signatures.SCRAPER_LIBRARIES) |lib| _ = try ac.addPattern(lib);
    for (policy.bot_signatures.SEARCH_CRAWLERS) |c| _ = try ac.addPattern(c);
    ac.build();
    try runs.append(tag(
        measure(io, 200_000, @as(*const policy.aho_corasick.BotMatcher, ac), botBody),
        "bot_matcher",
        "aho_corasick_40_signatures",
    ));
    var naive = tag(
        measure(io, 200_000, {}, naiveBody),
        "bot_matcher",
        "sequential_substring_40_signatures",
    );
    naive.impl = "sibuna-naive";
    try runs.append(naive);
}

// ------------------------------------------------------------ ip filtering

const test_ips = [_][]const u8{
    "192.168.1.50", "10.200.1.1", "172.20.5.10", "54.239.10.20", "8.8.8.8", "1.1.1.1",
};
const test_ips6 = [_][]const u8{
    "2001:db8::1", "2001:db8:1::5", "2a02:1234::9", "fe80::1", "::1", "2606:4700::1111",
};

fn trieBody(trie: *const policy.radix_trie.Trie, iters: u64) u64 {
    var found: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        if (trie.matchIpStr(test_ips[i % test_ips.len])) |a| found +%= @intFromEnum(a);
    }
    return found;
}

fn trie6Body(trie: *const policy.radix_trie.Trie, iters: u64) u64 {
    var found: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        if (trie.matchIpStr(test_ips6[i % test_ips6.len])) |a| found +%= @intFromEnum(a);
    }
    return found;
}

fn benchIpFilter(io: std.Io, gpa: std.mem.Allocator, runs: *Runs) !void {
    const trie = try gpa.create(policy.radix_trie.Trie);
    defer gpa.destroy(trie);
    trie.* = policy.radix_trie.Trie.init();
    const cidrs = [_][]const u8{
        "192.168.0.0/16", "10.0.0.0/8",    "172.16.0.0/12",  "54.239.0.0/16",
        "35.184.0.0/13",  "2001:db8::/32", "2a02:1234::/32", "2606:4700::/32",
    };
    for (cidrs) |c| try trie.insertCidr(c, .deny);
    try runs.append(tag(
        measure(io, 200_000, @as(*const policy.radix_trie.Trie, trie), trieBody),
        "ip_filter",
        "ipv4_cidr_classification",
    ));
    try runs.append(tag(
        measure(io, 200_000, @as(*const policy.radix_trie.Trie, trie), trie6Body),
        "ip_filter",
        "ipv6_cidr_classification",
    ));
}

// ------------------------------------------------------------------ tokens

const MacCtx = struct {
    key: [32]u8,
    token: [crypto.MacToken.encoded_size]u8,
    fp: u64,
    now: u64,
};

fn macBody(ctx: *const MacCtx, iters: u64) u64 {
    var ok: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(ctx);
        if (crypto.MacToken.verify(&ctx.key, &ctx.token, ctx.now, ctx.fp)) |t| {
            ok +%= t.expiry;
        } else |_| {}
    }
    return ok;
}

const EdCtx = struct {
    public_key: crypto.Ed25519.PublicKey,
    token: [crypto.Token.encoded_size]u8,
    fp: u64,
    now: u64,
};

fn edBody(ctx: *const EdCtx, iters: u64) u64 {
    var ok: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(ctx);
        if (crypto.Token.verify(ctx.public_key, &ctx.token, ctx.now, ctx.fp)) |t| {
            ok +%= t.expiry;
        } else |_| {}
    }
    return ok;
}

fn benchTokens(io: std.Io, runs: *Runs) !void {
    const seed = [_]u8{0x42} ** 32;
    const keys = crypto.Keys.derive(&seed);
    const now: u64 = 1_725_700_000;
    const fp = crypto.computeFingerprintKeyed(&keys.fingerprint, "203.0.113.195", "Chrome/128");
    const mac = MacCtx{
        .key = keys.token,
        .token = crypto.MacToken.mint(&keys.token, now, 7200, 1, fp),
        .fp = fp,
        .now = now,
    };
    try runs.append(tag(
        measure(io, 200_000, &mac, macBody),
        "token_auth",
        "blake3_mac_token",
    ));
    const kp = try crypto.Ed25519.KeyPair.generateDeterministic(keys.ed25519_seed);
    const ed = EdCtx{
        .public_key = kp.public_key,
        .token = crypto.Token.mint(kp, now, 7200, 1, fp),
        .fp = fp,
        .now = now,
    };
    try runs.append(tag(
        measure(io, 10_000, &ed, edBody),
        "token_auth",
        "ed25519_compact_token",
    ));
}

// ------------------------------------------------------------------- state

fn spentBody(s: *store.ChallengeStore, iters: u64) u64 {
    var n: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        var t: store.ChallengeTag = undefined;
        std.mem.writeInt(u64, t[0..8], std.hash.Wyhash.hash(1, std.mem.asBytes(&i)), .little);
        std.mem.writeInt(u64, t[8..16], std.hash.Wyhash.hash(2, std.mem.asBytes(&i)), .little);
        s.markSpent(&t, 200_000, 100) catch @panic("spent benchmark insertion failed");
        if (s.isSpent(&t, 150)) n += 1;
    }
    return n;
}

fn gcraBody(l: *store.RateLimiter, iters: u64) u64 {
    var limited: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const limits = store.RateLimits{ .rate = 100, .window_ms = 10_000 };
        const d = l.check(test_ips[i % test_ips.len], 10_000 + i, limits);
        if (d.limited) limited += 1;
    }
    return limited;
}

fn benchState(io: std.Io, gpa: std.mem.Allocator, runs: *Runs) !void {
    const s = try gpa.create(store.ChallengeStore);
    defer gpa.destroy(s);
    s.* = .{};
    try runs.append(tag(
        measure(io, 40_000, s, spentBody),
        "challenge_store",
        "robin_hood_spend_and_lookup",
    ));
    const l = try gpa.create(store.RateLimiter);
    defer gpa.destroy(l);
    l.* = store.RateLimiter.init();
    try runs.append(tag(
        measure(io, 200_000, l, gcraBody),
        "rate_limiter",
        "gcra_check",
    ));
}

// -------------------------------------------------------------------- http

const raw_req =
    "GET /api/v1/data?page=2 HTTP/1.1\r\nHost: example.com\r\n" ++
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0 Safari/537.36\r\n" ++
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" ++
    "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n" ++
    "Cookie: __sibuna_token=v1_YWJjZGVmZ2hpams; session=xyz123\r\n\r\n";

fn parseBody(_: void, iters: u64) u64 {
    var n: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(&raw_req);
        const req = net.parseRequest(raw_req) catch continue;
        if (req.getCookie("__sibuna_token")) |c| n +%= c.len;
    }
    return n;
}

fn policyBody(engine: *const policy.Engine, iters: u64) u64 {
    var n: u64 = 0;
    var i: u64 = 0;
    const req = net.parseRequest(raw_req) catch unreachable;
    var hdrs: [net.MAX_HEADERS]policy.Header = undefined;
    for (req.headers[0..req.header_count], 0..) |h, idx| {
        hdrs[idx] = .{ .name = h.name, .value = h.value };
    }
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(engine);
        const d = engine.evaluateRequest(.{
            .path = req.path,
            .query = req.query,
            .client_ip = "203.0.113.7",
            .user_agent = req.getHeader("user-agent") orelse "",
            .headers = hdrs[0..req.header_count],
        });
        n +%= @intFromEnum(d.action);
    }
    return n;
}

const BodyCtx = struct { engine: *const policy.Engine, body: []const u8 };

fn wafBodyScan(ctx: BodyCtx, iters: u64) u64 {
    var n: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.doNotOptimizeAway(&ctx);
        const d = ctx.engine.evaluateRequest(.{
            .path = "/submit",
            .client_ip = "203.0.113.7",
            .user_agent = "Mozilla/5.0",
            .body = ctx.body,
        });
        n +%= @intFromEnum(d.action);
    }
    return n;
}

fn benchHttpAndPolicy(io: std.Io, gpa: std.mem.Allocator, runs: *Runs) !void {
    try runs.append(tag(
        measure(io, 200_000, {}, parseBody),
        "http_parser",
        "zero_copy_request_and_cookie",
    ));
    const engine = try gpa.create(policy.Engine);
    defer gpa.destroy(engine);
    engine.initInPlace(16);
    const view: *const policy.Engine = engine;
    try runs.append(tag(
        measure(io, 100_000, view, policyBody),
        "policy_engine",
        "browser_request_full_classification",
    ));
    engine.waf_enabled = false;
    try runs.append(tag(
        measure(io, 100_000, view, policyBody),
        "policy_engine",
        "browser_request_gate_profile",
    ));
    engine.waf_enabled = true;
    const body = try gpa.alloc(u8, 8192);
    defer gpa.free(body);
    const filler = "the quick brown fox jumps over the lazy dog, and the form holds a note. ";
    for (body, 0..) |*b, idx| b.* = filler[idx % filler.len];
    var scan = tag(
        measure(io, 5_000, BodyCtx{ .engine = engine, .body = body }, wafBodyScan),
        "waf_inspect",
        "8kb_body_semantic_scan",
    );
    scan.bytes_per_op = body.len;
    try runs.append(scan);
}

// ------------------------------------------------------------------ output

fn printJson(io: std.Io, runs: []const Run) !void {
    var buffer: [32 * 1024]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(io, &buffer);
    const out = &w.interface;
    const zig_version = @import("builtin").zig_version_string;
    try out.print("{{\"meta\":{{\"zig\":\"{s}\",\"engine_bytes\":{d}," ++
        "\"bot_table_bytes\":{d},\"waf_table_bytes\":{d}," ++
        "\"allocation_measurement\":\"not instrumented; API/source audit only\"}}," ++
        "\"runs\":[\n", .{
        zig_version,
        @sizeOf(policy.Engine),
        @sizeOf(policy.aho_corasick.BotMatcher),
        @sizeOf(policy.waf.Signatures),
    });
    for (runs, 0..) |r, idx| {
        const comma: []const u8 = if (idx + 1 < runs.len) "," else "";
        try out.print(
            "{{\"impl\":\"{s}\",\"subsystem\":\"{s}\",\"workload\":\"{s}\"," ++
                "\"measured\":{},\"iterations\":{d},\"ns_per_op_median\":{d:.2}," ++
                "\"ns_per_op_min\":{d:.2},\"ns_per_op_max\":{d:.2},\"ops_per_sec\":{d}," ++
                "\"alloc_bytes\":null,\"bytes_per_op\":{d}}}{s}\n",
            .{
                r.impl,        r.subsystem,        r.workload,      r.measured,
                r.iterations,  r.ns_per_op_median, r.ns_per_op_min, r.ns_per_op_max,
                r.ops_per_sec, r.bytes_per_op,     comma,
            },
        );
    }
    try out.print("]}}\n", .{});
    try out.flush();
}

fn printSummary(runs: []const Run) void {
    std.debug.print("\n=== Sibuna Benchmark Summary ===\n" ++
        "(local wall-clock measurements; allocation counts are not instrumented)\n\n", .{});
    std.debug.print("{s:<13} | {s:<16} | {s:<36} | {s:>10} | {s:>12} | {s:>8}\n", .{
        "Impl", "Subsystem", "Workload", "ns/op", "ops/sec", "Alloc",
    });
    for (runs) |r| {
        std.debug.print("{s:<13} | {s:<16} | {s:<36} | {d:>10.1} | {d:>12} | {s:>8}\n", .{
            r.impl, r.subsystem, r.workload, r.ns_per_op_median, r.ops_per_sec, "n/a",
        });
    }
    std.debug.print("\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var runs = Runs{};
    try benchProofOfWork(io, gpa, &runs);
    try benchBotMatcher(io, gpa, &runs);
    try benchIpFilter(io, gpa, &runs);
    try benchTokens(io, &runs);
    try benchState(io, gpa, &runs);
    try benchHttpAndPolicy(io, gpa, &runs);
    printSummary(runs.slice());
    try printJson(io, runs.slice());
}

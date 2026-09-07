//! Sibuna Daemon Entry Point
//!
//! Ultra-High-Performance Web AI Firewall & Anti-Crawler Daemon in Pure Zig 0.16.

const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const net = @import("net");
const policy = @import("policy");
const challenge = @import("challenge");
const store = @import("store");

const wasm_bytes = @embedFile("wasm_solver");
const challenge_html = @embedFile("challenge_html");
const worker_js = @embedFile("worker_js");

const AppState = struct {
    config: core.Config,
    policy_engine: policy.Engine,
    challenge_store: store.ChallengeStore,
    coordinator: challenge.Coordinator,
};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    _ = init.gpa;

    var args_buf: [64][]const u8 = undefined;
    var arg_count: usize = 0;

    var arg_it = std.process.Args.Iterator.init(init.minimal.args);
    defer arg_it.deinit();
    _ = arg_it.next(); // skip binary name

    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return 0;
        }
        if (arg_count < 64) {
            args_buf[arg_count] = arg;
            arg_count += 1;
        }
    }

    const cfg = core.Config.parseArgs(args_buf[0..arg_count]);

    var state = AppState{
        .config = cfg,
        .policy_engine = policy.Engine.init(cfg.default_difficulty),
        .challenge_store = store.ChallengeStore{},
        .coordinator = undefined,
    };
    state.coordinator = challenge.Coordinator.init(
        &state.challenge_store,
        cfg.secret_seed,
        cfg.default_difficulty,
        @intCast(cfg.challenge_ttl_seconds),
        cfg.token_ttl_seconds,
    );

    printBanner(cfg);

    const addr = std.Io.net.IpAddress.parse(cfg.listen_host, cfg.listen_port) catch |err| {
        std.debug.print("Failed to parse listen address {s}:{d}: {any}\n", .{
            cfg.listen_host,
            cfg.listen_port,
            err,
        });
        return 1;
    };

    var server = addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("Failed to bind socket on port {d}: {any}\n", .{ cfg.listen_port, err });
        return 1;
    };
    defer server.deinit(io);

    while (true) {
        const client_stream = server.accept(io) catch continue;
        handleConnection(client_stream, io, &state) catch {};
    }
}

fn printBanner(cfg: core.Config) void {
    const mode_name = switch (cfg.mode) {
        .reverse_proxy => "reverse_proxy",
        .forward_auth => "forward_auth",
    };
    std.debug.print(
        \\--------------------------------------------------------------------------------
        \\  SIBUNA Web AI Firewall & Anti-Crawler Daemon v0.1.0
        \\  "Weighing incoming connections with silicon speed"
        \\--------------------------------------------------------------------------------
        \\Mode:       {s}
        \\Listening:  {s}:{d}
        \\Upstream:   {s}:{d}
        \\Difficulty: {d} leading hex zero chars
        \\Memory:     Zero-allocation hot path, <15 MB resident set size
        \\--------------------------------------------------------------------------------
        \\
    , .{
        mode_name,
        cfg.listen_host,
        cfg.listen_port,
        cfg.upstream_host,
        cfg.upstream_port,
        cfg.default_difficulty,
    });
}

fn printHelp() void {
    std.debug.print(
        \\Usage: sibuna [options]
        \\
        \\Options:
        \\  --port, -p <port>           Listening port (default: 8080)
        \\  --host, -h <host>           Listening host (default: 0.0.0.0)
        \\  --upstream-host <host>      Upstream target host (default: 127.0.0.1)
        \\  --upstream-port, -u <port>  Upstream target port (default: 3000)
        \\  --mode, -m <mode>           Mode: reverse_proxy | forward_auth (default: reverse_proxy)
        \\  --difficulty, -d <diff>     PoW difficulty leading hex zeros (default: 4)
        \\  --verbose, -v               Enable verbose diagnostic logging
        \\  --help                      Show this help message
        \\
    , .{});
}

fn handleConnection(client_stream: std.Io.net.Stream, io: std.Io, state: *AppState) !void {
    defer client_stream.close(io);

    var conn_buf: [16 * 1024]u8 = undefined;
    var reader = client_stream.reader(io, &conn_buf);
    var raw_req = reader.interface.peekGreedy(1) catch return;
    if (raw_req.len == 0) return;

    var req = net.parseRequest(raw_req) catch {
        var writer_buf: [1024]u8 = undefined;
        var writer = client_stream.writer(io, &writer_buf);
        try net.response.write400(&writer.interface, "Malformed HTTP request");
        return;
    };

    if (req.getHeader("content-length")) |clen_str| {
        const clen = std.fmt.parseInt(usize, clen_str, 10) catch 0;
        const header_end = std.mem.indexOf(u8, raw_req, "\r\n\r\n") orelse 0;
        const total_needed = (header_end + 4) + clen;
        while (raw_req.len < total_needed and raw_req.len < conn_buf.len) {
            reader.interface.fill(total_needed - raw_req.len) catch break;
            raw_req = reader.interface.buffered();
        }
        if (header_end + 4 <= raw_req.len) {
            req.body = raw_req[header_end + 4 .. @min(raw_req.len, total_needed)];
        }
    }

    var writer_buf: [16 * 1024]u8 = undefined;
    var writer = client_stream.writer(io, &writer_buf);

    const client_ip = req.getHeader("x-forwarded-for") orelse
        req.getHeader("x-real-ip") orelse "127.0.0.1";
    const user_agent = req.getHeader("user-agent") orelse "";
    const ts = std.Io.Clock.real.now(io);
    const now = @as(u64, @intCast(@max(0, ts.toSeconds())));

    if (try handleInternalRoutes(
        client_stream,
        io,
        &writer.interface,
        req,
        state,
        client_ip,
        user_agent,
        now,
    )) {
        return;
    }

    try handleFirewallTraffic(
        client_stream,
        io,
        &writer.interface,
        req,
        state,
        client_ip,
        user_agent,
        raw_req,
        now,
    );
}

fn handleInternalRoutes(
    client_stream: std.Io.net.Stream,
    io: std.Io,
    writer: *std.Io.Writer,
    req: net.Request,
    state: *AppState,
    client_ip: []const u8,
    user_agent: []const u8,
    now: u64,
) !bool {
    _ = client_stream;
    _ = io;
    if (std.mem.eql(u8, req.path, "/__sibuna/wasm/sibuna-pow.wasm")) {
        try net.response.write200(writer, "application/wasm", wasm_bytes);
        return true;
    }
    if (std.mem.eql(u8, req.path, "/__sibuna/worker.js")) {
        try net.response.write200(writer, "application/javascript", worker_js);
        return true;
    }
    if (std.mem.eql(u8, req.path, "/__sibuna/challenge")) {
        try net.response.write200(writer, "text/html; charset=utf-8", challenge_html);
        return true;
    }
    if (std.mem.eql(u8, req.path, "/__sibuna/challenge.json")) {
        const ch = try state.coordinator.createChallenge(client_ip, user_agent, now);
        var json_buf: [256]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &json_buf,
            "{{\"id\":\"{s}\",\"difficulty\":{d},\"algorithm\":\"{s}\"}}",
            .{ ch.id, ch.difficulty, ch.algorithm },
        );
        try net.response.write200(writer, "application/json", json);
        return true;
    }
    if (std.mem.eql(u8, req.path, "/__sibuna/verify") and req.method == .POST) {
        try handleVerifySolution(writer, req.body, state, client_ip, user_agent, now);
        return true;
    }
    if (std.mem.eql(u8, req.path, "/__sibuna/health")) {
        const health_json = "{\"status\":\"ok\",\"engine\":\"sibuna\"}";
        try net.response.write200(writer, "application/json", health_json);
        return true;
    }
    return false;
}

fn handleVerifySolution(
    writer: *std.Io.Writer,
    body: []const u8,
    state: *AppState,
    client_ip: []const u8,
    user_agent: []const u8,
    now: u64,
) !void {
    const cid = extractJsonString(body, "challenge_id") orelse {
        try net.response.write400(writer, "Missing challenge_id field");
        return;
    };
    const nonce_str = extractJsonString(body, "nonce") orelse {
        try net.response.write400(writer, "Missing nonce field");
        return;
    };
    const nonce = std.fmt.parseInt(u64, nonce_str, 10) catch {
        try net.response.write400(writer, "Invalid numeric nonce");
        return;
    };

    const res = state.coordinator.verifyAndMint(
        cid,
        nonce,
        client_ip,
        user_agent,
        now,
    ) catch |err| {
        try net.response.write400(writer, core.explainError(err));
        return;
    };

    try net.response.write302(
        writer,
        "/",
        state.config.cookie_name,
        &res.token,
        res.ttl_seconds,
    );
}

fn handleFirewallTraffic(
    client_stream: std.Io.net.Stream,
    io: std.Io,
    writer: *std.Io.Writer,
    req: net.Request,
    state: *AppState,
    client_ip: []const u8,
    user_agent: []const u8,
    raw_req: []const u8,
    now: u64,
) !void {
    // 1. Check existing session cookie
    if (req.getCookie(state.config.cookie_name)) |cookie_val| {
        if (state.coordinator.verifyCookie(cookie_val, client_ip, user_agent, now)) |_| {
            if (state.config.mode == .forward_auth) {
                try net.response.write200(writer, "text/plain", "OK");
            } else {
                try net.streamProxy(
                    client_stream,
                    io,
                    state.config.upstream_host,
                    state.config.upstream_port,
                    raw_req,
                );
            }
            return;
        } else |_| {}
    }

    // 2. Evaluate bot and IP reputation policies
    const decision = state.policy_engine.evaluate(req.path, client_ip, user_agent);
    switch (decision.action) {
        .allow => {
            if (state.config.mode == .forward_auth) {
                try net.response.write200(writer, "text/plain", "OK");
            } else {
                try net.streamProxy(
                    client_stream,
                    io,
                    state.config.upstream_host,
                    state.config.upstream_port,
                    raw_req,
                );
            }
        },
        .deny => {
            try net.response.write403(
                writer,
                "Forbidden: Connection blocked by Sibuna AI Firewall policy.",
            );
        },
        .challenge, .weigh => {
            if (state.config.mode == .forward_auth) {
                try net.response.write401(
                    writer,
                    "Unauthorized: Proof-of-Work Challenge Required",
                );
            } else {
                try net.response.write200(writer, "text/html; charset=utf-8", challenge_html);
            }
        },
    }
}

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
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
    while (end_idx < rest.len and
        rest[end_idx] != '"' and
        rest[end_idx] != ',' and
        rest[end_idx] != '}' and
        rest[end_idx] != ' ' and
        rest[end_idx] != '\r' and
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
}

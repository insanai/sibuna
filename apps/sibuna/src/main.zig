//! Sibuna Daemon Entry Point
//!
//! Parses configuration, resolves the master secret, loads policy, wires the
//! optional persistent storage layer, and starts the accept loops.

const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const policy = @import("policy");
const server = @import("server.zig");
const storage = @import("storage.zig");

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var args_buf: [96][]const u8 = undefined;
    var arg_count: usize = 0;
    var arg_it = std.process.Args.Iterator.init(init.minimal.args);
    defer arg_it.deinit();
    _ = arg_it.next();
    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return 0;
        }
        if (arg_count < args_buf.len) {
            args_buf[arg_count] = arg;
            arg_count += 1;
        }
    }
    var cfg = core.Config.parseArgs(args_buf[0..arg_count]);
    const seed = resolveSecret(io, init.environ_map, &cfg) orelse return 1;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const engine = try gpa.create(policy.Engine);
    engine.initInPlace(cfg.default_difficulty);
    engine.waf_enabled = cfg.waf;
    const policy_text = if (cfg.policy_file) |pfile| loadCustomPolicy(
        io,
        arena.allocator(),
        pfile,
        engine,
    ) else null;
    const slot = try gpa.create(server.EngineSlot);
    slot.* = .{ .engine = engine };

    const state = try gpa.create(server.AppState);
    state.init(cfg, slot, &seed);

    var persistent: ?*storage.Persistent = null;
    if (cfg.data_dir != null) {
        persistent = storage.Persistent.start(gpa, io, cfg, state, policy_text) catch |err| {
            std.debug.print("Failed to start persistent storage: {t}\n", .{err});
            return 1;
        };
    }
    defer if (persistent) |p| p.stop();

    printBanner(cfg, persistent != null);

    const addr = std.Io.net.IpAddress.parse(cfg.listen_host, cfg.listen_port) catch |err| {
        std.debug.print(
            "Failed to parse listen address {s}:{d}: {t}\n",
            .{ cfg.listen_host, cfg.listen_port, err },
        );
        return 1;
    };
    var listener = addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("Failed to bind socket on port {d}: {t}\n", .{ cfg.listen_port, err });
        return 1;
    };
    defer listener.deinit(io);

    server.runServer(&listener, io, state);
    return 0;
}

/// Secret precedence: `--secret-file`, then `SIBUNA_SECRET`, then a random
/// per-process seed (tokens then die with the process, which is fine for a
/// single node but wrong for a cluster, so the banner warns).
fn resolveSecret(io: std.Io, environ: *std.process.Environ.Map, cfg: *core.Config) ?[32]u8 {
    if (cfg.secret_file) |path| {
        const file = std.Io.Dir.openFile(.cwd(), io, path, .{}) catch |err| {
            std.debug.print("Cannot open secret file {s}: {t}\n", .{ path, err });
            return null;
        };
        defer file.close(io);
        var buf: [256]u8 = undefined;
        var reader = file.reader(io, &buf);
        const content = reader.interface.peekGreedy(1) catch "";
        const seed = crypto.parseSeed(content) orelse {
            std.debug.print(
                "Secret file {s} must hold 64 hex characters or 32 raw bytes\n",
                .{path},
            );
            return null;
        };
        cfg.secret_seed = seed;
        return seed;
    }
    if (environ.get("SIBUNA_SECRET")) |text| {
        const seed = crypto.parseSeed(text) orelse {
            std.debug.print("SIBUNA_SECRET must hold 64 hex characters\n", .{});
            return null;
        };
        cfg.secret_seed = seed;
        cfg.secret_file = "env";
        return seed;
    }
    var seed: [32]u8 = undefined;
    io.random(&seed);
    cfg.secret_seed = seed;
    return seed;
}

fn printBanner(cfg: core.Config, persistent: bool) void {
    std.debug.print(
        \\--------------------------------------------------------------------------------
        \\  SIBUNA Web AI Firewall & Anti-Crawler Daemon v{s}
        \\  "Weighing incoming connections with silicon speed"
        \\--------------------------------------------------------------------------------
        \\Mode:        {s}
        \\Listening:   {s}:{d}
        \\Upstream:    {s}:{d}
        \\Proof:       {s} at {d} work bits ({s} tokens)
        \\Surface:     {s}
        \\Storage:     {s}
        \\Secret:      {s}
        \\--------------------------------------------------------------------------------
        \\
    , .{
        server.version,
        cfg.mode.name(),
        cfg.listen_host,
        cfg.listen_port,
        cfg.upstream_host,
        cfg.upstream_port,
        cfg.algorithm.name(),
        cfg.default_difficulty,
        @tagName(cfg.token_scheme),
        if (cfg.waf) "shield (challenge + semantic WAF + limits)" else "gate (challenge only)",
        if (persistent) "zaxonlite (policies, reputation, forensics)" else "in-memory only",
        if (cfg.secret_file != null) "loaded from file" else "random (set --secret-file)",
    });
}

/// Loads the JSON policy into `engine` and returns the file text (owned by
/// `allocator`) so the storage layer can replay it on every rebuild.
fn loadCustomPolicy(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    engine: *policy.Engine,
) ?[]const u8 {
    const file = std.Io.Dir.openFile(.cwd(), io, path, .{}) catch |err| {
        std.debug.print("Warning: unable to open policy file {s}: {t}\n", .{ path, err });
        return null;
    };
    defer file.close(io);
    var buf: [256 * 1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const content = reader.interface.peekGreedy(1) catch |err| {
        std.debug.print("Warning: failed to read policy file {s}: {t}\n", .{ path, err });
        return null;
    };
    const owned = allocator.dupe(u8, content) catch return null;
    engine.loadFromJsonInto(allocator, owned) catch |err| {
        std.debug.print("Warning: failed to parse policy file {s}: {t}\n", .{ path, err });
    };
    return owned;
}

fn printHelp() void {
    std.debug.print(
        \\Usage: sibuna [options]
        \\
        \\Network:
        \\  --port, -p <port>            Listening port (default: 8080)
        \\  --host, -h <host>            Listening host (default: 0.0.0.0)
        \\  --upstream-host <host>       Upstream origin host (default: 127.0.0.1)
        \\  --upstream-port, -u <port>   Upstream origin port (default: 3000)
        \\  --mode, -m <mode>            reverse_proxy | forward_auth (default: reverse_proxy)
        \\  --workers, -w <n>            Accept threads (default: one per CPU)
        \\  --trust-forwarded            Honour X-Forwarded-For / X-Real-IP from the peer
        \\  --idle-timeout <s>           Socket idle timeout in seconds (default: 15)
        \\
        \\Proof of work and sessions:
        \\  --algorithm, -a <alg>        posw | hashcash (default: posw)
        \\  --difficulty, -d <bits>      Work bits (default: 16)
        \\  --posw-challenges <t>        PoSW openings per proof (default: 16)
        \\  --token-scheme <s>           mac | ed25519 (default: mac)
        \\  --token-ttl <s>              Session lifetime in seconds (default: 86400)
        \\  --challenge-ttl <s>          Challenge lifetime in seconds (default: 300)
        \\  --secret-file, -s <path>     Master seed (64 hex chars); random if omitted
        \\  --cookie-name <name>         Session cookie name (default: __sibuna_token)
        \\  --secure-cookie              Emit the Secure cookie attribute
        \\
        \\Surface:
        \\  --gate | --no-waf            Bot challenge only (Anubis-style)
        \\  --shield | --waf             Bot challenge + semantic WAF (default)
        \\  --rate-limit <n>             Requests per window per client (default: 100)
        \\  --rate-window <s>            Rate window seconds (default: 10)
        \\  --ban-seconds <s>            Honeypot ban duration (default: 3600)
        \\  --policy-file, -P <path>     Declarative JSON policy file
        \\
        \\Storage and cluster (Zaxonlite):
        \\  --data-dir, -D <path>        Enable persistent policies, reputation, forensics
        \\  --cluster-node <id>          This node's id (enables replication)
        \\  --cluster-listen <host:port> This node's cluster endpoint
        \\  --cluster-peer <id@host:port> Peer member (repeatable)
        \\  --cluster-secret-file <path> Shared cluster PSK for loopback development
        \\
        \\  --verbose, -v                Verbose logging
        \\  --help                       Show this help message
        \\
    , .{});
}

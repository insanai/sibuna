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
const build_options = @import("build_options");
const console_start = if (build_options.console) @import("console_start.zig") else struct {};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    // One process-lifetime arena owns the command line and the policy text.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const argv = try readArgs(arena.allocator(), init.minimal.args) orelse return 0;
    const subcommand = argv.len != 0 and std.mem.eql(u8, argv[0], "console");
    if (subcommand) {
        if (!build_options.console) return consoleNotCompiled();
        if (argv.len < 2 or !std.mem.eql(u8, argv[1], "init-admin"))
            return @import("console_command.zig").execute(gpa, io, argv[1..]);
    }
    const daemon_args = if (subcommand) argv[1..] else argv;
    const data_args = try arena.allocator().alloc([]const u8, daemon_args.len);
    const parsed = if (build_options.console)
        console_start.parse(daemon_args, data_args) catch |err| return invalidConsole(err)
    else {};
    var cfg = dataPlaneConfig(if (build_options.console) parsed.data_args else daemon_args) orelse
        return 1;
    if (build_options.console) if (parsed.query_steps) |steps| {
        cfg.console_query_steps = steps;
    };
    if (build_options.console) console_start.applyCapture(&cfg, parsed);
    if (build_options.console and !console_start.validate(parsed.config, cfg.data_dir != null))
        return 1;
    if (build_options.console) if (parsed.initial_admin) |username| {
        return @import("console_init.zig").execute(gpa, io, cfg, username.slice());
    };
    const seed = resolveSecret(io, init.environ_map, &cfg) orelse return 1;
    const signals = @import("shutdown.zig").Signals.init();
    defer signals.deinit();

    const engine = try gpa.create(policy.Engine);
    defer gpa.destroy(engine);
    engine.initInPlace(cfg.default_difficulty);
    policy.page_template.defaults(&engine.pages, @import("challenge_page.zig").default);
    engine.waf_enabled = cfg.waf;
    const policy_text = if (cfg.policy_file) |pfile| loadCustomPolicy(
        io,
        arena.allocator(),
        pfile,
        engine,
    ) catch return 1 else null;
    const slot = try gpa.create(server.EngineSlot);
    defer gpa.destroy(slot);
    slot.* = .{ .engine = engine };

    const state = try gpa.create(server.AppState);
    defer gpa.destroy(state);
    state.init(cfg, slot, &seed);

    var persistent: ?*storage.Persistent = null;
    if (cfg.data_dir != null) {
        persistent = storage.Persistent.start(gpa, io, cfg, state, policy_text) catch |err| {
            std.debug.print("Failed to start persistent storage: {t}\n", .{err});
            return 1;
        };
    }
    defer if (persistent) |p| if (!p.shutdown()) abandonedStorageExit();

    const runtime = if (build_options.console and parsed.config.enabled)
        try console_start.Runtime.start(gpa, io, parsed.config, persistent.?)
    else
        null;
    defer if (build_options.console) {
        if (runtime) |running| running.stop();
    };

    printBanner(cfg, persistent != null);

    return runListener(io, cfg, state);
}

/// Threads left blocked inside the consensus library cannot be joined; the process
/// exits without the remaining teardown. Acknowledged writes are already durable.
fn abandonedStorageExit() noreturn {
    std.log.warn("storage: exiting with an abandoned cluster member", .{});
    std.process.exit(0);
}

fn consoleNotCompiled() u8 {
    std.debug.print("CONSOLEBUILD: console support is not compiled. " ++
        "Hint: build with storage and console enabled.\n", .{});
    return 1;
}

fn dataPlaneConfig(args: []const []const u8) ?core.Config {
    var diagnostic: core.Config.Diagnostic = .{};
    return core.Config.parseArgsDiagnosed(args, &diagnostic) catch |err| {
        _ = invalidArguments(err, diagnostic);
        return null;
    };
}

/// A command line the daemon does not fully understand never starts: a flag that is
/// ignored or a value that silently keeps its default is a deployment mistake nobody sees.
fn invalidArguments(err: core.Config.ParseError, diagnostic: core.Config.Diagnostic) u8 {
    var text: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    writer.print("The daemon cannot start with this command line.\n\nOption:   {s}\n", .{
        diagnostic.option,
    }) catch {};
    if (diagnostic.value.len != 0) writer.print("Value:    {s}\n", .{diagnostic.value}) catch {};
    if (diagnostic.expected.len != 0)
        writer.print("Expected: {s}\n", .{diagnostic.expected}) catch {};
    writer.print("Error:    {t}\n", .{err}) catch {};
    const hint = switch (err) {
        error.UnknownOption => "Check the spelling against sibuna --help; every option " ++
            "must be recognised, and flags take no value.",
        error.MissingValue, error.MissingMode => "Supply a value after the option.",
        error.DuplicateMode => "Give --mode once.",
        error.TooManyPeers => "A cluster lists at most eight peers.",
        else => "Correct the value; see sibuna --help for each option's range.",
    };
    var block: [2048]u8 = undefined;
    var out = std.Io.Writer.fixed(&block);
    core.diagnostic.write(&out, "INVALID COMMAND LINE", writer.buffered(), hint) catch {};
    std.debug.print("{s}\n", .{out.buffered()});
    return 1;
}

/// Storage is sized to the command line itself: no argument can fall off the end of a fixed
/// buffer, because an option that silently disappears (a trailing `--secure-cookie`, a
/// misspelled flag) is exactly the deployment mistake strict parsing exists to stop.
fn readArgs(arena: std.mem.Allocator, args: std.process.Args) !?[]const []const u8 {
    const raw = try args.toSlice(arena);
    const given = raw[@min(raw.len, 1)..];
    const output = try arena.alloc([]const u8, given.len);
    for (given, output) |arg, *slot| {
        if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return null;
        }
        if (std.mem.eql(u8, arg, "--version")) {
            std.debug.print("sibuna {s}\n", .{server.version});
            return null;
        }
        slot.* = arg;
    }
    return output;
}

fn runListener(io: std.Io, cfg: core.Config, state: *server.AppState) u8 {
    if (@import("shutdown.zig").wasRequested()) return 0;
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

    @import("shutdown.zig").run(&listener, io, state) catch |err| {
        std.debug.print("Failed to start shutdown monitor: {t}\n", .{err});
        return 1;
    };
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
/// `allocator`) so the storage layer can replay it on every rebuild. A named file that
/// cannot be read or compiled stops startup: serving with a partial policy would admit
/// traffic the operator meant to stop.
fn loadCustomPolicy(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    engine: *policy.Engine,
) ![]const u8 {
    const file = std.Io.Dir.openFile(.cwd(), io, path, .{}) catch |err| {
        std.debug.print("POLICYFILE: unable to open policy file {s}: {t}. " ++
            "Hint: check the path and permissions, or omit --policy-file.\n", .{ path, err });
        return err;
    };
    defer file.close(io);
    var buf: [256 * 1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const content = reader.interface.peekGreedy(1) catch |err| {
        std.debug.print("POLICYFILE: failed to read policy file {s}: {t}.\n", .{ path, err });
        return err;
    };
    const owned = try allocator.dupe(u8, content);
    var diagnostic: policy.loader.Diagnostic = .{};
    policy.loader.parseDiagnosed(allocator, owned, engine, &diagnostic) catch |err| {
        explainPolicyError(err, path, diagnostic);
        return err;
    };
    return owned;
}

fn explainPolicyError(err: anyerror, path: []const u8, diagnostic: policy.loader.Diagnostic) void {
    const explanation = policy.loader.explain(err);
    var text: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    writer.print("{s}\n\nFile:   {s}\nError:  {t}\n", .{
        explanation.message,
        path,
        err,
    }) catch {};
    if (diagnostic.rule.len != 0) writer.print("Rule:   {s}\n", .{diagnostic.rule}) catch {};
    if (diagnostic.field.len != 0) writer.print("Field:  {s}\n", .{diagnostic.field}) catch {};
    if (diagnostic.value.len != 0) writer.print("Value:  {s}\n", .{diagnostic.value}) catch {};
    var block: [2048]u8 = undefined;
    var out = std.Io.Writer.fixed(&block);
    core.diagnostic.write(&out, explanation.title, writer.buffered(), explanation.hint) catch {};
    std.debug.print("{s}\n", .{out.buffered()});
}

fn printConsoleHelp() void {
    if (build_options.console) std.debug.print(
        "Local bootstrap: sibuna init-admin <username> --data-dir <path>\n" ++
            "Console: --console <host:port> (requires --data-dir); " ++
            "--console-query-steps <n> (SQLite steps per Security aggregate, " ++
            "100000-50000000, default 4000000; cluster RPC uses 10000000); " ++
            "--console-capture-heads (store redacted request and origin response heads " ++
            "per incident; off by default); --console-capture-header <name> (repeatable, " ++
            "up to 16: keep this header's value in stored heads; credential names stay " ++
            "redacted); " ++
            "--console-key-file <path> (64 hex characters, owner-only permissions); " ++
            "--console-origin <https-origin>; --console-behind-proxy; " ++
            "--console-trusted-proxy <CIDR> (repeatable); " ++
            "--console-advertise <origin> (link peers show for this console); " ++
            "--console-location <latitude,longitude> (declared server position on globe); " ++
            "--console-peer <node-id>=<https://origin> (repeatable management peer); " ++
            "--console-peer-key-file <path> (independent owner-only 64-hex key); " ++
            "--console-peer-ca-file <path> (optional PEM management trust anchors); " ++
            "--console-probe <node-id>=<http://ip:port> (repeatable peer data-plane " ++
            "listeners to health-probe).\n" ++
            "Account CLI: sibuna console users [--after <id>]\n" ++
            "  sibuna console add-user <name> [--role viewer|operator|admin]\n" ++
            "  sibuna console set-user <id> --revision <n> " ++
            "--role <role> --disabled true|false\n" ++
            "  sibuna console reset-password|revoke-sessions <id> --revision <n>\n" ++
            "GeoIP CLI: sibuna console geoip status\n" ++
            "  sibuna console geoip update --version <YYYY-MM-DD|YYYY-MM> " ++
            "[--provider user-country|dbip] [--month <YYYY-MM>, DB-IP alias]\n" ++
            "    [--checksum <sha256>] [--timeout <seconds, default 1200>]\n" ++
            "Policy CLI: sibuna console policies export (JSON array to stdout)\n" ++
            "  sibuna console policies import --file <exported.json> " ++
            "(replaces every managed rule atomically)\n" ++
            "Token CLI: sibuna console tokens [--after <id>]\n" ++
            "  sibuna console mint-token <label> --scope <scope> (repeatable) " ++
            "[--role <role>] [--expires <unix-seconds>]\n" ++
            "  sibuna console revoke-token|remove-token <id> --revision <n>\n" ++
            "  Scopes: stats_read, events_read, policy_read, policy_write, " ++
            "geoip_read, geoip_write, users_read, users_write.\n" ++
            "  Required: --origin <origin>; --username <name> --password-file <path>;\n" ++
            "  or --token-file <path> for account/GeoIP operations only.\n" ++
            "  optional --factor-file <path>. Credential files must be private regular files.\n" ++
            "  HTTPS is required except for literal loopback HTTP; redirects are refused.\n",
        .{},
    );
}

fn printHelp() void {
    printConsoleHelp();
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
        \\  --max-connections <n>        Concurrent connections served (default: 1024)
        \\  --trust-forwarded            Honour X-Forwarded-For / X-Real-IP from the peer
        \\  --idle-timeout <s>           HTTP socket idle timeout in seconds (default: 15)
        \\  --websocket-idle-timeout <s> WebSocket idle timeout in seconds (default: 300)
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
        \\  --challenge-rate-limit <n>   Challenge issues and verifies per window (default: 30)
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
        \\  --version                    Print the version and exit
        \\
        \\Unknown options and out-of-range values stop startup with a diagnostic.
        \\
    , .{});
}

fn invalidConsole(err: anyerror) u8 {
    std.debug.print("CONSOLE002: invalid console options ({t}). " ++
        "Hint: check --console host:port, proxy settings, and query steps " ++
        "(100000-50000000, supplied once).\n", .{err});
    return 1;
}

//! Sibuna Core Configuration
//!
//! Daemon options, defaults, and command-line parsing for the reverse
//! proxy and forward-auth modes. Parsing never allocates: string options
//! borrow the argument slices for the life of the process.

const std = @import("std");

pub const Mode = enum {
    reverse_proxy,
    forward_auth,

    pub fn parse(text: []const u8) ?Mode {
        if (std.mem.eql(u8, text, "proxy") or std.mem.eql(u8, text, "reverse_proxy")) {
            return .reverse_proxy;
        }
        if (std.mem.eql(u8, text, "forward_auth") or std.mem.eql(u8, text, "auth")) {
            return .forward_auth;
        }
        return null;
    }

    pub fn name(self: Mode) []const u8 {
        return switch (self) {
            .reverse_proxy => "reverse_proxy",
            .forward_auth => "forward_auth",
        };
    }
};

pub const PowAlgorithm = enum {
    hashcash,
    posw,

    pub fn parse(text: []const u8) ?PowAlgorithm {
        if (std.ascii.eqlIgnoreCase(text, "hashcash") or std.ascii.eqlIgnoreCase(text, "sha256")) {
            return .hashcash;
        }
        if (std.ascii.eqlIgnoreCase(text, "posw")) return .posw;
        return null;
    }

    pub fn name(self: PowAlgorithm) []const u8 {
        return switch (self) {
            .hashcash => "hashcash",
            .posw => "posw",
        };
    }
};

pub const TokenScheme = enum {
    mac,
    ed25519,

    pub fn parse(text: []const u8) ?TokenScheme {
        if (std.ascii.eqlIgnoreCase(text, "mac")) return .mac;
        if (std.ascii.eqlIgnoreCase(text, "ed25519")) return .ed25519;
        return null;
    }
};

pub const max_cluster_peers = 8;

pub const Config = struct {
    listen_host: []const u8 = "0.0.0.0",
    listen_port: u16 = 8080,
    upstream_host: []const u8 = "127.0.0.1",
    upstream_port: u16 = 3000,
    mode: Mode = .reverse_proxy,
    /// Work bits: hashcash leading zero bits, or PoSW depth plus three.
    default_difficulty: u32 = 16,
    algorithm: PowAlgorithm = .posw,
    posw_challenges: u8 = 16,
    token_scheme: TokenScheme = .mac,
    token_ttl_seconds: u64 = 86400,
    challenge_ttl_seconds: u64 = 300,
    cookie_name: []const u8 = "__sibuna_token",
    secure_cookie: bool = false,
    /// Master seed; null means "derive from `secret_file`, the environment,
    /// or a fresh random value at startup".
    secret_seed: ?[32]u8 = null,
    secret_file: ?[]const u8 = null,
    policy_file: ?[]const u8 = null,
    /// Trust `X-Forwarded-For` / `X-Real-IP` from the peer. Defaults to on
    /// in forward-auth mode, where the ingress is the only peer.
    trust_forwarded: ?bool = null,
    /// Accept threads; zero means one per CPU. Each accepted connection is
    /// then served on its own thread up to `max_connections`.
    workers: u16 = 0,
    /// Connections served concurrently; further ones are answered 503.
    max_connections: u32 = 1024,
    /// Longest silence a connection may hold a worker: a request head must arrive within
    /// it, and during an exchange it bounds the gap between successive relayed chunks on
    /// either socket, so a silent origin is cut while a slow active response is not.
    idle_timeout_seconds: u32 = 15,
    /// An admitted WebSocket has its own idle deadline, refreshed by traffic either way.
    websocket_idle_timeout_seconds: u32 = 300,
    rate_limit: u32 = 100,
    rate_window_seconds: u64 = 10,
    /// Challenge issuances and solution verifications a client may spend per rate window.
    /// These routes bypass policy, so they carry their own budget: issuing is cheap but
    /// verifying a proof is not, and neither may be free to a client the limiter has
    /// already refused elsewhere.
    challenge_rate_limit: u32 = 30,
    ban_seconds: u64 = 3600,
    waf: bool = true,
    /// SQLite virtual-machine steps one console period aggregate may spend before it fails
    /// as unavailable; paged reads keep a fixed light budget. Bounded on both sides.
    console_query_steps: u64 = 4_000_000,
    /// Store redacted request heads (and, for audited admitted requests, the origin
    /// response head) beside each incident. Off by default; console builds only.
    console_capture_heads: bool = false,
    /// Header names whose values the stored heads keep beside the built-in list.
    console_capture_headers: @import("incident_heads.zig").Extra = .{},
    /// Zaxonlite data directory; null runs without persistent storage.
    data_dir: ?[]const u8 = null,
    cluster_node: u32 = 0,
    cluster_listen: ?[]const u8 = null,
    cluster_peers: [max_cluster_peers][]const u8 = undefined,
    cluster_peer_count: u8 = 0,
    cluster_secret_file: ?[]const u8 = null,
    cluster_tls_cert: ?[]const u8 = null,
    cluster_tls_key: ?[]const u8 = null,
    cluster_tls_ca: ?[]const u8 = null,
    /// Storage worker cadence: incident drain and policy change polling.
    storage_poll_ms: u64 = 500,
    verbose: bool = false,

    pub fn default() Config {
        return .{};
    }

    pub fn trustsForwarded(self: Config) bool {
        return self.trust_forwarded orelse (self.mode == .forward_auth);
    }

    pub const ParseError = error{
        InvalidMode,
        MissingMode,
        DuplicateMode,
        UnknownOption,
        MissingValue,
        InvalidValue,
        TooManyPeers,
    };

    /// Where a rejected command line went wrong, for the operator's diagnostic.
    pub const Diagnostic = struct {
        option: []const u8 = "",
        value: []const u8 = "",
        expected: []const u8 = "",
    };

    pub fn parseArgs(args: []const []const u8) ParseError!Config {
        var diagnostic: Diagnostic = .{};
        return parseArgsDiagnosed(args, &diagnostic);
    }

    /// Every option is either recognised and valid or the whole command line is rejected:
    /// a misspelled flag or an out-of-range value never silently keeps the default.
    pub fn parseArgsDiagnosed(
        args: []const []const u8,
        diagnostic: *Diagnostic,
    ) ParseError!Config {
        var cfg = Config.default();
        var mode_seen = false;
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            diagnostic.* = .{ .option = arg };
            if (std.mem.startsWith(u8, arg, "--mode=")) return error.InvalidMode;
            if (eqlAny(arg, "--mode", "-m")) {
                if (mode_seen) return error.DuplicateMode;
                i += 1;
                if (i == args.len) return error.MissingMode;
                diagnostic.value = args[i];
                diagnostic.expected = "reverse_proxy or forward_auth";
                cfg.mode = Mode.parse(args[i]) orelse return error.InvalidMode;
                mode_seen = true;
                continue;
            }
            if (applyFlag(&cfg, arg)) continue;
            if (!takesValue(arg)) return error.UnknownOption;
            i += 1;
            if (i == args.len) return error.MissingValue;
            diagnostic.value = args[i];
            try applyOption(&cfg, arg, args[i], diagnostic);
        }
        return cfg;
    }

    fn applyFlag(cfg: *Config, arg: []const u8) bool {
        if (eqlAny(arg, "--verbose", "-v")) {
            cfg.verbose = true;
        } else if (eqlAny(arg, "--trust-forwarded", "--trust-forwarded")) {
            cfg.trust_forwarded = true;
        } else if (eqlAny(arg, "--no-trust-forwarded", "--no-trust-forwarded")) {
            cfg.trust_forwarded = false;
        } else if (eqlAny(arg, "--no-waf", "--gate")) {
            cfg.waf = false;
        } else if (eqlAny(arg, "--waf", "--shield")) {
            cfg.waf = true;
        } else if (eqlAny(arg, "--secure-cookie", "--secure-cookie")) {
            cfg.secure_cookie = true;
        } else {
            return false;
        }
        return true;
    }

    const valued_options = [_][]const u8{
        "--port",
        "-p",
        "--host",
        "-h",
        "--upstream-host",
        "--upstream-port",
        "-u",
        "--difficulty",
        "-d",
        "--algorithm",
        "-a",
        "--posw-challenges",
        "--token-scheme",
        "--token-ttl",
        "--challenge-ttl",
        "--cookie-name",
        "--secret-file",
        "-s",
        "--policy-file",
        "-P",
        "--workers",
        "-w",
        "--max-connections",
        "--idle-timeout",
        "--websocket-idle-timeout",
        "--rate-limit",
        "--rate-window",
        "--challenge-rate-limit",
        "--ban-seconds",
        "--data-dir",
        "-D",
        "--cluster-node",
        "--cluster-listen",
        "--cluster-peer",
        "--cluster-secret-file",
        "--cluster-tls-cert",
        "--cluster-tls-key",
        "--cluster-tls-ca",
        "--storage-poll-ms",
    };

    fn takesValue(arg: []const u8) bool {
        for (valued_options) |option| if (std.mem.eql(u8, arg, option)) return true;
        return false;
    }

    /// Connections, idle leases and task slots share one 8192-entry capacity.
    pub const max_connections_limit: u32 = 8192;

    fn applyOption(
        cfg: *Config,
        arg: []const u8,
        v: []const u8,
        d: *Diagnostic,
    ) ParseError!void {
        if (eqlAny(arg, "--port", "-p")) {
            cfg.listen_port = try number(u16, v, 1, 65535, "a port 1-65535", d);
        } else if (eqlAny(arg, "--host", "-h")) {
            cfg.listen_host = try textValue(v, "a host name or address", d);
        } else if (eqlAny(arg, "--upstream-host", "--upstream-host")) {
            cfg.upstream_host = try textValue(v, "a host name or address", d);
        } else if (eqlAny(arg, "--upstream-port", "-u")) {
            cfg.upstream_port = try number(u16, v, 1, 65535, "a port 1-65535", d);
        } else if (eqlAny(arg, "--difficulty", "-d")) {
            cfg.default_difficulty = try number(u32, v, 1, 64, "work bits 1-64", d);
        } else if (eqlAny(arg, "--algorithm", "-a")) {
            d.expected = "posw or hashcash";
            cfg.algorithm = PowAlgorithm.parse(v) orelse return error.InvalidValue;
        } else if (eqlAny(arg, "--posw-challenges", "--posw-challenges")) {
            cfg.posw_challenges = try number(u8, v, 1, 32, "openings 1-32", d);
        } else if (eqlAny(arg, "--token-scheme", "--token-scheme")) {
            d.expected = "mac or ed25519";
            cfg.token_scheme = TokenScheme.parse(v) orelse return error.InvalidValue;
        } else if (eqlAny(arg, "--token-ttl", "--token-ttl")) {
            cfg.token_ttl_seconds = try number(u64, v, 1, 31_536_000, "seconds 1-31536000", d);
        } else if (eqlAny(arg, "--challenge-ttl", "--challenge-ttl")) {
            cfg.challenge_ttl_seconds = try number(u64, v, 1, 86_400, "seconds 1-86400", d);
        } else if (eqlAny(arg, "--cookie-name", "--cookie-name")) {
            cfg.cookie_name = try cookieName(v, d);
        } else if (eqlAny(arg, "--secret-file", "-s")) {
            cfg.secret_file = try textValue(v, "a file path", d);
        } else if (eqlAny(arg, "--policy-file", "-P")) {
            cfg.policy_file = try textValue(v, "a file path", d);
        } else {
            return applyServiceOption(cfg, arg, v, d);
        }
    }

    fn applyServiceOption(
        cfg: *Config,
        arg: []const u8,
        v: []const u8,
        d: *Diagnostic,
    ) ParseError!void {
        if (eqlAny(arg, "--workers", "-w")) {
            cfg.workers = try number(u16, v, 0, 64, "0 for one per CPU, or 1-64", d);
        } else if (eqlAny(arg, "--max-connections", "--max-connections")) {
            cfg.max_connections = try number(u32, v, 1, max_connections_limit, "1-8192", d);
        } else if (eqlAny(arg, "--idle-timeout", "--idle-timeout")) {
            cfg.idle_timeout_seconds = try number(u32, v, 0, 86_400, "seconds 0-86400", d);
        } else if (eqlAny(arg, "--websocket-idle-timeout", "--websocket-idle-timeout")) {
            const seconds = try number(u32, v, 0, 86_400, "seconds 0-86400", d);
            cfg.websocket_idle_timeout_seconds = seconds;
        } else if (eqlAny(arg, "--rate-limit", "--rate-limit")) {
            cfg.rate_limit = try number(u32, v, 1, std.math.maxInt(u32), "requests 1 or more", d);
        } else if (eqlAny(arg, "--rate-window", "--rate-window")) {
            cfg.rate_window_seconds = try number(u64, v, 1, 86_400, "seconds 1-86400", d);
        } else if (eqlAny(arg, "--challenge-rate-limit", "--challenge-rate-limit")) {
            const limit = try number(u32, v, 1, std.math.maxInt(u32), "requests 1 or more", d);
            cfg.challenge_rate_limit = limit;
        } else if (eqlAny(arg, "--ban-seconds", "--ban-seconds")) {
            cfg.ban_seconds = try number(u64, v, 0, 31_536_000, "seconds 0-31536000", d);
        } else {
            return applyStorageOption(cfg, arg, v, d);
        }
    }

    fn applyStorageOption(
        cfg: *Config,
        arg: []const u8,
        v: []const u8,
        d: *Diagnostic,
    ) ParseError!void {
        if (eqlAny(arg, "--data-dir", "-D")) {
            cfg.data_dir = try textValue(v, "a directory path", d);
        } else if (eqlAny(arg, "--cluster-node", "--cluster-node")) {
            cfg.cluster_node = try number(u32, v, 0, std.math.maxInt(u32), "a node id", d);
        } else if (eqlAny(arg, "--cluster-listen", "--cluster-listen")) {
            cfg.cluster_listen = try textValue(v, "host:port", d);
        } else if (eqlAny(arg, "--cluster-peer", "--cluster-peer")) {
            d.expected = "at most 8 peers of the form id@host:port";
            if (cfg.cluster_peer_count == max_cluster_peers) return error.TooManyPeers;
            cfg.cluster_peers[cfg.cluster_peer_count] = try textValue(v, "id@host:port", d);
            cfg.cluster_peer_count += 1;
        } else if (eqlAny(arg, "--cluster-secret-file", "--cluster-secret-file")) {
            cfg.cluster_secret_file = try textValue(v, "a file path", d);
        } else if (eqlAny(arg, "--cluster-tls-cert", "--cluster-tls-cert")) {
            cfg.cluster_tls_cert = try textValue(v, "a file path", d);
        } else if (eqlAny(arg, "--cluster-tls-key", "--cluster-tls-key")) {
            cfg.cluster_tls_key = try textValue(v, "a file path", d);
        } else if (eqlAny(arg, "--cluster-tls-ca", "--cluster-tls-ca")) {
            cfg.cluster_tls_ca = try textValue(v, "a file path", d);
        } else if (eqlAny(arg, "--storage-poll-ms", "--storage-poll-ms")) {
            cfg.storage_poll_ms = try number(u64, v, 1, 60_000, "milliseconds 1-60000", d);
        } else {
            return error.UnknownOption;
        }
    }
};

fn number(
    comptime T: type,
    v: []const u8,
    min: T,
    max: T,
    expected: []const u8,
    d: *Config.Diagnostic,
) Config.ParseError!T {
    d.expected = expected;
    const value = std.fmt.parseInt(T, v, 10) catch return error.InvalidValue;
    if (value < min or value > max) return error.InvalidValue;
    return value;
}

fn textValue(
    v: []const u8,
    expected: []const u8,
    d: *Config.Diagnostic,
) Config.ParseError![]const u8 {
    d.expected = expected;
    if (v.len == 0 or v.len > 4096) return error.InvalidValue;
    for (v) |byte| if (byte < 32 or byte == 127) return error.InvalidValue;
    return v;
}

/// RFC 6265 cookie names: at most 64 token characters.
fn cookieName(v: []const u8, d: *Config.Diagnostic) Config.ParseError![]const u8 {
    d.expected = "a cookie name of 1-64 token characters";
    if (v.len == 0 or v.len > 64) return error.InvalidValue;
    for (v) |byte| {
        const punctuation = std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null;
        if (!std.ascii.isAlphanumeric(byte) and !punctuation) return error.InvalidValue;
    }
    return v;
}

fn eqlAny(arg: []const u8, long: []const u8, short: []const u8) bool {
    return std.mem.eql(u8, arg, long) or std.mem.eql(u8, arg, short);
}

test "config defaults and arg parsing" {
    const cfg = Config.default();
    try std.testing.expectEqual(@as(u16, 8080), cfg.listen_port);
    try std.testing.expectEqual(@as(u32, 16), cfg.default_difficulty);
    try std.testing.expectEqual(PowAlgorithm.posw, cfg.algorithm);
    try std.testing.expect(!cfg.trustsForwarded());

    const args = [_][]const u8{
        "--port",                 "9090",
        "--upstream-port",        "8000",
        "--difficulty",           "18",
        "--mode",                 "forward_auth",
        "--policy-file",          "/etc/sibuna/policy.json",
        "--algorithm",            "hashcash",
        "--token-scheme",         "ed25519",
        "--workers",              "3",
        "--rate-limit",           "20",
        "--idle-timeout",         "7",
        "--max-connections",      "500",
        "--rate-window",          "5",
        "--challenge-rate-limit", "6",
        "--no-waf",               "--secret-file",
        "/run/secret",            "--data-dir",
        "/var/lib/sibuna",        "--cluster-node",
        "2",                      "--cluster-peer",
        "1@10.0.0.1:9901",        "--cluster-peer",
        "3@10.0.0.3:9901",        "--verbose",
    };
    const parsed = try Config.parseArgs(&args);
    try std.testing.expectEqual(@as(u16, 9090), parsed.listen_port);
    try std.testing.expectEqual(@as(u16, 8000), parsed.upstream_port);
    try std.testing.expectEqual(@as(u32, 18), parsed.default_difficulty);
    try std.testing.expectEqual(Mode.forward_auth, parsed.mode);
    try std.testing.expect(parsed.trustsForwarded());
    try std.testing.expectEqualStrings("/etc/sibuna/policy.json", parsed.policy_file.?);
    try std.testing.expectEqual(PowAlgorithm.hashcash, parsed.algorithm);
    try std.testing.expectEqual(TokenScheme.ed25519, parsed.token_scheme);
    try std.testing.expectEqual(@as(u16, 3), parsed.workers);
    try std.testing.expectEqual(@as(u32, 20), parsed.rate_limit);
    try std.testing.expectEqual(@as(u32, 7), parsed.idle_timeout_seconds);
    try std.testing.expectEqual(@as(u32, 500), parsed.max_connections);
    try std.testing.expectEqual(@as(u64, 5), parsed.rate_window_seconds);
    try std.testing.expectEqual(@as(u32, 6), parsed.challenge_rate_limit);
    try std.testing.expect(!parsed.waf);
    try std.testing.expectEqualStrings("/run/secret", parsed.secret_file.?);
    try std.testing.expectEqualStrings("/var/lib/sibuna", parsed.data_dir.?);
    try std.testing.expectEqual(@as(u32, 2), parsed.cluster_node);
    try std.testing.expectEqual(@as(u8, 2), parsed.cluster_peer_count);
    try std.testing.expectEqualStrings("3@10.0.0.3:9901", parsed.cluster_peers[1]);
    try std.testing.expect(parsed.verbose);
}

test "unknown options and invalid values reject the command line and name the fault" {
    const t = std.testing;
    // `at` indexes the argument the diagnostic must name.
    const cases = [_]struct { args: []const []const u8, err: anyerror, at: usize = 0 }{
        .{ .args = &.{"--prot"}, .err = error.UnknownOption },
        .{ .args = &.{"--port"}, .err = error.MissingValue },
        .{ .args = &.{ "--port", "70000" }, .err = error.InvalidValue },
        .{ .args = &.{ "--port", "eighty" }, .err = error.InvalidValue },
        .{ .args = &.{ "-d", "0" }, .err = error.InvalidValue },
        .{ .args = &.{ "--algorithm", "md5" }, .err = error.InvalidValue },
        .{ .args = &.{ "--workers", "65" }, .err = error.InvalidValue },
        .{ .args = &.{ "--rate-limit", "0" }, .err = error.InvalidValue },
        .{ .args = &.{ "--max-connections", "9000" }, .err = error.InvalidValue },
        .{ .args = &.{ "--cookie-name", "a b" }, .err = error.InvalidValue },
        .{ .args = &.{ "--verbose", "yes" }, .err = error.UnknownOption, .at = 1 },
        .{ .args = &.{ "--mode", "proxy", "-m", "auth" }, .err = error.DuplicateMode, .at = 2 },
        .{ .args = &.{"--mode=proxy"}, .err = error.InvalidMode },
    };
    for (cases) |case| {
        var diagnostic: Config.Diagnostic = .{};
        try t.expectError(case.err, Config.parseArgsDiagnosed(case.args, &diagnostic));
        try t.expectEqualStrings(case.args[case.at], diagnostic.option);
    }
    var peers: [9][]const u8 = undefined;
    var many: [18][]const u8 = undefined;
    for (&peers, 0..) |*peer, index| peer.* = if (index == 0) "1@h:1" else "2@h:2";
    for (0..9) |index| {
        many[index * 2] = "--cluster-peer";
        many[index * 2 + 1] = peers[index];
    }
    try t.expectError(error.TooManyPeers, Config.parseArgs(&many));
    const accepted = try Config.parseArgs(&.{ "--rate-limit", "100000000", "--workers", "0" });
    try t.expectEqual(@as(u32, 100_000_000), accepted.rate_limit);
}

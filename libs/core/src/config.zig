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
    /// Accept worker threads; zero means one per CPU.
    workers: u16 = 0,
    rate_limit: u32 = 100,
    rate_window_seconds: u64 = 10,
    ban_seconds: u64 = 3600,
    waf: bool = true,
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

    pub fn parseArgs(args: []const []const u8) Config {
        var cfg = Config.default();
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            const value: ?[]const u8 = if (i + 1 < args.len) args[i + 1] else null;
            if (applyFlag(&cfg, arg)) continue;
            if (value) |v| {
                if (applyOption(&cfg, arg, v)) i += 1;
            }
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

    fn applyOption(cfg: *Config, arg: []const u8, v: []const u8) bool {
        if (eqlAny(arg, "--port", "-p")) {
            cfg.listen_port = std.fmt.parseInt(u16, v, 10) catch cfg.listen_port;
        } else if (eqlAny(arg, "--host", "-h")) {
            cfg.listen_host = v;
        } else if (eqlAny(arg, "--upstream-host", "--upstream-host")) {
            cfg.upstream_host = v;
        } else if (eqlAny(arg, "--upstream-port", "-u")) {
            cfg.upstream_port = std.fmt.parseInt(u16, v, 10) catch cfg.upstream_port;
        } else if (eqlAny(arg, "--mode", "-m")) {
            if (Mode.parse(v)) |m| cfg.mode = m;
        } else if (eqlAny(arg, "--difficulty", "-d")) {
            cfg.default_difficulty = std.fmt.parseInt(u32, v, 10) catch cfg.default_difficulty;
        } else if (eqlAny(arg, "--algorithm", "-a")) {
            if (PowAlgorithm.parse(v)) |a| cfg.algorithm = a;
        } else if (eqlAny(arg, "--posw-challenges", "--posw-challenges")) {
            cfg.posw_challenges = std.fmt.parseInt(u8, v, 10) catch cfg.posw_challenges;
        } else if (eqlAny(arg, "--token-scheme", "--token-scheme")) {
            if (TokenScheme.parse(v)) |t| cfg.token_scheme = t;
        } else if (eqlAny(arg, "--token-ttl", "--token-ttl")) {
            cfg.token_ttl_seconds = std.fmt.parseInt(u64, v, 10) catch cfg.token_ttl_seconds;
        } else if (eqlAny(arg, "--challenge-ttl", "--challenge-ttl")) {
            cfg.challenge_ttl_seconds = std.fmt.parseInt(
                u64,
                v,
                10,
            ) catch cfg.challenge_ttl_seconds;
        } else if (eqlAny(arg, "--cookie-name", "--cookie-name")) {
            cfg.cookie_name = v;
        } else if (eqlAny(arg, "--secret-file", "-s")) {
            cfg.secret_file = v;
        } else if (eqlAny(arg, "--policy-file", "-P")) {
            cfg.policy_file = v;
        } else if (eqlAny(arg, "--workers", "-w")) {
            cfg.workers = std.fmt.parseInt(u16, v, 10) catch cfg.workers;
        } else if (eqlAny(arg, "--rate-limit", "--rate-limit")) {
            cfg.rate_limit = std.fmt.parseInt(u32, v, 10) catch cfg.rate_limit;
        } else if (eqlAny(arg, "--rate-window", "--rate-window")) {
            cfg.rate_window_seconds = std.fmt.parseInt(u64, v, 10) catch cfg.rate_window_seconds;
        } else if (eqlAny(arg, "--ban-seconds", "--ban-seconds")) {
            cfg.ban_seconds = std.fmt.parseInt(u64, v, 10) catch cfg.ban_seconds;
        } else {
            return applyStorageOption(cfg, arg, v);
        }
        return true;
    }

    fn applyStorageOption(cfg: *Config, arg: []const u8, v: []const u8) bool {
        if (eqlAny(arg, "--data-dir", "-D")) {
            cfg.data_dir = v;
        } else if (eqlAny(arg, "--cluster-node", "--cluster-node")) {
            cfg.cluster_node = std.fmt.parseInt(u32, v, 10) catch cfg.cluster_node;
        } else if (eqlAny(arg, "--cluster-listen", "--cluster-listen")) {
            cfg.cluster_listen = v;
        } else if (eqlAny(arg, "--cluster-peer", "--cluster-peer")) {
            if (cfg.cluster_peer_count < max_cluster_peers) {
                cfg.cluster_peers[cfg.cluster_peer_count] = v;
                cfg.cluster_peer_count += 1;
            }
        } else if (eqlAny(arg, "--cluster-secret-file", "--cluster-secret-file")) {
            cfg.cluster_secret_file = v;
        } else if (eqlAny(arg, "--cluster-tls-cert", "--cluster-tls-cert")) {
            cfg.cluster_tls_cert = v;
        } else if (eqlAny(arg, "--cluster-tls-key", "--cluster-tls-key")) {
            cfg.cluster_tls_key = v;
        } else if (eqlAny(arg, "--cluster-tls-ca", "--cluster-tls-ca")) {
            cfg.cluster_tls_ca = v;
        } else if (eqlAny(arg, "--storage-poll-ms", "--storage-poll-ms")) {
            cfg.storage_poll_ms = std.fmt.parseInt(u64, v, 10) catch cfg.storage_poll_ms;
        } else {
            return false;
        }
        return true;
    }
};

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
        "--port",          "9090",
        "--upstream-port", "8000",
        "--difficulty",    "18",
        "--mode",          "forward_auth",
        "--policy-file",   "/etc/sibuna/policy.json",
        "--algorithm",     "hashcash",
        "--token-scheme",  "ed25519",
        "--workers",       "3",
        "--rate-limit",    "20",
        "--rate-window",   "5",
        "--no-waf",        "--secret-file",
        "/run/secret",     "--data-dir",
        "/var/lib/sibuna", "--cluster-node",
        "2",               "--cluster-peer",
        "1@10.0.0.1:9901", "--cluster-peer",
        "3@10.0.0.3:9901", "--verbose",
    };
    const parsed = Config.parseArgs(&args);
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
    try std.testing.expectEqual(@as(u64, 5), parsed.rate_window_seconds);
    try std.testing.expect(!parsed.waf);
    try std.testing.expectEqualStrings("/run/secret", parsed.secret_file.?);
    try std.testing.expectEqualStrings("/var/lib/sibuna", parsed.data_dir.?);
    try std.testing.expectEqual(@as(u32, 2), parsed.cluster_node);
    try std.testing.expectEqual(@as(u8, 2), parsed.cluster_peer_count);
    try std.testing.expectEqualStrings("3@10.0.0.3:9901", parsed.cluster_peers[1]);
    try std.testing.expect(parsed.verbose);
}

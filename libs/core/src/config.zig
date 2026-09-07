//! Sibuna Core Configuration
//!
//! Provides firewall configuration options, default parameter values,
//! and command-line argument parsing for standalone and forward-auth modes.

const std = @import("std");

pub const Mode = enum {
    reverse_proxy,
    forward_auth,

    pub fn parse(text: []const u8) ?Mode {
        if (std.mem.eql(u8, text, "proxy") or
            std.mem.eql(u8, text, "reverse_proxy"))
        {
            return .reverse_proxy;
        }
        if (std.mem.eql(u8, text, "forward_auth") or
            std.mem.eql(u8, text, "auth"))
        {
            return .forward_auth;
        }
        return null;
    }
};

pub const Config = struct {
    listen_host: []const u8 = "0.0.0.0",
    listen_port: u16 = 8080,
    upstream_host: []const u8 = "127.0.0.1",
    upstream_port: u16 = 3000,
    mode: Mode = .reverse_proxy,
    default_difficulty: u32 = 4,
    token_ttl_seconds: u64 = 86400,
    challenge_ttl_seconds: u64 = 600,
    cookie_name: []const u8 = "__sibuna_token",
    secret_seed: [32]u8 = [_]u8{42} ** 32,
    policy_file: ?[]const u8 = null,
    verbose: bool = false,

    pub fn default() Config {
        return .{};
    }

    pub fn parseArgs(args: []const []const u8) Config {
        var cfg = Config.default();
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.listen_port = std.fmt.parseInt(u16, args[i], 10) catch cfg.listen_port;
                }
            } else if (std.mem.eql(u8, arg, "--host") or std.mem.eql(u8, arg, "-h")) {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.listen_host = args[i];
                }
            } else if (std.mem.eql(u8, arg, "--upstream-host")) {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.upstream_host = args[i];
                }
            } else if (std.mem.eql(u8, arg, "--upstream-port") or
                std.mem.eql(u8, arg, "-u"))
            {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.upstream_port = std.fmt.parseInt(u16, args[i], 10) catch cfg.upstream_port;
                }
            } else if (std.mem.eql(u8, arg, "--mode") or std.mem.eql(u8, arg, "-m")) {
                if (i + 1 < args.len) {
                    i += 1;
                    if (Mode.parse(args[i])) |m| cfg.mode = m;
                }
            } else if (std.mem.eql(u8, arg, "--difficulty") or
                std.mem.eql(u8, arg, "-d"))
            {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.default_difficulty = std.fmt.parseInt(u32, args[i], 10) catch
                        cfg.default_difficulty;
                }
            } else if (std.mem.eql(u8, arg, "--policy-file") or
                std.mem.eql(u8, arg, "-P"))
            {
                if (i + 1 < args.len) {
                    i += 1;
                    cfg.policy_file = args[i];
                }
            } else if (std.mem.eql(u8, arg, "--verbose") or
                std.mem.eql(u8, arg, "-v"))
            {
                cfg.verbose = true;
            }
        }
        return cfg;
    }
};

test "config defaults and arg parsing" {
    const cfg = Config.default();
    try std.testing.expectEqual(@as(u16, 8080), cfg.listen_port);
    try std.testing.expectEqual(@as(u32, 4), cfg.default_difficulty);

    const args = [_][]const u8{
        "--port",          "9090",
        "--upstream-port", "8000",
        "--difficulty",    "5",
        "--mode",          "forward_auth",
        "--policy-file",   "/etc/sibuna/policy.json",
        "--verbose",
    };
    const parsed = Config.parseArgs(&args);
    try std.testing.expectEqual(@as(u16, 9090), parsed.listen_port);
    try std.testing.expectEqual(@as(u16, 8000), parsed.upstream_port);
    try std.testing.expectEqual(@as(u32, 5), parsed.default_difficulty);
    try std.testing.expectEqual(Mode.forward_auth, parsed.mode);
    try std.testing.expectEqualStrings("/etc/sibuna/policy.json", parsed.policy_file.?);
    try std.testing.expect(parsed.verbose);
}

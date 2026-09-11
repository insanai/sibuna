//! Daemon composition only: console flags never change core's data-plane parser.
const std = @import("std");
const console = @import("console");
const Persistent = @import("persistent.zig").Persistent;
pub const Parsed = struct {
    config: console.ConsoleConfig,
    query_steps: ?u64 = null,
    capture_heads: bool = false,
    capture_headers: @import("core").incident_heads.Extra = .{},
    data_args: []const []const u8,
    initial_admin: ?console.protocol.Bytes(64) = null,
};

pub fn parse(args: []const []const u8, remaining: [][]const u8) !Parsed {
    var config: console.ConsoleConfig = .{};
    var initial_admin: ?console.protocol.Bytes(64) = null;
    var count: usize = 0;
    var i: usize = 0;
    var options_seen = false;
    var query_steps: ?u64 = null;
    var capture_heads = false;
    var capture_headers: @import("core").incident_heads.Extra = .{};
    while (i < args.len) : (i += 1) {
        const flag = args[i];
        if (i == 0 and std.mem.eql(u8, flag, "init-admin")) {
            i += 1;
            if (i == args.len or !console.protocol.validUsername(args[i]))
                return error.InvalidUsername;
            initial_admin = try console.protocol.Bytes(64).init(args[i]);
            continue;
        }
        if (!std.mem.startsWith(u8, flag, "--console")) {
            if (count == remaining.len) return error.TooManyArguments;
            remaining[count] = flag;
            count += 1;
            continue;
        }
        options_seen = true;
        if (std.mem.eql(u8, flag, "--console-behind-proxy")) {
            config.behind_proxy = true;
            continue;
        }
        if (std.mem.eql(u8, flag, "--console-capture-heads")) {
            capture_heads = true;
            continue;
        }
        if (std.mem.eql(u8, flag, "--console-cookie-secure")) {
            if (config.cookie_secure) return error.DuplicateCookieSecure;
            config.cookie_secure = true;
            continue;
        }
        i += 1;
        if (i == args.len or std.mem.startsWith(u8, args[i], "--")) return error.MissingValue;
        const value = args[i];
        if (std.mem.eql(u8, flag, "--console-query-steps")) {
            if (query_steps != null) return error.DuplicateQuerySteps;
            query_steps = try parseQuerySteps(value);
        } else if (std.mem.eql(u8, flag, "--console-capture-header")) {
            _ = capture_headers.add(value) catch |err| return switch (err) {
                error.InvalidHeaderName => error.InvalidCaptureHeader,
                error.TooManyHeaders => error.TooManyCaptureHeaders,
            };
        } else try option(&config, flag, value);
    }
    if (initial_admin != null and options_seen) return error.UnexpectedConsoleOptions;
    if (options_seen and !config.enabled) return error.ConsoleRequired;
    if (capture_headers.count != 0 and !capture_heads) return error.CaptureHeaderWithoutCapture;
    return .{
        .config = config,
        .query_steps = query_steps,
        .capture_heads = capture_heads,
        .capture_headers = capture_headers,
        .data_args = remaining[0..count],
        .initial_admin = initial_admin,
    };
}

fn option(config: *console.ConsoleConfig, flag: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, flag, "--console")) {
        if (config.enabled) return error.DuplicateConsole;
        try endpoint(config, value);
        config.enabled = true;
    } else if (std.mem.eql(u8, flag, "--console-key-file")) {
        if (config.key_file.len != 0) return error.DuplicateConsoleKey;
        config.key_file = try console.protocol.Bytes(1024).init(value);
    } else if (std.mem.eql(u8, flag, "--console-origin")) {
        if (config.origin.len != 0) return error.DuplicateOrigin;
        config.origin = try console.protocol.Bytes(255).init(value);
    } else if (std.mem.eql(u8, flag, "--console-trusted-proxy")) {
        if (config.trusted_proxy_count == config.trusted_proxies.len)
            return error.TooManyProxies;
        config.trusted_proxies[config.trusted_proxy_count] =
            try console.protocol.Bytes(49).init(value);
        config.trusted_proxy_count += 1;
    } else if (std.mem.eql(u8, flag, "--console-advertise")) {
        if (config.advertise.len != 0) return error.DuplicateAdvertise;
        config.advertise = try console.protocol.Bytes(255).init(value);
    } else if (std.mem.eql(u8, flag, "--console-probe")) {
        try probe(config, value);
    } else if (std.mem.eql(u8, flag, "--console-location")) {
        if (config.server_location != null) return error.DuplicateLocation;
        config.server_location = try console.protocol.Location.parse(value);
    } else if (std.mem.eql(u8, flag, "--console-peer")) {
        const peers = &config.peers;
        if (peers.count == peers.targets.len) return error.TooManyPeers;
        const at = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidPeer;
        peers.targets[peers.count] = .{
            .node = std.fmt.parseInt(u32, value[0..at], 10) catch return error.InvalidPeer,
            .origin = try console.protocol.Bytes(255).init(value[at + 1 ..]),
        };
        peers.count += 1;
    } else if (std.mem.eql(u8, flag, "--console-peer-key-file")) {
        if (config.peers.key_file.len != 0) return error.DuplicatePeerKey;
        try config.peers.key_file.set(value);
    } else if (std.mem.eql(u8, flag, "--console-peer-ca-file")) {
        if (config.peers.ca_file.len != 0) return error.DuplicatePeerTrust;
        try config.peers.ca_file.set(value);
    } else return error.UnknownConsoleOption;
}

/// `<node-id>=<http://ip:port>`: the peer's data-plane listener, never a discovered address.
fn probe(config: *console.ConsoleConfig, value: []const u8) !void {
    if (config.probe_count == config.probes.len) return error.TooManyProbes;
    const equals = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidProbe;
    const node = std.fmt.parseInt(u32, value[0..equals], 10) catch return error.InvalidProbe;
    if (node == 0) return error.InvalidProbe;
    config.probes[config.probe_count] = .{
        .node = node,
        .url = try console.protocol.Bytes(255).init(value[equals + 1 ..]),
    };
    config.probe_count += 1;
}

fn endpoint(config: *console.ConsoleConfig, value: []const u8) !void {
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidAddress;
    var host = value[0..colon];
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']')
        host = host[1 .. host.len - 1];
    if (host.len == 0) return error.InvalidAddress;
    config.host = try console.protocol.Bytes(45).init(host);
    config.port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch return error.InvalidAddress;
}

pub const Runtime = struct {
    app: *console.App,
    kernel: *console.Kernel,

    pub fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        config: console.ConsoleConfig,
        owner: *Persistent,
    ) !Runtime {
        try config.validate(true);
        if (config.behind_proxy and config.key_file.len == 0) return error.ConsoleKeyRequired;
        var key: ?[32]u8 = null;
        if (config.key_file.len != 0)
            key = try @import("console_key.zig").read(io, config.key_file.slice());
        defer if (key) |*bytes| std.crypto.secureZero(u8, bytes);
        var composed = config;
        composed.node_id = owner.node_id;
        composed.proxy_mode = switch (owner.state.config.mode) {
            .reverse_proxy => .reverse_proxy,
            .forward_auth => .forward_auth,
        };
        composed.version = @import("server.zig").version;
        try composed.validate(true);
        var peer_key = try peerKey(io, composed, owner);
        defer if (peer_key) |*bytes| std.crypto.secureZero(u8, bytes);
        const app = try console.App.init(gpa, io, .{
            .config = composed,
            .mailbox = &owner.console_mailbox,
            .incidents = &owner.console_incidents,
            .metrics = &owner.state.metrics,
            .bans = &owner.state.bans,
            .geo = &owner.console_geo,
            .totp_key = key,
            .peer_key = peer_key,
            .boot = owner.console_node.boot,
        });
        errdefer app.deinit();
        const spec = owner.state.coordinator.default_spec;
        app.challenge_defaults = .{
            .algorithm = switch (spec.algorithm) {
                .hashcash => .hashcash,
                .posw => .posw,
            },
            .difficulty = spec.difficulty,
            .parameter = switch (spec.algorithm) {
                .hashcash => @intCast(spec.hashcashBits()),
                .posw => spec.poswDepth(),
            },
            .openings = if (spec.algorithm == .posw) spec.posw_challenges else 0,
        };
        if (try app.request(.rule_hits_start) != .command_recorded)
            return error.StorageUnavailable;
        const host = if (config.host.len == 0) "127.0.0.1" else config.host.slice();
        const kernel = try console.Kernel.start(
            gpa,
            io,
            try std.Io.net.IpAddress.parse(host, config.port),
            app,
            console.App.handle,
        );
        errdefer kernel.stop();
        owner.state.telemetry = app.telemetry;
        errdefer owner.state.telemetry = null;
        const advertised = if (config.advertise.len != 0) config.advertise else app.config.origin;
        const url = console.protocol.Bytes(console.protocol.nodes.max_url).init(
            advertised.slice(),
        ) catch return error.ConsoleAdvertiseTooLong;
        const recorded = try app.request(.{ .node_advertise = url });
        if (recorded != .command_recorded) return error.StorageUnavailable;
        try announce(app, config);
        return .{ .app = app, .kernel = kernel };
    }

    fn announce(app: *console.App, config: console.ConsoleConfig) !void {
        if (app.setup_required) std.debug.print(
            "Console is uninitialized. Stop Sibuna and run init-admin locally.\n",
            .{},
        );
        std.debug.print("Console: {s}/console/\n", .{app.config.origin.slice()});
        std.debug.print(
            "Console capacity envelope: {d} MiB; " ++
                "database/cache and allocator overhead are separate.\n",
            .{(try config.budget.reservedBytes()) / (1024 * 1024)},
        );
    }

    pub fn stop(self: Runtime) void {
        self.app.stopping.store(true, .release);
        self.app.peers.stop();
        self.app.peer_job.stop();
        self.app.mailbox.stop(self.app.io);
        self.kernel.stop();
        self.app.deinit();
    }
};

/// Reject file aliases and equal secret material for the two local console key domains.
fn peerKey(io: std.Io, config: console.ConsoleConfig, owner: *Persistent) !?[32]u8 {
    if (config.peers.count == 0) return null;
    const path = config.peers.key_file.slice();
    const core = owner.state.config;
    const paths = [_]?[]const u8{
        config.key_file.slice(), core.secret_file, core.cluster_secret_file,
    };
    for (paths) |p| {
        if (p) |other| if (std.mem.eql(u8, path, other)) return error.PeerKeyReused;
    }
    var key = try @import("console_key.zig").read(io, path);
    errdefer std.crypto.secureZero(u8, &key);
    if (config.key_file.len != 0) {
        var other = try @import("console_key.zig").read(io, config.key_file.slice());
        defer std.crypto.secureZero(u8, &other);
        if (std.crypto.timing_safe.eql([32]u8, key, other)) return error.PeerKeyReused;
    }
    return key;
}

test "console parsing preserves data-plane arguments and rejects unknown flags" {
    var remaining: [16][]const u8 = undefined;
    const parsed = try parse(&.{ "--port", "8081", "--console", "[::1]:9443" }, &remaining);
    try std.testing.expectEqualSlices([]const u8, &.{ "--port", "8081" }, parsed.data_args);
    try std.testing.expectEqualStrings("::1", parsed.config.host.slice());
    try std.testing.expectError(
        error.UnknownConsoleOption,
        parse(&.{ "--console-mistake", "1" }, &remaining),
    );
    try std.testing.expectError(error.MissingValue, parse(&.{"--console"}, &remaining));
    const peers = try parse(&.{
        "--console",             "127.0.0.1:9443",      "--console-advertise",
        "http://127.0.0.1:9443", "--console-probe",     "2=http://127.0.0.1:8082",
        "--console-probe",       "3=http://[::1]:8083",
    }, &remaining);
    try std.testing.expectEqual(@as(u8, 2), peers.config.probe_count);
    try std.testing.expectEqual(@as(u32, 3), peers.config.probes[1].node);
    try std.testing.expectEqualStrings("http://127.0.0.1:9443", peers.config.advertise.slice());
    try std.testing.expectError(error.InvalidProbe, parse(&.{
        "--console", "127.0.0.1:9443", "--console-probe", "x=http://127.0.0.1:1",
    }, &remaining));
}

/// Head capture and its kept-header additions are console options applied to core config.
pub fn applyCapture(cfg: *@import("core").Config, parsed: Parsed) void {
    if (!parsed.capture_heads) return;
    cfg.console_capture_heads = true;
    cfg.console_capture_headers = parsed.capture_headers;
}

pub fn validate(config: console.ConsoleConfig, has_storage: bool) bool {
    config.validate(has_storage) catch |err| {
        std.debug.print("CONSOLE001: console configuration rejected ({t}). " ++
            "Hint: configure storage and a trusted HTTPS ingress for remote access.\n", .{err});
        return false;
    };
    return true;
}

test "console location is explicit, bounded and separate from data-plane arguments" {
    const t = std.testing;
    var remaining: [8][]const u8 = undefined;
    const parsed = try parse(&.{
        "--console", "127.0.0.1:9443", "--console-location", "1.3521,103.8198", "--gate",
    }, &remaining);
    try t.expectEqual(@as(f64, 103.8198), parsed.config.server_location.?.lon);
    try t.expectEqualStrings("--gate", parsed.data_args[0]);
    try t.expectError(error.InvalidLocation, parse(&.{
        "--console", "127.0.0.1:9443", "--console-location", "nan,0",
    }, &remaining));
    try t.expectError(error.DuplicateLocation, parse(&.{
        "--console", "127.0.0.1:9443", "--console-location", "0,0", "--console-location", "0,0",
    }, &remaining));
}

test "management peer parsing owns origins and rejects self identity after composition" {
    const t = std.testing;
    var remaining: [16][]const u8 = undefined;
    var parsed = try parse(&.{
        "--console",               "127.0.0.1:9443",
        "--console-behind-proxy",  "--console-origin",
        "https://console.test",    "--console-trusted-proxy",
        "127.0.0.1/32",            "--console-peer",
        "2=https://peer.test:443", "--console-peer-key-file",
        "peer.key",                "--console-peer-ca-file",
        "ca.pem",                  "--gate",
    }, &remaining);
    try t.expectEqualStrings("--gate", parsed.data_args[0]);
    try t.expectEqualStrings("ca.pem", parsed.config.peers.ca_file.slice());
    parsed.config.node_id = 1;
    try parsed.config.validate(true);
    parsed.config.node_id = 2;
    try t.expectError(error.InvalidPeer, parsed.config.validate(true));
    try t.expectError(error.DuplicatePeerKey, parse(&.{
        "--console",               "127.0.0.1:9443", "--console-peer-key-file", "a",
        "--console-peer-key-file", "b",
    }, &remaining));
}

fn parseQuerySteps(value: []const u8) error{InvalidQuerySteps}!u64 {
    if (value.len == 0) return error.InvalidQuerySteps;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidQuerySteps;
    const steps = std.fmt.parseInt(u64, value, 10) catch return error.InvalidQuerySteps;
    if (steps < 100_000 or steps > 50_000_000) return error.InvalidQuerySteps;
    return steps;
}

test "console query budget is bounded and never passed to the data-plane parser" {
    const t = std.testing;
    var remaining: [8][]const u8 = undefined;
    for ([_][]const u8{ "100000", "4000000", "50000000" }) |value| {
        const parsed = try parse(&.{
            "--console", "127.0.0.1:9443", "--console-query-steps", value, "--gate",
        }, &remaining);
        try t.expectEqual(try std.fmt.parseInt(u64, value, 10), parsed.query_steps.?);
        try t.expectEqualSlices([]const u8, &.{"--gate"}, parsed.data_args);
    }
    const invalid = [_][]const u8{
        "99999", "50000001", "-1", "+100000", "4M", "", "18446744073709551616",
    };
    for (invalid) |value| {
        try t.expectError(error.InvalidQuerySteps, parse(&.{
            "--console", "127.0.0.1:9443", "--console-query-steps", value,
        }, &remaining));
    }
    try t.expectError(error.DuplicateQuerySteps, parse(&.{
        "--console",             "127.0.0.1:9443", "--console-query-steps", "100000",
        "--console-query-steps", "100000",
    }, &remaining));
    try t.expectError(error.ConsoleRequired, parse(&.{
        "--console-query-steps", "100000",
    }, &remaining));
    try t.expectError(error.MissingValue, parse(&.{"--console-query-steps"}, &remaining));
}

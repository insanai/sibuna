//! Daemon composition only: console flags never change core's data-plane parser.
const std = @import("std");
const console = @import("console");
const Persistent = @import("persistent.zig").Persistent;
pub const Parsed = struct {
    config: console.ConsoleConfig,
    data_args: []const []const u8,
    initial_admin: ?console.protocol.Bytes(64) = null,
};

pub fn parse(args: []const []const u8, remaining: [][]const u8) !Parsed {
    var config: console.ConsoleConfig = .{};
    var initial_admin: ?console.protocol.Bytes(64) = null;
    var count: usize = 0;
    var i: usize = 0;
    var options_seen = false;
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
        if (std.mem.eql(u8, flag, "--console-cookie-secure")) {
            if (config.cookie_secure) return error.DuplicateCookieSecure;
            config.cookie_secure = true;
            continue;
        }
        i += 1;
        if (i == args.len or std.mem.startsWith(u8, args[i], "--")) return error.MissingValue;
        const value = args[i];
        if (std.mem.eql(u8, flag, "--console")) {
            if (config.enabled) return error.DuplicateConsole;
            try endpoint(&config, value);
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
            try probe(&config, value);
        } else return error.UnknownConsoleOption;
    }
    if (initial_admin != null and options_seen) return error.UnexpectedConsoleOptions;
    if (options_seen and !config.enabled) return error.ConsoleRequired;
    return .{ .config = config, .data_args = remaining[0..count], .initial_admin = initial_admin };
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
        const app = try console.App.init(
            gpa,
            io,
            composed,
            &owner.console_mailbox,
            &owner.console_incidents,
            &owner.state.metrics,
            key,
            owner.console_node.boot,
        );
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
        const host = if (config.host.len == 0) "127.0.0.1" else config.host.slice();
        const kernel = try console.Kernel.start(
            gpa,
            io,
            try std.Io.net.IpAddress.parse(host, config.port),
            app,
            console.App.handle,
        );
        owner.state.telemetry = app.telemetry;
        const advertised = if (config.advertise.len != 0) config.advertise else app.config.origin;
        const url = console.protocol.Bytes(console.protocol.nodes.max_url).init(
            advertised.slice(),
        ) catch return error.ConsoleAdvertiseTooLong;
        const recorded = try app.request(.{ .node_advertise = url });
        if (recorded != .command_recorded) return error.StorageUnavailable;
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
        return .{ .app = app, .kernel = kernel };
    }

    pub fn stop(self: Runtime) void {
        self.app.mailbox.stop(self.app.io);
        self.kernel.stop();
        self.app.deinit();
    }
};

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

pub fn validate(config: console.ConsoleConfig, has_storage: bool) bool {
    config.validate(has_storage) catch |err| {
        std.debug.print("CONSOLE001: console configuration rejected ({t}). " ++
            "Hint: configure storage and a trusted HTTPS ingress for remote access.\n", .{err});
        return false;
    };
    return true;
}

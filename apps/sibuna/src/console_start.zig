//! Daemon composition only: console flags never change core's data-plane parser.
const std = @import("std");
const console = @import("console");
const Persistent = @import("persistent.zig").Persistent;
pub const Parsed = struct { config: console.ConsoleConfig, data_args: []const []const u8 };

pub fn parse(args: []const []const u8, remaining: [][]const u8) !Parsed {
    var config: console.ConsoleConfig = .{};
    var count: usize = 0;
    var i: usize = 0;
    var options_seen = false;
    while (i < args.len) : (i += 1) {
        const flag = args[i];
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
        } else if (std.mem.eql(u8, flag, "--console-origin")) {
            if (config.origin.len != 0) return error.DuplicateOrigin;
            config.origin = try console.protocol.Bytes(255).init(value);
        } else if (std.mem.eql(u8, flag, "--console-trusted-proxy")) {
            if (config.trusted_proxy_count == config.trusted_proxies.len)
                return error.TooManyProxies;
            config.trusted_proxies[config.trusted_proxy_count] =
                try console.protocol.Bytes(49).init(value);
            config.trusted_proxy_count += 1;
        } else return error.UnknownConsoleOption;
    }
    if (options_seen and !config.enabled) return error.ConsoleRequired;
    return .{ .config = config, .data_args = remaining[0..count] };
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
        // Off-loopback is fail-closed until the TOTP enrollment/verification route is wired.
        if (config.behind_proxy) return error.ConsoleTotpRequired;
        const app = try console.App.init(
            gpa,
            io,
            config,
            &owner.console_mailbox,
            &owner.state.metrics,
        );
        errdefer app.deinit();
        const host = if (config.host.len == 0) "127.0.0.1" else config.host.slice();
        const kernel = try console.Kernel.start(
            gpa,
            io,
            try std.Io.net.IpAddress.parse(host, config.port),
            app,
            console.App.handle,
        );
        owner.state.telemetry = app.telemetry;
        if (app.setup_required) std.debug.print(
            "Console setup key (one-time bootstrap): {s}\n",
            .{std.fmt.bytesToHex(app.bootstrap_key, .lower)},
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
}

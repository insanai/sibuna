const std = @import("std");
const core = @import("core");
const store = @import("store");
const Stats = @import("stats.zig").Stats;
const serve = @import("serve");
const p = @import("console_protocol");
const Mailbox = @import("mailbox.zig").Mailbox;
const Config = @import("config.zig").ConsoleConfig;
const Password = @import("password.zig").Password;
const Limiter = @import("limiter.zig").Limiter;
const http = @import("http.zig");
const auth = @import("auth_routes.zig");

pub const App = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    config: Config,
    mailbox: *Mailbox,
    passwords: Password,
    limiter: Limiter = .{},
    bootstrap_key: [32]u8,
    dummy_hash: p.Bytes(255),
    setup_required: bool,
    telemetry: *store.ConsoleTelemetry,
    metrics: *const core.Metrics,
    stats: Stats = .{},
    collector: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn init(
        gpa: std.mem.Allocator,
        io: std.Io,
        cfg: Config,
        mailbox: *Mailbox,
        metrics: *const core.Metrics,
    ) !*App {
        const self = try gpa.create(App);
        errdefer gpa.destroy(self);
        const telemetry = try gpa.create(store.ConsoleTelemetry);
        errdefer gpa.destroy(telemetry);
        telemetry.* = store.ConsoleTelemetry.init();
        self.* = .{
            .gpa = gpa,
            .io = io,
            .config = cfg,
            .mailbox = mailbox,
            .passwords = try Password.init(gpa),
            .telemetry = telemetry,
            .metrics = metrics,
            .bootstrap_key = undefined,
            .dummy_hash = .{},
            .setup_required = false,
        };
        errdefer self.passwords.deinit();
        io.random(&self.bootstrap_key);
        self.dummy_hash = try self.passwords.hash(io, "dummy password never grants access");
        const status = try self.request(.setup_status);
        if (status != .setup_required) return error.StorageUnavailable;
        self.setup_required = status.setup_required;
        if (self.config.origin.len == 0) {
            var buffer: [255]u8 = undefined;
            const host = if (cfg.host.len == 0) "127.0.0.1" else cfg.host.slice();
            const ipv6 = std.mem.indexOfScalar(u8, host, ':') != null;
            self.config.origin = try p.Bytes(255).init(try std.fmt.bufPrint(
                &buffer,
                "http://{s}{s}{s}:{d}",
                .{ if (ipv6) "[" else "", host, if (ipv6) "]" else "", cfg.port },
            ));
        }
        self.collector = try std.Thread.spawn(
            .{ .stack_size = 256 * 1024 },
            collect,
            .{self},
        );
        return self;
    }

    /// Called only after the kernel has joined all handlers and streams.
    pub fn deinit(self: *App) void {
        self.stopping.store(true, .release);
        if (self.collector) |thread| thread.join();
        self.passwords.deinit();
        self.gpa.destroy(self.telemetry);
        std.crypto.secureZero(u8, &self.bootstrap_key);
        self.gpa.destroy(self);
    }

    fn collect(self: *App) void {
        while (!self.stopping.load(.acquire)) {
            self.stats.collect(self.io, self.telemetry, self.now());
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(250), .awake) catch return;
        }
    }

    pub fn request(self: *App, operation: p.StorageRequest) !p.StorageResult {
        const ticket = try self.mailbox.submit(self.io, operation, .urgent);
        errdefer self.mailbox.abandon(self.io, ticket) catch |err| {
            std.log.err("console request cancellation: {t}", .{err});
        };
        const start = std.Io.Clock.awake.now(self.io);
        while (true) {
            if (try self.mailbox.poll(self.io, ticket)) |result| return result;
            if (std.Io.Clock.awake.now(self.io).nanoseconds - start.nanoseconds >
                10 * std.time.ns_per_s) return error.StorageTimeout;
            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake);
        }
    }

    pub fn now(self: *App) u64 {
        return @intCast(@max(0, @divTrunc(
            std.Io.Clock.real.now(self.io).nanoseconds,
            std.time.ns_per_s,
        )));
    }

    pub fn handle(raw: *anyopaque, context: *http.Context) http.Context.Error!void {
        const self: *App = @ptrCast(@alignCast(raw));
        self.dispatch(context) catch |err| switch (err) {
            error.WriteFailed, error.ReadFailed, error.EndOfStream => return,
            error.InvalidRequest, error.TooLarge, error.InvalidPassword => {
                try http.fail(context, .bad_request, "CONSOLE002");
            },
            error.Busy => try http.fail(context, .too_many_requests, "CONSOLE003"),
            else => {
                std.log.warn("console application request failed: {t}", .{err});
                try http.fail(context, .service_unavailable, "CONSOLE004");
            },
        };
    }

    fn dispatch(self: *App, context: *http.Context) !void {
        const path = context.request.head.target;
        if (std.mem.eql(u8, path, "/console/assets/world-110m.bin")) {
            const user = try self.principal(context) orelse return;
            if (user.must_change) return http.fail(context, .forbidden, "CONSOLE403");
            if (context.request.head.method != .GET) return error.InvalidRequest;
            return context.respond(
                .ok,
                "application/octet-stream",
                @embedFile("console_world"),
                &.{},
            );
        }
        if (try @import("assets.zig").serve(context, path)) return;
        const method = context.request.head.method;
        if (method == .POST) {
            const origin = try context.header("Origin") orelse return error.InvalidRequest;
            if (!std.mem.eql(u8, origin, self.config.origin.slice())) return error.InvalidRequest;
        }
        if (std.mem.eql(u8, path, "/console/api/setup")) {
            if (method == .GET) {
                const status = try self.request(.setup_status);
                if (status != .setup_required) return error.StorageUnavailable;
                return http.json(context, .{ .setup_required = status.setup_required }, &.{});
            }
            if (method == .POST) return auth.bootstrap(self, context);
        }
        if (std.mem.eql(u8, path, "/console/api/login") and method == .POST)
            return auth.login(self, context);
        if (std.mem.eql(u8, path, "/console/api/session") and method == .GET) {
            const identity = try self.principal(context) orelse return;
            const raw_token = try http.sessionToken(context);
            const csrf = std.fmt.bytesToHex(http.csrfToken(raw_token), .lower);
            return http.json(context, .{
                .user = identity.actor,
                .role = @tagName(identity.role),
                .must_change = identity.must_change,
                .expires = identity.expires,
                .csrf = @as([]const u8, &csrf),
            }, &.{});
        }
        if (std.mem.eql(u8, path, "/console/stream") and method == .GET)
            return @import("stream.zig").handle(self, context);
        if (std.mem.eql(u8, path, "/console/api/stats") and method == .GET) {
            const identity = try self.principal(context) orelse return;
            if (identity.must_change) return http.fail(context, .forbidden, "CONSOLE403");
            return http.json(context, self.stats.snapshot(
                self.io,
                self.telemetry,
                self.metrics,
                self.now(),
            ), &.{});
        }
        if (std.mem.eql(u8, path, "/console/api/password") and method == .POST)
            return auth.password(self, context);
        if (std.mem.eql(u8, path, "/console/api/logout") and method == .POST)
            return auth.logout(self, context);
        if (method == .GET and (std.mem.eql(u8, path, "/console") or
            std.mem.eql(u8, path, "/console/")))
            return context.respond(.ok, "text/html; charset=utf-8", shell, &.{});
        return http.fail(context, .not_found, "CONSOLE404");
    }

    pub fn principal(self: *App, context: *http.Context) !?p.Principal {
        const digest = http.session(context) catch {
            try http.fail(context, .unauthorized, "CONSOLE401");
            return null;
        };
        const result = try self.request(.{ .authorize = .{
            .session_digest = digest,
            .now = self.now(),
        } });
        if (result != .authorized) {
            try http.fail(context, .unauthorized, "CONSOLE401");
            return null;
        }
        return result.authorized;
    }
};

const shell = @embedFile("console_shell");

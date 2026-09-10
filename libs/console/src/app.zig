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
    totp_key: ?[32]u8,
    limiter: Limiter = .{},
    query_budget: @import("query_budget.zig").Budget = .{},
    dummy_hash: p.Bytes(255),
    setup_required: bool,
    telemetry: *store.ConsoleTelemetry,
    incidents: *store.ConsoleIncidents,
    metrics: *const core.Metrics,
    stats: Stats = .{},
    hub: *@import("subscription_hub.zig").Hub,
    peers: @import("peer_store.zig").Store,
    peer_job: @import("peer_job.zig").Job = .{},
    subscriptions: @import("subscription_job.zig").Job = .{},
    history: @import("rankings_journal.zig").Journal = .{},
    minutes: @import("minute_journal.zig").Journal = .{},
    retention: @import("retention_job.zig").Job = .{},
    challenge_defaults: p.challenges.Defaults = .{},
    /// The composing storage owner outlives every console task and incident flush.
    geo: *@import("geoip_generation.zig").Registry,
    geo_job: @import("geoip_job.zig").Job = .{},
    geo_maintenance: @import("geoip_maintenance.zig").Maintenance = .{},
    cluster: @import("cluster_probe.zig").Probe = .{},
    notifier: @import("notifier_job.zig").Job = .{},
    drafts: @import("page_routes.zig").Drafts = .{},
    detector: @import("notify_events.zig").Detector = .{},
    bans_seen: u64 = 0,
    collector: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),

    pub const Input = struct {
        config: Config,
        mailbox: *Mailbox,
        incidents: *store.ConsoleIncidents,
        metrics: *const core.Metrics,
        geo: *@import("geoip_generation.zig").Registry,
        totp_key: ?[32]u8,
        peer_key: ?[32]u8 = null,
        boot: [16]u8,
    };

    pub fn init(gpa: std.mem.Allocator, io: std.Io, input: Input) !*App {
        const cfg = input.config;
        const boot = input.boot;
        const self = try gpa.create(App);
        errdefer gpa.destroy(self);
        const telemetry = try gpa.create(store.ConsoleTelemetry);
        errdefer gpa.destroy(telemetry);
        telemetry.* = store.ConsoleTelemetry.init();
        const hub = try @import("subscription_hub.zig").Hub.init(gpa, io, boot);
        errdefer hub.deinit();
        self.* = .{
            .gpa = gpa,
            .totp_key = input.totp_key,
            .io = io,
            .config = cfg,
            .mailbox = input.mailbox,
            .incidents = input.incidents,
            .passwords = try Password.init(gpa),
            .telemetry = telemetry,
            .hub = hub,
            .peers = .init(io, cfg.peers, cfg.node_id, input.peer_key),
            .metrics = input.metrics,
            .geo = input.geo,
            .dummy_hash = .{},
            .setup_required = false,
        };
        errdefer {
            self.peers.deinit();
            self.passwords.deinit();
            if (self.totp_key) |*key| std.crypto.secureZero(u8, key);
        }
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
        try self.startServices(boot);
        return self;
    }

    fn startServices(self: *App, boot: [16]u8) !void {
        const cfg = self.config;
        const io = self.io;
        const incidents = self.incidents;
        self.geo_job.app = self;
        self.history.node = cfg.node_id;
        std.debug.assert(!std.mem.allEqual(u8, &boot, 0));
        self.history.boot = boot;
        self.minutes.node = cfg.node_id;
        self.minutes.boot = self.history.boot;
        self.retention.holder = .{ .node = cfg.node_id, .boot = self.history.boot };
        try self.geo_job.restore();
        self.stats.boot = self.history.boot;
        self.stats.node = cfg.node_id;
        self.stats.proxy_mode = cfg.proxy_mode;
        self.stats.server_location = cfg.server_location;
        self.stats.started_ms = @import("stats.zig").monotonicMs(io);
        self.stats.incident_geo.started_at = self.now();
        incidents.enabled.store(true, .release);
        errdefer incidents.enabled.store(false, .release);
        try self.cluster.init(io, &self.config);
        self.cluster.notifier = &self.notifier;
        try self.cluster.start();
        errdefer self.cluster.stop();
        self.notifier.app = self;
        self.notifier.holder = .{ .node = cfg.node_id, .boot = self.history.boot };
        try self.notifier.start();
        errdefer self.notifier.stop();
        try self.subscriptions.start(self);
        errdefer self.subscriptions.stop();
        try self.peer_job.start(&self.peers, self.gpa);
        errdefer self.peer_job.stop();
        self.collector = try std.Thread.spawn(
            .{ .stack_size = 256 * 1024 },
            collect,
            .{self},
        );
    }

    /// Called only after the kernel has joined all handlers and streams.
    pub fn deinit(self: *App) void {
        self.incidents.enabled.store(false, .release);
        self.stopping.store(true, .release);
        self.peers.stop();
        self.peer_job.stop();
        self.peers.deinit();
        self.hub.stop();
        self.subscriptions.stop();
        self.cluster.stop();
        self.notifier.stop();
        self.geo_job.stop();
        if (self.collector) |thread| thread.join();
        self.geo_maintenance.stop(self.io, self.mailbox);
        self.history.stop(self.io, self.mailbox);
        self.minutes.stop(self.io, self.mailbox);
        self.retention.stop(self.io, self.mailbox);
        self.passwords.deinit();
        if (self.totp_key) |*key| std.crypto.secureZero(u8, key);
        self.hub.deinit();
        self.gpa.destroy(self.telemetry);
        self.gpa.destroy(self);
    }

    fn collect(self: *App) void {
        while (!self.stopping.load(.acquire)) {
            const second = self.now();
            for (0..2) |_| {
                const minute = self.stats.takeClosedRanking(self.io, second) orelse break;
                self.history.offer(&minute, self.telemetry.dropped.load(.monotonic));
            }
            self.stats.collect(self.io, self.telemetry, second, self.geo);
            self.stats.collectIncidents(self.io, self.incidents, self.geo, second);
            self.observeEvents(second);
            const ms: u64 = @intCast(@max(0, @divTrunc(
                std.Io.Clock.awake.now(self.io).nanoseconds,
                std.time.ns_per_ms,
            )));
            self.history.tick(self.io, self.mailbox, second, ms);
            self.stats.journal(self.io, &self.minutes);
            self.minutes.tick(self.io, self.mailbox, second, ms);
            if (self.retention.tick(self.io, self.mailbox, ms))
                _ = self.stats.retention_failures.fetchAdd(1, .monotonic);
            if (self.geo_maintenance.tick(
                self.io,
                self.mailbox,
                second,
                ms,
                self.geo.loaded.load(.acquire) and !self.geo_job.running.load(.acquire),
            ))
                _ = self.stats.geo_maintenance_failures.fetchAdd(1, .monotonic);
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(250), .awake) catch return;
        }
    }

    /// Denial spikes and issued bans become notification events; both are counted from
    /// atomics already maintained by the data plane, so nothing here touches a request.
    fn observeEvents(self: *App, second: u64) void {
        const totals = self.telemetry.totals();
        if (self.detector.observe(second, totals.denied)) |denied| {
            var text: [64]u8 = undefined;
            const detail = std.fmt.bufPrint(&text, "denied {d} in 60 s", .{denied}) catch "";
            self.notifier.raise(.denial_spike, second, detail);
        }
        const issued = self.metrics.bans_issued.load(.monotonic);
        if (issued != self.bans_seen) {
            var text: [64]u8 = undefined;
            const detail = std.fmt.bufPrint(&text, "{d} local bans issued", .{
                issued - self.bans_seen,
            }) catch "";
            self.notifier.raise(.ban, second, detail);
            self.bans_seen = issued;
        }
    }

    pub fn request(self: *App, operation: p.StorageRequest) !p.StorageResult {
        return self.requestAt(operation, .urgent);
    }

    pub fn background(self: *App, operation: p.StorageRequest) !p.StorageResult {
        return self.requestAt(operation, .background);
    }

    /// Longest wait for the storage owner before a request is answered as unknown.
    pub const storage_wait_seconds = 10;

    fn requestAt(
        self: *App,
        operation: p.StorageRequest,
        priority: Mailbox.Priority,
    ) !p.StorageResult {
        const ticket = self.mailbox.submit(self.io, operation, priority) catch |err| {
            p.releaseRequest(operation, self.gpa);
            return err;
        };
        errdefer self.mailbox.abandon(self.io, ticket) catch |err| {
            std.log.err("console request cancellation: {t}", .{err});
        };
        const start = std.Io.Clock.awake.now(self.io);
        while (true) {
            if (try self.mailbox.poll(self.io, ticket)) |result| return result;
            if (std.Io.Clock.awake.now(self.io).nanoseconds - start.nanoseconds >
                storage_wait_seconds * std.time.ns_per_s) return error.StorageTimeout;
            self.mailbox.waitFor(self.io, ticket, .{ .deadline = .{
                .clock = .awake,
                .raw = start.addDuration(.fromSeconds(storage_wait_seconds)),
            } }) catch |err| switch (err) {
                error.Timeout => {},
                else => return err,
            };
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
            error.InvalidRequest, error.InvalidLimit, error.TooLarge, error.InvalidPassword => {
                try http.fail(context, .bad_request, "CONSOLE002");
            },
            error.Busy => try http.fail(context, .too_many_requests, "CONSOLE003"),
            // The storage owner did not answer within its deadline: a lost quorum or a
            // stalled store. The operation's outcome is unknown, not proven failed.
            error.StorageTimeout => try http.fail(context, .service_unavailable, "CONSOLEQUORUM"),
            else => {
                std.log.warn("console application request failed: {t}", .{err});
                try http.fail(context, .service_unavailable, "CONSOLE004");
            },
        };
    }

    pub fn needsTotp(self: *App, role: p.Role, enabled: bool) bool {
        return self.config.behind_proxy and role == .admin and !enabled;
    }

    pub fn restricted(self: *App, identity: p.Principal) bool {
        return identity.must_change or self.needsTotp(
            identity.account_role orelse identity.role,
            identity.totp_enabled,
        );
    }

    fn dispatch(self: *App, context: *http.Context) !void {
        const forwarded = if (self.config.behind_proxy)
            try context.header("X-Forwarded-Proto")
        else
            null;
        if (!@import("ingress.zig").accepts(&self.config, context.peer, forwarded))
            return http.fail(context, .forbidden, "CONSOLE403");
        // The head has arrived, so the slow-read bound no longer applies; the request may
        // now wait the storage deadline (a lost quorum answers late, not never) and reply.
        context.extend(storage_wait_seconds + 2);
        const path = context.request.head.target;
        const method = context.request.head.method;
        if (method == .GET and std.mem.eql(u8, path, "/console/assets/world-110m.bin")) {
            const identity = try self.principal(context) orelse return;
            if (self.restricted(identity) or identity.token_id != null)
                return http.fail(context, .forbidden, "CONSOLE403");
            return context.respond(
                .ok,
                "application/octet-stream",
                @embedFile("console_world"),
                &.{},
            );
        }
        if (try @import("assets.zig").serve(context, path)) return;
        if (method == .GET and (std.mem.eql(u8, path, "/console") or
            std.mem.eql(u8, path, "/console/")))
            return context.respond(.ok, "text/html; charset=utf-8", shell, &.{});
        const route = @import("routes.zig").find(path, method) orelse
            return http.fail(context, .not_found, "CONSOLE404");
        const automation = try context.header("Authorization") != null;
        if (automation and route.token_scope == null)
            return http.fail(context, .forbidden, "CONSOLE403");
        if (method == .POST) {
            if (try context.header("Origin")) |origin| {
                if (!std.mem.eql(u8, origin, self.config.origin.slice())) {
                    return error.InvalidRequest;
                }
            } else if (!automation) return error.InvalidRequest;
        }
        var identity: ?p.Principal = null;
        if (route.access != .public) {
            identity = try self.routePrincipal(context, route) orelse return;
        }
        return self.executeRoute(context, route, identity);
    }

    fn routePrincipal(
        self: *App,
        context: *http.Context,
        route: @import("routes.zig").Route,
    ) !?p.Principal {
        const identity = try self.principal(context) orelse return null;
        const access_restricted = route.access == .full and self.restricted(identity);
        const scope_missing = if (identity.token_id != null)
            route.token_scope == null or identity.scopes & route.token_scope.?.bit() == 0
        else
            false;
        if (access_restricted or scope_missing or !identity.role.allows(route.action) or
            (identity.kiosk and !route.kiosk))
        {
            try http.fail(context, .forbidden, "CONSOLE403");
            return null;
        }
        if (context.request.head.method == .POST) {
            if (identity.token_id == null) try http.csrf(context, identity.csrf_digest);
            if (route.mutation and !self.query_budget.allow(
                self.io,
                try http.session(context),
                self.now(),
                .mutation,
            )) {
                try http.fail(context, .too_many_requests, "CONSOLEMUTATION");
                return null;
            }
        }
        return identity;
    }

    fn executeRoute(
        self: *App,
        context: *http.Context,
        route: @import("routes.zig").Route,
        identity: ?p.Principal,
    ) !void {
        const access = @import("access_routes.zig");
        switch (route.handler) {
            .node_status,
            .nodes_members,
            .node_command,
            .node_command_read,
            .audit_query,
            .audit_read,
            .audit_export,
            .users_query,
            .users_create,
            .users_change,
            .tokens_query,
            .tokens_create,
            .tokens_revoke,
            => return access.dispatch(self, context, identity.?, route.handler),
            .setup_status => return self.setupReply(context),
            .challenges => return @import("challenge_routes.zig").handle(self, context),
            .rankings => return @import("ranking_routes.zig").handle(self, context),
            .timeline => return @import("timeline_routes.zig").handle(self, context),
            .minutes => return @import("minute_routes.zig").handle(self, context),
            .events_similar => return @import("similarity_routes.zig").query(self, context),
            .policies => return @import("policy_routes.zig").query(self, context, false),
            .policies_test => return @import("policy_routes.zig").query(self, context, true),
            .policy_edit, .inspection_edit => return @import("policy_routes.zig")
                .edit(self, context, identity.?, route.handler == .inspection_edit),
            .policy_read => return @import("policy_read_routes.zig").read(self, context),
            .security_query, .security_trends => return @import("security_routes.zig").query(
                self,
                context,
                route.handler == .security_trends,
            ),
            .events => return @import("event_routes.zig").query(self, context, false),
            .events_export => return @import("event_routes.zig").query(self, context, true),
            .login => return auth.login(self, context),
            .kiosk_token, .kiosk_exchange => return @import("kiosk_routes.zig").handle(
                self,
                context,
                identity,
            ),
            .logout => return auth.logout(self, context),
            else => return self.managementRoute(context, route, identity.?),
            .settings_query,
            .settings_change,
            .notifications_query,
            .notifications_save,
            .notifications_remove,
            .notifications_test,
            => return @import("settings_routes.zig").handle(
                self,
                context,
                identity.?,
                route.handler,
            ),
            .password => return auth.password(self, context, identity.?),
            .geoip => return @import("geoip_routes.zig").handle(self, context, identity.?),
            .totp => return @import("totp_routes.zig")
                .handle(self, context, route.path, identity.?),
            .peer => return @import("stream.zig").peer(self, context),
            .stream => return @import("stream.zig").handle(self, context, identity.?),
            .stats => return http.json(context, self.stats.snapshot(
                self.io,
                self.telemetry,
                self.metrics,
                self.now(),
            ), &.{}),
            .session => return self.sessionReply(context, identity.?),
        }
    }

    /// Settings-owned pages and the policy workflows: every handler the route table can
    /// name is listed here or in `executeRoute`; an unlisted one is a programming error.
    fn managementRoute(
        self: *App,
        context: *http.Context,
        route: @import("routes.zig").Route,
        identity: p.Principal,
    ) !void {
        return switch (route.handler) {
            .pages_read, .pages_edit, .pages_preview, .pages_preview_get => @import(
                "page_routes.zig",
            ).handle(self, context, identity, route),
            .policy_order,
            .policy_replay,
            .reputation_query,
            .reputation_edit,
            .reputation_remove,
            .country_preview,
            .country_apply,
            .import_chunk,
            .import_commit,
            => @import("workflow_routes.zig").handle(self, context, identity, route.handler),
            .about => self.aboutReply(context),
            else => unreachable,
        };
    }

    /// Version, node identity, binding and proxy facts; never secrets or key material.
    fn aboutReply(self: *App, context: *http.Context) !void {
        const cfg = &self.config;
        return http.json(context, .{
            .version = cfg.version,
            .node = cfg.node_id,
            .schema = @import("schema.zig").version,
            .origin = cfg.origin.slice(),
            .advertise = cfg.advertise.slice(),
            .behind_proxy = cfg.behind_proxy,
            .trusted_proxies = cfg.trusted_proxy_count,
            .probes = cfg.probe_count,
            .cookie_secure = cfg.cookie_secure or cfg.behind_proxy,
            .key_file = cfg.key_file.len != 0,
        }, &.{});
    }

    fn setupReply(self: *App, context: *http.Context) !void {
        const status = try self.request(.setup_status);
        if (status != .setup_required) return error.StorageUnavailable;
        return http.json(context, .{ .setup_required = status.setup_required }, &.{});
    }

    fn sessionReply(self: *App, context: *http.Context, user: p.Principal) !void {
        const raw = try http.sessionToken(context);
        const csrf = std.fmt.bytesToHex(http.csrfToken(raw), .lower);
        return http.json(context, .{
            .user = p.Counter{ .value = user.actor },
            .role = @tagName(user.role),
            .must_change = user.must_change,
            .expires = user.expires,
            .totp_required = self.needsTotp(user.role, user.totp_enabled),
            .kiosk = user.kiosk,
            .csrf = @as([]const u8, &csrf),
        }, &.{});
    }

    pub fn principal(self: *App, context: *http.Context) !?p.Principal {
        const credential = http.credential(context) catch {
            try http.fail(context, .unauthorized, "CONSOLE401");
            return null;
        };
        const result = try self.request(.{ .authorize = .{
            .session_digest = credential.digest,
            .kind = credential.kind,
            .touch = true,
        } });
        if (result == .failed and result.failed == .unavailable) {
            // Storage could not answer (lost quorum or an unavailable replica): the
            // credential is unknown rather than rejected, so never answer 401 here.
            try http.fail(context, .service_unavailable, "CONSOLEQUORUM");
            return null;
        }
        if (result != .authorized) {
            try http.fail(context, .unauthorized, "CONSOLE401");
            return null;
        }
        return result.authorized;
    }
};

const shell = @embedFile("console_shell");

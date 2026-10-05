//! Live transport fixture: synthetic rules isolate connector behavior. Signed
//! source authentication is qualified independently by the artifact probe.
const std = @import("std");
const Io = std.Io;
const crs = @import("crs");
const core = @import("core");
const net = @import("net");
const policy = @import("policy");
const server = @import("server.zig");
const t = std.testing;
const store = @import("store");
const console_enabled = @import("build_options").console;
const io = t.io;
pub const Options = struct {
    source: []const u8,
    mode: crs.config.Mode = .enforce,
    profile: crs.config.Profile = .full,
    forward_auth: bool = false,
    deadline_ms: u64 = 30_000,
    rate: u32 = 1000,
    capture: bool = false,
};
pub const Finding = struct {
    evidence: core.security_evidence.Crs,
    path: [128]u8 = @splat(0),
    category: [32]u8 = @splat(0),
    payload_bytes: usize,
    request: [core.incident_heads.request_bytes]u8 = @splat(0),
    response: [core.incident_heads.response_bytes]u8 = @splat(0),
    response_state: core.incident_heads.ResponseState,
};
pub const Fixture = struct {
    engine: policy.Engine = undefined,
    engine_slot: server.EngineSlot = undefined,
    state: server.AppState = undefined,
    publisher: crs.publication.Publisher = .{},
    telemetry: if (console_enabled) store.ConsoleTelemetry else void =
        if (console_enabled) undefined else {},
    listener: Io.net.Server = undefined,
    origin: Io.net.Server = undefined,
    worker: std.Thread = undefined,
    origin_worker: std.Thread = undefined,
    origin_stopping: std.atomic.Value(bool) = .init(false),
    received: std.atomic.Value(u32) = .init(0),
    body_digest: [32]u8 = @splat(0),
    error_seen: std.atomic.Value(bool) = .init(false),
    findings: store.BoundedQueue(Finding, 16) = .init(),

    pub fn create(options: Options) !*Fixture {
        const self = try t.allocator.create(Fixture);
        errdefer t.allocator.destroy(self);
        self.* = .{};
        self.engine.initInPlace(8);
        try self.engine.addRule(.{ .name = "admit", .path_pattern = "*", .action = .allow });
        self.engine_slot = .{ .engine = &self.engine };
        const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.origin = try address.listen(io, .{ .reuse_address = true });
        errdefer self.origin.deinit(io);
        self.listener = try address.listen(io, .{ .reuse_address = true });
        errdefer self.listener.deinit(io);
        var config: core.Config = .{
            .upstream_port = self.origin.socket.address.ip4.port,
            .rate_limit = options.rate,
            .idle_timeout_seconds = 0,
            .websocket_idle_timeout_seconds = 0,
            .workers = 1,
            .console_capture_heads = options.capture,
        };
        if (options.forward_auth) config.mode = .forward_auth;
        self.state.init(config, &self.engine_slot, &@as([32]u8, @splat(3)));
        self.state.hooks = .{ .context = self, .record_incident = record };
        try self.publisher.publish(try generation(options));
        errdefer self.closePublisher();
        if (console_enabled) {
            self.telemetry = store.ConsoleTelemetry.init();
            self.state.telemetry = &self.telemetry;
        }
        self.state.crs = &self.publisher;
        self.state.crs_timeout_ms = options.deadline_ms;
        self.worker = try std.Thread.spawn(.{}, serve, .{self});
        errdefer {
            server.requestStop(&self.listener, io, &self.state);
            self.worker.join();
        }
        self.origin_worker = try std.Thread.spawn(.{}, origins, .{self});
        return self;
    }

    pub fn destroy(self: *Fixture) void {
        server.requestStop(&self.listener, io, &self.state);
        self.worker.join();
        self.origin_stopping.store(true, .release);
        const wake = net.connect.bounded(io, self.origin.socket.address) catch unreachable;
        wake.close(io);
        self.origin_worker.join();
        self.listener.deinit(io);
        self.origin.deinit(io);
        self.closePublisher();
        const failed = self.error_seen.load(.acquire);
        t.allocator.destroy(self);
        t.expect(!failed) catch @panic("fixture worker failed");
    }

    fn closePublisher(self: *Fixture) void {
        self.publisher.close() catch unreachable;
        self.publisher.deinit();
    }

    pub fn connect(self: *Fixture) !Io.net.Stream {
        return net.connect.bounded(io, self.listener.socket.address);
    }

    fn serve(self: *Fixture) void {
        server.runServer(&self.listener, io, &self.state) catch
            self.error_seen.store(true, .release);
    }

    fn record(context: ?*anyopaque, incident: core.Incident) void {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        const evidence = incident.crs orelse return;
        var finding: Finding = .{
            .evidence = evidence,
            .payload_bytes = incident.payload.len,
            .response_state = incident.response_state,
        };
        const path = @min(finding.path.len, incident.path.len);
        const category = @min(finding.category.len, incident.category.len);
        @memcpy(finding.path[0..path], incident.path[0..path]);
        @memcpy(finding.category[0..category], incident.category[0..category]);
        @memcpy(finding.request[0..incident.request_head.len], incident.request_head);
        @memcpy(finding.response[0..incident.response_head.len], incident.response_head);
        _ = self.findings.push(finding);
    }

    fn origins(self: *Fixture) void {
        var workers: [16]std.Thread = undefined;
        var used: usize = 0;
        defer for (workers[0..used]) |worker| worker.join();
        while (used < workers.len) {
            const stream = self.origin.accept(io) catch return;
            if (self.origin_stopping.load(.acquire)) {
                stream.close(io);
                return;
            }
            workers[used] = std.Thread.spawn(.{}, originConnection, .{ self, stream }) catch {
                stream.close(io);
                self.error_seen.store(true, .release);
                return;
            };
            used += 1;
        }
    }

    fn originConnection(self: *Fixture, stream: Io.net.Stream) void {
        defer stream.close(io);
        originReply(self, stream) catch self.error_seen.store(true, .release);
    }
};

fn generation(options: Options) !*crs.generation.Generation {
    const package = try t.allocator.create(crs.release_package.Package);
    errdefer t.allocator.destroy(package);
    package.* = .{
        .allocator = t.allocator,
        .bounded = .{ .parent = t.allocator, .limit = crs.release_package.compiled_capacity },
        .program = undefined,
        .receipt = .{ .digest = @splat(1), .created = 1, .archive_bytes = 1 },
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
    };
    var compiler = crs.compiler.Compiler.init(t.allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("connector-test.conf", options.source);
    var plan = try compiler.finish();
    defer plan.deinit();
    package.program = try crs.rule_program.compile(package.bounded.allocator(), &plan, &.{}, .{});
    errdefer package.program.deinit();
    return crs.generation.Generation.create(t.allocator, package, .{
        .revision = 1,
        .activation = .{ .mode = options.mode, .profile = options.profile },
        .observation = if (options.forward_auth) .request_metadata else .request_response,
        .limits = .{
            .entries = 512,
            .bytes = 32768,
            .request = 256 * 1024,
            .response = 256 * 1024,
            .events = 32,
            .tags = 64,
            .pieces = 64,
            .work = 16_000_000,
            .reservation = 16 * 1024 * 1024,
        },
        .slots = 1,
        .reservation = 16 * 1024 * 1024,
    });
}

fn originReply(self: *Fixture, stream: Io.net.Stream) !void {
    var buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    const r = &reader.interface;
    while (std.mem.indexOf(u8, r.buffered(), "\r\n\r\n") == null)
        try r.fill(r.bufferedLen() + 1);
    const end = std.mem.indexOf(u8, r.buffered(), "\r\n\r\n").? + 4;
    const request = try net.parseRequest(r.buffered()[0..end]);
    const stream_response = std.mem.eql(u8, request.path, "/stream");
    const upgrade = std.mem.eql(u8, request.path, "/socket");
    const block = std.mem.eql(u8, request.path, "/response-deny");
    r.toss(end);
    var body: [256 * 1024]u8 = undefined;
    const acquired = try net.entity.read(
        .{ .reader = r, .output = &body },
        .{ .length = request.contentLength() orelse 0 },
    );
    std.crypto.hash.sha2.Sha256.hash(acquired, &self.body_digest, .{});
    _ = self.received.fetchAdd(1, .release);
    var out: [1024]u8 = undefined;
    var writer = stream.writer(io, &out);
    const w = &writer.interface;
    if (upgrade) {
        try w.writeAll("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n" ++
            "Upgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
    } else if (stream_response) {
        try w.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Connection: close\r\n\r\ndata: ready\n\n");
    } else {
        const payload = if (block) "confidential" else "accepted";
        try w.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ payload.len, payload });
    }
    try w.flush();
    if (stream_response or upgrade) {
        var byte: [1]u8 = undefined;
        _ = r.readSliceShort(&byte) catch {};
    }
}

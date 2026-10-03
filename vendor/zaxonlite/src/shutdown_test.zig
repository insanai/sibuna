//! Real-socket regressions for shutdown, establishment deadlines and replay safety.
const std = @import("std");
const Io = std.Io;
const zx = @import("zaxonlite");
const client = zx.client;
const testing = std.testing;
const io = testing.io;
const gpa = testing.allocator;
const cluster_secret = "0123456789abcdef0123456789abcdef";

fn after(ms: u64) Io.Clock.Timestamp {
    return .{ .clock = .awake, .raw = .{
        .nanoseconds = Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds +
            @as(i96, ms) * std.time.ns_per_ms,
    } };
}

fn expired(end: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >= end.raw.nanoseconds;
}

/// Bounds even cleanup joins when a lifecycle regression would otherwise hang CI.
const Guard = struct {
    done: Io.Event = .unset,
    end: Io.Clock.Timestamp = undefined,
    thread: ?std.Thread = null,

    fn start(self: *Guard) !void {
        self.end = after(5000);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn stop(self: *Guard) void {
        self.done.set(io);
        self.thread.?.join();
    }

    fn run(self: *Guard) void {
        while (!self.done.isSet()) {
            if (expired(self.end)) {
                std.debug.print("shutdown regression exceeded five-second watchdog\n", .{});
                std.c._exit(1);
            }
            self.done.waitTimeout(io, .{ .deadline = self.end }) catch {};
        }
    }
};

const Peer = struct {
    listener: Io.net.Server,
    thread: ?std.Thread = null,
    mutex: Io.Mutex = .init,
    active: ?Io.net.Stream = null,
    stopping: bool = false,
    mode: enum { silent, drip, reply, lose_reply },
    secret: ?[]const u8 = null,
    requests: usize = 0,
    accepted: Io.Event = .unset,

    fn init(mode: @FieldType(Peer, "mode")) !Peer {
        const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        return .{ .listener = try address.listen(io, .{}), .mode = mode };
    }

    fn endpoint(self: *const Peer) client.Endpoint {
        return .{ .host = "127.0.0.1", .port = self.listener.socket.address.getPort() };
    }

    fn start(self: *Peer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn stop(self: *Peer) void {
        self.mutex.lockUncancelable(io);
        self.stopping = true;
        if (self.active) |stream| stream.shutdown(io, .both) catch {};
        self.mutex.unlock(io);
        if (self.thread) |thread| {
            const address = self.listener.socket.address;
            if (address.connect(io, .{ .mode = .stream })) |stream| stream.close(io) else |_| {}
            thread.join();
            self.thread = null;
        }
        self.listener.deinit(io);
    }

    fn run(self: *Peer) void {
        const stream = self.listener.accept(io) catch return;
        defer stream.close(io);
        self.mutex.lockUncancelable(io);
        if (self.stopping) {
            self.mutex.unlock(io);
            return;
        }
        self.active = stream;
        self.mutex.unlock(io);
        defer {
            self.mutex.lockUncancelable(io);
            self.active = null;
            self.mutex.unlock(io);
        }
        self.accepted.set(io);
        self.serve(stream) catch {};
    }

    fn serve(self: *Peer, stream: Io.net.Stream) !void {
        var rb: [1024]u8 = undefined;
        var wb: [1024]u8 = undefined;
        var reader = stream.reader(io, &rb);
        var writer = stream.writer(io, &wb);
        if (self.mode == .silent) {
            while (true) _ = try reader.interface.takeByte();
        }
        const hello_header = try zx.wire.readFrameHeader(&reader.interface);
        const hello = try zx.wire.readFrameBody(gpa, &reader.interface, hello_header);
        defer gpa.free(hello);
        if (self.mode == .drip) {
            // A declared challenge that trickles bytes must not reset the deadline.
            try writer.interface.writeAll(&.{ 65, 0, 0, 0, 14 });
            for (0..64) |_| {
                try writer.interface.writeByte(0);
                try writer.interface.flush();
                try io.sleep(.fromMilliseconds(10), .awake);
            }
            return;
        }
        var auth: ?zx.transport_auth.Session = if (self.secret) |secret|
            try zx.transport_auth.accept(
                gpa,
                io,
                &reader.interface,
                &writer.interface,
                secret,
                hello,
            )
        else
            null;
        const body = if (auth) |*session| blk: {
            const frame = try session.readFrame(gpa, &reader.interface);
            break :blk frame.body;
        } else blk: {
            const header = try zx.wire.readFrameHeader(&reader.interface);
            break :blk try zx.wire.readFrameBody(gpa, &reader.interface, header);
        };
        defer gpa.free(body);
        self.requests += 1;
        if (self.mode == .lose_reply) return;
        if (auth) |*session| {
            try session.writeFrame(&writer.interface, .rpc_response, "{\"ok\":true}");
        } else try zx.wire.writeFrame(&writer.interface, .rpc_response, "{\"ok\":true}");
        try writer.interface.flush();
    }
};

test "PSK handshake to a silent endpoint has a total deadline" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    const end = after(2000);
    try testing.expectError(error.Timeout, client.Connection.openWithTransport(
        gpa,
        io,
        peer.endpoint(),
        .{ .secret = "secret", .connect_timeout_ms = 50 },
    ));
    try testing.expect(!expired(end));
}

test "zero establishment budget expires before dialing" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    try testing.expectError(error.Timeout, client.Connection.openWithTransport(
        gpa,
        io,
        .{ .host = "127.0.0.1", .port = 1 },
        .{ .connect_timeout_ms = 0 },
    ));
}

test "outer deadline bounds readiness response and invalidates its connection" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    const end = after(50);
    const connection = try client.Connection.openWithTransportDeadline(
        gpa,
        io,
        peer.endpoint(),
        .{},
        end,
    );
    defer connection.close();
    try testing.expectError(error.Timeout, connection.callWithDeadline("{\"op\":\"status\"}", end));
    try testing.expectError(error.Timeout, connection.callWithDeadline("{}", end));
}

test "establishment watchdog is disarmed for a long-lived connection" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.reply);
    defer peer.stop();
    try peer.start();
    const connection = try client.Connection.openWithTransport(
        gpa,
        io,
        peer.endpoint(),
        .{ .connect_timeout_ms = 50 },
    );
    defer connection.close();
    try io.sleep(.fromMilliseconds(100), .awake);
    const body = try connection.callWithDeadline("{}", after(1000));
    defer gpa.free(body);
    try testing.expectEqualStrings("{\"ok\":true}", body);
}

test "cluster rotates from a stalled PSK seed to a healthy seed" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var silent = try Peer.init(.silent);
    defer silent.stop();
    try silent.start();
    var healthy = try Peer.init(.reply);
    healthy.secret = "secret";
    defer healthy.stop();
    try healthy.start();
    const endpoints = [_]client.Endpoint{ silent.endpoint(), healthy.endpoint() };
    var cluster = client.ClusterConnection.init(gpa, io, &endpoints, .{
        .secret = "secret",
        .connect_timeout_ms = 100,
    });
    defer cluster.deinit();
    var result = try cluster.call("{}", false);
    defer result.deinit(gpa);
    try testing.expectEqualStrings("{\"ok\":true}", result.body);
}

test "lost response is returned without replaying an application request" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.lose_reply);
    defer peer.stop();
    try peer.start();
    const endpoints = [_]client.Endpoint{peer.endpoint()};
    var cluster = client.ClusterConnection.init(gpa, io, &endpoints, .{});
    defer cluster.deinit();
    if (cluster.call("{\"op\":\"exec\",\"sql\":\"insert into t values(1)\"}", false)) |value| {
        var result = value;
        result.deinit(gpa);
        return error.TestUnexpectedResult;
    } else |err| try testing.expect(err != error.NoLeaderReachable);
    try testing.expectEqual(@as(usize, 1), cluster.next_endpoint);
}

test "explicit cancellation interrupts PSK authentication without becoming a timeout" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    const endpoints = [_]client.Endpoint{peer.endpoint()};
    var cluster = client.ClusterConnection.init(gpa, io, &endpoints, .{ .secret = "secret" });
    defer cluster.deinit();
    const Worker = struct {
        cluster: *client.ClusterConnection,
        result: ?anyerror = null,
        fn run(self: *@This()) void {
            var result = self.cluster.call("{}", false) catch |err| {
                self.result = err;
                return;
            };
            result.deinit(gpa);
        }
    };
    var worker = Worker{ .cluster = &cluster };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    peer.accepted.waitUncancelable(io);
    cluster.cancelCurrent();
    thread.join();
    try testing.expectEqual(@as(?anyerror, error.Canceled), worker.result);
}

const LocalNode = struct {
    tmp: testing.TmpDir,
    path: []u8,
    address: []u8,
    member: [1]zx.EmbeddedMember,
    node: ?*zx.Embedded = null,

    fn init() !LocalNode {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buffer);
        const path = try gpa.dupe(u8, buffer[0..len]);
        errdefer gpa.free(path);
        const bind = try Io.net.IpAddress.parse("127.0.0.1", 0);
        const socket = try bind.bind(io, .{ .mode = .stream });
        defer socket.close(io);
        const address = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{socket.address.getPort()});
        return .{
            .tmp = tmp,
            .path = path,
            .address = address,
            .member = .{.{ .id = 1, .address = address }},
        };
    }

    fn open(self: *LocalNode) !void {
        self.node = try zx.Embedded.open(gpa, io, .{
            .directory = self.path,
            .node_id = 1,
            .members = &self.member,
            .allow_insecure_test_tcp = true,
        });
    }

    fn deinit(self: *LocalNode) void {
        if (self.node) |node| node.close();
        gpa.free(self.address);
        gpa.free(self.path);
        self.tmp.cleanup();
    }
};

test "stop with an outstanding applied wait closes and can restart the same endpoint" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var local = try LocalNode.init();
    defer local.deinit();
    try local.open();
    const endpoint = try client.Endpoint.parse(local.address);
    const waiting = try client.Connection.open(gpa, io, endpoint);
    defer waiting.close();
    const Worker = struct {
        connection: *client.Connection,
        fn run(self: *@This()) void {
            const body = self.connection.callWithDeadline(
                "{\"op\":\"wait\",\"applied\":999999,\"timeout_ms\":60000}",
                after(4000),
            ) catch return;
            gpa.free(body);
        }
    };
    var worker = Worker{ .connection = waiting };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    const stop = try client.Connection.open(gpa, io, endpoint);
    defer stop.close();
    const response = try stop.callWithDeadline("{\"op\":\"stop\"}", after(2000));
    defer gpa.free(response);
    try testing.expectEqualStrings("{\"ok\":true}", response);
    const end = after(2000);
    while (!local.node.?.finished.load(.acquire)) {
        if (expired(end)) return error.CleanStopDidNotFinish;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    switch (local.node.?.localServerState()) {
        .stopped => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.CleanStopStateMismatch,
    }
    local.node.?.close();
    local.node = null;
    thread.join();
    try testing.expect(!expired(end));
    try local.open();
}

test "embedded exposes a real local storage failure and stops with code four" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var local = try LocalNode.init();
    defer local.deinit();
    try local.open();
    const embedded = local.node.?;

    _ = try embedded.exec("create table fatal_probe(id integer)");
    var response = try embedded.call("{\"op\":\"anchor\"}", false);
    gpa.free(response);

    const trim_path = try std.fmt.allocPrint(gpa, "{s}/consensus/TRIM", .{local.path});
    defer gpa.free(trim_path);
    try Io.Dir.cwd().deleteFile(io, trim_path);
    try Io.Dir.cwd().createDir(io, trim_path, @fromBackingInt(@intCast(0o700)));

    _ = try embedded.exec("insert into fatal_probe values (1)");
    response = try embedded.call("{\"op\":\"anchor\"}", false);
    defer gpa.free(response);
    try testing.expect(std.mem.indexOf(u8, response, "internal") != null);
    const end = after(2000);
    while (switch (embedded.localServerState()) {
        .failed => false,
        else => true,
    }) {
        if (expired(end)) return error.LocalFailureNotPublished;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    switch (embedded.localServerState()) {
        .failed => |name| try testing.expect(name.len != 0),
        else => return error.LocalFailureStateMismatch,
    }
    try testing.expectError(
        error.LocalNodeFailed,
        embedded.exec("insert into fatal_probe values (2)"),
    );
    try testing.expectError(
        error.LocalNodeFailed,
        embedded.query(gpa, "select * from fatal_probe"),
    );
    try testing.expectError(error.LocalNodeFailed, embedded.call("{\"op\":\"status\"}", false));
    while (!embedded.finished.load(.acquire)) {
        if (expired(end)) return error.FailedServerDidNotFinish;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    try testing.expectEqual(@as(u8, 4), embedded.exit_code.load(.acquire));
    const close_end = after(2000);
    embedded.close();
    local.node = null;
    try testing.expect(!expired(close_end));
}

test "zero startup budget stops and joins the newly spawned server" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var local = try LocalNode.init();
    defer local.deinit();
    const end = after(2000);
    try testing.expectError(error.ServerStartupTimeout, zx.Embedded.open(gpa, io, .{
        .directory = local.path,
        .node_id = 1,
        .members = &local.member,
        .allow_insecure_test_tcp = true,
        .startup_timeout_ms = 0,
    }));
    try testing.expect(!expired(end));
    try local.open();
}

test "partial authentication progress does not renew the deadline" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.drip);
    defer peer.stop();
    try peer.start();
    const end = after(500);
    try testing.expectError(error.Timeout, client.Connection.openWithTransport(
        gpa,
        io,
        peer.endpoint(),
        .{ .secret = "secret", .connect_timeout_ms = 80 },
    ));
    try testing.expect(!expired(end));
}

test "embedded close interrupts an outbound peer still authenticating" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    var local = try LocalNode.init();
    defer local.deinit();
    const peer_address = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{peer.endpoint().port});
    defer gpa.free(peer_address);
    const members = [_]zx.EmbeddedMember{ local.member[0], .{ .id = 2, .address = peer_address } };
    local.node = try zx.Embedded.open(gpa, io, .{
        .directory = local.path,
        .node_id = 1,
        .members = &members,
        .auth_secret = cluster_secret,
        .allow_psk_only_loopback = true,
    });
    peer.accepted.waitUncancelable(io);
    const end = after(2000);
    local.node.?.close();
    local.node = null;
    try testing.expect(!expired(end));
}

test "gateway close interrupts both directions of a silent backend connection" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    var local = try LocalNode.init();
    defer local.deinit();
    const backend = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{peer.endpoint().port});
    defer gpa.free(backend);
    const members = [_]zx.EmbeddedMember{
        .{ .id = 1, .address = local.address, .role = .gateway },
        .{ .id = 2, .address = backend },
    };
    local.node = try zx.Embedded.open(gpa, io, .{
        .directory = local.path,
        .node_id = 1,
        .members = &members,
        .allow_insecure_test_tcp = true,
    });
    // Startup itself probes the gateway and therefore creates a backend stream.
    peer.accepted.waitUncancelable(io);
    const end = after(2000);
    local.node.?.close();
    local.node = null;
    try testing.expect(!expired(end));
}

test "TLS authentication to a silent endpoint shares the establishment budget" {
    var guard = Guard{};
    try guard.start();
    defer guard.stop();
    var local = try LocalNode.init();
    defer local.deinit();
    const cert = try std.fmt.allocPrint(gpa, "{s}/node.crt", .{local.path});
    defer gpa.free(cert);
    const key = try std.fmt.allocPrint(gpa, "{s}/node.key", .{local.path});
    defer gpa.free(key);
    const generated = try std.process.run(gpa, io, .{ .argv = &.{
        "openssl",  "req",                     "-x509",   "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",  "-subj",   "/CN=zaxon-node-1",
        "-days",    "1",                       "-keyout", key,       "-out",
        cert,
    } });
    defer gpa.free(generated.stdout);
    defer gpa.free(generated.stderr);
    try testing.expect(generated.term == .exited and generated.term.exited == 0);
    var context = try zx.tls.Context.initClient(.{
        .cert_path = cert,
        .key_path = key,
        .ca_path = cert,
    });
    defer context.deinit();
    var peer = try Peer.init(.silent);
    defer peer.stop();
    try peer.start();
    try testing.expectError(error.Timeout, client.Connection.openWithTransport(
        gpa,
        io,
        peer.endpoint(),
        .{ .tls = &context, .secret = "secret", .connect_timeout_ms = 80 },
    ));
}

const Status = struct {
    role: []const u8,
    journal_records: u64,
};

fn status(connection: *client.Connection) !std.json.Parsed(Status) {
    const body = try connection.callWithDeadline("{\"op\":\"status\"}", after(1000));
    defer gpa.free(body);
    return std.json.parseFromSlice(Status, gpa, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

const WriteWorker = struct {
    connection: *client.Connection,
    done: Io.Event = .unset,
    succeeded: bool = false,

    fn run(self: *WriteWorker) void {
        defer self.done.set(io);
        const body = self.connection.callWithDeadline(
            "{\"op\":\"exec\",\"sql\":\"create table if not exists shutdown_probe(id integer)\"}",
            after(12000),
        ) catch return;
        defer gpa.free(body);
        self.succeeded = std.mem.startsWith(u8, body, "{\"ok\":true");
    }
};

test "three-node PSK leader stops with a durable proposal and queued writers" {
    var guard = Guard{};
    // Election/setup may take longer on a loaded CI host; shutdown itself is
    // measured separately and must finish long before the writers' deadlines.
    try guard.start();
    defer guard.stop();
    var first = try LocalNode.init();
    defer first.deinit();
    var second = try LocalNode.init();
    defer second.deinit();
    var third = try LocalNode.init();
    defer third.deinit();
    const locals = [_]*LocalNode{ &first, &second, &third };
    const members = [_]zx.EmbeddedMember{
        .{ .id = 1, .address = first.address },
        .{ .id = 2, .address = second.address },
        .{ .id = 3, .address = third.address },
    };
    for (locals, 0..) |local, index| {
        local.node = try zx.Embedded.open(gpa, io, .{
            .directory = local.path,
            .node_id = @intCast(index + 1),
            .members = &members,
            .auth_secret = cluster_secret,
            .allow_psk_only_loopback = true,
            .enable_test_faults = true,
            .test_faults = .{ .vote_delay_ms = 60_000 },
        });
    }
    try stopLeaderWithWrites(&locals);
}

fn stopLeaderWithWrites(locals: []const *LocalNode) !void {
    const end = after(2500);
    while (!expired(end)) {
        for (locals) |local| {
            const endpoint = try client.Endpoint.parse(local.address);
            const control = try client.Connection.openWithSecret(gpa, io, endpoint, cluster_secret);
            defer control.close();
            const snapshot = try status(control);
            defer snapshot.deinit();
            if (!std.mem.eql(u8, snapshot.value.role, "leader")) continue;
            try stopWithWrites(local, control, endpoint, snapshot.value.journal_records);
            return;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.LeaderNotElected;
}

fn stopWithWrites(
    local: *LocalNode,
    control: *client.Connection,
    endpoint: client.Endpoint,
    baseline_records: u64,
) !void {
    var workers: [3]WriteWorker = undefined;
    var threads: [3]std.Thread = undefined;
    var started: usize = 0;
    defer for (workers[0..started], threads[0..started]) |worker, thread| {
        thread.join();
        worker.connection.close();
    };
    for (&workers, &threads) |*worker, *thread| {
        const connection = try client.Connection.openWithSecret(gpa, io, endpoint, cluster_secret);
        worker.* = .{ .connection = connection };
        thread.* = std.Thread.spawn(.{}, WriteWorker.run, .{worker}) catch |err| {
            connection.close();
            return err;
        };
        started += 1;
    }
    const end = after(1000);
    while (true) {
        const snapshot = try status(control);
        defer snapshot.deinit();
        if (snapshot.value.journal_records > baseline_records) break;
        if (expired(end)) return error.ProposalNotPersisted;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    for (&workers) |*worker| try testing.expect(!worker.done.isSet());
    const stop_end = after(2000);
    const response = try control.callWithDeadline("{\"op\":\"stop\"}", stop_end);
    defer gpa.free(response);
    try testing.expectEqualStrings("{\"ok\":true}", response);
    local.node.?.close();
    local.node = null;
    for (&workers) |*worker| {
        while (!worker.done.isSet()) {
            if (expired(stop_end)) return error.HandlerDidNotStop;
            worker.done.waitTimeout(io, .{ .deadline = stop_end }) catch {};
        }
        try testing.expect(!worker.succeeded);
    }
    try testing.expect(!expired(stop_end));
}

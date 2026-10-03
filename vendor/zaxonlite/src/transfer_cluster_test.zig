//! The beyond-retention state-transfer integration controller (ZDS 0011).
//!
//! Spawns a three-voter mTLS cluster with test-sized journal segments,
//! drives enough decisions to rotate and physically reclaim history below
//! a certified chosen trim, then replaces a voter. The replacement joins
//! with nothing, and the reclaimed prefix forces the anchor-pinned state
//! transfer instead of range catch-up. The join runs a crash ladder: the
//! receiver dies at every stateless-phase transfer failpoint in sequence
//! (`after_transfer_resume` is not a rung — it differs from
//! `after_transfer_anchor` by in-memory state only, and a crash at or
//! after the durable anchor ends the stateless phase), the sender dies
//! mid-copy while pinning, and the final clean start must converge from
//! the durable anchor it already installed.
//!
//! Usage: transfer-cluster-test <path-to-zaxon>

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;
const tls = zaxonlite.tls;
const PortReservations = @import("test_ports.zig").FourReservations;

const Endpoint = client.Endpoint;

/// Test-only journal geometry: segments rotate every 256 records, so a
/// few hundred writes produce several sealed segments to reclaim.
const segment_records = "256";
const seed_rows = 600;

const NodeProc = struct {
    id: u32,
    port: u16,
    directory: []const u8,
    log_path: []const u8,
    cert: []const u8,
    key: []const u8,
    child: ?std.process.Child = null,
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    ca_path: []const u8,
    ca_key_path: []const u8,
    nodes: [4]NodeProc,
    replacement_port: u16,
    port_reservations: *PortReservations,
    admin: tls.Context,

    fn endpointOf(self: *Cluster, index: usize) Endpoint {
        return .{ .host = "127.0.0.1", .port = self.nodes[index].port };
    }

    /// Spawns one node. `peer_ids`/`peer_ports` describe its --peer flags;
    /// `env_failpoint` arms a crash inside the process via /usr/bin/env.
    fn spawnNode(
        self: *Cluster,
        index: usize,
        peer_ids: []const u32,
        peer_ports: []const u16,
        env_failpoint: ?[]const u8,
    ) !void {
        const node = &self.nodes[index];
        std.debug.assert(node.child == null);

        // Hold every kernel-selected port until its owning child is spawned.
        self.port_reservations.release(self.io, index);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.gpa);
        var scratch: std.ArrayList([]u8) = .empty;
        defer {
            for (scratch.items) |item| self.gpa.free(item);
            scratch.deinit(self.gpa);
        }

        if (env_failpoint) |failpoint| {
            const assignment = try std.fmt.allocPrint(
                self.gpa,
                "ZAXON_FAILPOINT={s}",
                .{failpoint},
            );
            try scratch.append(self.gpa, assignment);
            try argv.appendSlice(self.gpa, &.{ "/usr/bin/env", assignment });
        }
        try argv.appendSlice(self.gpa, &.{ self.zaxon, "serve", "--data", node.directory });
        const node_text = try std.fmt.allocPrint(self.gpa, "{d}", .{node.id});
        try scratch.append(self.gpa, node_text);
        try argv.appendSlice(self.gpa, &.{ "--node", node_text });
        const listen_text = try std.fmt.allocPrint(
            self.gpa,
            "127.0.0.1:{d}",
            .{node.port},
        );
        try scratch.append(self.gpa, listen_text);
        try argv.appendSlice(self.gpa, &.{ "--listen", listen_text });
        for (peer_ids, peer_ports) |peer_id, peer_port| {
            const peer_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}@127.0.0.1:{d}",
                .{ peer_id, peer_port },
            );
            try scratch.append(self.gpa, peer_text);
            try argv.appendSlice(self.gpa, &.{ "--peer", peer_text });
        }
        try argv.appendSlice(self.gpa, &.{
            "--tls-cert", node.cert,
            "--tls-key",  node.key,
            "--tls-ca",   self.ca_path,
        });
        try argv.appendSlice(self.gpa, &.{
            "--enrollment-ca-key", self.ca_key_path,
        });
        try argv.appendSlice(self.gpa, &.{ "--admin", "ops" });
        try argv.appendSlice(self.gpa, &.{ "--sync", "os" });
        try argv.append(self.gpa, "--enable-failpoints");
        try argv.appendSlice(self.gpa, &.{ "--segment-records", segment_records });

        const log_file = try Io.Dir.cwd().createFile(self.io, node.log_path, .{});
        node.child = try std.process.spawn(self.io, .{
            .argv = argv.items,
            .stdin = .ignore,
            .stdout = .{ .file = log_file },
            .stderr = .{ .file = log_file },
        });
        log_file.close(self.io);
    }

    fn killNode(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            child.kill(self.io);
            node.child = null;
            self.io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
    }

    fn waitNodeExit(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            _ = child.wait(self.io) catch {};
            node.child = null;
            self.io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
    }

    fn killAll(self: *Cluster) void {
        for (0..self.nodes.len) |index| self.killNode(index);
    }
};

var progress_step: []const u8 = "init";

fn step(name: []const u8) void {
    progress_step = name;
    std.debug.print("== {s}\n", .{name});
}

fn fail(cluster: *Cluster, comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(
        "FAILED at step '{s}': " ++ format ++ "\n",
        .{progress_step} ++ args,
    );
    for (cluster.nodes) |node| {
        std.debug.print("---- node {d} log tail ----\n", .{node.id});
        const body = Io.Dir.cwd().readFileAlloc(
            cluster.io,
            node.log_path,
            cluster.gpa,
            .limited(1 << 20),
        ) catch continue;
        defer cluster.gpa.free(body);
        const start = if (body.len > 4000) body.len - 4000 else 0;
        std.debug.print("{s}\n", .{body[start..]});
    }
    cluster.killAll();
    std.process.exit(1);
}

fn rpcTry(cluster: *Cluster, endpoint: Endpoint, request: []const u8) ?[]u8 {
    const connection = client.Connection.openWithTransport(
        cluster.gpa,
        cluster.io,
        endpoint,
        .{ .tls = &cluster.admin },
    ) catch return null;
    defer connection.close();
    return connection.call(request) catch null;
}

const Parsed = std.json.Parsed(std.json.Value);

fn parse(cluster: *Cluster, body: []const u8) Parsed {
    return std.json.parseFromSlice(std.json.Value, cluster.gpa, body, .{}) catch
        fail(cluster, "malformed JSON response: {s}", .{body});
}

fn field(parsed: *const Parsed, name: []const u8) ?std.json.Value {
    return switch (parsed.value) {
        .object => |object| object.get(name),
        else => null,
    };
}

fn fieldInt(parsed: *const Parsed, name: []const u8) ?i64 {
    const value = field(parsed, name) orelse return null;
    return switch (value) {
        .integer => |n| n,
        else => null,
    };
}

fn isOk(parsed: *const Parsed) bool {
    const value = field(parsed, "ok") orelse return false;
    return value == .bool and value.bool;
}

/// Sends `request` to any endpoint until an ok response arrives, retrying
/// through elections and the membership handover's write pause.
fn mustCallAny(
    cluster: *Cluster,
    endpoints: []const Endpoint,
    request: []const u8,
    deadline_ms: u64,
) []u8 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        for (endpoints) |endpoint| {
            const body = rpcTry(cluster, endpoint, request) orelse continue;
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (isOk(&parsed)) return body;
            cluster.gpa.free(body);
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "rpc deadline exceeded: {s}", .{request});
}

/// Reads one integer status field from one node, or null while the node
/// is unreachable or not ok.
fn statusInt(cluster: *Cluster, endpoint: Endpoint, name: []const u8) ?i64 {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse
        return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    return fieldInt(&parsed, name);
}

/// Polls one status field until `minimum` is reached.
fn waitStatusAtLeast(
    cluster: *Cluster,
    endpoint: Endpoint,
    name: []const u8,
    minimum: i64,
    deadline_ms: u64,
) i64 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, name)) |value| {
            if (value >= minimum) return value;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "status {s} never reached {d} at port {d}", .{
        name,
        minimum,
        endpoint.port,
    });
}

fn waitForConfiguration(
    cluster: *Cluster,
    endpoint: Endpoint,
    configuration_id: i64,
    deadline_ms: u64,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, "configuration_id")) |id| {
            if (id == configuration_id) return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for configuration {d} at port {d}", .{
        configuration_id,
        endpoint.port,
    });
}

/// Waits until a surviving voter (node 1 or 2) is the known leader and
/// returns its node index; the retired voter may be advertised for a
/// few ticks after the handover.
fn waitForSurvivorLeader(
    cluster: *Cluster,
    endpoints: []const Endpoint,
    deadline_ms: u64,
) usize {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        for (endpoints[0..2]) |endpoint| {
            if (statusInt(cluster, endpoint, "leader")) |leader| {
                if (leader == 1 or leader == 2) {
                    return @intCast(leader - 1);
                }
            }
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "no surviving voter became leader", .{});
}

fn waitForLeader(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) u32 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, "leader")) |leader| {
            return @intCast(leader);
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for a leader at port {d}", .{endpoint.port});
}

/// The row count of table t at `level`, served by any of `endpoints`.
fn countRows(
    cluster: *Cluster,
    endpoints: []const Endpoint,
    comptime level: []const u8,
    deadline_ms: u64,
) i64 {
    const body = mustCallAny(
        cluster,
        endpoints,
        "{\"op\":\"query\",\"sql\":\"select count(*) from t\"," ++
            "\"level\":\"" ++ level ++ "\"}",
        deadline_ms,
    );
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    const rows = field(&parsed, "rows") orelse
        fail(cluster, "count reply missing rows: {s}", .{body});
    if (rows != .array or rows.array.items.len != 1) {
        fail(cluster, "unexpected count shape: {s}", .{body});
    }
    const first = rows.array.items[0];
    if (first != .array or first.array.items.len != 1) {
        fail(cluster, "unexpected count row shape: {s}", .{body});
    }
    return switch (first.array.items[0]) {
        .integer => |n| n,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch
            fail(cluster, "unparsable count: {s}", .{body}),
        else => fail(cluster, "unexpected count cell: {s}", .{body}),
    };
}

fn runProgram(io: Io, argv: []const []const u8) !void {
    // Inherit stderr so a failing child leaves its diagnostic in the
    // controller's output instead of vanishing.
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.ProgramFailed;
}

fn generateTlsIdentity(
    gpa: std.mem.Allocator,
    io: Io,
    dir: []const u8,
    name: []const u8,
    signer: ?[]const u8,
    common_name: []const u8,
) !void {
    const key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, name });
    defer gpa.free(key);
    const crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, name });
    defer gpa.free(crt);
    const subject = try std.fmt.allocPrint(gpa, "/CN={s}", .{common_name});
    defer gpa.free(subject);
    try runProgram(io, &.{
        "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
        "-out",    key,
    });
    const signing = signer orelse {
        try runProgram(io, &.{
            "openssl", "req", "-x509", "-new", "-key",  key,
            "-out",    crt,   "-days", "2",    "-subj", subject,
        });
        return;
    };
    const csr = try std.fmt.allocPrint(gpa, "{s}/{s}.csr", .{ dir, name });
    defer gpa.free(csr);
    const signer_key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, signing });
    defer gpa.free(signer_key);
    const signer_crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, signing });
    defer gpa.free(signer_crt);
    try runProgram(io, &.{
        "openssl", "req", "-new", "-key", key, "-out", csr, "-subj", subject,
    });
    try runProgram(io, &.{
        "openssl", "x509",     "-req",   "-in",      csr,
        "-CA",     signer_crt, "-CAkey", signer_key, "-CAcreateserial",
        "-out",    crt,        "-days",  "2",
    });
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const zaxon = iterator.next() orelse {
        std.debug.print("usage: transfer-cluster-test <path-to-zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);

    var port_reservations = try PortReservations.init(io);
    defer port_reservations.deinit(io);

    const root = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/zx-transfer-{x}", .{nonce});
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    step("generate cluster CA, node, and admin certificates");
    try generateTlsIdentity(gpa, io, root, "ca", null, "zaxon-transfer-test-ca");
    inline for (.{ 1, 2, 3 }) |node_id| {
        const name = std.fmt.comptimePrint("node{d}", .{node_id});
        const common = std.fmt.comptimePrint("zaxon-node-{d}", .{node_id});
        try generateTlsIdentity(gpa, io, root, name, "ca", common);
    }
    try generateTlsIdentity(gpa, io, root, "admin", "ca", "zaxon-admin-ops");

    const ca_path = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{root});
    defer gpa.free(ca_path);
    const ca_key_path = try std.fmt.allocPrint(gpa, "{s}/ca.key", .{root});
    defer gpa.free(ca_key_path);
    const admin_cert = try std.fmt.allocPrint(gpa, "{s}/admin.crt", .{root});
    defer gpa.free(admin_cert);
    const admin_key = try std.fmt.allocPrint(gpa, "{s}/admin.key", .{root});
    defer gpa.free(admin_key);

    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .ca_path = ca_path,
        .ca_key_path = ca_key_path,
        .nodes = undefined,
        .replacement_port = port_reservations.ports[3],
        .port_reservations = &port_reservations,
        .admin = try tls.Context.initClient(.{
            .cert_path = admin_cert,
            .key_path = admin_key,
            .ca_path = ca_path,
        }),
    };
    inline for (.{ 0, 1, 2 }) |index| {
        const node_id: u32 = index + 1;
        cluster.nodes[index] = .{
            .id = node_id,
            .port = port_reservations.ports[index],
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, node_id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, node_id }),
            .cert = try std.fmt.allocPrint(gpa, "{s}/node{d}.crt", .{ root, node_id }),
            .key = try std.fmt.allocPrint(gpa, "{s}/node{d}.key", .{ root, node_id }),
        };
    }
    cluster.nodes[3] = .{
        .id = 4,
        .port = cluster.replacement_port,
        .directory = try std.fmt.allocPrint(gpa, "{s}/n4", .{root}),
        .log_path = try std.fmt.allocPrint(gpa, "{s}/n4.log", .{root}),
        .cert = try std.fmt.allocPrint(gpa, "{s}/n4-id/node.crt", .{root}),
        .key = try std.fmt.allocPrint(gpa, "{s}/n4-id/node.key", .{root}),
    };
    defer for (cluster.nodes) |node| {
        gpa.free(node.directory);
        gpa.free(node.log_path);
        gpa.free(node.cert);
        gpa.free(node.key);
    };
    defer cluster.killAll();

    try runScenario(&cluster);
    std.debug.print("transfer cluster test: scenario complete\n", .{});
    return 0;
}

fn runScenario(cluster: *Cluster) !void {
    const gpa = cluster.gpa;
    const io = cluster.io;
    const initial_ids = [_]u32{ 1, 2, 3 };
    const initial_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.nodes[2].port,
    };

    step("start the three-voter cluster with test-sized segments");
    try cluster.spawnNode(0, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(1, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(2, &initial_ids, &initial_ports, null);
    const endpoints = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(1),
        cluster.endpointOf(2),
    };
    _ = waitForLeader(cluster, endpoints[0], 30_000);

    step("write enough rows to rotate several journal segments");
    gpa.free(mustCallAny(
        cluster,
        &endpoints,
        "{\"op\":\"exec\",\"sql\":\"create table t(id integer primary key, v text)\"}",
        30_000,
    ));
    for (0..seed_rows) |_| {
        gpa.free(mustCallAny(
            cluster,
            &endpoints,
            "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('seed')\"}",
            30_000,
        ));
    }

    step("anchor every voter and reclaim history below the chosen trim");
    for (0..endpoints.len) |index| {
        gpa.free(mustCallAny(
            cluster,
            endpoints[index .. index + 1],
            "{\"op\":\"anchor\"}",
            30_000,
        ));
    }
    for (endpoints) |endpoint| {
        _ = waitStatusAtLeast(cluster, endpoint, "chosen_trim_slot", 1, 60_000);
        _ = waitStatusAtLeast(cluster, endpoint, "retained_first_slot", 2, 60_000);
    }

    step("replace voter 3; survivors activate the next configuration");
    var replace_buffer: [192]u8 = undefined;
    const replace_request = std.fmt.bufPrint(
        &replace_buffer,
        "{{\"op\":\"replace-voter\",\"operation\":1," ++
            "\"expected_config\":1,\"old_node\":3,\"new_node\":4," ++
            "\"endpoint\":\"127.0.0.1:{d}\"}}",
        .{cluster.replacement_port},
    ) catch unreachable;
    gpa.free(mustCallAny(cluster, &endpoints, replace_request, 60_000));
    waitForConfiguration(cluster, endpoints[0], 2, 60_000);
    waitForConfiguration(cluster, endpoints[1], 2, 60_000);

    step("enroll the replacement voter");
    const token_path = try std.fmt.allocPrint(gpa, "{s}/n4-token", .{cluster.root});
    defer gpa.free(token_path);
    const identity_dir = try std.fmt.allocPrint(gpa, "{s}/n4-id", .{cluster.root});
    defer gpa.free(identity_dir);
    {
        // The retired voter can linger as the advertised leader for a
        // few ticks after the handover; issue the token through a
        // surviving configuration-2 leader, not a fixed node.
        const issuer_index = waitForSurvivorLeader(cluster, &endpoints, 60_000);
        var endpoint_buffer: [32]u8 = undefined;
        const issuer = std.fmt.bufPrint(
            &endpoint_buffer,
            "127.0.0.1:{d}",
            .{cluster.nodes[issuer_index].port},
        ) catch unreachable;
        const admin_cert = try std.fmt.allocPrint(gpa, "{s}/admin.crt", .{cluster.root});
        defer gpa.free(admin_cert);
        const admin_key = try std.fmt.allocPrint(gpa, "{s}/admin.key", .{cluster.root});
        defer gpa.free(admin_key);
        runProgram(io, &.{
            cluster.zaxon,   "enroll-token", "--connect",  issuer,
            "--node",        "4",            "--to",       token_path,
            "--ttl-seconds", "300",          "--tls-cert", admin_cert,
            "--tls-key",     admin_key,      "--tls-ca",   cluster.ca_path,
        }) catch fail(cluster, "enroll-token failed", .{});
        runProgram(io, &.{
            cluster.zaxon,    "enroll",     "--token-file", token_path,
            "--identity-dir", identity_dir, "--data",       cluster.nodes[3].directory,
        }) catch fail(cluster, "enroll failed", .{});
    }

    try runJoinLadder(cluster, &endpoints);
}

/// Whether a node's log (truncated at its last spawn) already carries
/// the crash line the armed failpoint prints before `_exit`.
fn logHasFailpoint(cluster: *Cluster, index: usize, name: []const u8) bool {
    const body = Io.Dir.cwd().readFileAlloc(
        cluster.io,
        cluster.nodes[index].log_path,
        cluster.gpa,
        .limited(1 << 20),
    ) catch return false;
    defer cluster.gpa.free(body);
    var line_buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "failpoint '{s}' hit",
        .{name},
    ) catch unreachable;
    return std.mem.indexOf(u8, body, line) != null;
}

/// Waits, bounded, until `index` dies at exactly the armed failpoint,
/// then reaps the child. A node that exits for any other reason, or a
/// failpoint that never fires, fails the scenario with log diagnostics.
fn waitFailpointExit(
    cluster: *Cluster,
    index: usize,
    name: []const u8,
    deadline_ms: u64,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (logHasFailpoint(cluster, index, name)) {
            cluster.waitNodeExit(index);
            return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "node {d} never hit {s}", .{ cluster.nodes[index].id, name });
}

/// The join crash ladder: the receiver dies at every stateless-phase
/// transfer failpoint in sequence, the sender is killed mid-copy on one
/// rung with another peer completing the send, and the final clean start
/// must converge from the durable anchor. Every rung runs on an
/// otherwise idle cluster: the joiner's leaderless recovery probes are
/// themselves under test. A crash at or after the durable anchor ends
/// the stateless phase, so `after_transfer_anchor` is the last crashing
/// rung; `after_transfer_resume` differs from it by in-memory state
/// only.
fn runJoinLadder(cluster: *Cluster, endpoints: []const Endpoint) !void {
    const gpa = cluster.gpa;
    const updated_ids = [_]u32{ 1, 2, 4 };
    const updated_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.replacement_port,
    };

    step("receiver dies mid-stream on a transferred chunk");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_chunk");
    waitFailpointExit(cluster, 3, "after_transfer_chunk", 180_000);

    step("receiver dies after staging the transferred image");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_stage");
    waitFailpointExit(cluster, 3, "after_transfer_stage", 180_000);

    step("receiver dies after the digest check, before the install rename");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "before_transfer_install");
    waitFailpointExit(cluster, 3, "before_transfer_install", 180_000);

    step("receiver dies after the install rename, before the anchor");
    // No anchor binds the renamed image, so the next start discards it
    // and transfers again.
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_install");
    waitFailpointExit(cluster, 3, "after_transfer_install", 420_000);

    step("sender dies mid-copy while pinning; another peer completes the send");
    // Node 1 restarts with the pin failpoint in its environment, the
    // same mechanism every receiver rung trusts: it cannot be lost or
    // disarmed by timing. The joiner's recovery probe retreats until a
    // snapshot request is actually sent, and the rotation starts at the
    // lowest registry peer, so the first served request always lands on
    // node 1; it dies mid-copy, the receiver waits out its source pin,
    // and node 2 completes the send. The receiver is armed to die
    // between the durable anchor and the in-memory resume, which also
    // ends the stateless phase.
    cluster.killNode(0);
    try cluster.spawnNode(0, &updated_ids, &updated_ports, "during_transfer_pin");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_anchor");
    waitFailpointExit(cluster, 0, "during_transfer_pin", 180_000);
    try cluster.spawnNode(0, &updated_ids, &updated_ports, null);
    waitFailpointExit(cluster, 3, "after_transfer_anchor", 300_000);

    step("clean start converges from the installed anchor");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, null);
    const receiver = cluster.endpointOf(3);
    waitForConfiguration(cluster, receiver, 2, 60_000);
    const anchor_slot = waitStatusAtLeast(
        cluster,
        receiver,
        "durable_state_slot",
        1,
        180_000,
    );
    for (0..2) |survivor| {
        const retained = statusInt(
            cluster,
            endpoints[survivor],
            "retained_first_slot",
        ) orelse fail(cluster, "survivor status unavailable", .{});
        if (retained <= 1) {
            fail(cluster, "survivor retained genesis; transfer was not forced", .{});
        }
    }

    step("the transferred replica matches its peers and accepts writes");
    const active = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(1),
        receiver,
    };
    _ = waitStatusAtLeast(cluster, receiver, "applied_slot", anchor_slot, 180_000);
    gpa.free(mustCallAny(
        cluster,
        &active,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('post-transfer')\"}",
        60_000,
    ));
    const baseline = countRows(cluster, &active, "linearizable", 60_000);
    if (baseline != seed_rows + 1) {
        fail(cluster, "{d} rows after transfer, expected {d}", .{
            baseline,
            seed_rows + 1,
        });
    }
    const reference = waitReplicaMatch(cluster, active[0], baseline, null, 60_000);
    for (active[1..]) |endpoint| {
        _ = waitReplicaMatch(cluster, endpoint, baseline, reference, 60_000);
    }

    step("the transferred replica survives its own restart");
    cluster.killNode(3);
    try cluster.spawnNode(3, &updated_ids, &updated_ports, null);
    waitForConfiguration(cluster, receiver, 2, 60_000);
    gpa.free(mustCallAny(
        cluster,
        &active,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('post-restart')\"}",
        60_000,
    ));
    const after = countRows(cluster, &active, "linearizable", 60_000);
    if (after != baseline + 1) {
        fail(cluster, "restart count moved from {d} to {d}", .{ baseline, after });
    }
    const restarted = waitReplicaMatch(cluster, active[0], after, null, 60_000);
    for (active[1..]) |endpoint| {
        _ = waitReplicaMatch(cluster, endpoint, after, restarted, 60_000);
    }
}

/// One replica's materialized identity: the row multiset checksum of
/// table t plus the application chain hash from status. Replicas at the
/// same data frontier must agree on every field.
const Fingerprint = struct {
    rows: i64,
    content: [32]u8,
    chain: [64]u8,
};

fn replicaFingerprint(cluster: *Cluster, endpoint: Endpoint) ?Fingerprint {
    const single = [_]Endpoint{endpoint};
    // The canonical ordered row encoding: every id with its value type
    // and exact bytes, so a materialization error that preserves counts
    // and lengths still changes the digest.
    const body = rpcTry(cluster, single[0], "{\"op\":\"query\"," ++
        "\"sql\":\"select count(*), coalesce(group_concat(" ++
        "id || ':' || typeof(v) || ':' || coalesce(hex(v), 'null'), ','), " ++
        "'') from (select id, v from t order by id)\"," ++
        "\"level\":\"any\"}") orelse
        return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    const rows = field(&parsed, "rows") orelse return null;
    if (rows != .array or rows.array.items.len != 1) return null;
    const cells = rows.array.items[0];
    if (cells != .array or cells.array.items.len != 2) return null;
    const encoded = switch (cells.array.items[1]) {
        .string => |text| text,
        else => return null,
    };
    var print = Fingerprint{
        .rows = jsonInt(cells.array.items[0]) orelse return null,
        .content = undefined,
        .chain = undefined,
    };
    std.crypto.hash.sha2.Sha256.hash(encoded, &print.content, .{});
    const status = rpcTry(cluster, single[0], "{\"op\":\"status\"}") orelse
        return null;
    defer cluster.gpa.free(status);
    const status_parsed = parse(cluster, status);
    defer status_parsed.deinit();
    const chain = fieldString(&status_parsed, "chain") orelse return null;
    if (chain.len != 64) return null;
    @memcpy(&print.chain, chain);
    return print;
}

fn jsonInt(value: std.json.Value) ?i64 {
    return switch (value) {
        .integer => |n| n,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch null,
        else => null,
    };
}

fn fieldString(parsed: *const Parsed, name: []const u8) ?[]const u8 {
    const value = field(parsed, name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

/// Polls one replica until its locally served fingerprint reaches
/// `rows` and, when a reference is given, matches it exactly.
/// Replication lag is tolerated; divergence is not.
fn waitReplicaMatch(
    cluster: *Cluster,
    endpoint: Endpoint,
    rows: i64,
    reference: ?Fingerprint,
    deadline_ms: u64,
) Fingerprint {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (replicaFingerprint(cluster, endpoint)) |print| {
            if (print.rows == rows) {
                if (reference) |expected| {
                    if (!std.mem.eql(u8, &print.content, &expected.content) or
                        !std.mem.eql(u8, &print.chain, &expected.chain))
                    {
                        fail(cluster, "port {d} diverges from its peers", .{
                            endpoint.port,
                        });
                    }
                }
                return print;
            }
            if (print.rows > rows) {
                fail(cluster, "port {d} sees {d} rows, expected {d}", .{
                    endpoint.port,
                    print.rows,
                    rows,
                });
            }
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "port {d} never reached {d} rows", .{ endpoint.port, rows });
}

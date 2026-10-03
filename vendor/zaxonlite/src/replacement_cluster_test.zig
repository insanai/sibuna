//! The voter-replacement cluster integration controller.
//!
//! Spawns a three-voter mTLS cluster and drives one decided one-for-one
//! replacement (1,2,3 -> 1,2,4) end to end: admin authorization and its
//! refusals, the privileged request against the leader, survivor rollover
//! through the in-process transport swap while a client TCP connection
//! stays open, a crash injected inside the swap, retirement of the
//! replaced voter, idempotent operation retry, flag precedence against
//! the decided registry on restart, and in-process/restart equivalence by
//! registry digest.
//!
//! The replacement voter itself enrolls and catches up in a later phase;
//! this controller proves the survivors and the decision path.
//!
//! Usage: replace-cluster-test <path-to-zaxon>

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;
const tls = zaxonlite.tls;
const PortReservations = @import("test_ports.zig").FourReservations;

const Endpoint = client.Endpoint;

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

        // The kernel-selected port stays unavailable to every other process
        // until the child that owns it is ready to be spawned.
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
        // Keep automatic anchors out of the handover/transfer assertions.
        try argv.appendSlice(self.gpa, &.{
            "--test-anchor-interval-ms",
            "3600000",
        });

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

fn logContains(cluster: *Cluster, index: usize, needle: []const u8) bool {
    const body = Io.Dir.cwd().readFileAlloc(
        cluster.io,
        cluster.nodes[index].log_path,
        cluster.gpa,
        .limited(1 << 20),
    ) catch return false;
    defer cluster.gpa.free(body);
    return std.mem.indexOf(u8, body, needle) != null;
}

fn statusInt(cluster: *Cluster, endpoint: Endpoint, name: []const u8) ?i64 {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    return fieldInt(&parsed, name);
}

fn statusDatabaseId(cluster: *Cluster, endpoint: Endpoint) u128 {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse
        fail(cluster, "status unavailable at port {d}", .{endpoint.port});
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    const text = fieldString(&parsed, "database_id") orelse
        fail(cluster, "status has no database_id", .{});
    return std.fmt.parseInt(u128, text, 16) catch
        fail(cluster, "invalid database_id {s}", .{text});
}

fn waitForInstalled(
    cluster: *Cluster,
    endpoint: Endpoint,
    minimum_applied: u64,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= 60_000) : (elapsed += 50) {
        const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse {
            cluster.io.sleep(.fromMilliseconds(50), .awake) catch {};
            continue;
        };
        defer cluster.gpa.free(body);
        const parsed = parse(cluster, body);
        defer parsed.deinit();
        const state = fieldString(&parsed, "installation_state") orelse continue;
        const applied = fieldInt(&parsed, "applied_slot") orelse continue;
        if ((std.mem.eql(u8, state, "installed") or
            std.mem.eql(u8, state, "active")) and applied >= minimum_applied) return;
        cluster.io.sleep(.fromMilliseconds(50), .awake) catch {};
    }
    fail(cluster, "replacement did not install through slot {d}", .{minimum_applied});
}

fn appliedAnchor(
    cluster: *Cluster,
    index: usize,
    database_id: u128,
) ?zaxonlite.applied_anchor.Anchor {
    var node_dir = Io.Dir.cwd().openDir(
        cluster.io,
        cluster.nodes[index].directory,
        .{},
    ) catch return null;
    defer node_dir.close(cluster.io);
    var consensus = node_dir.openDir(cluster.io, "consensus", .{}) catch return null;
    defer consensus.close(cluster.io);
    return zaxonlite.applied_anchor.select(cluster.io, consensus, database_id);
}

fn waitForAnchorConfiguration(
    cluster: *Cluster,
    index: usize,
    database_id: u128,
    configuration_id: u64,
) zaxonlite.applied_anchor.Anchor {
    var elapsed: u64 = 0;
    while (elapsed <= 30_000) : (elapsed += 25) {
        if (appliedAnchor(cluster, index, database_id)) |anchor| {
            if (anchor.configuration_id == configuration_id) return anchor;
        }
        cluster.io.sleep(.fromMilliseconds(25), .awake) catch {};
    }
    fail(cluster, "node {d} did not publish configuration {d} anchor", .{
        cluster.nodes[index].id,
        configuration_id,
    });
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

// ----------------------------------------------------------------------
// RPC helpers (admin-certificate TLS client)
// ----------------------------------------------------------------------

fn rpcWith(
    cluster: *Cluster,
    context: *const tls.Context,
    endpoint: Endpoint,
    request: []const u8,
) ?[]u8 {
    const connection = client.Connection.openWithTransport(
        cluster.gpa,
        cluster.io,
        endpoint,
        .{ .tls = context },
    ) catch return null;
    defer connection.close();
    return connection.call(request) catch null;
}

fn rpcTry(cluster: *Cluster, endpoint: Endpoint, request: []const u8) ?[]u8 {
    return rpcWith(cluster, &cluster.admin, endpoint, request);
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

fn fieldString(parsed: *const Parsed, name: []const u8) ?[]const u8 {
    const value = field(parsed, name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn isOk(parsed: *const Parsed) bool {
    const value = field(parsed, "ok") orelse return false;
    return value == .bool and value.bool;
}

/// Sends `request` to any endpoint until an ok response arrives, retrying
/// through elections, rollovers, and the swap's write pause.
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

const MembershipView = struct {
    configuration_id: u64,
    phase: [32]u8,
    phase_len: usize,
    digest: [64]u8,
    voters: [8]u32,
    voter_count: usize,

    fn phaseSlice(self: *const MembershipView) []const u8 {
        return self.phase[0..self.phase_len];
    }
};

fn membershipView(cluster: *Cluster, endpoint: Endpoint) ?MembershipView {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"membership\"}") orelse
        return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    var view = MembershipView{
        .configuration_id = @intCast(fieldInt(&parsed, "configuration_id") orelse
            return null),
        .phase = undefined,
        .phase_len = 0,
        .digest = undefined,
        .voters = undefined,
        .voter_count = 0,
    };
    const phase = fieldString(&parsed, "phase") orelse return null;
    view.phase_len = @min(phase.len, view.phase.len);
    @memcpy(view.phase[0..view.phase_len], phase[0..view.phase_len]);
    const digest = fieldString(&parsed, "registry_digest") orelse return null;
    if (digest.len != 64) return null;
    @memcpy(&view.digest, digest);
    const nodes = field(&parsed, "nodes") orelse return null;
    if (nodes != .array) return null;
    for (nodes.array.items) |item| {
        if (item != .object) return null;
        const role = item.object.get("role") orelse return null;
        if (role != .string) return null;
        const votes = std.mem.eql(u8, role.string, "data-voter") or
            std.mem.eql(u8, role.string, "witness");
        if (!votes) continue;
        const id = item.object.get("id") orelse return null;
        if (id != .integer) return null;
        if (view.voter_count == view.voters.len) return null;
        view.voters[view.voter_count] = @intCast(id.integer);
        view.voter_count += 1;
    }
    return view;
}

fn waitForConfiguration(
    cluster: *Cluster,
    endpoint: Endpoint,
    configuration_id: u64,
    deadline_ms: u64,
) MembershipView {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (membershipView(cluster, endpoint)) |view| {
            if (view.configuration_id == configuration_id) return view;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for configuration {d} at port {d}", .{
        configuration_id,
        endpoint.port,
    });
}

fn statusLeader(cluster: *Cluster, endpoint: Endpoint) ?u32 {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse
        return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    const leader = fieldInt(&parsed, "leader") orelse return null;
    return @intCast(leader);
}

fn waitForLeader(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) u32 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusLeader(cluster, endpoint)) |leader| return leader;
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for a leader at port {d}", .{endpoint.port});
}

/// Polls status until trim coordination has chosen a nonzero trim slot.
/// A survivor whose journal replay froze the pre-handover configuration
/// hashes its history leaves differently, so every trim round dies on
/// error.HistoryMismatch and the chosen slot never advances.
fn waitForTrimSlot(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        poll: {
            const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse
                break :poll;
            defer cluster.gpa.free(body);
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (!isOk(&parsed)) break :poll;
            const slot = fieldInt(&parsed, "chosen_trim_slot") orelse break :poll;
            if (slot > 0) return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "chosen_trim_slot never advanced at port {d}; " ++
        "diverged history hashes freeze trim coordination", .{endpoint.port});
}

fn expectErrorCode(
    cluster: *Cluster,
    body: ?[]u8,
    expected: []const u8,
) void {
    const bytes = body orelse fail(cluster, "expected a response", .{});
    defer cluster.gpa.free(bytes);
    const parsed = parse(cluster, bytes);
    defer parsed.deinit();
    if (isOk(&parsed)) fail(cluster, "expected {s}, got ok: {s}", .{ expected, bytes });
    const code = fieldString(&parsed, "error") orelse
        fail(cluster, "missing error code: {s}", .{bytes});
    if (!std.mem.eql(u8, code, expected)) {
        fail(cluster, "expected error {s}, got {s}", .{ expected, bytes });
    }
}

// ----------------------------------------------------------------------
// Certificates
// ----------------------------------------------------------------------

fn runProgram(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
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

// ----------------------------------------------------------------------
// Scenario
// ----------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const zaxon = iterator.next() orelse {
        std.debug.print("usage: replace-cluster-test <path-to-zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);

    var port_reservations = try PortReservations.init(io);
    defer port_reservations.deinit(io);

    const root = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/zx-replace-{x}", .{nonce});
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    step("generate cluster CA, node, admin, and impostor certificates");
    try generateTlsIdentity(gpa, io, root, "ca", null, "zaxon-replace-test-ca");
    inline for (.{ 1, 2, 3 }) |node_id| {
        const name = std.fmt.comptimePrint("node{d}", .{node_id});
        const common = std.fmt.comptimePrint("zaxon-node-{d}", .{node_id});
        try generateTlsIdentity(gpa, io, root, name, "ca", common);
    }
    try generateTlsIdentity(gpa, io, root, "admin", "ca", "zaxon-admin-ops");
    try generateTlsIdentity(gpa, io, root, "eve", "ca", "zaxon-admin-eve");

    const ca_path = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{root});
    defer gpa.free(ca_path);
    const ca_key_path = try std.fmt.allocPrint(gpa, "{s}/ca.key", .{root});
    defer gpa.free(ca_key_path);
    const admin_cert = try std.fmt.allocPrint(gpa, "{s}/admin.crt", .{root});
    defer gpa.free(admin_cert);
    const admin_key = try std.fmt.allocPrint(gpa, "{s}/admin.key", .{root});
    defer gpa.free(admin_key);
    const eve_cert = try std.fmt.allocPrint(gpa, "{s}/eve.crt", .{root});
    defer gpa.free(eve_cert);
    const eve_key = try std.fmt.allocPrint(gpa, "{s}/eve.key", .{root});
    defer gpa.free(eve_key);
    const node1_cert = try std.fmt.allocPrint(gpa, "{s}/node1.crt", .{root});
    defer gpa.free(node1_cert);
    const node1_key = try std.fmt.allocPrint(gpa, "{s}/node1.key", .{root});
    defer gpa.free(node1_key);

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
    // The replacement joins with the identity its enrollment issues, not a
    // pre-minted certificate.
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

    const initial_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.nodes[2].port,
    };
    const initial_ids = [_]u32{ 1, 2, 3 };

    step("start the three-voter mTLS cluster");
    // Runtime failpoints are armed after leader discovery, so the crash
    // schedule does not depend on which voter wins the first election.
    try cluster.spawnNode(0, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(1, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(2, &initial_ids, &initial_ports, null);

    const endpoints = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(1),
        cluster.endpointOf(2),
    };

    step("wait for a leader and write through the cluster");
    const first_leader = waitForLeader(&cluster, endpoints[0], 30_000);
    const leader_index: usize = @intCast(first_leader - 1);
    const swap_crash_index: usize = if (leader_index == 1) 0 else 1;
    const held_index: usize = if (swap_crash_index == 0) 1 else 0;
    gpa.free(mustCallAny(
        &cluster,
        &endpoints,
        "{\"op\":\"exec\",\"sql\":\"create table t(id integer primary key, v text)\"}",
        30_000,
    ));
    gpa.free(mustCallAny(
        &cluster,
        &endpoints,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('before-replacement')\"}",
        30_000,
    ));

    step("read the decided membership");
    const before = membershipView(&cluster, endpoints[0]) orelse
        fail(&cluster, "membership unavailable", .{});
    if (before.voter_count != 3) {
        fail(&cluster, "expected 3 voters, got {d}", .{before.voter_count});
    }
    const sealed_configuration = before.configuration_id;
    const next_configuration = sealed_configuration + 1;

    step("refuse a node certificate and an unlisted admin");
    var replace_buffer: [256]u8 = undefined;
    const replace_request = std.fmt.bufPrint(
        &replace_buffer,
        "{{\"op\":\"replace-voter\",\"operation\":1," ++
            "\"expected_config\":{d},\"old_node\":3,\"new_node\":4," ++
            "\"endpoint\":\"127.0.0.1:{d}\"}}",
        .{ sealed_configuration, cluster.replacement_port },
    ) catch unreachable;
    {
        var node_identity = tls.Context.initClient(.{
            .cert_path = node1_cert,
            .key_path = node1_key,
            .ca_path = ca_path,
        }) catch |err| fail(&cluster, "node client context failed: {t}", .{err});
        defer node_identity.deinit();
        expectErrorCode(
            &cluster,
            rpcWith(&cluster, &node_identity, endpoints[0], replace_request),
            "unauthorized",
        );
        var eve_identity = tls.Context.initClient(.{
            .cert_path = eve_cert,
            .key_path = eve_key,
            .ca_path = ca_path,
        }) catch |err| fail(&cluster, "eve client context failed: {t}", .{err});
        defer eve_identity.deinit();
        expectErrorCode(
            &cluster,
            rpcWith(&cluster, &eve_identity, endpoints[0], replace_request),
            "unauthorized",
        );
    }

    step("submit the replacement through the authorized admin");
    {
        const arm_swap = mustCallAny(
            &cluster,
            endpoints[swap_crash_index .. swap_crash_index + 1],
            "{\"op\":\"failpoint\",\"name\":\"before_transport_swap\"}",
            30_000,
        );
        gpa.free(arm_swap);
        const arm = rpcTry(
            &cluster,
            endpoints[leader_index],
            "{\"op\":\"failpoint\",\"name\":\"after_replacement_submission\"}",
        ) orelse fail(&cluster, "failed to arm replacement submission crash", .{});
        gpa.free(arm);
        if (rpcTry(&cluster, endpoints[leader_index], replace_request)) |body| {
            gpa.free(body);
            fail(&cluster, "replacement leader replied past its failpoint", .{});
        }
        cluster.waitNodeExit(leader_index);
        try cluster.spawnNode(leader_index, &initial_ids, &initial_ports, null);
    }

    step("hold one client TCP connection open across the swap");
    _ = waitForLeader(&cluster, endpoints[held_index], 30_000);
    const held = client.Connection.openWithTransport(
        gpa,
        io,
        endpoints[held_index],
        .{ .tls = &cluster.admin },
    ) catch |err| fail(&cluster, "held connection failed: {t}", .{err});
    defer held.close();
    {
        const body = held.call("{\"op\":\"status\"}") catch |err|
            fail(&cluster, "held status failed: {t}", .{err});
        gpa.free(body);
    }

    step("retry the ambiguous request after the leader restarts");
    {
        const body = mustCallAny(&cluster, &endpoints, replace_request, 30_000);
        defer gpa.free(body);
        const parsed = parse(&cluster, body);
        defer parsed.deinit();
        const phase = fieldString(&parsed, "phase") orelse
            fail(&cluster, "missing phase: {s}", .{body});
        if (!std.mem.eql(u8, phase, "proposed") and
            !std.mem.eql(u8, phase, "complete"))
        {
            fail(&cluster, "unexpected phase {s}", .{phase});
        }
    }

    step("wait for the crashed swap survivor to exit and restart it");
    // The armed survivor dies inside the swap window. Its stale
    // bootstrap flags are harmless because the durable registry is now
    // the restart authority.
    cluster.waitNodeExit(swap_crash_index);
    const updated_ids = [_]u32{ 1, 2, 4 };
    const updated_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.replacement_port,
    };
    try cluster.spawnNode(swap_crash_index, &initial_ids, &initial_ports, null);

    step("wait for both survivors to activate the next configuration");
    const after_1 = waitForConfiguration(&cluster, endpoints[0], next_configuration, 60_000);
    const after_2 = waitForConfiguration(&cluster, endpoints[1], next_configuration, 60_000);
    if (!std.mem.eql(u8, &after_1.digest, &after_2.digest)) {
        fail(&cluster, "survivors disagree on the registry digest", .{});
    }
    if (after_1.voter_count != 3) {
        fail(&cluster, "expected 3 voters after replacement", .{});
    }
    const expected_voters = [_]u32{ 1, 2, 4 };
    if (!std.mem.eql(u32, after_1.voters[0..3], &expected_voters)) {
        fail(&cluster, "voters are {any}, expected 1,2,4", .{after_1.voters[0..3]});
    }
    const database_id = statusDatabaseId(&cluster, endpoints[0]);
    const handover_1 = waitForAnchorConfiguration(
        &cluster,
        0,
        database_id,
        next_configuration,
    );
    const handover_2 = waitForAnchorConfiguration(
        &cluster,
        1,
        database_id,
        next_configuration,
    );
    if (handover_1.global_slot != handover_2.global_slot or
        !std.mem.eql(u8, &handover_1.history_hash, &handover_2.history_hash))
    {
        fail(&cluster, "survivors published different handover anchors", .{});
    }
    const stop_slot = handover_1.global_slot;
    if (appliedAnchor(&cluster, 2, database_id)) |retired_anchor| {
        if (retired_anchor.configuration_id != sealed_configuration) {
            fail(&cluster, "retired voter published a later configuration anchor", .{});
        }
    }

    step("the held client connection survived the in-process swap");
    {
        const body = held.call("{\"op\":\"status\"}") catch |err|
            fail(&cluster, "held connection died across the swap: {t}", .{err});
        gpa.free(body);
    }

    step("survivors accept writes in the next configuration");
    const survivor_endpoints = [_]Endpoint{ endpoints[0], endpoints[1] };
    gpa.free(mustCallAny(
        &cluster,
        &survivor_endpoints,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('after-replacement')\"}",
        60_000,
    ));

    step("retrying the same operation is idempotent");
    {
        const body = mustCallAny(&cluster, &survivor_endpoints, replace_request, 30_000);
        defer gpa.free(body);
        const parsed = parse(&cluster, body);
        defer parsed.deinit();
        const phase = fieldString(&parsed, "phase") orelse
            fail(&cluster, "missing phase: {s}", .{body});
        if (!std.mem.eql(u8, phase, "complete")) {
            fail(&cluster, "retry phase is {s}, expected complete", .{phase});
        }
        const configuration = fieldInt(&parsed, "configuration_id") orelse
            fail(&cluster, "missing configuration_id: {s}", .{body});
        if (@as(u64, @intCast(configuration)) != next_configuration) {
            fail(&cluster, "retry names configuration {d}", .{configuration});
        }
    }

    step("a different request under a retained id is rejected");
    {
        var conflict_buffer: [256]u8 = undefined;
        const conflict_request = std.fmt.bufPrint(
            &conflict_buffer,
            "{{\"op\":\"replace-voter\",\"operation\":1," ++
                "\"expected_config\":{d},\"old_node\":2,\"new_node\":9," ++
                "\"endpoint\":\"127.0.0.1:{d}\"}}",
            .{ next_configuration, cluster.replacement_port + 1 },
        ) catch unreachable;
        expectErrorCode(
            &cluster,
            rpcTry(&cluster, survivor_endpoints[0], conflict_request),
            "operation_conflict",
        );
    }

    step("the replaced voter stays sealed on its final configuration");
    {
        var elapsed: u64 = 0;
        var sealed_seen = false;
        while (elapsed <= 30_000) {
            if (membershipView(&cluster, endpoints[2])) |view| {
                if (view.configuration_id == sealed_configuration) {
                    sealed_seen = true;
                    break;
                }
                fail(&cluster, "replaced voter advanced to {d}", .{
                    view.configuration_id,
                });
            }
            elapsed += 250;
            io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
        if (!sealed_seen) fail(&cluster, "replaced voter unreachable", .{});
    }

    step("stale bootstrap flags converge through the decided registry");
    cluster.killNode(0);
    cluster.waitNodeExit(0);
    try cluster.spawnNode(0, &initial_ids, &initial_ports, null);
    const restarted = waitForConfiguration(
        &cluster,
        endpoints[0],
        next_configuration,
        60_000,
    );
    if (!std.mem.eql(u8, &restarted.digest, &after_1.digest)) {
        fail(&cluster, "restart produced a different registry digest", .{});
    }

    step("writes still commit after the restart");
    gpa.free(mustCallAny(
        &cluster,
        &survivor_endpoints,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('after-restart')\"}",
        60_000,
    ));
    {
        const body = mustCallAny(
            &cluster,
            &survivor_endpoints,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t\",\"level\":\"linearizable\"}",
            60_000,
        );
        defer gpa.free(body);
        if (std.mem.indexOf(u8, body, "\"3\"") == null and
            std.mem.indexOf(u8, body, ":3") == null)
        {
            fail(&cluster, "expected 3 rows, got {s}", .{body});
        }
    }

    step("issue an enrollment token for the replacement voter");
    const token_path = try std.fmt.allocPrint(gpa, "{s}/n4-token", .{root});
    defer gpa.free(token_path);
    const identity_dir = try std.fmt.allocPrint(gpa, "{s}/n4-id", .{root});
    defer gpa.free(identity_dir);
    {
        var endpoint_buffer: [32]u8 = undefined;
        const issuer = std.fmt.bufPrint(
            &endpoint_buffer,
            "127.0.0.1:{d}",
            .{cluster.nodes[0].port},
        ) catch unreachable;
        runProgram(io, &.{
            cluster.zaxon,   "enroll-token", "--connect",  issuer,
            "--node",        "4",            "--to",       token_path,
            "--ttl-seconds", "300",          "--tls-cert", admin_cert,
            "--tls-key",     admin_key,      "--tls-ca",   ca_path,
        }) catch fail(&cluster, "enroll-token failed", .{});
    }

    step("enroll the replacement and record its join descriptor");
    runProgram(io, &.{
        cluster.zaxon,    "enroll",     "--token-file", token_path,
        "--identity-dir", identity_dir, "--data",       cluster.nodes[3].directory,
    }) catch fail(&cluster, "enroll failed", .{});

    step("a crash while installing the fetched registry converges by restart");
    // The armed failpoint kills node 4 right after it durably stores the
    // fetched registry blob, before CURRENT and REGISTRY advance. The
    // restart repeats the join from its durable prefix.
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_registry_blob");
    cluster.waitNodeExit(3);

    step("start the replacement voter; it fetches the decided registry");
    for (0..2) |index| {
        const retained = statusInt(&cluster, endpoints[index], "retained_first_slot") orelse
            fail(&cluster, "survivor {d} status unavailable", .{index + 1});
        if (retained != 1) {
            fail(&cluster, "survivor {d} retained history starts at {d}, expected 1", .{
                index + 1,
                retained,
            });
        }
    }
    try cluster.spawnNode(3, &updated_ids, &updated_ports, null);
    const joined = waitForConfiguration(
        &cluster,
        cluster.endpointOf(3),
        next_configuration,
        60_000,
    );
    if (!std.mem.eql(u8, &joined.digest, &after_1.digest)) {
        fail(&cluster, "replacement installed a different registry digest", .{});
    }
    waitForInstalled(&cluster, cluster.endpointOf(3), stop_slot);
    const join_anchor = waitForAnchorConfiguration(
        &cluster,
        3,
        database_id,
        next_configuration,
    );
    if (join_anchor.generation != 1 or join_anchor.global_slot < stop_slot) {
        fail(&cluster, "replacement did not install the handover image", .{});
    }
    var pinning_survivor: ?usize = null;
    for (0..2) |index| {
        if (logContains(&cluster, index, "declining transfer for peer 4")) {
            fail(&cluster, "survivor declined the required replacement image", .{});
        }
        if (logContains(&cluster, index, "pinning transfer image for peer 4")) {
            pinning_survivor = index;
        }
    }
    const sender_index = pinning_survivor orelse
        fail(&cluster, "no survivor pinned an image for peer 4", .{});
    const sender_anchor = appliedAnchor(&cluster, sender_index, database_id) orelse
        fail(&cluster, "pinning survivor has no APPLIED anchor", .{});
    if (sender_anchor.global_slot != join_anchor.global_slot or
        !std.mem.eql(u8, &sender_anchor.history_hash, &join_anchor.history_hash))
    {
        fail(&cluster, "replacement installed a different transfer anchor", .{});
    }

    step("the replacement participates: quorum survives a survivor stop");
    cluster.killNode(1);
    const active_endpoints = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(3),
    };
    gpa.free(mustCallAny(
        &cluster,
        &active_endpoints,
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('with-replacement')\"}",
        60_000,
    ));
    {
        const body = mustCallAny(
            &cluster,
            &active_endpoints,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t\",\"level\":\"linearizable\"}",
            60_000,
        );
        defer gpa.free(body);
        if (std.mem.indexOf(u8, body, "\"4\"") == null and
            std.mem.indexOf(u8, body, ":4") == null)
        {
            fail(&cluster, "expected 4 rows with the replacement voting, got {s}", .{body});
        }
    }
    try cluster.spawnNode(1, &updated_ids, &updated_ports, null);
    _ = waitForConfiguration(&cluster, endpoints[1], next_configuration, 60_000);

    step("the operator CLI reports membership and retries idempotently");
    {
        var endpoint_buffer: [32]u8 = undefined;
        const connect = std.fmt.bufPrint(
            &endpoint_buffer,
            "127.0.0.1:{d}",
            .{cluster.nodes[0].port},
        ) catch unreachable;
        runProgram(io, &.{
            cluster.zaxon, "membership", "status",    "--connect", connect,
            "--tls-cert",  admin_cert,   "--tls-key", admin_key,   "--tls-ca",
            ca_path,       "--json",
        }) catch fail(&cluster, "zaxon membership status failed", .{});
        var operation_buffer: [24]u8 = undefined;
        const expected_text = std.fmt.bufPrint(
            &operation_buffer,
            "{d}",
            .{sealed_configuration},
        ) catch unreachable;
        var new_node_buffer: [40]u8 = undefined;
        const new_node_spec = std.fmt.bufPrint(
            &new_node_buffer,
            "4@127.0.0.1:{d}",
            .{cluster.replacement_port},
        ) catch unreachable;
        runProgram(io, &.{
            cluster.zaxon, "replace-voter", "--connect",         connect,
            "--operation", "1",             "--expected-config", expected_text,
            "--old-node",  "3",             "--new-node",        new_node_spec,
            "--tls-cert",  admin_cert,      "--tls-key",         admin_key,
            "--tls-ca",    ca_path,
        }) catch fail(&cluster, "zaxon replace-voter retry failed", .{});
    }

    step("trim coordination still completes after the replacement");
    // Regression: journal replay across the membership handover once froze
    // the configuration used for history-leaf hashing, so a survivor
    // restarted after the swap disagreed with its peers' history hashes
    // and trim coordination silently stalled on error.HistoryMismatch.
    // Fresh writes plus a durable anchor on every data voter make a trim
    // candidate proposable; the chosen slot must then advance everywhere.
    {
        const voter_endpoints = [_]Endpoint{
            cluster.endpointOf(0),
            cluster.endpointOf(1),
            cluster.endpointOf(3),
        };
        for (0..4) |_| {
            gpa.free(mustCallAny(
                &cluster,
                &voter_endpoints,
                "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('pre-trim')\"}",
                60_000,
            ));
        }
        for (0..voter_endpoints.len) |index| {
            gpa.free(mustCallAny(
                &cluster,
                voter_endpoints[index .. index + 1],
                "{\"op\":\"anchor\"}",
                30_000,
            ));
        }
        for (voter_endpoints) |endpoint| {
            waitForTrimSlot(&cluster, endpoint, 60_000);
        }
    }

    step("stop cluster");
    cluster.killAll();
    std.debug.print("replacement cluster test: scenario complete\n", .{});
    return 0;
}

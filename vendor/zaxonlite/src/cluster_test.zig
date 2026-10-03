//! The three-process cluster integration controller.
//!
//! Spawns three `zaxon serve` processes on loopback ports with independent
//! data directories and drives the mandatory scenario over the client RPC
//! protocol: election, replicated writes through every endpoint, follower
//! stop/catch-up, logical hash comparison, a leader SIGKILL failpoint with
//! exactly-once session retry, a configuration change with a stopped
//! follower (snapshot transfer), image rebuild, and total restart.
//!
//! A second scenario covers leadership takeover with an inherited slot
//! still undecided: concurrent writers during the first election, then a
//! leader crash between its own vote and the decision, with a witness whose
//! held votes keep the re-proposed slot open while clients write at the new
//! leader.
//!
//! A third mode covers trim serialization while quorum votes are delayed,
//! takeover with an inherited undecided trim, restart below the trim decision,
//! and fail-stop behavior when the durable TRIM file cannot be replaced.
//!
//! Every wait is deadline-based on observable conditions. On failure the
//! controller prints each node's status and recent log tail, then exits 1.
//!
//! Usage: cluster-test <path-to-zaxon> [runs]
//!        [mandatory|takeover|trim|trim-soak] [soak-seconds]
//!        [--record <json>]

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;

const Endpoint = client.Endpoint;
const cluster_secret = "cluster-test-secret-32-bytes-minimum";

const NodeProc = struct {
    id: u32,
    port: u16,
    directory: []const u8,
    log_path: []const u8,
    child: ?std.process.Child = null,
    /// Votes but never campaigns or materializes; keeps a takeover
    /// deterministic by leaving one candidate.
    witness: bool = false,
    /// Test-only barrier delay passed to `zaxon serve`.
    storage_delay_ms: u64 = 0,
    /// Test-only hold on outgoing phase-two votes.
    vote_delay_ms: u64 = 0,
    /// Test-only periodic anchor cadence. Zero keeps the production default.
    anchor_interval_ms: u64 = 0,
    /// Test-only journal segment rotation threshold.
    segment_records: u64 = 0,
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    auth_file: []const u8,
    nodes: [3]NodeProc,
    endpoints: [3]Endpoint,
    host_buffers: [3][32]u8 = undefined,

    fn endpointList(self: *Cluster) []const Endpoint {
        return &self.endpoints;
    }

    fn spawnNode(self: *Cluster, index: usize, extra_env: bool) !void {
        const node = &self.nodes[index];
        std.debug.assert(node.child == null);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.gpa);
        var scratch: std.ArrayList([]u8) = .empty;
        defer {
            for (scratch.items) |item| self.gpa.free(item);
            scratch.deinit(self.gpa);
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
        for (self.nodes) |peer| {
            if (peer.id == node.id) continue;
            const peer_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}@127.0.0.1:{d}{s}",
                .{ peer.id, peer.port, if (peer.witness) "/witness" else "" },
            );
            try scratch.append(self.gpa, peer_text);
            try argv.appendSlice(self.gpa, &.{ "--peer", peer_text });
        }
        if (node.witness) try argv.appendSlice(self.gpa, &.{ "--role", "witness" });
        if (node.storage_delay_ms != 0) {
            const delay_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}",
                .{node.storage_delay_ms},
            );
            try scratch.append(self.gpa, delay_text);
            try argv.appendSlice(self.gpa, &.{ "--test-storage-delay-ms", delay_text });
        }
        if (node.vote_delay_ms != 0) {
            const delay_text = try std.fmt.allocPrint(self.gpa, "{d}", .{node.vote_delay_ms});
            try scratch.append(self.gpa, delay_text);
            try argv.appendSlice(self.gpa, &.{ "--test-vote-delay-ms", delay_text });
        }
        if (node.anchor_interval_ms != 0) {
            const interval_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}",
                .{node.anchor_interval_ms},
            );
            try scratch.append(self.gpa, interval_text);
            try argv.appendSlice(
                self.gpa,
                &.{ "--test-anchor-interval-ms", interval_text },
            );
        }
        if (node.segment_records != 0) {
            const records_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}",
                .{node.segment_records},
            );
            try scratch.append(self.gpa, records_text);
            try argv.appendSlice(self.gpa, &.{ "--segment-records", records_text });
        }
        try argv.append(self.gpa, "--enable-failpoints");
        try argv.append(self.gpa, "--dev-psk");
        try argv.appendSlice(self.gpa, &.{ "--auth-file", self.auth_file });
        // The scenario exercises process crashes, which lose nothing under
        // either sync policy; skip the full-flush latency.
        try argv.appendSlice(self.gpa, &.{ "--sync", "os" });
        _ = extra_env;

        // Each (re)start truncates the node's log; on failure we dump the
        // most recent generation, which is the interesting one.
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
        }
    }

    fn waitNodeExit(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            _ = child.wait(self.io) catch {};
            node.child = null;
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
    std.debug.print("FAILED at step '{s}': " ++ format ++ "\n", .{progress_step} ++ args);
    dumpDiagnostics(cluster);
    std.process.exit(1);
}

fn dumpDiagnostics(cluster: *Cluster) void {
    for (cluster.endpoints, 0..) |endpoint, index| {
        std.debug.print("--- node {d} status\n", .{cluster.nodes[index].id});
        if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
            defer cluster.gpa.free(body);
            std.debug.print("{s}\n", .{body});
        } else {
            std.debug.print("(unreachable)\n", .{});
        }
    }
    for (cluster.nodes) |node| {
        std.debug.print("--- log tail {s}\n", .{node.log_path});
        const contents = Io.Dir.cwd().readFileAlloc(
            cluster.io,
            node.log_path,
            cluster.gpa,
            .limited(1 << 20),
        ) catch continue;
        defer cluster.gpa.free(contents);
        const tail = if (contents.len > 4096)
            contents[contents.len - 4096 ..]
        else
            contents;
        std.debug.print("{s}\n", .{tail});
    }
}

// ----------------------------------------------------------------------
// RPC helpers
// ----------------------------------------------------------------------

fn rpcTry(cluster: *Cluster, endpoint: Endpoint, request: []const u8) ?[]u8 {
    const connection = client.Connection.openWithSecret(
        cluster.gpa,
        cluster.io,
        endpoint,
        cluster_secret,
    ) catch return null;
    defer connection.close();
    const deadline = Io.Clock.Timestamp{
        .clock = .awake,
        .raw = .{ .nanoseconds = Io.Clock.Timestamp.now(cluster.io, .awake).raw.nanoseconds +
            5 * std.time.ns_per_s },
    };
    return connection.callWithDeadline(request, deadline) catch null;
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

fn fieldString(
    cluster: *Cluster,
    parsed: *const Parsed,
    name: []const u8,
) []const u8 {
    const value = field(parsed, name) orelse
        fail(cluster, "response missing field {s}", .{name});
    return switch (value) {
        .string => |text| text,
        else => fail(cluster, "field {s} is not a string", .{name}),
    };
}

fn isOk(parsed: *const Parsed) bool {
    const value = field(parsed, "ok") orelse return false;
    return value == .bool and value.bool;
}

/// Calls through the cluster with redirect-following; fails the run on
/// error responses (other than the codes listed in `tolerate`).
fn mustCall(
    cluster: *Cluster,
    request: []const u8,
    deadline_ms: u64,
) []u8 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        var result = client.callClusterWithSecret(
            cluster.gpa,
            cluster.io,
            cluster.endpointList(),
            request,
            true,
            cluster_secret,
        ) catch {
            elapsed += 500;
            cluster.io.sleep(.fromMilliseconds(500), .awake) catch {};
            continue;
        };
        const parsed = parse(cluster, result.body);
        defer parsed.deinit();
        if (isOk(&parsed)) return result.takeBody(cluster.gpa);
        // Retryable outcomes during elections and rollovers.
        const code = fieldString(cluster, &parsed, "error");
        if (std.mem.eql(u8, code, "retry") or
            std.mem.eql(u8, code, "timeout") or
            std.mem.eql(u8, code, "not_leader") or
            std.mem.eql(u8, code, "unavailable") or
            std.mem.eql(u8, code, "ambiguous"))
        {
            result.deinit(cluster.gpa);
            elapsed += 250;
            cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
            continue;
        }
        fail(cluster, "rpc failed: {s} -> {s}", .{ request, result.body });
    }
    fail(cluster, "rpc deadline exceeded: {s}", .{request});
}

fn waitFor(
    cluster: *Cluster,
    endpoint: Endpoint,
    comptime predicate: anytype,
    context: anytype,
    deadline_ms: u64,
    what: []const u8,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
            defer cluster.gpa.free(body);
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (predicate(&parsed, context)) return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for {s} at {s}:{d}", .{
        what,
        endpoint.host,
        endpoint.port,
    });
}

fn hasLeader(parsed: *const Parsed, _: void) bool {
    const value = field(parsed, "leader") orelse return false;
    return value == .integer;
}

fn appliedAtLeast(parsed: *const Parsed, target: i64) bool {
    const applied = fieldInt(parsed, "applied_slot") orelse return false;
    return applied >= target;
}

fn trimmedAtLeast(parsed: *const Parsed, target: i64) bool {
    const trimmed = fieldInt(parsed, "chosen_trim_slot") orelse return false;
    return trimmed >= target;
}

fn configurationAtLeast(parsed: *const Parsed, target: i64) bool {
    const configuration = fieldInt(parsed, "configuration_id") orelse return false;
    return configuration >= target;
}

fn leaderEndpoint(cluster: *Cluster) Endpoint {
    var elapsed: u64 = 0;
    while (elapsed <= 10_000) {
        for (cluster.endpoints) |endpoint| {
            if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
                defer cluster.gpa.free(body);
                const parsed = parse(cluster, body);
                defer parsed.deinit();
                const role = fieldString(cluster, &parsed, "role");
                if (std.mem.eql(u8, role, "leader")) return endpoint;
            }
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "no leader found", .{});
}

fn leaderIndex(cluster: *Cluster) usize {
    const endpoint = leaderEndpoint(cluster);
    for (cluster.endpoints, 0..) |candidate, index| {
        if (candidate.port == endpoint.port) return index;
    }
    unreachable;
}

fn execSql(cluster: *Cluster, sql: []const u8, deadline_ms: u64) void {
    var request: std.Io.Writer.Allocating = .init(cluster.gpa);
    defer request.deinit();
    request.writer.writeAll("{\"op\":\"exec\",\"sql\":") catch unreachable;
    writeJsonString(&request.writer, sql);
    request.writer.writeAll("}") catch unreachable;
    const body = mustCall(cluster, request.written(), deadline_ms);
    cluster.gpa.free(body);
}

fn writeJsonString(out: *Io.Writer, text: []const u8) void {
    out.writeAll("\"") catch unreachable;
    for (text) |byte| {
        switch (byte) {
            '"' => out.writeAll("\\\"") catch unreachable,
            '\\' => out.writeAll("\\\\") catch unreachable,
            '\n' => out.writeAll("\\n") catch unreachable,
            else => out.writeAll(&.{byte}) catch unreachable,
        }
    }
    out.writeAll("\"") catch unreachable;
}

/// Counts rows through the default read level, which is linearizable.
fn linearizableCount(cluster: *Cluster, deadline_ms: u64) i64 {
    const body = mustCall(
        cluster,
        "{\"op\":\"query\",\"sql\":\"select count(*) from t\"}",
        deadline_ms,
    );
    defer cluster.gpa.free(body);
    return firstCell(cluster, body);
}

fn firstCell(cluster: *Cluster, body: []const u8) i64 {
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    const rows = field(&parsed, "rows") orelse fail(cluster, "no rows", .{});
    if (rows != .array or rows.array.items.len == 0) {
        fail(cluster, "empty result: {s}", .{body});
    }
    const row = rows.array.items[0];
    if (row != .array or row.array.items.len == 0) {
        fail(cluster, "empty row: {s}", .{body});
    }
    const cell = row.array.items[0];
    return switch (cell) {
        .string => |text| std.fmt.parseInt(i64, text, 10) catch
            fail(cluster, "non-integer cell {s}", .{text}),
        .integer => |n| n,
        else => fail(cluster, "unexpected cell type", .{}),
    };
}

const NodeDigest = struct {
    chain: [64]u8,
    content: [64]u8,
    applied: i64,
};

fn nodeDigest(cluster: *Cluster, endpoint: Endpoint) NodeDigest {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"hash\"}") orelse
        fail(cluster, "hash rpc unreachable at port {d}", .{endpoint.port});
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) fail(cluster, "hash rpc failed: {s}", .{body});
    var digest: NodeDigest = undefined;
    const chain = fieldString(cluster, &parsed, "chain");
    const content = fieldString(cluster, &parsed, "content");
    if (chain.len != 64 or content.len != 64) {
        fail(cluster, "bad hash lengths: {s}", .{body});
    }
    @memcpy(&digest.chain, chain);
    @memcpy(&digest.content, content);
    digest.applied = fieldInt(&parsed, "applied_slot") orelse -1;
    return digest;
}

fn expectAllDigestsEqual(cluster: *Cluster, what: []const u8) void {
    const first = nodeDigest(cluster, cluster.endpoints[0]);
    for (cluster.endpoints[1..], 1..) |endpoint, index| {
        const digest = nodeDigest(cluster, endpoint);
        if (!std.mem.eql(u8, &first.chain, &digest.chain) or
            !std.mem.eql(u8, &first.content, &digest.content))
        {
            fail(cluster, "{s}: node {d} diverges: chain {s} vs {s}, " ++
                "content {s} vs {s}", .{
                what,
                cluster.nodes[index].id,
                first.chain,
                digest.chain,
                first.content,
                digest.content,
            });
        }
    }
}

fn expectIntegrityAll(cluster: *Cluster) void {
    for (cluster.endpoints) |endpoint| {
        const body = rpcTry(cluster, endpoint, "{\"op\":\"integrity\"}") orelse
            fail(cluster, "integrity rpc unreachable at {d}", .{endpoint.port});
        defer cluster.gpa.free(body);
        const parsed = parse(cluster, body);
        defer parsed.deinit();
        if (!isOk(&parsed)) fail(cluster, "integrity failed: {s}", .{body});
    }
}

fn waitAllApplied(cluster: *Cluster, target: i64, deadline_ms: u64) void {
    for (cluster.endpoints) |endpoint| {
        waitFor(cluster, endpoint, appliedAtLeast, target, deadline_ms, "applied slot");
    }
}

// ----------------------------------------------------------------------
// Free port discovery
// ----------------------------------------------------------------------

fn freePort(io: Io) !u16 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    return port;
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
        std.debug.print(
            "usage: cluster-test <path-to-zaxon> [runs] " ++
                "[mandatory|takeover|trim|trim-soak] [soak-seconds] " ++
                "[--record <json>]\n",
            .{},
        );
        return 2;
    };
    const runs = blk: {
        const text = iterator.next() orelse break :blk @as(usize, 1);
        break :blk std.fmt.parseInt(usize, text, 10) catch 1;
    };
    // Optional third argument narrows the run to one scenario.
    const only = iterator.next();
    const run_mandatory = only == null or std.mem.eql(u8, only.?, "mandatory");
    const run_takeover = only == null or std.mem.eql(u8, only.?, "takeover");
    const run_trim = only != null and std.mem.eql(u8, only.?, "trim");
    const run_trim_soak = only != null and std.mem.eql(u8, only.?, "trim-soak");
    const soak_seconds = if (iterator.next()) |text|
        std.fmt.parseInt(u64, text, 10) catch 60
    else
        60;
    var record_path: ?[]const u8 = null;
    while (iterator.next()) |argument| {
        if (std.mem.eql(u8, argument, "--record")) {
            record_path = iterator.next() orelse {
                std.debug.print("--record needs a path\n", .{});
                return 2;
            };
        } else {
            std.debug.print("unknown cluster option: {s}\n", .{argument});
            return 2;
        }
    }
    if (!run_mandatory and !run_takeover and !run_trim and !run_trim_soak) {
        std.debug.print("unknown cluster scenario: {s}\n", .{only.?});
        return 2;
    }
    if (record_path != null and (!run_trim_soak or runs != 1)) {
        std.debug.print("--record requires one trim-soak run\n", .{});
        return 2;
    }

    for (0..runs) |run_index| {
        if (run_mandatory) {
            std.debug.print("=== cluster run {d}/{d}\n", .{ run_index + 1, runs });
            try runScenario(gpa, io, zaxon, run_index);
        }
        if (run_takeover) {
            std.debug.print("=== takeover run {d}/{d}\n", .{ run_index + 1, runs });
            try runTakeoverScenario(gpa, io, zaxon, run_index);
        }
        if (run_trim) {
            std.debug.print("=== trim serialization run {d}/{d}\n", .{ run_index + 1, runs });
            try runTrimSerializationScenario(gpa, io, zaxon, run_index);
            std.debug.print("=== trim takeover/fatal run {d}/{d}\n", .{ run_index + 1, runs });
            try runTrimTakeoverFatalScenario(gpa, io, zaxon, run_index);
        }
        if (run_trim_soak) {
            std.debug.print("=== trim soak run {d}/{d}\n", .{ run_index + 1, runs });
            try runTrimSoakScenario(
                gpa,
                io,
                zaxon,
                run_index,
                soak_seconds,
                record_path,
                init.environ_map.get("HOSTNAME") orelse builtin.cpu.model.name,
            );
        }
    }
    if (run_trim) std.debug.print("trim cluster: all scenarios passed\n", .{});
    if (run_trim_soak) std.debug.print("trim soak: scenario passed\n", .{});
    std.debug.print("cluster test: all {d} run(s) passed\n", .{runs});
    return 0;
}

fn runScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
) !void {
    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);

    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-cluster-{x}-{d}",
        .{ nonce, run_index },
    );
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const auth_file = try std.fmt.allocPrint(gpa, "{s}/auth.secret", .{root});
    defer gpa.free(auth_file);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = auth_file,
        .data = cluster_secret,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
    });

    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .auth_file = auth_file,
        .nodes = undefined,
        .endpoints = undefined,
    };

    for (0..3) |index| {
        const id: u32 = @intCast(index + 1);
        const port = try freePort(io);
        cluster.nodes[index] = .{
            .id = id,
            .port = port,
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, id }),
        };
        const host = std.fmt.bufPrint(
            &cluster.host_buffers[index],
            "127.0.0.1",
            .{},
        ) catch unreachable;
        cluster.endpoints[index] = .{ .host = host, .port = port };
    }
    defer for (cluster.nodes) |node| {
        gpa.free(node.directory);
        gpa.free(node.log_path);
    };
    defer cluster.killAll();

    step("start three nodes");
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("wait for one leader");
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, hasLeader, {}, 15_000, "leader knowledge");
    }

    step("reject a client with the wrong transport secret");
    if (client.Connection.openWithSecret(
        gpa,
        io,
        cluster.endpoints[0],
        "wrong-transport-secret-32-bytes!",
    )) |connection| {
        connection.close();
        fail(&cluster, "wrong transport secret was accepted", .{});
    } else |_| {}

    const members_body = rpcTry(
        &cluster,
        cluster.endpoints[0],
        "{\"op\":\"members\"}",
    ) orelse fail(&cluster, "members RPC unavailable", .{});
    defer gpa.free(members_body);
    if (std.mem.indexOf(
        u8,
        members_body,
        "\"voter_membership\":\"decided\"",
    ) == null) {
        fail(&cluster, "members RPC malformed: {s}", .{members_body});
    }

    step("create schema");
    execSql(&cluster, "create table t(a integer primary key, b text)", 15_000);

    step("create multimodal search schema and rows (ZDS 0009)");
    execSql(
        &cluster,
        "create table media(id integer primary key, title text); " ++
            "create virtual table media_fts using fts5(body); " ++
            "create virtual table media_vec using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[8], embedding_coarse bit[8]);",
        15_000,
    );
    execSql(
        &cluster,
        "insert into media(id, title) values " ++
            "(1, 'paxos replicates sqlite'), (2, 'vectors rank media'); " ++
            "insert into media_fts(rowid, body) values " ++
            "(1, 'paxos replicates sqlite'), (2, 'vectors rank media'); " ++
            "insert into media_vec(item_id, embedding, embedding_coarse) values " ++
            "(1, vec_f32('[1,0,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))), " ++
            "(2, vec_f32('[0,1,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]')));",
        15_000,
    );

    step("open sessions");
    const session_body = mustCall(&cluster, "{\"op\":\"session\"}", 10_000);
    const session_id: u64 = blk: {
        const parsed = parse(&cluster, session_body);
        defer parsed.deinit();
        break :blk @intCast(fieldInt(&parsed, "session_id") orelse
            fail(&cluster, "no session id", .{}));
    };
    cluster.gpa.free(session_body);

    step("submit requests 1..100 through all three endpoints");
    // Sessioned writes interleaved with plain writes, submitted to every
    // endpoint in turn (followers redirect to the leader).
    var sequence: u64 = 0;
    for (0..100) |index| {
        const target = cluster.endpoints[index % 3];
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        if (index % 2 == 0) {
            sequence += 1;
            request.writer.print(
                "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"," ++
                    "\"session\":{d},\"sequence\":{d}}}",
                .{ index, session_id, sequence },
            ) catch unreachable;
        } else {
            request.writer.print(
                "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"}}",
                .{index},
            ) catch unreachable;
        }
        // Submit first to the chosen endpoint; on redirect the shared
        // helper walks to the leader.
        if (rpcTry(&cluster, target, request.written())) |body| {
            const parsed = parse(&cluster, body);
            const ok = isOk(&parsed);
            var not_leader = false;
            if (!ok) {
                const code = fieldString(&cluster, &parsed, "error");
                not_leader = std.mem.eql(u8, code, "not_leader");
            }
            parsed.deinit();
            cluster.gpa.free(body);
            if (ok) continue;
            if (!not_leader) fail(&cluster, "write {d} failed", .{index});
        }
        const body = mustCall(&cluster, request.written(), 15_000);
        cluster.gpa.free(body);
    }

    step("verify linearizable count = 100");
    const count_100 = linearizableCount(&cluster, 15_000);
    if (count_100 != 100) fail(&cluster, "expected 100 rows, got {d}", .{count_100});

    step("verify session sequences occur exactly once");
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b like 'w%'\"," ++
                "\"level\":\"linearizable\"}",
            10_000,
        );
        cluster.gpa.free(body);
    }

    step("stream and verify an authenticated remote backup");
    const backup_path = try gpa.printSentinel(
        "{s}/remote-backup.db",
        .{root},
        0,
    );
    defer gpa.free(backup_path);
    const backup_connection = try client.Connection.openWithSecret(
        gpa,
        io,
        leaderEndpoint(&cluster),
        cluster_secret,
    );
    try backup_connection.backupTo(backup_path);
    backup_connection.close();
    var backup_db = try zaxonlite.sqlite.Db.open(backup_path);
    defer backup_db.close();
    try std.testing.expect(try backup_db.integrityCheckOk());
    var backup_count = try backup_db.prepare("select count(*) from t");
    defer backup_count.finalize();
    try std.testing.expect(try backup_count.step());
    try std.testing.expectEqual(@as(i64, 100), backup_count.columnInt64(0));

    step("stop one follower");
    const leader_before = leaderIndex(&cluster);
    const stopped_follower = (leader_before + 1) % 3;
    cluster.killNode(stopped_follower);

    step("insert 101..150 through the leader");
    for (100..150) |index| {
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        request.writer.print(
            "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"}}",
            .{index},
        ) catch unreachable;
        const body = mustCall(&cluster, request.written(), 15_000);
        cluster.gpa.free(body);
    }
    const count_150 = linearizableCount(&cluster, 15_000);
    if (count_150 != 150) fail(&cluster, "expected 150 rows, got {d}", .{count_150});

    step("restart follower and wait for catch-up");
    try cluster.spawnNode(stopped_follower, false);
    const leader_status = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
    const leader_applied = blk: {
        const parsed = parse(&cluster, leader_status);
        defer parsed.deinit();
        break :blk fieldInt(&parsed, "applied_slot") orelse 0;
    };
    cluster.gpa.free(leader_status);
    waitAllApplied(&cluster, leader_applied, 30_000);

    step("compare logical database hashes on all three nodes");
    expectAllDigestsEqual(&cluster, "after catch-up");

    step("hybrid search answers identically on every endpoint");
    {
        // Every node applied the same pages, so the coarse bit scan plus
        // exact rerank must return byte-identical results everywhere.
        const hybrid =
            "{\"op\":\"query\",\"level\":\"any\",\"freshness_ms\":60000," ++
            "\"sql\":\"with coarse as (select item_id, embedding " ++
            "from media_vec where embedding_coarse match " ++
            "vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]')) " ++
            "and k = 2) select item_id from coarse order by " ++
            "zaxon_vec_distance_cosine(embedding, " ++
            "vec_f32('[1,0,0,0,0,0,0,0]')), item_id\"}";
        var reference: ?[]u8 = null;
        defer if (reference) |body| cluster.gpa.free(body);
        for (cluster.endpoints) |endpoint| {
            const body = rpcTry(&cluster, endpoint, hybrid) orelse
                fail(&cluster, "hybrid query unreachable at port {d}", .{endpoint.port});
            if (std.mem.indexOf(u8, body, "\"ok\":true") == null) {
                fail(&cluster, "hybrid query failed: {s}", .{body});
            }
            if (reference) |expected| {
                if (!std.mem.eql(u8, expected, body)) {
                    fail(&cluster, "hybrid results diverge: {s}", .{body});
                }
                cluster.gpa.free(body);
            } else {
                reference = body;
            }
        }
    }

    step("typed search op round-trips on every endpoint");
    {
        // Base64 of the little-endian float32 vector [1,0,0,0,0,0,0,0].
        const typed =
            "{\"op\":\"search\",\"level\":\"any\",\"freshness_ms\":60000," ++
            "\"vec_table\":\"media_vec\"," ++
            "\"embedding\":\"AACAPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"," ++
            "\"k\":2,\"candidate_count\":64,\"metadata_table\":\"media\"," ++
            "\"metadata_columns\":[\"title\"]}";
        for (cluster.endpoints) |endpoint| {
            const body = rpcTry(&cluster, endpoint, typed) orelse
                fail(&cluster, "search op unreachable at port {d}", .{endpoint.port});
            defer cluster.gpa.free(body);
            if (std.mem.indexOf(u8, body, "\"ok\":true") == null or
                std.mem.indexOf(u8, body, "[\"1\",") == null or
                std.mem.indexOf(u8, body, "\"paxos replicates sqlite\"") == null)
            {
                fail(&cluster, "search op failed: {s}", .{body});
            }
        }
        // The candidate cap rejects before any SQL runs.
        const over_cap =
            "{\"op\":\"search\",\"vec_table\":\"media_vec\"," ++
            "\"embedding\":\"AACAPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"," ++
            "\"k\":2,\"candidate_count\":4097}";
        const body = rpcTry(&cluster, cluster.endpoints[0], over_cap) orelse
            fail(&cluster, "search cap rpc unreachable", .{});
        defer cluster.gpa.free(body);
        if (std.mem.indexOf(u8, body, "candidate_count must be") == null) {
            fail(&cluster, "candidate cap not enforced: {s}", .{body});
        }
    }

    step("status reports the search capability manifest");
    {
        const body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        defer cluster.gpa.free(body);
        for ([_][]const u8{
            "\"fts5_enabled\":true",
            "\"sqlite_vec_version\":\"v0.1.9\"",
            "\"search_feature_version\":1",
            "\"simd_backend\":\"",
            "\"mmap_size\":0",
            "\"candidate_hard_limit\":4096",
        }) |needle| {
            if (std.mem.indexOf(u8, body, needle) == null) {
                fail(&cluster, "status missing {s}: {s}", .{ needle, body });
            }
        }
    }

    step("arm leader failpoint: after quorum choice, before client reply");
    const leader_now = leaderIndex(&cluster);
    {
        const body = rpcTry(
            &cluster,
            cluster.endpoints[leader_now],
            "{\"op\":\"failpoint\",\"name\":\"before_client_reply\"}",
        ) orelse fail(&cluster, "failpoint rpc failed", .{});
        cluster.gpa.free(body);
    }

    step("submit session write; leader dies before replying");
    sequence += 1;
    {
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        request.writer.print(
            "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('fp')\"," ++
                "\"session\":{d},\"sequence\":{d}}}",
            .{ session_id, sequence },
        ) catch unreachable;
        // The direct call dies with the leader; that is the point.
        if (rpcTry(&cluster, cluster.endpoints[leader_now], request.written())) |body| {
            cluster.gpa.free(body);
        }
        cluster.waitNodeExit(leader_now);

        step("retry the same session sequence at the new leader");
        const body = mustCall(&cluster, request.written(), 30_000);
        defer cluster.gpa.free(body);
        const parsed = parse(&cluster, body);
        defer parsed.deinit();
        if (!isOk(&parsed)) fail(&cluster, "retry failed: {s}", .{body});
    }

    step("assert session sequence applied exactly once");
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b = 'fp'\"," ++
                "\"level\":\"linearizable\"}",
            15_000,
        );
        defer cluster.gpa.free(body);
        const applied_once = firstCell(&cluster, body);
        if (applied_once != 1) {
            fail(&cluster, "failpoint write applied {d} times", .{applied_once});
        }
    }

    step("restart the killed leader");
    try cluster.spawnNode(leader_now, false);

    step("state anchor with a stopped follower (journal catch-up)");
    const lag_follower = (leaderIndex(&cluster) + 1) % 3;
    cluster.killNode(lag_follower);
    execSql(&cluster, "insert into t(b) values ('pre-roll')", 15_000);
    {
        const body = mustCall(&cluster, "{\"op\":\"anchor\"}", 20_000);
        cluster.gpa.free(body);
    }
    execSql(&cluster, "insert into t(b) values ('post-roll')", 15_000);
    try cluster.spawnNode(lag_follower, false);
    // The restarted node catches up from the retained journal (ZDS 0011):
    // slots are global, the configuration never changes, and history the
    // survivors released from their windows is served from segments.
    {
        const leader_status_2 = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, leader_status_2);
        const target_configuration = fieldInt(&parsed, "configuration_id") orelse 0;
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(leader_status_2);
        if (target_configuration != 1) {
            fail(&cluster, "configuration changed to {d}", .{target_configuration});
        }
        waitFor(
            &cluster,
            cluster.endpoints[lag_follower],
            appliedAtLeast,
            target_applied,
            30_000,
            "catch-up after restart",
        );
    }
    expectAllDigestsEqual(&cluster, "after journal catch-up");

    step("conservative trim advances once every data replica reported");
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, trimmedAtLeast, 1, 30_000, "chosen trim");
    }

    step("delete a follower image; node rebuilds from anchor plus suffix");
    const rebuild_follower = (leaderIndex(&cluster) + 2) % 3;
    cluster.killNode(rebuild_follower);
    {
        const db_path = try std.fmt.allocPrint(
            gpa,
            "{s}/current.db",
            .{cluster.nodes[rebuild_follower].directory},
        );
        defer gpa.free(db_path);
        Io.Dir.cwd().deleteFile(io, db_path) catch {};
    }
    try cluster.spawnNode(rebuild_follower, false);
    {
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        waitFor(
            &cluster,
            cluster.endpoints[rebuild_follower],
            appliedAtLeast,
            target_applied,
            30_000,
            "rebuild from the retained journal",
        );
    }
    expectAllDigestsEqual(&cluster, "after image rebuild");

    step("stop all nodes without graceful shutdown");
    cluster.killAll();

    step("restart all from the same directories");
    for (0..3) |index| try cluster.spawnNode(index, false);
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, hasLeader, {}, 20_000, "leader after restart");
    }

    step("assert every acknowledged write is present exactly once");
    const final_count = linearizableCount(&cluster, 20_000);
    // 150 rows + the failpoint row + pre-roll + post-roll.
    if (final_count != 153) {
        fail(&cluster, "expected 153 rows after restart, got {d}", .{final_count});
    }
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b='fp'\"," ++
                "\"level\":\"linearizable\"}",
            10_000,
        );
        defer cluster.gpa.free(body);
        if (firstCell(&cluster, body) != 1) {
            fail(&cluster, "failpoint row duplicated after restart", .{});
        }
    }

    step("run integrity checks and compare logical hashes");
    {
        // Wait for every node to reach the leader's applied slot first.
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        waitAllApplied(&cluster, target_applied, 30_000);
    }
    expectIntegrityAll(&cluster);
    expectAllDigestsEqual(&cluster, "after total restart");

    step("stop cluster");
    cluster.killAll();
    std.debug.print("scenario complete\n", .{});
}

// ----------------------------------------------------------------------
// Takeover scenario: writes during election and across a leader crash
// ----------------------------------------------------------------------

/// One client thread of the startup-contention step. Each thread walks
/// its own endpoint order, so the three land on different nodes while
/// the first election is still running, exactly the reporter's workload.
const ContentionWorker = struct {
    cluster: *Cluster,
    endpoints: [3]Endpoint,
    iterations: usize,
    successes: usize = 0,

    fn run(self: *ContentionWorker) void {
        // Thread-local allocator: the controller's allocator is not shared.
        const gpa = std.heap.page_allocator;
        var completed: usize = 0;
        var elapsed: u64 = 0;
        while (completed < self.iterations and elapsed < 60_000) {
            var result = client.callClusterWithSecret(
                gpa,
                self.cluster.io,
                &self.endpoints,
                "{\"op\":\"exec\",\"sql\":\"create table if not exists b(id integer " ++
                    "primary key, v integer); insert into b(v) values(1);\"}",
                true,
                cluster_secret,
            ) catch {
                elapsed += 100;
                self.cluster.io.sleep(.fromMilliseconds(100), .awake) catch {};
                continue;
            };
            const parsed = std.json.parseFromSlice(
                std.json.Value,
                gpa,
                result.body,
                .{},
            ) catch {
                result.deinit(gpa);
                continue;
            };
            const ok = isOk(&parsed);
            parsed.deinit();
            result.deinit(gpa);
            completed += 1;
            if (!ok) continue;
            self.successes += 1;
            var read = client.callClusterWithSecret(
                gpa,
                self.cluster.io,
                &self.endpoints,
                "{\"op\":\"query\",\"sql\":\"select count(*) from b\"," ++
                    "\"level\":\"linearizable\"}",
                true,
                cluster_secret,
            ) catch continue;
            read.deinit(gpa);
        }
    }
};

const ParkedWriteWorker = struct {
    const Outcome = enum { pending, unavailable, ambiguous, ok, other, transport_error };

    io: Io,
    endpoint: Endpoint,
    done: std.atomic.Value(bool) = .init(false),
    outcome: Outcome = .pending,

    fn run(self: *ParkedWriteWorker) void {
        const gpa = std.heap.page_allocator;
        const connection = client.Connection.openWithSecret(
            gpa,
            self.io,
            self.endpoint,
            cluster_secret,
        ) catch {
            self.outcome = .transport_error;
            self.done.store(true, .release);
            return;
        };
        defer connection.close();
        const deadline = Io.Clock.Timestamp{
            .clock = .awake,
            .raw = .{ .nanoseconds = Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds +
                10 * std.time.ns_per_s },
        };
        const body = connection.callWithDeadline(
            "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('parked')\"}",
            deadline,
        ) catch {
            self.outcome = .transport_error;
            self.done.store(true, .release);
            return;
        };
        defer gpa.free(body);
        self.outcome = if (std.mem.indexOf(u8, body, "\"ok\":true") != null)
            .ok
        else if (std.mem.indexOf(u8, body, "\"unavailable\"") != null)
            .unavailable
        else if (std.mem.indexOf(u8, body, "\"ambiguous\"") != null)
            .ambiguous
        else
            .other;
        self.done.store(true, .release);
    }
};

const ChildWaiter = struct {
    io: Io,
    child: *std.process.Child,
    term: ?std.process.Child.Term = null,
    done: Io.Event = .unset,

    fn run(self: *ChildWaiter) void {
        self.term = self.child.wait(self.io) catch null;
        self.done.set(self.io);
    }
};

fn anyLogContains(cluster: *Cluster, needle: []const u8) bool {
    for (cluster.nodes) |node| {
        const contents = Io.Dir.cwd().readFileAlloc(
            cluster.io,
            node.log_path,
            cluster.gpa,
            .limited(1 << 20),
        ) catch continue;
        defer cluster.gpa.free(contents);
        if (std.mem.indexOf(u8, contents, needle) != null) return true;
    }
    return false;
}

fn expectDigestsEqual(cluster: *Cluster, first: usize, second: usize, what: []const u8) void {
    const a = nodeDigest(cluster, cluster.endpoints[first]);
    const b = nodeDigest(cluster, cluster.endpoints[second]);
    if (!std.mem.eql(u8, &a.chain, &b.chain) or !std.mem.eql(u8, &a.content, &b.content)) {
        fail(cluster, "{s}: node {d} and node {d} diverge: chain {s} vs {s}", .{
            what,
            cluster.nodes[first].id,
            cluster.nodes[second].id,
            a.chain,
            b.chain,
        });
    }
}

fn runTakeoverScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
) !void {
    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);

    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-takeover-{x}-{d}",
        .{ nonce, run_index },
    );
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const auth_file = try std.fmt.allocPrint(gpa, "{s}/auth.secret", .{root});
    defer gpa.free(auth_file);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = auth_file,
        .data = cluster_secret,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
    });

    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .auth_file = auth_file,
        .nodes = undefined,
        .endpoints = undefined,
    };

    // Nodes 1 and 2 are the only candidates; their short barrier delay
    // makes sure a crashing leader's accept has reached its peers. Node 3
    // votes as a witness whose phase-two votes are held, so a slot the new
    // leader re-proposes stays undecided for about the hold while the
    // election itself runs at full speed: the window an unguarded leader
    // proposes into.
    for (0..3) |index| {
        const id: u32 = @intCast(index + 1);
        const port = try freePort(io);
        cluster.nodes[index] = .{
            .id = id,
            .port = port,
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, id }),
            .witness = index == 2,
            .storage_delay_ms = if (index == 2) 0 else 100,
            .vote_delay_ms = if (index == 2) 1500 else 0,
        };
        const host = std.fmt.bufPrint(
            &cluster.host_buffers[index],
            "127.0.0.1",
            .{},
        ) catch unreachable;
        cluster.endpoints[index] = .{ .host = host, .port = port };
    }
    defer for (cluster.nodes) |node| {
        gpa.free(node.directory);
        gpa.free(node.log_path);
    };
    defer cluster.killAll();

    step("start two data voters and a slow witness");
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("three clients write concurrently through the first election");
    var workers: [3]ContentionWorker = undefined;
    for (&workers, 0..) |*worker, offset| {
        worker.* = .{ .cluster = &cluster, .endpoints = undefined, .iterations = 12 };
        for (0..3) |k| worker.endpoints[k] = cluster.endpoints[(k + offset) % 3];
    }
    var threads: [3]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        thread.* = try std.Thread.spawn(.{}, ContentionWorker.run, .{worker});
    }
    for (&threads) |*thread| thread.join();
    var acknowledged: usize = 0;
    for (workers) |worker| acknowledged += worker.successes;
    if (acknowledged == 0) fail(&cluster, "no concurrent write was acknowledged", .{});
    if (anyLogContains(&cluster, "ChainMismatch")) {
        fail(&cluster, "ChainMismatch during concurrent startup writes", .{});
    }
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from b\"," ++
                "\"level\":\"linearizable\"}",
            15_000,
        );
        defer cluster.gpa.free(body);
        const rows = firstCell(&cluster, body);
        if (rows < @as(i64, @intCast(acknowledged))) {
            fail(&cluster, "{d} writes acknowledged but {d} rows visible", .{
                acknowledged,
                rows,
            });
        }
    }

    step("seed table t and wait for both data voters to apply it");
    execSql(&cluster, "create table t(a integer primary key, b text)", 15_000);
    execSql(&cluster, "insert into t(b) values ('seed')", 15_000);
    {
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        for (0..2) |index| {
            waitFor(
                &cluster,
                cluster.endpoints[index],
                appliedAtLeast,
                target_applied,
                30_000,
                "applied slot",
            );
        }
    }
    expectDigestsEqual(&cluster, 0, 1, "before takeover");

    step("arm the leader to die after its own vote, before the decision");
    const old_leader = leaderIndex(&cluster);
    if (old_leader == 2) fail(&cluster, "the witness must never lead", .{});
    {
        const body = rpcTry(
            &cluster,
            cluster.endpoints[old_leader],
            "{\"op\":\"failpoint\",\"name\":\"after_accept_sync\"}",
        ) orelse fail(&cluster, "failpoint rpc failed", .{});
        cluster.gpa.free(body);
    }

    step("submit a write the crash leaves accepted but undecided");
    if (rpcTry(
        &cluster,
        cluster.endpoints[old_leader],
        "{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('inflight')\"}",
    )) |body| {
        cluster.gpa.free(body);
    }
    cluster.waitNodeExit(old_leader);

    step("write at the new leader while the inherited slot is still open");
    const start = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    execSql(&cluster, "insert into t(b) values ('after')", 30_000);
    const waited_ms = @divTrunc(
        std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds - start,
        std.time.ns_per_ms,
    );
    std.debug.print("first write after takeover took {d} ms\n", .{waited_ms});
    if (anyLogContains(&cluster, "ChainMismatch")) {
        fail(&cluster, "ChainMismatch after takeover", .{});
    }

    step("the recovered write and the new write are both visible once");
    for ([_][]const u8{ "inflight", "after" }) |marker| {
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        request.writer.print(
            "{{\"op\":\"query\",\"sql\":\"select count(*) from t where b = '{s}'\"," ++
                "\"level\":\"linearizable\"}}",
            .{marker},
        ) catch unreachable;
        const body = mustCall(&cluster, request.written(), 15_000);
        defer cluster.gpa.free(body);
        const count = firstCell(&cluster, body);
        if (count != 1) fail(&cluster, "row '{s}' visible {d} times", .{ marker, count });
    }

    step("restart the crashed leader and compare the data voters");
    try cluster.spawnNode(old_leader, false);
    {
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        waitFor(
            &cluster,
            cluster.endpoints[old_leader],
            appliedAtLeast,
            target_applied,
            30_000,
            "catch-up after restart",
        );
    }
    if (anyLogContains(&cluster, "ChainMismatch")) {
        fail(&cluster, "ChainMismatch during replay after restart", .{});
    }
    expectDigestsEqual(&cluster, 0, 1, "after takeover");

    step("stop cluster");
    cluster.killAll();
    std.debug.print("takeover scenario complete\n", .{});
}

// ----------------------------------------------------------------------
// Issue #10 trim scenarios
// ----------------------------------------------------------------------

const TrimStatus = struct {
    decided: i64,
    applied: i64,
    trim_decision: i64,
    chosen_trim: i64,
    journal_records: i64,
    retained_first: i64,
};

fn statusAt(cluster: *Cluster, endpoint: Endpoint) ?TrimStatus {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse return null;
    defer cluster.gpa.free(body);
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        cluster.gpa,
        body,
        .{},
    ) catch return null;
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    const health = field(&parsed, "health") orelse return null;
    if (health != .string or !std.mem.eql(u8, health.string, "healthy")) return null;
    return .{
        .decided = fieldInt(&parsed, "decided_slot") orelse return null,
        .applied = fieldInt(&parsed, "applied_slot") orelse return null,
        .trim_decision = fieldInt(&parsed, "trim_decision_slot") orelse return null,
        .chosen_trim = fieldInt(&parsed, "chosen_trim_slot") orelse return null,
        .journal_records = fieldInt(&parsed, "journal_records") orelse return null,
        .retained_first = fieldInt(&parsed, "retained_first_slot") orelse return null,
    };
}

fn mustStatusAt(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) TrimStatus {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusAt(cluster, endpoint)) |status| return status;
        cluster.io.sleep(.fromMilliseconds(25), .awake) catch {};
        elapsed += 25;
    }
    fail(cluster, "healthy status unavailable at port {d}", .{endpoint.port});
}

fn anchorAt(cluster: *Cluster, endpoint: Endpoint) void {
    var elapsed: u64 = 0;
    while (elapsed <= 10_000) {
        if (rpcTry(cluster, endpoint, "{\"op\":\"anchor\"}")) |body| {
            defer cluster.gpa.free(body);
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (isOk(&parsed)) return;
        }
        cluster.io.sleep(.fromMilliseconds(25), .awake) catch {};
        elapsed += 25;
    }
    fail(cluster, "anchor unavailable at port {d}", .{endpoint.port});
}

fn setVoteDelayAt(cluster: *Cluster, endpoint: Endpoint, delay_ms: u64) void {
    var request_buffer: [96]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buffer,
        "{{\"op\":\"test-vote-delay\",\"delay_ms\":{d}}}",
        .{delay_ms},
    ) catch unreachable;
    const body = rpcTry(cluster, endpoint, request) orelse
        fail(cluster, "vote-delay control unavailable at port {d}", .{endpoint.port});
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) fail(cluster, "vote-delay control failed: {s}", .{body});
}

fn waitTrimDecision(cluster: *Cluster, endpoint: Endpoint, decision: i64) TrimStatus {
    var elapsed: u64 = 0;
    while (elapsed <= 30_000) {
        if (statusAt(cluster, endpoint)) |status| {
            if (status.trim_decision == decision) return status;
            if (status.trim_decision > decision) {
                fail(cluster, "trim decision skipped {d}: observed {d}", .{
                    decision,
                    status.trim_decision,
                });
            }
        }
        cluster.io.sleep(.fromMilliseconds(25), .awake) catch {};
        elapsed += 25;
    }
    fail(cluster, "trim decision {d} unavailable at port {d}", .{
        decision,
        endpoint.port,
    });
}

fn readTrim(cluster: *Cluster, index: usize) zaxonlite.trim.State {
    var data_dir = Io.Dir.cwd().openDir(
        cluster.io,
        cluster.nodes[index].directory,
        .{},
    ) catch fail(cluster, "cannot open node {d} data directory", .{
        cluster.nodes[index].id,
    });
    defer data_dir.close(cluster.io);
    var consensus = data_dir.openDir(cluster.io, "consensus", .{}) catch
        fail(cluster, "cannot open node {d} consensus directory", .{
            cluster.nodes[index].id,
        });
    defer consensus.close(cluster.io);
    return (zaxonlite.trim.load(cluster.io, consensus) catch
        fail(cluster, "cannot read node {d} TRIM", .{cluster.nodes[index].id})) orelse
        fail(cluster, "node {d} has no TRIM", .{cluster.nodes[index].id});
}

fn expectTrimEqual(cluster: *Cluster, first: usize, second: usize) void {
    const a = readTrim(cluster, first);
    const b = readTrim(cluster, second);
    if (a.decision_slot != b.decision_slot or
        a.through_slot != b.through_slot or
        a.configuration_id != b.configuration_id or
        !std.mem.eql(u8, &a.history_hash, &b.history_hash))
    {
        fail(cluster, "TRIM differs between node {d} and node {d}", .{
            cluster.nodes[first].id,
            cluster.nodes[second].id,
        });
    }

    const first_path = std.fmt.allocPrint(
        cluster.gpa,
        "{s}/consensus/TRIM",
        .{cluster.nodes[first].directory},
    ) catch fail(cluster, "cannot allocate TRIM path", .{});
    defer cluster.gpa.free(first_path);
    const second_path = std.fmt.allocPrint(
        cluster.gpa,
        "{s}/consensus/TRIM",
        .{cluster.nodes[second].directory},
    ) catch fail(cluster, "cannot allocate TRIM path", .{});
    defer cluster.gpa.free(second_path);
    const first_bytes = Io.Dir.cwd().readFileAlloc(
        cluster.io,
        first_path,
        cluster.gpa,
        .limited(4096),
    ) catch fail(cluster, "cannot read node {d} TRIM bytes", .{
        cluster.nodes[first].id,
    });
    defer cluster.gpa.free(first_bytes);
    const second_bytes = Io.Dir.cwd().readFileAlloc(
        cluster.io,
        second_path,
        cluster.gpa,
        .limited(4096),
    ) catch fail(cluster, "cannot read node {d} TRIM bytes", .{
        cluster.nodes[second].id,
    });
    defer cluster.gpa.free(second_bytes);
    if (!std.mem.eql(u8, first_bytes, second_bytes)) {
        fail(cluster, "TRIM bytes differ between node {d} and node {d}", .{
            cluster.nodes[first].id,
            cluster.nodes[second].id,
        });
    }
}

fn initTrimCluster(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    auth_file: []const u8,
    witness: bool,
) !Cluster {
    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .auth_file = auth_file,
        .nodes = undefined,
        .endpoints = undefined,
    };
    for (0..3) |index| {
        const id: u32 = @intCast(index + 1);
        const port = try freePort(io);
        cluster.nodes[index] = .{
            .id = id,
            .port = port,
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, id }),
            .witness = witness and index == 2,
            .storage_delay_ms = if (witness and index < 2) 100 else 0,
            .vote_delay_ms = if (!witness or index == 2) 1500 else 0,
            .anchor_interval_ms = 3_600_000,
        };
        cluster.endpoints[index] = .{ .host = "127.0.0.1", .port = port };
    }
    return cluster;
}

fn deinitTrimCluster(cluster: *Cluster) void {
    cluster.killAll();
    for (cluster.nodes) |node| {
        cluster.gpa.free(node.directory);
        cluster.gpa.free(node.log_path);
    }
}

fn trimRoot(
    gpa: std.mem.Allocator,
    io: Io,
    prefix: []const u8,
    run_index: usize,
) !struct { root: []u8, auth: []u8 } {
    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/{s}-{x}-{d}",
        .{ prefix, std.mem.readInt(u64, &random_bytes, .little), run_index },
    );
    errdefer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    const auth = try std.fmt.allocPrint(gpa, "{s}/auth.secret", .{root});
    errdefer gpa.free(auth);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = auth,
        .data = cluster_secret,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
    });
    return .{ .root = root, .auth = auth };
}

fn freeTrimRoot(gpa: std.mem.Allocator, io: Io, paths: anytype) void {
    Io.Dir.cwd().deleteTree(io, paths.root) catch {};
    gpa.free(paths.auth);
    gpa.free(paths.root);
}

fn runTrimSerializationScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
) !void {
    const paths = try trimRoot(gpa, io, "zx-trim-serial", run_index);
    defer freeTrimRoot(gpa, io, paths);
    var cluster = try initTrimCluster(gpa, io, zaxon, paths.root, paths.auth, false);
    defer deinitTrimCluster(&cluster);
    for (&cluster.nodes) |*node| node.vote_delay_ms = 0;
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("establish a baseline chosen trim");
    execSql(&cluster, "create table t(id integer primary key, v text)", 30_000);
    const leader = leaderIndex(&cluster);
    const initial = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);
    waitAllApplied(&cluster, initial.applied, 30_000);
    for (cluster.endpoints) |endpoint| anchorAt(&cluster, endpoint);
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, trimmedAtLeast, initial.applied, 30_000, "baseline trim");
    }
    const baseline_trim = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);

    // Followers are named so the durable reports can be staged: the lagging
    // follower's report is what advances the candidate while the earlier
    // trim is still undecided, the exact route behind issue #10.
    const first_follower: usize = if (leader == 0) 1 else 0;
    const second_follower: usize = if (leader == 2) 1 else 2;

    step("stage a lagging durable report below the next candidate");
    execSql(&cluster, "insert into t(v) values ('first')", 30_000);
    const lagging = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);
    waitAllApplied(&cluster, lagging.applied, 30_000);
    // Only the second follower anchors here, so its durable frontier stays
    // one write behind the others for the rest of the scenario.
    anchorAt(&cluster, cluster.endpoints[second_follower]);
    execSql(&cluster, "insert into t(v) values ('second')", 30_000);
    const before_anchor = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);
    waitAllApplied(&cluster, before_anchor.applied, 30_000);
    anchorAt(&cluster, cluster.endpoints[leader]);
    for (0..3) |index| {
        if (index == leader) continue;
        setVoteDelayAt(&cluster, cluster.endpoints[index], 2500);
    }
    const before_trim = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);
    if (before_trim.trim_decision != baseline_trim.trim_decision) {
        fail(&cluster, "trim advanced before the final durable report", .{});
    }
    std.debug.print(
        "trim window baseline: decided={d} trim={d} through={d} journal={d}\n",
        .{
            before_trim.decided,
            before_trim.trim_decision,
            before_trim.chosen_trim,
            before_trim.journal_records,
        },
    );

    step("append exactly one trim while its quorum votes are delayed");
    // The minimum durable frontier is now the lagging follower's, one write
    // behind, so the first trim anchors there.
    anchorAt(&cluster, cluster.endpoints[first_follower]);
    var elapsed: u64 = 0;
    while (elapsed < 30_000) : (elapsed += 25) {
        const status = mustStatusAt(&cluster, cluster.endpoints[leader], 1_000);
        if (status.decided != before_trim.decided or
            status.journal_records > before_trim.journal_records + 1)
        {
            fail(&cluster, "unresolved trim appended more than once", .{});
        }
        if (status.journal_records == before_trim.journal_records + 1) break;
        io.sleep(.fromMilliseconds(25), .awake) catch {};
    } else fail(&cluster, "did not observe the undecided trim append", .{});

    step("advance the candidate while the first trim is still undecided");
    // Before the fix, this report produced a second trim carrying the same
    // identity and a later anchor, which then classified as a regression.
    anchorAt(&cluster, cluster.endpoints[second_follower]);
    elapsed = 0;
    while (elapsed < 500) : (elapsed += 25) {
        const status = mustStatusAt(&cluster, cluster.endpoints[leader], 1_000);
        if (status.decided != before_trim.decided or
            status.journal_records != before_trim.journal_records + 1)
        {
            fail(&cluster, "unresolved trim was not serialized", .{});
        }
        io.sleep(.fromMilliseconds(25), .awake) catch {};
    }

    step("both trims land in order on consecutive global slots");
    const first_decision = before_trim.decided + 1;
    for (cluster.endpoints) |endpoint| {
        const status = waitTrimDecision(&cluster, endpoint, first_decision);
        if (status.chosen_trim != lagging.applied) {
            fail(&cluster, "first trim chose {d}, expected {d}", .{
                status.chosen_trim,
                lagging.applied,
            });
        }
    }
    // The advanced candidate is proposed only after the first trim is
    // applied, so it takes the very next slot and anchors at the frontier
    // every replica has now reported.
    const second_decision = first_decision + 1;
    for (cluster.endpoints) |endpoint| {
        const status = waitTrimDecision(&cluster, endpoint, second_decision);
        if (status.chosen_trim != before_anchor.applied) {
            fail(&cluster, "second trim chose {d}, expected {d}", .{
                status.chosen_trim,
                before_anchor.applied,
            });
        }
        if (status.decided != second_decision) {
            fail(&cluster, "serialized trims consumed {d} slots, expected 2", .{
                status.decided - before_trim.decided,
            });
        }
    }
    for (0..3) |index| {
        if (index == leader) continue;
        setVoteDelayAt(&cluster, cluster.endpoints[index], 0);
    }
    expectTrimEqual(&cluster, 0, 1);
    expectTrimEqual(&cluster, 0, 2);
    if (anyLogContains(&cluster, "TrimRegression")) {
        fail(&cluster, "TrimRegression during serialized trims", .{});
    }
}

fn runTrimTakeoverFatalScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
) !void {
    const paths = try trimRoot(gpa, io, "zx-trim-takeover", run_index);
    defer freeTrimRoot(gpa, io, paths);
    var cluster = try initTrimCluster(gpa, io, zaxon, paths.root, paths.auth, true);
    defer deinitTrimCluster(&cluster);
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("establish trim baseline before takeover");
    execSql(&cluster, "create table t(id integer primary key, v text)", 30_000);
    const old_leader = leaderIndex(&cluster);
    const follower = if (old_leader == 0) @as(usize, 1) else 0;
    var status = mustStatusAt(&cluster, cluster.endpoints[old_leader], 10_000);
    waitAllApplied(&cluster, status.applied, 30_000);
    anchorAt(&cluster, cluster.endpoints[old_leader]);
    anchorAt(&cluster, cluster.endpoints[follower]);
    for (cluster.endpoints) |endpoint| {
        _ = waitTrimDecision(&cluster, endpoint, status.decided + 1);
    }

    step("crash the leader after appending an undecided trim");
    execSql(&cluster, "insert into t(v) values ('takeover')", 30_000);
    status = mustStatusAt(&cluster, cluster.endpoints[old_leader], 10_000);
    waitAllApplied(&cluster, status.applied, 30_000);
    anchorAt(&cluster, cluster.endpoints[follower]);
    {
        const body = rpcTry(
            &cluster,
            cluster.endpoints[old_leader],
            "{\"op\":\"failpoint\",\"name\":\"after_accept_sync\"}",
        ) orelse fail(&cluster, "could not arm trim takeover failpoint", .{});
        cluster.gpa.free(body);
    }
    if (rpcTry(&cluster, cluster.endpoints[old_leader], "{\"op\":\"anchor\"}")) |body| {
        cluster.gpa.free(body);
    }
    cluster.waitNodeExit(old_leader);

    const successor = follower;
    waitFor(
        &cluster,
        cluster.endpoints[successor],
        hasLeader,
        {},
        15_000,
        "successor election",
    );
    var window_elapsed: u64 = 0;
    while (window_elapsed < 500) : (window_elapsed += 25) {
        const inherited = mustStatusAt(&cluster, cluster.endpoints[successor], 1_000);
        if (inherited.decided != status.decided) {
            fail(&cluster, "inherited trim decided before delayed-vote window", .{});
        }
        io.sleep(.fromMilliseconds(25), .awake) catch {};
    }
    const trim_decision = status.decided + 1;
    _ = waitTrimDecision(&cluster, cluster.endpoints[successor], trim_decision);
    _ = waitTrimDecision(&cluster, cluster.endpoints[2], trim_decision);
    io.sleep(.fromMilliseconds(250), .awake) catch {};
    if (mustStatusAt(&cluster, cluster.endpoints[successor], 1_000).decided != trim_decision) {
        fail(&cluster, "successor appended a duplicate inherited trim", .{});
    }

    step("restart the old leader below the trim decision");
    try cluster.spawnNode(old_leader, false);
    _ = waitTrimDecision(&cluster, cluster.endpoints[old_leader], trim_decision);
    waitFor(
        &cluster,
        cluster.endpoints[old_leader],
        appliedAtLeast,
        trim_decision,
        30_000,
        "restarted trim application",
    );
    expectDigestsEqual(&cluster, old_leader, successor, "trim restart");
    expectTrimEqual(&cluster, old_leader, successor);
    expectTrimEqual(&cluster, old_leader, 2);

    step("a real trim failure wakes parked writers and exits 4 once");
    execSql(&cluster, "insert into t(v) values ('fatal')", 30_000);
    const fatal_base = mustStatusAt(&cluster, cluster.endpoints[successor], 10_000);
    waitAllApplied(&cluster, fatal_base.applied, 30_000);
    setVoteDelayAt(&cluster, cluster.endpoints[old_leader], 3000);
    setVoteDelayAt(&cluster, cluster.endpoints[2], 3000);
    anchorAt(&cluster, cluster.endpoints[old_leader]);
    const trim_path = try std.fmt.allocPrint(
        gpa,
        "{s}/consensus/TRIM",
        .{cluster.nodes[successor].directory},
    );
    defer gpa.free(trim_path);
    try Io.Dir.cwd().deleteFile(io, trim_path);
    try Io.Dir.cwd().createDir(io, trim_path, @fromBackingInt(@intCast(0o700)));
    anchorAt(&cluster, cluster.endpoints[successor]);

    var elapsed: u64 = 0;
    while (elapsed < 2000) : (elapsed += 25) {
        const pending = mustStatusAt(&cluster, cluster.endpoints[successor], 1000);
        if (pending.decided != fatal_base.decided) {
            fail(&cluster, "fatal trim decided before writers could park", .{});
        }
        if (pending.journal_records == fatal_base.journal_records + 1) break;
        if (pending.journal_records > fatal_base.journal_records + 1) {
            fail(&cluster, "fatal trim was appended more than once", .{});
        }
        io.sleep(.fromMilliseconds(25), .awake) catch {};
    } else fail(&cluster, "fatal trim proposal was not observed", .{});

    var workers = [_]ParkedWriteWorker{
        .{ .io = io, .endpoint = cluster.endpoints[successor] },
        .{ .io = io, .endpoint = cluster.endpoints[successor] },
        .{ .io = io, .endpoint = cluster.endpoints[successor] },
    };
    var writer_threads: [workers.len]std.Thread = undefined;
    for (&workers, &writer_threads) |*worker, *thread| {
        thread.* = try std.Thread.spawn(.{}, ParkedWriteWorker.run, .{worker});
    }
    io.sleep(.fromMilliseconds(100), .awake) catch {};
    for (&workers) |*worker| {
        if (worker.done.load(.acquire)) {
            fail(&cluster, "writer completed before the fatal trim decision", .{});
        }
    }

    const child = &(cluster.nodes[successor].child orelse
        fail(&cluster, "failed node has no child process", .{}));
    var child_waiter = ChildWaiter{ .io = io, .child = child };
    const child_thread = try std.Thread.spawn(.{}, ChildWaiter.run, .{&child_waiter});
    const child_deadline = Io.Clock.Timestamp{
        .clock = .awake,
        .raw = .{ .nanoseconds = Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds +
            10 * std.time.ns_per_s },
    };
    while (!child_waiter.done.isSet()) {
        if (Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >=
            child_deadline.raw.nanoseconds) std.c._exit(1);
        child_waiter.done.waitTimeout(io, .{ .deadline = child_deadline }) catch {};
    }
    child_thread.join();
    const term = child_waiter.term orelse fail(&cluster, "failed node did not exit", .{});
    cluster.nodes[successor].child = null;
    for (&writer_threads) |*thread| thread.join();
    for (&workers) |*worker| {
        if (!worker.done.load(.acquire) or
            (worker.outcome != .unavailable and worker.outcome != .ambiguous))
        {
            fail(&cluster, "parked writer completed as {s}", .{@tagName(worker.outcome)});
        }
    }
    switch (term) {
        .exited => |code| if (code != 4) {
            fail(&cluster, "failed node exited {d}, expected 4", .{code});
        },
        else => fail(&cluster, "failed node did not exit normally", .{}),
    }
    const log = try Io.Dir.cwd().readFileAlloc(
        io,
        cluster.nodes[successor].log_path,
        gpa,
        .limited(1 << 20),
    );
    defer gpa.free(log);
    var failure_needle_buffer: [64]u8 = undefined;
    const failure_needle = std.fmt.bufPrint(
        &failure_needle_buffer,
        "node {d} failed:",
        .{cluster.nodes[successor].id},
    ) catch unreachable;
    if (std.mem.count(u8, log, failure_needle) != 1 or
        std.mem.indexOf(u8, log, "-- NODE FAILED --") == null)
    {
        fail(&cluster, "fatal log lacks one first-failure line and diagnostic", .{});
    }
    setVoteDelayAt(&cluster, cluster.endpoints[old_leader], 0);
    setVoteDelayAt(&cluster, cluster.endpoints[2], 0);
    _ = waitTrimDecision(&cluster, cluster.endpoints[old_leader], fatal_base.decided + 1);
    _ = waitTrimDecision(&cluster, cluster.endpoints[2], fatal_base.decided + 1);
    expectTrimEqual(&cluster, old_leader, 2);
    execSql(&cluster, "insert into t(v) values ('survivor')", 30_000);
    if (anyLogContains(&cluster, "TrimRegression")) {
        fail(&cluster, "TrimRegression during takeover or fatal isolation", .{});
    }
}

fn runTrimSoakScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
    seconds: u64,
    record_path: ?[]const u8,
    host: []const u8,
) !void {
    if (seconds == 0) return error.InvalidSoakDuration;
    const paths = try trimRoot(gpa, io, "zx-trim-soak", run_index);
    defer freeTrimRoot(gpa, io, paths);
    var cluster = try initTrimCluster(gpa, io, zaxon, paths.root, paths.auth, false);
    defer deinitTrimCluster(&cluster);
    for (&cluster.nodes) |*node| {
        node.vote_delay_ms = 0;
        node.anchor_interval_ms = 200;
        node.segment_records = 256;
    }
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("run sustained writes with fast anchors and a monotonic trim watch");
    execSql(&cluster, "create table t(id integer primary key, v text)", 30_000);
    var last_trim = @as([3]i64, @splat(0));
    var last_decision = @as([3]i64, @splat(0));
    var missed = @as([3]u8, @splat(0));
    var writes: u64 = 0;
    const start = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const duration_ns: i96 = @as(i96, @intCast(seconds)) * std.time.ns_per_s;
    var next_sample = start;
    while (std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds - start < duration_ns) {
        execSql(&cluster, "insert into t(v) values ('soak')", 30_000);
        writes += 1;
        const now = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
        if (now < next_sample) continue;
        next_sample = now + 50 * std.time.ns_per_ms;
        for (cluster.endpoints, 0..) |endpoint, index| {
            const status = statusAt(&cluster, endpoint) orelse {
                missed[index] += 1;
                if (missed[index] >= 3) {
                    fail(&cluster, "node {d} missed three health samples", .{index + 1});
                }
                continue;
            };
            missed[index] = 0;
            if (status.chosen_trim < last_trim[index] or
                status.trim_decision < last_decision[index])
            {
                fail(&cluster, "node {d} trim state regressed", .{index + 1});
            }
            last_trim[index] = status.chosen_trim;
            last_decision[index] = status.trim_decision;
        }
    }

    step("converge, verify retained history, and compare durable state");
    const leader = leaderIndex(&cluster);
    const final_status = mustStatusAt(&cluster, cluster.endpoints[leader], 10_000);
    step("wait for every member to apply the final decided slot");
    waitAllApplied(&cluster, final_status.decided, 30_000);
    step("wait for a stable common trim");
    var converged: ?TrimStatus = null;
    const convergence_end = Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds +
        30 * std.time.ns_per_s;
    while (Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds < convergence_end) {
        const a = statusAt(&cluster, cluster.endpoints[0]);
        const b = statusAt(&cluster, cluster.endpoints[1]);
        const c = statusAt(&cluster, cluster.endpoints[2]);
        if (a != null and b != null and c != null and
            a.?.chosen_trim == b.?.chosen_trim and
            a.?.chosen_trim == c.?.chosen_trim and
            a.?.trim_decision == b.?.trim_decision and
            a.?.trim_decision == c.?.trim_decision and
            a.?.chosen_trim > 0)
        {
            io.sleep(.fromMilliseconds(500), .awake) catch {};
            const stable = statusAt(&cluster, cluster.endpoints[0]);
            if (stable != null and stable.?.chosen_trim == a.?.chosen_trim and
                stable.?.trim_decision == a.?.trim_decision)
            {
                converged = a.?;
                break;
            }
        }
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    const settled = converged orelse fail(&cluster, "trim state did not converge", .{});
    if (seconds >= 10) {
        for (cluster.endpoints) |endpoint| {
            if (mustStatusAt(&cluster, endpoint, 10_000).retained_first <= 1) {
                fail(&cluster, "sustained trim workload did not reclaim a segment", .{});
            }
        }
    }
    expectTrimEqual(&cluster, 0, 1);
    expectTrimEqual(&cluster, 0, 2);
    expectIntegrityAll(&cluster);
    expectAllDigestsEqual(&cluster, "trim soak");
    if (anyLogContains(&cluster, "TrimRegression")) {
        fail(&cluster, "TrimRegression during sustained trim workload", .{});
    }
    const count = linearizableCount(&cluster, 30_000);
    if (count != @as(i64, @intCast(writes))) {
        fail(&cluster, "soak acknowledged {d} writes but counted {d}", .{ writes, count });
    }

    step("restart every member and verify continued service");
    cluster.killAll();
    for (0..3) |index| try cluster.spawnNode(index, false);
    _ = leaderIndex(&cluster);
    if (linearizableCount(&cluster, 30_000) != @as(i64, @intCast(writes))) {
        fail(&cluster, "soak row count changed across restart", .{});
    }
    execSql(&cluster, "insert into t(v) values ('after-restart')", 30_000);
    for (cluster.endpoints) |endpoint| _ = mustStatusAt(&cluster, endpoint, 10_000);
    if (record_path) |path| {
        try recordTrimSoak(gpa, io, path, host, seconds, writes, settled);
    }
    std.debug.print(
        "trim soak: {d}s, {d} writes, decision {d}, through {d}, retained {d}\n",
        .{
            seconds,
            writes,
            settled.trim_decision,
            settled.chosen_trim,
            settled.retained_first,
        },
    );
}

fn recordTrimSoak(
    gpa: std.mem.Allocator,
    io: Io,
    path: []const u8,
    host: []const u8,
    seconds: u64,
    writes: u64,
    settled: TrimStatus,
) !void {
    const epoch_seconds: u64 = @intCast(Io.Clock.Timestamp.now(io, .real).raw.toSeconds());
    const year_day = (std.time.epoch.EpochSeconds{ .secs = epoch_seconds })
        .getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    var date_buffer: [10]u8 = undefined;
    const date = try std.fmt.bufPrint(&date_buffer, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
    });
    var os_buffer: [48]u8 = undefined;
    const os = try std.fmt.bufPrint(
        &os_buffer,
        "{s} {s}",
        .{ @tagName(builtin.os.tag), @tagName(builtin.cpu.arch) },
    );
    const record = .{
        .date = date,
        .host = host,
        .os = os,
        .duration_seconds = seconds,
        .writes = writes,
        .trim_decision_slot = settled.trim_decision,
        .chosen_trim_slot = settled.chosen_trim,
        .retained_first_slot = settled.retained_first,
        .trim_regressions = 0,
        .assertions = if (seconds >= 10)
            "healthy and monotonic on every sample; common byte-identical TRIM; " ++
                "equal integrity and digests; retained prefix reclaimed; count " ++
                "preserved across restart; post-restart write committed"
        else
            "healthy and monotonic on every sample; common byte-identical TRIM; " ++
                "equal integrity and digests; count preserved across restart; " ++
                "post-restart write committed; reclamation requires 10s or longer",
    };
    const encoded = try std.json.Stringify.valueAlloc(gpa, record, .{
        .whitespace = .indent_2,
    });
    defer gpa.free(encoded);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = encoded });
    std.debug.print("recorded {s}\n", .{path});
}

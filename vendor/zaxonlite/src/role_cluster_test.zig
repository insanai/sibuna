//! Multi-process-equivalent embedded test for voter, witness, standby, and
//! read-replica behavior. Each facade owns a real TCP server and data dir.

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

const secret = "role-cluster-test-secret-32-bytes";
const member_count = 6;

pub fn main(init: std.process.Init) !u8 {
    // Logic and process-crash coverage need no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const gpa = init.gpa;
    const io = init.io;
    var tmp = try Temp.init(gpa, io);
    defer tmp.deinit();

    var addresses: [member_count][]u8 = undefined;
    defer for (addresses) |address| gpa.free(address);
    var members: [member_count]zaxonlite.EmbeddedMember = undefined;
    const roles = [_]zaxonlite.Role{
        .data_voter,
        .data_voter,
        .data_voter,
        .witness,
        .standby,
        .read_replica,
    };
    for (&members, &addresses, roles, 0..) |*member, *address, role, index| {
        address.* = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{try freePort(io)});
        member.* = .{
            .id = @intCast(index + 1),
            .address = address.*,
            .role = role,
        };
    }

    var nodes = @as([member_count]?*zaxonlite.Embedded, @splat(null));
    defer {
        var index = nodes.len;
        while (index > 0) {
            index -= 1;
            if (nodes[index]) |node| node.close();
        }
    }
    for (&nodes, 0..) |*node, index| {
        const directory = try std.fmt.allocPrint(
            gpa,
            "{s}/node-{d}",
            .{ tmp.path, index + 1 },
        );
        defer gpa.free(directory);
        node.* = try zaxonlite.Embedded.open(gpa, io, .{
            .directory = directory,
            .node_id = @intCast(index + 1),
            .members = &members,
            .cluster_id = "role-cluster",
            .auth_secret = secret,
            .allow_insecure_test_tcp = true,
        });
    }

    try retryExec(io, nodes[0].?, "create table role_test(value text)");
    try retryExec(io, nodes[1].?, "insert into role_test values ('chosen')");
    try expectReplica(io, gpa, members[4].address, "standby");
    try expectReplica(io, gpa, members[5].address, "read-replica");
    try expectCannotRead(gpa, io, members[3].address);
    try expectRogueStandbyCommitRejected(gpa, io, &members);
    for (nodes[0..3]) |*node| {
        if (node.*) |value| {
            value.close();
            node.* = null;
        }
    }
    io.sleep(.fromMilliseconds(750), .awake) catch {};
    try expectStale(gpa, io, members[5].address);
    std.debug.print("role cluster: voters, witness, and learners passed\n", .{});
    return 0;
}

fn retryExec(io: Io, node: *zaxonlite.Embedded, sql: []const u8) !void {
    var elapsed: u64 = 0;
    while (elapsed < 20_000) : (elapsed += 100) {
        if (node.exec(sql)) |_| return else |_| {}
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ClusterWriteTimeout;
}

fn expectReplica(
    io: Io,
    gpa: std.mem.Allocator,
    address: []const u8,
    expected_type: []const u8,
) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    var elapsed: u64 = 0;
    while (elapsed < 20_000) : (elapsed += 100) {
        const connection = zaxonlite.client.Connection.openWithSecret(
            gpa,
            io,
            endpoint,
            secret,
        ) catch {
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            continue;
        };
        defer connection.close();
        const status = connection.call("{\"op\":\"status\"}") catch continue;
        defer gpa.free(status);
        if (std.mem.indexOf(u8, status, expected_type) == null) {
            return error.WrongNodeType;
        }
        if (std.mem.indexOf(u8, status, "\"leader\":null") != null) {
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            continue;
        }
        const response = connection.call(
            "{\"op\":\"query\",\"sql\":\"select value from role_test\"," ++
                "\"level\":\"any\",\"freshness_ms\":2000}",
        ) catch continue;
        defer gpa.free(response);
        if (std.mem.indexOf(u8, response, "chosen") != null) return;
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ReplicaCatchUpTimeout;
}

fn expectCannotRead(gpa: std.mem.Allocator, io: Io, address: []const u8) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    const connection = try zaxonlite.client.Connection.openWithSecret(
        gpa,
        io,
        endpoint,
        secret,
    );
    defer connection.close();
    const response = try connection.call(
        "{\"op\":\"query\",\"sql\":\"select 1\",\"level\":\"any\"}",
    );
    defer gpa.free(response);
    if (std.mem.indexOf(u8, response, "\"error\":\"forbidden\"") == null) {
        return error.WitnessServedRead;
    }
}

/// Only a configured voter may certify a chosen slot to a learner. This
/// connects to the read replica while authenticated as the standby (a
/// configured non-voter) and sends a well-formed `learner_commit`; the
/// replica must reject the certification by closing the connection.
fn expectRogueStandbyCommitRejected(
    gpa: std.mem.Allocator,
    io: Io,
    members: []const zaxonlite.EmbeddedMember,
) !void {
    var peers: [member_count]zaxonlite.server.PeerAddress = undefined;
    for (&peers, members[0..member_count]) |*peer, member| {
        const peer_endpoint = try zaxonlite.client.Endpoint.parse(member.address);
        peer.* = .{
            .id = member.id,
            .host = peer_endpoint.host,
            .port = peer_endpoint.port,
            .role = member.role,
        };
    }
    const database_id = zaxonlite.server.deriveDatabaseId(&peers, "role-cluster");

    const standby = members[4];
    const replica = try zaxonlite.client.Endpoint.parse(members[5].address);
    const address = try std.Io.net.IpAddress.parse(replica.host, replica.port);
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var read_buffer: [16 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    const reader = &stream_reader.interface;
    var write_buffer: [16 * 1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);
    const writer = &stream_writer.interface;

    const hello = zaxonlite.wire.Hello{
        .version = zaxonlite.wire.protocol_version,
        .kind = .peer,
        .node_id = standby.id,
        .database_id = database_id,
        .configuration_id = 1,
    };
    var hello_buffer: [zaxonlite.wire.Hello.encoded_size]u8 = undefined;
    const hello_encoded = hello.encode(&hello_buffer);
    try zaxonlite.wire.writeFrame(writer, .hello, hello_encoded);
    try writer.flush();
    var session = try zaxonlite.transport_auth.connect(
        gpa,
        reader,
        writer,
        secret,
        hello_encoded,
    );

    // A payload-free noop entry would pass every later check in
    // `onLearnerCommit`, so the only rejection path is the voter guard.
    const commit = zaxonlite.wire.LearnerCommit{
        .configuration_id = 1,
        .slot = 1,
        .entry = .{ .command = .noop },
    };
    var commit_buffer: [zaxonlite.wire.LearnerCommit.encoded_max]u8 = undefined;
    const commit_body = commit.encode(&commit_buffer);

    // The replica sends no reply on this path; rejection is observed as a
    // closed connection, which surfaces as a failed send within a bounded
    // number of resend attempts.
    var attempt: u32 = 0;
    while (attempt < 50) : (attempt += 1) {
        session.writeFrame(writer, .learner_commit, commit_body) catch return;
        writer.flush() catch return;
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.RogueLearnerCommitAccepted;
}

fn expectStale(gpa: std.mem.Allocator, io: Io, address: []const u8) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    const connection = try zaxonlite.client.Connection.openWithSecret(
        gpa,
        io,
        endpoint,
        secret,
    );
    defer connection.close();
    const response = try connection.call(
        "{\"op\":\"query\",\"sql\":\"select value from role_test\"," ++
            "\"level\":\"any\",\"freshness_ms\":100}",
    );
    defer gpa.free(response);
    if (std.mem.indexOf(u8, response, "\"error\":\"stale\"") == null) {
        return error.StaleReplicaServedBoundedRead;
    }
}

fn freePort(io: Io) !u16 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    return port;
}

const Temp = struct {
    gpa: std.mem.Allocator,
    io: Io,
    path: []u8,

    fn init(gpa: std.mem.Allocator, io: Io) !Temp {
        var random: [8]u8 = undefined;
        io.random(&random);
        const path = try std.fmt.allocPrint(
            gpa,
            ".zig-cache/tmp/zx-role-{x}",
            .{std.mem.readInt(u64, &random, .little)},
        );
        try Io.Dir.cwd().createDirPath(io, path);
        return .{ .gpa = gpa, .io = io, .path = path };
    }

    fn deinit(self: *Temp) void {
        Io.Dir.cwd().deleteTree(self.io, self.path) catch {};
        self.gpa.free(self.path);
    }
};

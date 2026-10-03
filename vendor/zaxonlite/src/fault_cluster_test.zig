//! Real-TCP adverse schedule: peer frame loss, duplication, reordering,
//! fragmentation, delayed durable sync, and delayed votes in one three-voter
//! run. Aggressive anchoring also keeps the issue #10 trim scheduler under
//! unresolved-proposal pressure throughout the workload.

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

pub fn main(init: std.process.Init) !u8 {
    // Logic and process-crash coverage need no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const saved_anchor_interval = zaxonlite.Node.anchor_interval_ns;
    zaxonlite.Node.anchor_interval_ns = 20 * std.time.ns_per_ms;
    defer zaxonlite.Node.anchor_interval_ns = saved_anchor_interval;
    const saved_rotation_records = zaxonlite.segment.rotation_records;
    zaxonlite.segment.rotation_records = 64;
    defer zaxonlite.segment.rotation_records = saved_rotation_records;
    const gpa = init.gpa;
    const io = init.io;
    var tmp = try Temp.init(gpa, io);
    defer tmp.deinit();

    var addresses: [3][]u8 = undefined;
    defer for (addresses) |address| gpa.free(address);
    var members: [3]zaxonlite.EmbeddedMember = undefined;
    for (&members, &addresses, 0..) |*member, *address, index| {
        address.* = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{try freePort(io)});
        member.* = .{ .id = @intCast(index + 1), .address = address.* };
    }
    const faults = [_]zaxonlite.server.TestFaults{
        .{ .reorder_pairs = true, .fragment_bytes = 7, .vote_delay_ms = 75 },
        .{ .drop_every = 11, .vote_delay_ms = 90 },
        .{
            .duplicate_every = 7,
            .storage_delay_ms = 5,
            .vote_delay_ms = 110,
        },
    };
    var nodes = @as([3]?*zaxonlite.Embedded, @splat(null));
    defer {
        var index = nodes.len;
        while (index > 0) {
            index -= 1;
            if (nodes[index]) |node| node.close();
        }
    }
    for (&nodes, faults, 0..) |*node, schedule, index| {
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
            .cluster_id = "fault-cluster",
            .enable_test_faults = true,
            .allow_insecure_test_tcp = true,
            .test_faults = schedule,
        });
    }

    try retryExec(
        io,
        nodes[0].?,
        "create table if not exists f(id integer primary key, v text)",
    );
    // Retried writes must be sessioned: under frame loss an acknowledged
    // failure is ambiguous, and only the session sequence makes the retry
    // exactly-once.
    const session_id = try openSession(gpa, io, nodes[0].?);
    var request_buffer: [192]u8 = undefined;
    for (0..30) |index| {
        const request = std.fmt.bufPrint(
            &request_buffer,
            "{{\"op\":\"exec\",\"sql\":\"insert into f(v) values ('value-{d}')\"," ++
                "\"session\":{d},\"sequence\":{d}}}",
            .{ index, session_id, index + 1 },
        ) catch unreachable;
        try retryCall(gpa, io, nodes[index % nodes.len].?, request);
    }
    for (members) |member| try expectCount(gpa, io, member.address, 30);
    // The cadence is shorter than every phase-two vote delay, so repeated host
    // pumps necessarily observe unresolved trims. The issue #10 scheduler must
    // serialize them and eventually install a trim on every member.
    for (nodes) |node| try expectTrim(gpa, io, node.?);
    std.debug.print(
        "fault cluster: loss/duplicate/reorder/fragment/slow-sync/trim passed\n",
        .{},
    );
    return 0;
}

fn expectTrim(gpa: std.mem.Allocator, io: Io, node: *zaxonlite.Embedded) !void {
    const deadline = Deadline.start(io, 30_000);
    while (true) {
        switch (node.localServerState()) {
            .healthy => {},
            else => return error.NodeBecameUnhealthy,
        }
        if (node.call("{\"op\":\"status\"}", false)) |body| {
            defer gpa.free(body);
            if (jsonInt(body, "chosen_trim_slot")) |slot| {
                if (slot > 0) return;
            }
        } else |_| {}
        if (!deadline.tick()) break;
    }
    return error.TrimDidNotAdvance;
}

fn jsonInt(body: []const u8, field: []const u8) ?u64 {
    var needle_buffer: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buffer, "\"{s}\":", .{field}) catch
        return null;
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const value = body[start + needle.len ..];
    const end = std.mem.indexOfAny(u8, value, ",}") orelse value.len;
    return std.fmt.parseInt(u64, value[0..end], 10) catch null;
}

/// A wall-clock retry deadline: the fault schedule and a loaded host
/// both stretch attempts, so budgets count real time, and every
/// unsuccessful attempt sleeps before the next.
const Deadline = struct {
    io: Io,
    end_ns: i96,

    fn start(io: Io, budget_ms: u64) Deadline {
        const now = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
        return .{
            .io = io,
            .end_ns = now + @as(i96, budget_ms) * std.time.ns_per_ms,
        };
    }

    /// Sleeps one poll interval; returns false once the budget is spent.
    fn tick(self: *const Deadline) bool {
        self.io.sleep(.fromMilliseconds(100), .awake) catch {};
        const now = std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds;
        return now < self.end_ns;
    }
};

fn openSession(
    gpa: std.mem.Allocator,
    io: Io,
    node: *zaxonlite.Embedded,
) !u64 {
    const deadline = Deadline.start(io, 90_000);
    while (true) {
        if (node.call("{\"op\":\"session\"}", true)) |body| {
            defer gpa.free(body);
            if (std.mem.indexOf(u8, body, "\"session_id\":")) |start| {
                const digits = body[start + 13 ..];
                const end = std.mem.indexOfAny(u8, digits, ",}") orelse digits.len;
                return std.fmt.parseInt(u64, digits[0..end], 10) catch
                    error.InvalidResponse;
            }
        } else |_| {}
        if (!deadline.tick()) break;
    }
    return error.ClusterWriteTimeout;
}

fn retryCall(
    gpa: std.mem.Allocator,
    io: Io,
    node: *zaxonlite.Embedded,
    request: []const u8,
) !void {
    const deadline = Deadline.start(io, 90_000);
    while (true) {
        if (node.call(request, true)) |body| {
            defer gpa.free(body);
            if (std.mem.indexOf(u8, body, "\"ok\":true") != null) return;
        } else |_| {}
        if (!deadline.tick()) break;
    }
    return error.ClusterWriteTimeout;
}

fn retryExec(io: Io, node: *zaxonlite.Embedded, sql: []const u8) !void {
    const deadline = Deadline.start(io, 90_000);
    while (true) {
        if (node.exec(sql)) |_| return else |_| {}
        if (!deadline.tick()) break;
    }
    return error.ClusterWriteTimeout;
}

fn expectCount(
    gpa: std.mem.Allocator,
    io: Io,
    address: []const u8,
    expected: usize,
) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    const deadline = Deadline.start(io, 90_000);
    while (true) {
        const connection = zaxonlite.client.Connection.open(gpa, io, endpoint) catch {
            if (!deadline.tick()) break;
            continue;
        };
        const response = connection.call(
            "{\"op\":\"query\",\"sql\":\"select count(*) from f\"," ++
                "\"level\":\"any\"}",
        ) catch {
            connection.close();
            if (!deadline.tick()) break;
            continue;
        };
        connection.close();
        defer gpa.free(response);
        var expected_text_buffer: [32]u8 = undefined;
        const expected_text = std.fmt.bufPrint(
            &expected_text_buffer,
            "[[\"{d}\"]]",
            .{expected},
        ) catch unreachable;
        if (std.mem.indexOf(u8, response, expected_text) != null) return;
        if (!deadline.tick()) break;
    }
    return error.ReplicaCatchUpTimeout;
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
            ".zig-cache/tmp/zx-fault-{x}",
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

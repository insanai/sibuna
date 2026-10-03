//! Soak run: sustained mixed load against one durable node.
//!
//! Random writes, reads, idempotent session traffic, anchors, and full
//! restarts for a wall-clock budget, with continuous invariants: row count
//! matches an in-memory model, session sequences apply exactly once, and
//! the integrity report stays clean. Prints throughput statistics.
//!
//! Usage: soak [seconds] [seed]

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;

pub fn main(init: std.process.Init) !u8 {
    // Logic and process-crash coverage need no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const seconds = blk: {
        const text = iterator.next() orelse break :blk @as(u64, 15);
        break :blk std.fmt.parseInt(u64, text, 10) catch 15;
    };
    const seed = blk: {
        const text = iterator.next() orelse {
            var bytes: [8]u8 = undefined;
            io.random(&bytes);
            break :blk std.mem.readInt(u64, &bytes, .little);
        };
        break :blk std.fmt.parseInt(u64, text, 10) catch 0;
    };
    std.debug.print("soak: {d}s budget, seed {d}\n", .{ seconds, seed });

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var root_buffer: [64]u8 = undefined;
    const root = std.fmt.bufPrint(
        &root_buffer,
        ".zig-cache/tmp/zx-soak-{x}",
        .{seed},
    ) catch unreachable;
    Io.Dir.cwd().deleteTree(io, root) catch {};
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    var node = try Node.open(gpa, io, .{ .directory = root });
    var open = true;
    defer if (open) node.close();
    _ = try node.exec("create table s(id integer primary key, k integer, v text)");

    const session = try node.openSession();
    var next_sequence: u64 = 1;
    var expected_rows: i64 = 0;

    var writes: u64 = 0;
    var reads: u64 = 0;
    var anchors: u64 = 0;
    var restarts: u64 = 0;
    var session_writes: u64 = 0;

    const start = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline_ns: i96 = @as(i96, @intCast(seconds)) * std.time.ns_per_s;
    var sql_buffer: [192]u8 = undefined;

    while (true) {
        const elapsed = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake));
        if (elapsed.raw.nanoseconds >= deadline_ns) break;

        switch (random.intRangeAtMost(u8, 0, 99)) {
            0...54 => {
                const sql = std.mem.printSentinel(
                    &sql_buffer,
                    "insert into s(k, v) values ({d}, 'v{d}')",
                    .{ random.int(u16), writes },
                    0,
                ) catch unreachable;
                _ = try node.exec(sql);
                expected_rows += 1;
                writes += 1;
            },
            55...69 => {
                const sql = std.mem.printSentinel(
                    &sql_buffer,
                    "insert into s(k, v) values ({d}, 'session')",
                    .{random.int(u16)},
                    0,
                ) catch unreachable;
                const result = try node.execIdempotent(session, next_sequence, sql);
                if (result.replayed) return error.UnexpectedReplay;
                // Occasionally retry the same sequence: must replay.
                if (random.boolean()) {
                    const replay = try node.execIdempotent(session, next_sequence, sql);
                    if (!replay.replayed) return error.MissingReplay;
                }
                next_sequence += 1;
                expected_rows += 1;
                session_writes += 1;
            },
            70...92 => {
                var result = try node.query(gpa, "select count(*) from s");
                defer result.deinit();
                const count = try std.fmt.parseInt(i64, result.rows[0][0].?, 10);
                if (count != expected_rows) {
                    std.debug.print(
                        "count mismatch: expected {d}, got {d}\n",
                        .{ expected_rows, count },
                    );
                    return error.RowCountMismatch;
                }
                reads += 1;
            },
            93...95 => {
                try node.createStateAnchor();
                anchors += 1;
            },
            else => {
                node.close();
                open = false;
                node = try Node.open(gpa, io, .{ .directory = root });
                open = true;
                restarts += 1;
            },
        }
    }

    const report = try node.integrityCheck();
    if (!report.ok()) return error.IntegrityFailed;
    {
        var result = try node.query(gpa, "select count(*) from s");
        defer result.deinit();
        const count = try std.fmt.parseInt(i64, result.rows[0][0].?, 10);
        if (count != expected_rows) return error.RowCountMismatch;
    }

    const total = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake));
    const total_ms: u64 = @intCast(total.raw.toMilliseconds());
    std.debug.print(
        "soak: PASS  {d} writes, {d} session writes, {d} reads, " ++
            "{d} anchors, {d} restarts in {d} ms " ++
            "({d} writes/s)\n",
        .{
            writes,
            session_writes,
            reads,
            anchors,
            restarts,
            total_ms,
            if (total_ms > 0) (writes + session_writes) * 1000 / total_ms else 0,
        },
    );
    return 0;
}

//! Long-run retention gate: one durable node, enough writes to rotate
//! journal segments several times, with the host anchor/reclaim duties
//! driven the way a server pump drives them (ZDS 0011).
//!
//! The gate proves the properties the epoch rollover used to fake:
//! the configuration never changes, global slots only grow, segments
//! rotate and are physically reclaimed below the chosen trim, retention
//! stays bounded, and a restart recovers from the durable anchor plus
//! the retained suffix even though history below the anchor is gone.
//!
//! Usage: longrun [writes]

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;

pub fn main(init: std.process.Init) !u8 {
    // Process-crash coverage needs no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const writes = blk: {
        const text = iterator.next() orelse break :blk @as(u64, 20_000);
        break :blk std.fmt.parseInt(u64, text, 10) catch 20_000;
    };
    // Below one full segment (16,384 records at two records per write)
    // nothing rotates, so the reclamation assertions cannot hold.
    if (writes < 10_000) {
        return fail("{d} writes cannot rotate a segment; use 10000 or more", .{writes});
    }

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const directory = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-longrun-{x}",
        .{nonce},
    );
    defer gpa.free(directory);
    defer Io.Dir.cwd().deleteTree(io, directory) catch {};

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const wrote = try writePhase(gpa, io, directory, writes);
    if (wrote != 0) return wrote;
    const recovered = try restartPhase(gpa, io, directory, writes);
    if (recovered != 0) return recovered;

    const finished = std.Io.Clock.Timestamp.now(io, .awake);
    const elapsed_ms: u64 = @intCast(@divTrunc(
        started.durationTo(finished).raw.nanoseconds,
        std.time.ns_per_ms,
    ));
    std.debug.print(
        "longrun: {d} writes, bounded retention, anchored restart ok ({d} ms)\n",
        .{ writes, elapsed_ms },
    );
    return 0;
}

fn writePhase(
    gpa: std.mem.Allocator,
    io: Io,
    directory: []const u8,
    writes: u64,
) !u8 {
    const node = try Node.open(gpa, io, .{ .directory = directory });
    defer node.close();
    _ = try node.exec("create table t(id integer primary key, v integer)");
    var sql_buffer: [96:0]u8 = undefined;
    for (0..writes) |index| {
        const sql = std.mem.printSentinel(
            &sql_buffer,
            "insert into t(v) values ({d})",
            .{index},
            0,
        ) catch unreachable;
        _ = try node.exec(sql);
        // The host pump's periodic duties, at a test-friendly cadence.
        if (index % 1_000 == 999) {
            _ = try node.maybeCreateStateAnchor();
            try node.reclaim();
        }
        if (index % 2_000 == 1_999) {
            std.debug.print(
                "longrun: {d}/{d} writes\n",
                .{ index + 1, writes },
            );
        }
    }
    try node.createStateAnchor();
    try node.reclaim();

    const status = node.status();
    if (node.identity.configuration_id != 1) {
        return fail("configuration moved to {d}", .{
            node.identity.configuration_id,
        });
    }
    if (status.retained_first_slot <= 1) {
        return fail("no segment was physically reclaimed", .{});
    }
    // Retention stays bounded: the suffix above the trim plus the
    // active segment, never the whole history.
    if (status.journal_segment_count > 4) {
        return fail("{d} retained segments; retention is unbounded", .{
            status.journal_segment_count,
        });
    }
    if (status.chosen_trim_slot == 0 or
        status.durable_state_slot == 0)
    {
        return fail("anchor or trim never advanced", .{});
    }
    return 0;
}

// Restart: the image below the anchor is authoritative, the journal
// holds only the suffix, and recovery must still be complete.
fn restartPhase(
    gpa: std.mem.Allocator,
    io: Io,
    directory: []const u8,
    writes: u64,
) !u8 {
    const node = try Node.open(gpa, io, .{ .directory = directory });
    defer node.close();
    var result = try node.query(gpa, "select count(*), sum(v) from t");
    defer result.deinit();
    const count = try std.fmt.parseInt(u64, result.rows[0][0].?, 10);
    const sum = try std.fmt.parseInt(u64, result.rows[0][1].?, 10);
    if (count != writes) {
        return fail("recovered {d} rows, wrote {d}", .{ count, writes });
    }
    if (sum != writes * (writes - 1) / 2) {
        return fail("recovered sum {d} is wrong", .{sum});
    }
    const report = try node.integrityCheck();
    if (!report.ok()) return fail("integrity check failed", .{});
    _ = try node.exec("insert into t(v) values (-1)");
    return 0;
}

fn fail(comptime format: []const u8, arguments: anytype) u8 {
    std.debug.print("longrun FAILED: " ++ format ++ "\n", arguments);
    return 1;
}

//! Zaxonlite micro-benchmarks: single-node write path, read path, and
//! recovery time, with per-operation latency percentiles.
//!
//! The write path measured here is the full replication pipeline: SQLite
//! execute + WAL frame capture + payload store fsync + journal append +
//! journal fsync + commit accounting. Reads run over the live connection.
//! Recovery measures a full `Node.open` (journal replay + offline page
//! apply + validation) over the retained journal suffix.
//!
//! The write run also drives durable state anchors the way a server pump
//! does (`maybeCreateStateAnchor` after every write), forcing an anchor
//! at a fixed write interval so at least two anchor events land inside
//! the run at any bench scale. Afterwards it prints the lag
//! autocorrelation of the time-ordered per-write latency series at the
//! anchor-interval lag and at the journal segment-rotation lag, flagging
//! |r| > 0.2 as suspected periodicity. This is a self-contained printed
//! check; it emits no results-protocol file.
//!
//! Usage: bench [writes] [reads]

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const bench_stats = @import("bench_stats.zig");

const Node = zaxonlite.Node;

fn nowNs(io: Io) i96 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
}

/// Predeclared report-only autocorrelation threshold for periodicity,
/// matching the paxos-zig bench-gate's flag.
const periodicity_flag = 0.2;

/// Journal records per replicated write on the single-node path: one
/// accept and one commit (the long-run retention gate documents the
/// same two-records-per-write ratio).
const journal_records_per_write = 2;

/// One lag of the periodicity check over the per-write latency series.
const LagCheck = struct {
    name: []const u8,
    lag: usize,
    r: f64,
    available: bool,
};

/// Computes the check while `samples` is still in time order; a lag of
/// zero or past half the series is unavailable rather than misleading.
fn lagCheck(name: []const u8, samples: []const u64, lag: usize) LagCheck {
    if (lag == 0 or lag >= samples.len / 2) {
        return .{ .name = name, .lag = lag, .r = 0, .available = false };
    }
    return .{
        .name = name,
        .lag = lag,
        .r = bench_stats.autocorrelation(samples, lag),
        .available = true,
    };
}

fn printLagCheck(check: LagCheck, series_len: usize) void {
    if (!check.available) {
        std.debug.print(
            "{s} autocorrelation: lag {d} unavailable for {d} write samples\n",
            .{ check.name, check.lag, series_len },
        );
        return;
    }
    const verdict = if (@abs(check.r) > periodicity_flag)
        "  PERIODICITY SUSPECTED (|r| > 0.2)"
    else
        "";
    std.debug.print(
        "{s} autocorrelation: lag {d} writes r={d:.3}{s}\n",
        .{ check.name, check.lag, check.r, verdict },
    );
}

const Stats = struct {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
    mean: u64,

    fn compute(samples: []u64) Stats {
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        var total: u128 = 0;
        for (samples) |sample| total += sample;
        const n = samples.len;
        return .{
            .p50 = samples[n / 2],
            .p95 = samples[(n * 95) / 100],
            .p99 = samples[(n * 99) / 100],
            .max = samples[n - 1],
            .mean = @intCast(total / n),
        };
    }
};

fn printRow(
    name: []const u8,
    count: usize,
    elapsed_ns: i96,
    stats: Stats,
) void {
    const elapsed_ms: u64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
    const per_second = if (elapsed_ns > 0)
        @as(u64, @intCast(@divTrunc(
            @as(i96, @intCast(count)) * std.time.ns_per_s,
            elapsed_ns,
        )))
    else
        0;
    std.debug.print(
        "{s:<18} {d:>7} ops {d:>7} ms {d:>9} ops/s " ++
            "p50 {d:>7} us  p95 {d:>7} us  p99 {d:>7} us  max {d:>8} us\n",
        .{
            name,
            count,
            elapsed_ms,
            per_second,
            stats.p50 / 1000,
            stats.p95 / 1000,
            stats.p99 / 1000,
            stats.max / 1000,
        },
    );
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const write_count = blk: {
        const text = iterator.next() orelse break :blk @as(usize, 1000);
        break :blk std.fmt.parseInt(usize, text, 10) catch 1000;
    };
    const read_count = blk: {
        const text = iterator.next() orelse break :blk @as(usize, 10_000);
        break :blk std.fmt.parseInt(usize, text, 10) catch 10_000;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    var root_buffer: [64]u8 = undefined;
    const root = std.fmt.bufPrint(
        &root_buffer,
        ".zig-cache/tmp/zx-bench-{x}",
        .{nonce},
    ) catch unreachable;
    Io.Dir.cwd().deleteTree(io, root) catch {};
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    std.debug.print(
        "zaxonlite benchmark: {d} writes, {d} reads (fsync per write: payload + journal)\n",
        .{ write_count, read_count },
    );

    var node = try Node.open(gpa, io, .{ .directory = root });
    _ = try node.exec("create table b(id integer primary key, k integer, v text)");

    const control_ok = try benchWrites(gpa, io, node, write_count);
    try benchReads(gpa, io, node, read_count, write_count);
    try benchRecovery(gpa, io, &node, root, write_count);
    if (!control_ok) {
        std.debug.print(
            "FAILED: the event-labelled anchor positive control did not " ++
                "register; the periodicity instrument is broken\n",
            .{},
        );
        return 1;
    }
    return 0;
}

fn benchWrites(gpa: std.mem.Allocator, io: std.Io, node: *Node, write_count: usize) !bool {
    const write_samples = try gpa.alloc(u64, write_count);
    defer gpa.free(write_samples);
    // Anchors on the natural cadence would need 10,000 slots or 30
    // seconds; the forced interval guarantees at least two anchor
    // events inside the run at any bench scale while the maybe call
    // keeps the natural cadence live. The periodicity series measures
    // inter-completion time under the saturated loop -- each sample
    // closes only after the iteration's anchor and pump duties -- so an
    // anchor stall lands inside its own sample instead of vanishing
    // between two write timings. The headline row keeps the bare
    // per-exec timings.
    const interval_samples = try gpa.alloc(u64, write_count);
    defer gpa.free(interval_samples);
    const anchored_flags = try gpa.alloc(bool, write_count);
    defer gpa.free(anchored_flags);
    const anchor_every = @max(write_count / 8, 32);
    var anchor_events: usize = 0;
    var anchor_duty_ns: u128 = 0;
    var sql_buffer: [160]u8 = undefined;
    const write_start = nowNs(io);
    var last_completion = write_start;
    for (0..write_count) |index| {
        const sql = std.mem.printSentinel(
            &sql_buffer,
            "insert into b(k, v) values ({d}, 'value-{d}')",
            .{ index % 997, index },
            0,
        ) catch unreachable;
        const op_start = nowNs(io);
        _ = try node.exec(sql);
        const exec_done = nowNs(io);
        write_samples[index] = @intCast(exec_done - op_start);
        const iteration_anchored = try runAnchorDuty(node, index, anchor_every);
        if (iteration_anchored) anchor_events += 1;
        anchored_flags[index] = iteration_anchored;
        const completion = nowNs(io);
        anchor_duty_ns += @intCast(completion - exec_done);
        interval_samples[index] = @intCast(completion - last_completion);
        last_completion = completion;
    }
    const write_elapsed = nowNs(io) - write_start;
    // Both checks read the series in time order, before Stats.compute
    // sorts it into order statistics.
    // Autocorrelation remains useful evidence, but a few periodic
    // events can be drowned by host stalls. The event-labelled paired
    // shift is the positive control; bare exec timings answer the gate.
    const control_check = lagCheck(
        "anchor-cost visibility",
        interval_samples,
        anchor_every,
    );
    const anchor_check = lagCheck("anchor-interval", write_samples, anchor_every);
    const rotation_lag = zaxonlite.segment.rotation_records / journal_records_per_write;
    const rotation_check = lagCheck("segment-rotation", write_samples, rotation_lag);
    const shift = try reportWriteRun(
        gpa,
        interval_samples,
        write_samples,
        anchored_flags,
        write_elapsed,
        anchor_duty_ns,
        anchor_events,
        anchor_every,
    );
    printLagCheck(control_check, write_count);
    printLagCheck(anchor_check, write_count);
    printLagCheck(rotation_check, write_count);
    return anchor_events >= 2 and shift.paired >= 2 and shift.shift > 0;
}

/// One iteration's anchor duty: the forced cadence guarantees anchor
/// events at bench scale, and the maybe call keeps the natural cadence
/// live. Returns whether this iteration carried an anchor.
fn runAnchorDuty(node: *Node, index: usize, anchor_every: usize) !bool {
    if ((index + 1) % anchor_every == 0) {
        try node.createStateAnchor();
        return true;
    }
    return try node.maybeCreateStateAnchor();
}

/// Prints both latency rows plus the directly timed anchor duty cycle
/// and the shift between anchor-bearing and adjacent plain iterations:
/// the magnitudes the correlation only hints at.
fn reportWriteRun(
    gpa: std.mem.Allocator,
    interval_samples: []u64,
    write_samples: []u64,
    anchored_flags: []const bool,
    write_elapsed: i96,
    anchor_duty_ns: u128,
    anchor_events: usize,
    anchor_every: usize,
) !bench_stats.ShiftResult {
    const shift_scratch = try gpa.alloc(u64, anchor_events);
    defer gpa.free(shift_scratch);
    const duty_percent = @as(f64, @floatFromInt(anchor_duty_ns)) * 100.0 /
        @as(f64, @floatFromInt(@max(write_elapsed, 1)));
    const shift = bench_stats.pairedAnchorShift(
        shift_scratch,
        interval_samples,
        anchored_flags,
    );
    printRow("write", write_samples.len, write_elapsed, Stats.compute(write_samples));
    const interval_stats = Stats.compute(interval_samples);
    printRow("write+duties", interval_samples.len, write_elapsed, interval_stats);
    std.debug.print(
        "anchor events:     {d} during the write run (forced every {d} " ++
            "writes); anchor+pump duty cycle {d:.1}% (directly timed)\n",
        .{ anchor_events, anchor_every, duty_percent },
    );
    std.debug.print(
        "anchor-iteration shift: median {d} us over the nearest plain " ++
            "iteration within eight slots (nonnegative, zero-censored; " ++
            "{d} paired, {d} dropped)\n",
        .{ shift.shift / std.time.ns_per_us, shift.paired, shift.dropped },
    );
    return shift;
}

fn benchReads(
    gpa: std.mem.Allocator,
    io: std.Io,
    node: *Node,
    read_count: usize,
    write_count: usize,
) !void {
    const read_samples = try gpa.alloc(u64, read_count);
    defer gpa.free(read_samples);
    var sql_buffer: [160]u8 = undefined;
    const read_start = nowNs(io);
    for (0..read_count) |index| {
        const sql = std.fmt.bufPrint(
            &sql_buffer,
            "select v from b where id = {d}",
            .{1 + (index % write_count)},
        ) catch unreachable;
        const op_start = nowNs(io);
        var result = try node.query(gpa, sql);
        result.deinit();
        read_samples[index] = @intCast(nowNs(io) - op_start);
    }
    const read_elapsed = nowNs(io) - read_start;
    printRow("read", read_count, read_elapsed, Stats.compute(read_samples));
}

fn benchRecovery(
    gpa: std.mem.Allocator,
    io: std.Io,
    node_ptr: **Node,
    root: []const u8,
    write_count: usize,
) !void {
    node_ptr.*.close();
    const recovery_start = nowNs(io);
    node_ptr.* = try Node.open(gpa, io, .{ .directory = root });
    const recovery_elapsed = nowNs(io) - recovery_start;
    std.debug.print(
        "{s:<18} {d:>7} ms (journal replay + image validation, {d} committed writes)\n",
        .{
            "recovery",
            @as(u64, @intCast(@divTrunc(recovery_elapsed, std.time.ns_per_ms))),
            write_count,
        },
    );

    try node_ptr.*.createStateAnchor();
    node_ptr.*.close();
    {
        var db_buffer: [96]u8 = undefined;
        const db_path = std.fmt.bufPrint(&db_buffer, "{s}/current.db", .{root}) catch unreachable;
        Io.Dir.cwd().deleteFile(io, db_path) catch {};
    }
    const rebuild_start = nowNs(io);
    node_ptr.* = try Node.open(gpa, io, .{ .directory = root });
    const rebuild_elapsed = nowNs(io) - rebuild_start;
    std.debug.print(
        "{s:<18} {d:>7} ms (image restored from anchor)\n",
        .{
            "rebuild",
            @as(u64, @intCast(@divTrunc(rebuild_elapsed, std.time.ns_per_ms))),
        },
    );
    node_ptr.*.close();
}

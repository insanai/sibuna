//! Three-node cluster benchmark: replicated write and read throughput
//! and latency over one persistent client connection to the leader, with
//! per-node memory and CPU cost sampled from the real server processes.
//!
//! The workload is deliberately sequential — zaxonlite serializes one
//! replicated write at a time — so the numbers measure the full pipeline
//! (transport, consensus round trip, payload + journal fsync on a quorum)
//! rather than client-side pipelining.
//!
//! Usage: cluster-bench <path-to-zaxon> [--record <json>] [--keep]
//!        [--sync <os|full>]
//!        [plaintext|psk|tls] [writes] [reads]
//!
//! With `--record`, the run's results replace the matching mode+sync entry
//! in the named JSON file; the Zaxonlite book renders its benchmark table
//! from that file, so recorded runs flow into the compiled documentation.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;
const tls = zaxonlite.tls;

const Endpoint = client.Endpoint;
const bench_secret = "cluster-bench-secret-32-bytes-min!";

const Mode = enum { plaintext, psk, tls };

const NodeProc = struct {
    id: u32,
    port: u16,
    directory: []const u8,
    child: ?std.process.Child = null,
};

fn nowNs(io: Io) i96 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
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

fn opsPerSecond(count: usize, elapsed_ns: i96) u64 {
    if (elapsed_ns <= 0) return 0;
    return @intCast(@divTrunc(
        @as(i96, @intCast(count)) * std.time.ns_per_s,
        elapsed_ns,
    ));
}

fn printRow(name: []const u8, count: usize, elapsed_ns: i96, stats: Stats) void {
    const elapsed_ms: u64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
    const per_second = opsPerSecond(count, elapsed_ns);
    std.debug.print(
        "{s:<20} {d:>6} ops {d:>7} ms {d:>7} ops/s " ++
            "p50 {d:>6} us  p95 {d:>6} us  p99 {d:>6} us  max {d:>8} us\n",
        .{
            name,             count,            elapsed_ms,       per_second,
            stats.p50 / 1000, stats.p95 / 1000, stats.p99 / 1000, stats.max / 1000,
        },
    );
}

// ----------------------------------------------------------------------
// Process resource sampling (via ps; macOS and Linux compatible fields)
// ----------------------------------------------------------------------

const Usage = struct {
    rss_kb: u64,
    cpu_ms: u64,
};

fn sampleUsage(gpa: std.mem.Allocator, io: Io, pid: i32) !Usage {
    var pid_buffer: [16]u8 = undefined;
    const pid_text = std.fmt.bufPrint(&pid_buffer, "{d}", .{pid}) catch
        unreachable;
    var child = try std.process.spawn(io, .{
        .argv = &.{ "ps", "-o", "rss=,cputime=", "-p", pid_text },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    var buffer: [512]u8 = undefined;
    var reader = child.stdout.?.readerStreaming(io, &buffer);
    const output = try reader.interface.allocRemaining(gpa, .limited(4096));
    defer gpa.free(output);
    _ = try child.wait(io);

    var fields = std.mem.tokenizeAny(u8, output, " \t\r\n");
    const rss_text = fields.next() orelse return error.PsParse;
    const time_text = fields.next() orelse return error.PsParse;
    return .{
        .rss_kb = std.fmt.parseInt(u64, rss_text, 10) catch return error.PsParse,
        .cpu_ms = try parseCpuTimeMs(time_text),
    };
}

/// Parses `[[hh:]mm:]ss.cc` (the portable `cputime` rendering).
fn parseCpuTimeMs(text: []const u8) !u64 {
    var seconds_total: u64 = 0;
    var parts = std.mem.tokenizeScalar(u8, text, ':');
    while (parts.next()) |part| {
        const value = std.fmt.parseFloat(f64, part) catch return error.PsParse;
        seconds_total = seconds_total * 60;
        seconds_total += @intFromFloat(value);
        if (parts.peek() == null) {
            // Keep sub-second precision from the final component.
            const whole: f64 = @floatFromInt(@as(u64, @intFromFloat(value)));
            const fraction = value - whole;
            return seconds_total * 1000 + @as(u64, @intFromFloat(fraction * 1000));
        }
    }
    return seconds_total * 1000;
}

// ----------------------------------------------------------------------
// TLS material (generated per run with the system openssl CLI)
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

fn generateIdentity(
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
// Controller
// ----------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const zaxon_path = iterator.next() orelse {
        std.debug.print(
            "usage: cluster-bench <zaxon> <plaintext|psk|tls> [writes] [reads]\n",
            .{},
        );
        return 2;
    };
    var record_path: ?[]const u8 = null;
    var keep_artifacts = false;
    var sync_text: []const u8 = "full";
    var positionals: [3]?[]const u8 = .{ null, null, null };
    var positional_count: usize = 0;
    while (iterator.next()) |argument| {
        if (std.mem.eql(u8, argument, "--record")) {
            record_path = iterator.next() orelse {
                std.debug.print("--record needs a path\n", .{});
                return 2;
            };
        } else if (std.mem.eql(u8, argument, "--keep")) {
            keep_artifacts = true;
        } else if (std.mem.eql(u8, argument, "--sync")) {
            sync_text = iterator.next() orelse {
                std.debug.print("--sync needs os or full\n", .{});
                return 2;
            };
        } else if (positional_count < positionals.len) {
            positionals[positional_count] = argument;
            positional_count += 1;
        }
    }
    if (std.meta.stringToEnum(zaxonlite.durability.SyncMode, sync_text) == null) {
        std.debug.print("--sync must be os or full\n", .{});
        return 2;
    }
    const mode_text = positionals[0] orelse "psk";
    const mode = std.meta.stringToEnum(Mode, mode_text) orelse {
        std.debug.print("unknown mode: {s}\n", .{mode_text});
        return 2;
    };
    const write_count = blk: {
        const text = positionals[1] orelse break :blk @as(usize, 1000);
        break :blk std.fmt.parseInt(usize, text, 10) catch 1000;
    };
    const read_count = blk: {
        const text = positionals[2] orelse break :blk @as(usize, 2000);
        break :blk std.fmt.parseInt(usize, text, 10) catch 2000;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-cluster-bench-{x}",
        .{nonce},
    );
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer if (!keep_artifacts) Io.Dir.cwd().deleteTree(io, root) catch {};
    if (keep_artifacts) {
        std.debug.print("benchmark artifacts: {s}\n", .{root});
    }

    // Transport material.
    const auth_file = try std.fmt.allocPrint(gpa, "{s}/secret", .{root});
    defer gpa.free(auth_file);
    if (mode == .psk) {
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = auth_file,
            .data = bench_secret,
        });
        // The server refuses provider files readable by group or other.
        try Io.Dir.cwd().setFilePermissions(
            io,
            auth_file,
            @fromBackingInt(@intCast(0o600)),
            .{},
        );
    }
    if (mode == .tls) {
        try generateIdentity(gpa, io, root, "ca", null, "zaxon-bench-ca");
        for (1..4) |id| {
            var name_buffer: [8]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buffer, "n{d}", .{id}) catch
                unreachable;
            var cn_buffer: [32]u8 = undefined;
            const cn = std.fmt.bufPrint(
                &cn_buffer,
                "zaxon-node-{d}",
                .{id},
            ) catch unreachable;
            try generateIdentity(gpa, io, root, name, "ca", cn);
        }
        try generateIdentity(gpa, io, root, "client", "ca", "zaxon-bench-client");
    }
    const ca_path = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{root});
    defer gpa.free(ca_path);
    const client_cert = try std.fmt.allocPrint(gpa, "{s}/client.crt", .{root});
    defer gpa.free(client_cert);
    const client_key = try std.fmt.allocPrint(gpa, "{s}/client.key", .{root});
    defer gpa.free(client_key);

    // Cluster processes.
    const base_port: u16 = @intCast(30000 + nonce % 20000);
    var nodes: [3]NodeProc = undefined;
    var endpoints: [3]Endpoint = undefined;
    var host_buffers: [3][32]u8 = undefined;
    for (&nodes, 0..) |*node, index| {
        node.* = .{
            .id = @intCast(index + 1),
            .port = base_port + @as(u16, @intCast(index)),
            .directory = try std.fmt.allocPrint(
                gpa,
                "{s}/n{d}",
                .{ root, index + 1 },
            ),
        };
        const host = try std.fmt.bufPrint(
            &host_buffers[index],
            "127.0.0.1",
            .{},
        );
        endpoints[index] = .{ .host = host, .port = node.port };
    }
    defer for (nodes) |node| gpa.free(node.directory);

    for (&nodes) |*node| {
        try spawnNode(gpa, io, zaxon_path, root, mode, sync_text, &nodes, node);
    }
    defer for (&nodes) |*node| {
        if (node.child) |*child| {
            child.kill(io);
            node.child = null;
        }
    };

    // Client transport.
    var tls_context: ?tls.Context = null;
    defer if (tls_context) |*context| context.deinit();
    if (mode == .tls) {
        tls_context = try tls.Context.initClient(.{
            .cert_path = client_cert,
            .key_path = client_key,
            .ca_path = ca_path,
        });
    }
    const transport = client.Transport{
        .secret = if (mode == .psk) bench_secret else null,
        .tls = if (tls_context) |*context| context else null,
    };

    std.debug.print(
        "zaxonlite 3-node cluster benchmark: mode={s} sync={s} " ++
            "writes={d} reads={d}\n",
        .{ @tagName(mode), sync_text, write_count, read_count },
    );

    // Wait for a leader by creating the schema through the redirecting
    // cluster call. One call fails fast while the first election is still
    // in progress, so retry under a startup deadline.
    const create_sql =
        "{\"op\":\"exec\",\"sql\":\"create table b(id integer primary key, " ++
        "k integer, v text)\"}";
    var create = create: {
        var waited_ms: u64 = 0;
        while (true) {
            const result = client.callClusterWithTransport(
                gpa,
                io,
                &endpoints,
                create_sql,
                true,
                transport,
            ) catch |err| {
                if (waited_ms >= 15_000) {
                    std.debug.print(
                        "cluster never elected a reachable leader: {t}\n",
                        .{err},
                    );
                    return 1;
                }
                waited_ms += 250;
                io.sleep(.fromMilliseconds(250), .awake) catch {};
                continue;
            };
            break :create result;
        }
    };
    defer create.deinit(gpa);
    const leader_endpoint = create.endpoint;
    gpa.free(create.body);
    create.body = &.{};

    const before = try sampleAll(gpa, io, &nodes);

    // One persistent connection to the leader, like an embedded client.
    // Long full-sync stalls can starve leader heartbeats and move
    // leadership mid-run, so every response is verified and a declined
    // request re-resolves the leader; the retry latency stays in the
    // sample, which is the honest cost of the failover.
    const connection = try client.Connection.openWithTransport(
        gpa,
        io,
        leader_endpoint,
        transport,
    );
    var connection_ptr = connection;
    defer connection_ptr.close();
    const write_res = try runBenchWrites(
        gpa,
        io,
        &endpoints,
        &connection_ptr,
        transport,
        write_count,
    );
    const read_res = try runBenchReads(
        gpa,
        io,
        &endpoints,
        &connection_ptr,
        transport,
        read_count,
        write_count,
    );

    const after = try sampleAll(gpa, io, &nodes);
    std.debug.print("per-node resources (workload delta):\n", .{});
    for (nodes, 0..) |node, index| {
        std.debug.print(
            "  node {d}: rss {d:>4} MiB, cpu {d:>6} ms\n",
            .{
                node.id,
                after[index].rss_kb / 1024,
                after[index].cpu_ms - before[index].cpu_ms,
            },
        );
    }

    if (record_path) |path| {
        var max_rss_mib: u64 = 0;
        var max_cpu_ms: u64 = 0;
        for (0..nodes.len) |index| {
            max_rss_mib = @max(max_rss_mib, after[index].rss_kb / 1024);
            max_cpu_ms = @max(
                max_cpu_ms,
                after[index].cpu_ms - before[index].cpu_ms,
            );
        }
        try recordResults(gpa, io, path, .{
            .mode = @tagName(mode),
            .sync = sync_text,
            .writes = write_count,
            .payload_bytes = 256,
            .write_ops_s = opsPerSecond(write_count, write_res.elapsed),
            .write_p50_us = write_res.stats.p50 / 1000,
            .write_p95_us = write_res.stats.p95 / 1000,
            .write_p99_us = write_res.stats.p99 / 1000,
            .write_max_us = write_res.stats.max / 1000,
            .reads = read_count,
            .read_leader_ops_s = read_res.ops[0],
            .read_leader_p50_us = read_res.stats[0].p50 / 1000,
            .read_linearizable_ops_s = read_res.ops[1],
            .read_linearizable_p50_us = read_res.stats[1].p50 / 1000,
            .max_node_rss_mib = max_rss_mib,
            .max_node_cpu_ms = max_cpu_ms,
        });
        std.debug.print("recorded results to {s}\n", .{path});
    }

    // Orderly stop so WAL/journal state is clean for inspection.
    const stop = client.callClusterWithTransport(
        gpa,
        io,
        &endpoints,
        "{\"op\":\"stop\"}",
        false,
        transport,
    ) catch null;
    if (stop) |value| {
        var result = value;
        result.deinit(gpa);
    }
    return 0;
}

// ----------------------------------------------------------------------
// Recorded results: the book renders its benchmark table from this file
// ----------------------------------------------------------------------

const RunRecord = struct {
    mode: []const u8,
    sync: []const u8,
    writes: usize,
    payload_bytes: usize = 0,
    write_ops_s: u64,
    write_p50_us: u64,
    write_p95_us: u64 = 0,
    write_p99_us: u64,
    write_max_us: u64 = 0,
    reads: usize,
    read_leader_ops_s: u64,
    read_leader_p50_us: u64,
    read_linearizable_ops_s: u64,
    read_linearizable_p50_us: u64,
    max_node_rss_mib: u64,
    max_node_cpu_ms: u64,
};

const Results = struct {
    note: []const u8 = "",
    runs: []const RunRecord = &.{},
};

/// Replaces the entry matching this run's mode+sync in the JSON results
/// file (creating the file when absent) and keeps the rest, so repeated
/// recorded runs accumulate one row per configuration.
fn recordResults(
    gpa: std.mem.Allocator,
    io: Io,
    path: []const u8,
    run: RunRecord,
) !void {
    var parsed: ?std.json.Parsed(Results) = null;
    defer if (parsed) |*previous| previous.deinit();
    if (Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20))) |bytes| {
        defer gpa.free(bytes);
        parsed = std.json.parseFromSlice(Results, gpa, bytes, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        }) catch null;
    } else |_| {}

    var runs: std.ArrayList(RunRecord) = .empty;
    defer runs.deinit(gpa);
    if (parsed) |previous| {
        for (previous.value.runs) |existing| {
            if (std.mem.eql(u8, existing.mode, run.mode) and
                std.mem.eql(u8, existing.sync, run.sync))
            {
                continue;
            }
            try runs.append(gpa, existing);
        }
    }
    try runs.append(gpa, run);
    std.mem.sort(RunRecord, runs.items, {}, runOrder);

    const results = Results{
        .note = "3-node loopback cluster, ReleaseFast, sequential single " ++
            "client; indicative numbers from the machine that last ran " ++
            "`zig build bench-cluster -- --record ...`",
        .runs = runs.items,
    };
    const encoded = try std.json.Stringify.valueAlloc(gpa, results, .{
        .whitespace = .indent_2,
    });
    defer gpa.free(encoded);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = encoded });
}

fn runOrder(context: void, left: RunRecord, right: RunRecord) bool {
    _ = context;
    switch (std.mem.order(u8, left.mode, right.mode)) {
        .lt => return true,
        .gt => return false,
        .eq => return std.mem.order(u8, left.sync, right.sync) == .lt,
    }
}

fn sampleAll(
    gpa: std.mem.Allocator,
    io: Io,
    nodes: []const NodeProc,
) ![3]Usage {
    var usages: [3]Usage = undefined;
    for (nodes, 0..) |node, index| {
        if (comptime builtin.os.tag == .windows) {
            // `ps` has no counterpart here and `Child.id` is a handle
            // rather than a pid. The benchmark reports the columns it can
            // actually measure instead of inventing these two.
            usages[index] = .{ .rss_kb = 0, .cpu_ms = 0 };
            continue;
        }
        const pid = node.child.?.id orelse return error.NoPid;
        usages[index] = try sampleUsage(gpa, io, pid);
    }
    return usages;
}

fn spawnNode(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon_path: []const u8,
    root: []const u8,
    mode: Mode,
    sync_text: []const u8,
    all_nodes: []const NodeProc,
    node: *NodeProc,
) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    var scratch: std.ArrayList([]u8) = .empty;
    defer {
        for (scratch.items) |item| gpa.free(item);
        scratch.deinit(gpa);
    }

    try argv.appendSlice(gpa, &.{ zaxon_path, "serve", "--data", node.directory });
    const node_text = try std.fmt.allocPrint(gpa, "{d}", .{node.id});
    try scratch.append(gpa, node_text);
    try argv.appendSlice(gpa, &.{ "--node", node_text });
    const listen_text = try std.fmt.allocPrint(
        gpa,
        "127.0.0.1:{d}",
        .{node.port},
    );
    try scratch.append(gpa, listen_text);
    try argv.appendSlice(gpa, &.{ "--listen", listen_text });
    for (all_nodes) |peer| {
        if (peer.id == node.id) continue;
        const peer_text = try std.fmt.allocPrint(
            gpa,
            "{d}@127.0.0.1:{d}",
            .{ peer.id, peer.port },
        );
        try scratch.append(gpa, peer_text);
        try argv.appendSlice(gpa, &.{ "--peer", peer_text });
    }
    try appendSpawnNodeModeArgs(gpa, &argv, &scratch, root, node.id, mode);

    try argv.appendSlice(gpa, &.{ "--sync", sync_text });

    const log_path = try std.fmt.allocPrint(
        gpa,
        "{s}/n{d}.log",
        .{ root, node.id },
    );
    defer gpa.free(log_path);
    const log_file = try Io.Dir.cwd().createFile(io, log_path, .{});
    node.child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    });
    log_file.close(io);
}

const BenchWriteResult = struct {
    elapsed: i96,
    stats: Stats,
};

const BenchReadResult = struct {
    ops: [2]u64,
    stats: [2]Stats,
};

fn runBenchWrites(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    connection: **client.Connection,
    transport: client.Transport,
    write_count: usize,
) !BenchWriteResult {
    const write_samples = try gpa.alloc(u64, write_count);
    defer gpa.free(write_samples);
    const write_payload = @as([256]u8, @splat('x'));
    var request_buffer: [640]u8 = undefined;
    const write_start = nowNs(io);
    for (0..write_count) |index| {
        const request = std.fmt.bufPrint(
            &request_buffer,
            "{{\"op\":\"exec\",\"sql\":\"insert into b(k, v) values ({d}, '{s}')\"}}",
            .{ index % 997, &write_payload },
        ) catch unreachable;
        const op_start = nowNs(io);
        try executeLeaderCall(gpa, io, endpoints, connection, transport, request);
        write_samples[index] = @intCast(nowNs(io) - op_start);
    }
    const write_elapsed = nowNs(io) - write_start;
    const write_stats = Stats.compute(write_samples);
    printRow("write", write_count, write_elapsed, write_stats);
    return .{ .elapsed = write_elapsed, .stats = write_stats };
}

fn runBenchReads(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    connection: **client.Connection,
    transport: client.Transport,
    read_count: usize,
    write_count: usize,
) !BenchReadResult {
    var read_stats: [2]Stats = undefined;
    var read_ops: [2]u64 = undefined;
    var request_buffer: [640]u8 = undefined;
    inline for (.{ "leader", "linearizable" }, 0..) |level, level_index| {
        const read_samples = try gpa.alloc(u64, read_count);
        defer gpa.free(read_samples);
        const read_start = nowNs(io);
        for (0..read_count) |index| {
            const request = std.fmt.bufPrint(
                &request_buffer,
                "{{\"op\":\"query\",\"sql\":\"select v from b where id = {d}\"," ++
                    "\"level\":\"" ++ level ++ "\"}}",
                .{1 + (index % write_count)},
            ) catch unreachable;
            const op_start = nowNs(io);
            try executeLeaderCall(gpa, io, endpoints, connection, transport, request);
            read_samples[index] = @intCast(nowNs(io) - op_start);
        }
        const read_elapsed = nowNs(io) - read_start;
        read_stats[level_index] = Stats.compute(read_samples);
        read_ops[level_index] = opsPerSecond(read_count, read_elapsed);
        printRow("read-" ++ level, read_count, read_elapsed, read_stats[level_index]);
    }
    return .{ .ops = read_ops, .stats = read_stats };
}

fn executeLeaderCall(
    allocator: std.mem.Allocator,
    io_: Io,
    endpoint_list: []const Endpoint,
    connection_slot: **client.Connection,
    transport_: client.Transport,
    request: []const u8,
) !void {
    const body = try connection_slot.*.call(request);
    if (std.mem.startsWith(u8, body, "{\"ok\":true")) {
        allocator.free(body);
        return;
    }
    allocator.free(body);
    var retry = try client.callClusterWithTransport(
        allocator,
        io_,
        endpoint_list,
        request,
        true,
        transport_,
    );
    defer retry.deinit(allocator);
    if (!std.mem.startsWith(u8, retry.body, "{\"ok\":true")) return error.RequestFailed;
    connection_slot.*.close();
    connection_slot.* = try client.Connection.openWithTransport(
        allocator,
        io_,
        retry.endpoint,
        transport_,
    );
}

fn appendSpawnNodeModeArgs(
    gpa: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    scratch: *std.ArrayList([]u8),
    root: []const u8,
    node_id: u32,
    mode: Mode,
) !void {
    switch (mode) {
        .plaintext => try argv.appendSlice(gpa, &.{
            "--enable-failpoints",
            "--insecure-test-tcp",
        }),
        .psk => {
            const secret_path = try std.fmt.allocPrint(gpa, "{s}/secret", .{root});
            try scratch.append(gpa, secret_path);
            try argv.appendSlice(gpa, &.{ "--auth-file", secret_path });
            try argv.append(gpa, "--dev-psk");
        },
        .tls => {
            const cert = try std.fmt.allocPrint(gpa, "{s}/n{d}.crt", .{ root, node_id });
            try scratch.append(gpa, cert);
            const key = try std.fmt.allocPrint(gpa, "{s}/n{d}.key", .{ root, node_id });
            try scratch.append(gpa, key);
            const ca = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{root});
            try scratch.append(gpa, ca);
            try argv.appendSlice(gpa, &.{
                "--tls-cert", cert,
                "--tls-key",  key,
                "--tls-ca",   ca,
            });
        },
    }
}

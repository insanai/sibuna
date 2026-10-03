//! Search benchmarks (ZDS 0009 performance gates): scalar versus SIMD
//! rerank throughput across the compatibility dimensions, coarse-bit
//! versus float32 storage ratio, SQLite heap high-water versus candidate
//! count, mmap-on versus mmap-off query latency, RSS, and page faults,
//! and representative text/image recall at oversampling 4, 8, and 16.
//!
//! Usage: search-bench [--record <path>]
//!
//! Results publish as raw JSON so the Zaxonlite book compiles recorded
//! numbers, never prose copies.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const search = @import("zaxon_search");

const sqlite = zaxonlite.sqlite;

const fixture_dir = "benchmarks/data/representative-v1-512";
const max_result_name_bytes = 63;

fn nowNs(io: Io) i96 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
}

const Result = struct {
    name_buffer: [max_result_name_bytes]u8 = undefined,
    name_len: u8,
    value: f64,
    unit: []const u8,

    fn init(metric_name: []const u8, value: f64, unit: []const u8) Result {
        if (metric_name.len > max_result_name_bytes) {
            @panic("search benchmark metric name exceeds its static bound");
        }
        var result = Result{
            .name_len = @intCast(metric_name.len),
            .value = value,
            .unit = unit,
        };
        @memcpy(result.name_buffer[0..metric_name.len], metric_name);
        return result;
    }

    fn name(self: *const Result) []const u8 {
        return self.name_buffer[0..self.name_len];
    }
};

var results_buffer: [64]Result = undefined;
var results_len: usize = 0;

fn record(name: []const u8, value: f64, unit: []const u8) void {
    if (results_len == results_buffer.len) {
        @panic("search benchmark result count exceeds its static bound");
    }
    results_buffer[results_len] = Result.init(name, value, unit);
    results_len += 1;
    std.debug.print("{s:<44} {d:>14.3} {s}\n", .{ name, value, unit });
}

fn fillRandomUnit(random: std.Random, vector: []f32) void {
    var magnitude: f64 = 0;
    for (vector) |*x| {
        const value = random.floatNorm(f64);
        x.* = @floatCast(value);
        magnitude += value * value;
    }
    const inverse = 1.0 / @sqrt(@max(magnitude, 1e-12));
    for (vector) |*x| x.* = @floatCast(@as(f64, x.*) * inverse);
}

// ----------------------------------------------------------------------
// Kernel throughput
// ----------------------------------------------------------------------

fn benchKernels(io: Io, gpa: std.mem.Allocator) !void {
    var prng = std.Random.DefaultPrng.init(0xbe7c4);
    const random = prng.random();
    const dims_cases = [_]usize{ 384, 768, 1024, 1536, 1537 };
    const vectors = 4096;
    const repeats = 8;

    for (dims_cases) |dims| {
        const corpus = try gpa.alloc(f32, vectors * dims);
        defer gpa.free(corpus);
        const query = try gpa.alloc(f32, dims);
        defer gpa.free(query);
        for (0..vectors) |i| {
            fillRandomUnit(random, corpus[i * dims .. (i + 1) * dims]);
        }
        fillRandomUnit(random, query);
        const query_bytes = std.mem.sliceAsBytes(query);

        var name_buffer: [64]u8 = undefined;
        inline for (.{ "scalar", "simd" }) |kernel| {
            var checksum: f64 = 0;
            const start = nowNs(io);
            for (0..repeats) |_| {
                for (0..vectors) |i| {
                    const candidate = std.mem.sliceAsBytes(
                        corpus[i * dims .. (i + 1) * dims],
                    );
                    checksum += if (comptime std.mem.eql(u8, kernel, "scalar"))
                        try search.vector.cosineDistanceScalar(query_bytes, candidate)
                    else
                        try search.vector.cosineDistanceSimd(query_bytes, candidate);
                }
            }
            const elapsed = nowNs(io) - start;
            std.mem.doNotOptimizeAway(checksum);
            const per_second = @as(f64, @floatFromInt(vectors * repeats)) /
                (@as(f64, @floatFromInt(@as(i64, @intCast(elapsed)))) / 1e9);
            record(
                std.fmt.bufPrint(&name_buffer, "rerank_{s}_d{d}", .{
                    kernel, dims,
                }) catch unreachable,
                per_second,
                "vectors/s",
            );
        }
    }
    std.debug.print(
        "compiled backend: {s}\n",
        .{search.vector.backend.name()},
    );
}

// ----------------------------------------------------------------------
// Storage ratio and heap/mmap measurements over a synthetic vec0 corpus
// ----------------------------------------------------------------------

fn databaseBytes(db: *sqlite.Db) !u64 {
    var page_count = try db.prepare("pragma page_count");
    defer page_count.finalize();
    if (!try page_count.step()) return error.SqliteError;
    const pages: u64 = @intCast(page_count.columnInt64(0));
    return pages * @as(u64, try db.pageSize());
}

fn benchStorageRatio(gpa: std.mem.Allocator, root: []const u8) !void {
    var prng = std.Random.DefaultPrng.init(0x570e);
    const random = prng.random();
    const dims = 1536;
    const rows = 2048;

    var float_bytes: u64 = 0;
    var bit_bytes: u64 = 0;
    inline for (.{ "float", "bit" }) |kind| {
        var path_buffer: [128]u8 = undefined;
        const path = try std.mem.printSentinel(
            &path_buffer,
            "{s}/storage-{s}.db",
            .{ root, kind },
            0,
        );
        var db = try sqlite.Db.open(path);
        defer db.close();
        try db.exec("pragma journal_mode = wal");
        if (comptime std.mem.eql(u8, kind, "float")) {
            try db.exec("create virtual table v using vec0(" ++
                "item_id integer primary key, embedding float[1536])");
        } else {
            try db.exec("create virtual table v using vec0(" ++
                "item_id integer primary key, embedding_coarse bit[1536])");
        }
        var insert = try db.prepare(
            if (comptime std.mem.eql(u8, kind, "float"))
                "insert into v(item_id, embedding) values (?1, ?2)"
            else
                "insert into v(item_id, embedding_coarse) values (?1, vec_bit(?2))",
        );
        defer insert.finalize();
        const vector = try gpa.alloc(f32, dims);
        defer gpa.free(vector);
        var coarse: [dims / 8]u8 = undefined;
        try db.exec("begin");
        for (0..rows) |i| {
            fillRandomUnit(random, vector);
            try insert.reset();
            try insert.bindInt64(1, @intCast(i + 1));
            if (comptime std.mem.eql(u8, kind, "float")) {
                try insert.bindBlob(2, std.mem.sliceAsBytes(vector));
            } else {
                random.bytes(&coarse);
                try insert.bindBlob(2, &coarse);
            }
            _ = try insert.step();
        }
        try db.exec("commit");
        try db.checkpointTruncate();
        if (comptime std.mem.eql(u8, kind, "float")) {
            float_bytes = try databaseBytes(&db);
        } else {
            bit_bytes = try databaseBytes(&db);
        }
    }
    record("storage_float32_bytes", @floatFromInt(float_bytes), "bytes");
    record("storage_bit_bytes", @floatFromInt(bit_bytes), "bytes");
    record(
        "storage_ratio",
        @as(f64, @floatFromInt(float_bytes)) /
            @as(f64, @floatFromInt(bit_bytes)),
        "x",
    );
}

fn buildCorpusDb(
    gpa: std.mem.Allocator,
    random: std.Random,
    path: [:0]const u8,
    rows: usize,
    dims: usize,
) !void {
    var db = try sqlite.Db.open(path);
    defer db.close();
    try db.exec("pragma journal_mode = wal");
    var ddl_buffer: [256]u8 = undefined;
    try db.exec(try std.mem.printSentinel(
        &ddl_buffer,
        "create virtual table v using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[{d}], embedding_coarse bit[{d}])",
        .{ dims, dims },
        0,
    ));
    var insert = try db.prepare(
        "insert into v(item_id, embedding, embedding_coarse) " ++
            "values (?1, ?2, vec_quantize_binary(?2))",
    );
    defer insert.finalize();
    const vector = try gpa.alloc(f32, dims);
    defer gpa.free(vector);
    try db.exec("begin");
    for (0..rows) |i| {
        fillRandomUnit(random, vector);
        try insert.reset();
        try insert.bindInt64(1, @intCast(i + 1));
        try insert.bindBlob(2, std.mem.sliceAsBytes(vector));
        _ = try insert.step();
    }
    try db.exec("commit");
    try db.checkpointTruncate();
}

const coarse_rerank_sql =
    "with coarse as (" ++
    "select item_id, embedding from v " ++
    "where embedding_coarse match vec_quantize_binary(?1) and k = ?2) " ++
    "select item_id, " ++
    "zaxon_vec_distance_cosine(embedding, ?1) as exact_distance " ++
    "from coarse order by exact_distance, item_id limit ?3";

fn runHybrid(
    db: *sqlite.Db,
    query_bytes: []const u8,
    candidates: i64,
    k: i64,
) !usize {
    var stmt = try db.prepare(coarse_rerank_sql);
    defer stmt.finalize();
    try stmt.bindBlob(1, query_bytes);
    try stmt.bindInt64(2, candidates);
    try stmt.bindInt64(3, k);
    var rows: usize = 0;
    while (try stmt.step()) rows += 1;
    return rows;
}

fn benchHeapAndMmap(io: Io, gpa: std.mem.Allocator, root: []const u8) !void {
    var prng = std.Random.DefaultPrng.init(0x8ea9);
    const random = prng.random();
    const dims = 1536;
    const query = try gpa.alloc(f32, dims);
    defer gpa.free(query);
    fillRandomUnit(random, query);
    const query_bytes = std.mem.sliceAsBytes(query);
    try benchHeap(gpa, random, root, dims, query_bytes);
    try benchMmap(io, root, query_bytes);
}

fn benchHeap(
    gpa: std.mem.Allocator,
    random: std.Random,
    root: []const u8,
    dims: usize,
    query_bytes: []const u8,
) !void {
    // Heap high-water versus candidate count, at two corpus sizes: the
    // bound must follow the candidate count, not the row count.
    var heap_small: f64 = 0;
    var heap_large: f64 = 0;
    for ([_]usize{ 2048, 8192 }) |rows| {
        var path_buffer: [128]u8 = undefined;
        const path = try std.mem.printSentinel(
            &path_buffer,
            "{s}/heap-{d}.db",
            .{ root, rows },
            0,
        );
        try buildCorpusDb(gpa, random, path, rows, dims);
        var db = try sqlite.Db.open(path);
        defer db.close();
        for ([_]i64{ 64, 512, 4096 }) |candidates| {
            _ = try runHybrid(&db, query_bytes, candidates, 10);
            _ = sqlite.memoryHighwater(true);
            _ = try runHybrid(&db, query_bytes, candidates, 10);
            const highwater: f64 = @floatFromInt(sqlite.memoryHighwater(false));
            var name_buffer: [64]u8 = undefined;
            record(
                std.fmt.bufPrint(
                    &name_buffer,
                    "heap_rows{d}_c{d}",
                    .{ rows, candidates },
                ) catch unreachable,
                highwater,
                "bytes",
            );
            if (candidates == 4096) {
                if (rows == 2048) heap_small = highwater else heap_large = highwater;
            }
        }
    }
    // Quadrupling the corpus must not scale the query heap: allow noise,
    // reject proportional growth.
    record("heap_growth_vs_corpus", heap_large / heap_small, "x");
}

fn benchMmap(io: Io, root: []const u8, query_bytes: []const u8) !void {
    // mmap-off versus the 256 MiB opt-in profile on the same image.
    for ([_]u64{ 0, 256 * 1024 * 1024 }) |mmap_size| {
        var path_buffer: [128]u8 = undefined;
        const path = try std.mem.printSentinel(
            &path_buffer,
            "{s}/heap-8192.db",
            .{root},
            0,
        );
        var db = try sqlite.Db.openWithOptions(path, .{ .mmap_size = mmap_size });
        defer db.close();
        _ = try runHybrid(&db, query_bytes, 512, 10); // warm
        const usage_before = resourceUsage();
        const cache_misses_before = try db.cacheMisses();
        const iterations = 50;
        const start = nowNs(io);
        for (0..iterations) |_| {
            _ = try runHybrid(&db, query_bytes, 512, 10);
        }
        const elapsed = nowNs(io) - start;
        const usage_after = resourceUsage();
        const cache_misses_after = try db.cacheMisses();
        const mean_us = @as(f64, @floatFromInt(@as(i64, @intCast(elapsed)))) /
            (1000.0 * iterations);
        var name_buffer: [64]u8 = undefined;
        record(
            std.fmt.bufPrint(
                &name_buffer,
                "hybrid_query_mmap{d}",
                .{mmap_size / (1024 * 1024)},
            ) catch unreachable,
            mean_us,
            "us/query",
        );
        record(
            std.fmt.bufPrint(
                &name_buffer,
                "effective_mmap{d}",
                .{mmap_size / (1024 * 1024)},
            ) catch unreachable,
            @floatFromInt(db.effective_mmap_size),
            "bytes",
        );
        recordPageReads(mmap_size, cache_misses_before, cache_misses_after);
        recordResourceUsage(mmap_size, usage_before, usage_after);
    }
}

const ResourceUsage = struct {
    peak_rss_bytes: u64,
    minor_faults: u64,
    major_faults: u64,
};

fn recordPageReads(mmap_size: u64, before: u64, after: u64) void {
    var name_buffer: [64]u8 = undefined;
    record(
        std.fmt.bufPrint(
            &name_buffer,
            "sqlite_pages_read_mmap{d}",
            .{mmap_size / (1024 * 1024)},
        ) catch unreachable,
        @floatFromInt(after -| before),
        "pages",
    );
}

fn resourceUsage() ?ResourceUsage {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return null;
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    // Darwin reports bytes; Linux reports KiB.
    const rss_scale: u64 = if (builtin.os.tag == .macos) 1 else 1024;
    return .{
        .peak_rss_bytes = @as(u64, @intCast(usage.maxrss)) * rss_scale,
        .minor_faults = @intCast(usage.minflt),
        .major_faults = @intCast(usage.majflt),
    };
}

fn recordResourceUsage(
    mmap_size: u64,
    before: ?ResourceUsage,
    after: ?ResourceUsage,
) void {
    const initial = before orelse return;
    const final = after orelse return;
    const profile_mib = mmap_size / (1024 * 1024);
    var name_buffer: [64]u8 = undefined;
    record(
        std.fmt.bufPrint(
            &name_buffer,
            "rss_peak_mib_mmap{d}",
            .{profile_mib},
        ) catch unreachable,
        @as(f64, @floatFromInt(final.peak_rss_bytes)) / (1024.0 * 1024.0),
        "MiB",
    );
    record(
        std.fmt.bufPrint(
            &name_buffer,
            "minor_page_faults_mmap{d}",
            .{profile_mib},
        ) catch unreachable,
        @floatFromInt(final.minor_faults -| initial.minor_faults),
        "faults",
    );
    record(
        std.fmt.bufPrint(
            &name_buffer,
            "major_page_faults_mmap{d}",
            .{profile_mib},
        ) catch unreachable,
        @floatFromInt(final.major_faults -| initial.major_faults),
        "faults",
    );
}

// ----------------------------------------------------------------------
// Checked representative recall at oversampling factors 4, 8, and 16
// ----------------------------------------------------------------------

const Npy = struct {
    rows: usize,
    dims: usize,
    data: []f32,

    fn deinit(self: *const Npy, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }
};

/// Minimal NumPy v1 reader for little-endian float32 2-D arrays.
fn readNpy(io: Io, gpa: std.mem.Allocator, path: []const u8) !Npy {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(1024 * 1024 * 1024),
    );
    defer gpa.free(bytes);
    if (bytes.len < 10 or !std.mem.eql(u8, bytes[0..6], "\x93NUMPY")) {
        return error.BadNpy;
    }
    const header_len = std.mem.readInt(u16, bytes[8..10], .little);
    if (header_len > bytes.len - 10) return error.BadNpy;
    const header = bytes[10 .. 10 + header_len];
    if (std.mem.indexOf(u8, header, "'<f4'") == null) return error.BadNpy;
    if (std.mem.indexOf(u8, header, "'fortran_order': False") == null) {
        return error.BadNpy;
    }
    const shape_start = (std.mem.indexOf(u8, header, "(") orelse
        return error.BadNpy) + 1;
    const shape_end = std.mem.indexOfPos(u8, header, shape_start, ")") orelse
        return error.BadNpy;
    var shape_it = std.mem.tokenizeAny(u8, header[shape_start..shape_end], ", ");
    const rows = try std.fmt.parseInt(
        usize,
        shape_it.next() orelse return error.BadNpy,
        10,
    );
    const dims = try std.fmt.parseInt(
        usize,
        shape_it.next() orelse return error.BadNpy,
        10,
    );
    if (rows == 0 or dims == 0) return error.BadNpy;
    const payload = bytes[10 + header_len ..];
    const elements = std.math.mul(usize, rows, dims) catch
        return error.BadNpy;
    const payload_bytes = std.math.mul(usize, elements, @sizeOf(f32)) catch
        return error.BadNpy;
    if (payload.len != payload_bytes) return error.BadNpy;
    const data = try gpa.alloc(f32, elements);
    @memcpy(std.mem.sliceAsBytes(data), payload);
    return .{ .rows = rows, .dims = dims, .data = data };
}

const Neighbor = struct {
    id: usize,
    distance: f64,

    fn lessThan(_: void, a: Neighbor, b: Neighbor) bool {
        if (a.distance != b.distance) return a.distance < b.distance;
        return a.id < b.id;
    }
};

fn benchRecall(io: Io, gpa: std.mem.Allocator, root: []const u8) !void {
    var corpus_path_buffer: [128]u8 = undefined;
    const corpus_path = std.fmt.bufPrint(
        &corpus_path_buffer,
        "{s}/corpus.f32.npy",
        .{fixture_dir},
    ) catch unreachable;
    const corpus = try readNpy(io, gpa, corpus_path);
    defer corpus.deinit(gpa);
    var path_buffer: [128]u8 = undefined;
    const db_path = try std.mem.printSentinel(&path_buffer, "{s}/recall.db", .{root}, 0);
    try buildRecallDb(db_path, corpus);

    inline for (.{ "text", "image" }) |modality| {
        var queries_path_buffer: [128]u8 = undefined;
        const queries_path = std.fmt.bufPrint(
            &queries_path_buffer,
            "{s}/{s}-queries.f32.npy",
            .{ fixture_dir, modality },
        ) catch unreachable;
        const queries = try readNpy(io, gpa, queries_path);
        defer queries.deinit(gpa);
        if (queries.dims != corpus.dims) return error.BadNpy;
        try measureRecall(gpa, db_path, corpus, queries, modality);
    }
}

fn buildRecallDb(db_path: [:0]const u8, corpus: Npy) !void {
    var db = try sqlite.Db.open(db_path);
    defer db.close();
    try db.exec("pragma journal_mode = wal");
    var ddl_buffer: [256]u8 = undefined;
    try db.exec(try std.mem.printSentinel(
        &ddl_buffer,
        "create virtual table v using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[{d}], embedding_coarse bit[{d}])",
        .{ corpus.dims, corpus.dims },
        0,
    ));
    var insert = try db.prepare(
        "insert into v(item_id, embedding, embedding_coarse) " ++
            "values (?1, ?2, vec_quantize_binary(?2))",
    );
    defer insert.finalize();
    try db.exec("begin");
    for (0..corpus.rows) |i| {
        try insert.reset();
        try insert.bindInt64(1, @intCast(i));
        try insert.bindBlob(2, std.mem.sliceAsBytes(
            corpus.data[i * corpus.dims .. (i + 1) * corpus.dims],
        ));
        _ = try insert.step();
    }
    try db.exec("commit");
}

fn measureRecall(
    gpa: std.mem.Allocator,
    db_path: [:0]const u8,
    corpus: Npy,
    queries: Npy,
    modality: []const u8,
) !void {
    const k = 10;
    if (corpus.rows < k) return error.BadNpy;
    var db = try sqlite.Db.open(db_path);
    defer db.close();
    const exact = try gpa.alloc(Neighbor, corpus.rows);
    defer gpa.free(exact);
    for ([_]usize{ 4, 8, 16 }) |factor| {
        var hits: usize = 0;
        var total: usize = 0;
        for (0..queries.rows) |q| {
            const query = queries.data[q * queries.dims .. (q + 1) * queries.dims];
            const counts = try queryRecall(&db, corpus, query, exact, factor, k);
            hits += counts.hits;
            total += counts.total;
        }
        if (total == 0) return error.BadNpy;
        const recall = @as(f64, @floatFromInt(hits)) /
            @as(f64, @floatFromInt(total));
        var name_buffer: [64]u8 = undefined;
        record(
            std.fmt.bufPrint(
                &name_buffer,
                "recall_{s}_at_{d}_oversample_{d}",
                .{ modality, k, factor },
            ) catch unreachable,
            recall,
            "fraction",
        );
        // The checked fixture is deliberately separable. Any miss is a
        // mechanical regression in coarse selection or exact reranking,
        // not model-quality variance.
        if (hits != total) return error.RecallRegression;
    }
}

fn queryRecall(
    db: *sqlite.Db,
    corpus: Npy,
    query: []const f32,
    exact: []Neighbor,
    factor: usize,
    k: usize,
) !struct { hits: usize, total: usize } {
    const query_bytes = std.mem.sliceAsBytes(query);
    for (0..corpus.rows) |i| {
        const candidate = corpus.data[i * corpus.dims .. (i + 1) * corpus.dims];
        exact[i] = .{
            .id = i,
            .distance = try search.vector.cosineDistanceScalar(
                query_bytes,
                std.mem.sliceAsBytes(candidate),
            ),
        };
    }
    std.mem.sort(Neighbor, exact, {}, Neighbor.lessThan);
    var stmt = try db.prepare(coarse_rerank_sql);
    defer stmt.finalize();
    try stmt.bindBlob(1, query_bytes);
    try stmt.bindInt64(2, @intCast(@min(factor * k, 4096)));
    try stmt.bindInt64(3, @intCast(k));
    var hits: usize = 0;
    var total: usize = 0;
    while (try stmt.step()) {
        const id: usize = @intCast(stmt.columnInt64(0));
        for (exact[0..k]) |neighbor| {
            if (neighbor.id == id) {
                hits += 1;
                break;
            }
        }
        total += 1;
    }
    return .{ .hits = hits, .total = total };
}

// ----------------------------------------------------------------------
// Entry point and JSON recording
// ----------------------------------------------------------------------

fn writeResults(io: Io, path: []const u8) !void {
    var buffer: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
    defer buffer.deinit();
    const writer = &buffer.writer;
    try writer.writeAll("{\"format\":1,\"suite\":\"search\",\"results\":[");
    for (results_buffer[0..results_len], 0..) |result, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print(
            "{{\"name\":\"{s}\",\"value\":{d},\"unit\":\"{s}\"}}",
            .{ result.name(), result.value, result.unit },
        );
    }
    try writer.writeAll("]}\n");
    var file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, buffer.written(), 0);
    std.debug.print("recorded {s}\n", .{path});
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    var record_path: ?[]const u8 = null;
    while (iterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--record")) {
            record_path = iterator.next() orelse {
                std.debug.print("--record needs a path\n", .{});
                return 2;
            };
        }
    }

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    var root_buffer: [64]u8 = undefined;
    const root = std.fmt.bufPrint(
        &root_buffer,
        ".zig-cache/tmp/zx-search-bench-{x}",
        .{nonce},
    ) catch unreachable;
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    std.debug.print("search benchmark (backend {s})\n", .{
        search.vector.backend.name(),
    });
    try benchKernels(io, gpa);
    try benchStorageRatio(gpa, root);
    try benchHeapAndMmap(io, gpa, root);
    try benchRecall(io, gpa, root);

    if (record_path) |path| try writeResults(io, path);
    return 0;
}

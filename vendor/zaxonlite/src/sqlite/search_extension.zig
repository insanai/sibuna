//! Search SQL surface registration (ZDS 0009): the statically linked
//! sqlite-vec module plus the Zig fusion and distance functions, installed
//! on every connection by `core.Db.open` before any statement is prepared.
//!
//! The callbacks convert SQLite values, delegate every formula to the pure
//! `zaxon_search` module, and never allocate. Contract violations surface
//! as `SQLITE_CONSTRAINT` errors with static messages; NULL input
//! propagates NULL, matching the record's failure semantics.

const std = @import("std");
const c = @import("c");
const search = @import("zaxon_search");

/// sqlite-vec's entry point, statically linked from the pinned
/// amalgamation compiled with `-DSQLITE_CORE`.
extern fn sqlite3_vec_init(
    db: ?*c.sqlite3,
    error_message: [*c][*c]u8,
    api: ?*const anyopaque,
) c_int;

const function_flags: c_int =
    c.SQLITE_UTF8 | c.SQLITE_DETERMINISTIC | c.SQLITE_INNOCUOUS;

/// Registers the search extensions on a raw connection handle. Called by
/// `core.Db.open`; takes the handle rather than importing `core.zig` so
/// registration cannot create a module cycle. A connection must never
/// serve a schema whose virtual-table module is missing, so any failure
/// here fails the open.
pub fn register(handle: *c.sqlite3) error{SqliteError}!void {
    if (sqlite3_vec_init(handle, null, null) != c.SQLITE_OK) {
        return error.SqliteError;
    }
    inline for ([_]c_int{ 1, 2, 3 }) |arity| {
        try createScalar(handle, "rrf", arity, rrfFunc);
    }
    inline for ([_]c_int{ 3, 4 }) |arity| {
        try createScalar(handle, "dbsf", arity, dbsfFunc);
    }
    try createScalar(handle, "zaxon_vec_distance_cosine", 2, cosineFunc);
    try createScalar(handle, "zaxon_search_debug", 0, debugFunc);
    try createStddevWindow(handle);
}

const ScalarFn = *const fn (
    ?*c.sqlite3_context,
    c_int,
    [*c]?*c.sqlite3_value,
) callconv(.c) void;

fn createScalar(
    handle: *c.sqlite3,
    name: [:0]const u8,
    arity: c_int,
    func: ScalarFn,
) error{SqliteError}!void {
    const rc = c.sqlite3_create_function_v2(
        handle,
        name.ptr,
        arity,
        function_flags,
        null,
        func,
        null,
        null,
        null,
    );
    if (rc != c.SQLITE_OK) return error.SqliteError;
}

fn createStddevWindow(handle: *c.sqlite3) error{SqliteError}!void {
    const rc = c.sqlite3_create_window_function(
        handle,
        "stddev_samp",
        1,
        function_flags,
        null,
        stddevStep,
        stddevFinal,
        stddevValue,
        stddevInverse,
        null,
    );
    if (rc != c.SQLITE_OK) return error.SqliteError;
}

/// Reports a contract violation as `SQLITE_CONSTRAINT` with a static
/// message. SQLite copies the message, so string literals are safe.
fn resultContractError(ctx: ?*c.sqlite3_context, message: [:0]const u8) void {
    c.sqlite3_result_error(ctx, message.ptr, -1);
    c.sqlite3_result_error_code(ctx, c.SQLITE_CONSTRAINT);
}

fn anyNull(args: []const ?*c.sqlite3_value) bool {
    for (args) |value| {
        if (c.sqlite3_value_type(value) == c.SQLITE_NULL) return true;
    }
    return false;
}

/// Checked numeric conversion: integers and floats pass, as does text
/// SQLite itself can convert; everything else is a contract violation.
fn numericDouble(value: ?*c.sqlite3_value) ?f64 {
    const numeric = c.sqlite3_value_numeric_type(value);
    if (numeric != c.SQLITE_INTEGER and numeric != c.SQLITE_FLOAT) return null;
    return c.sqlite3_value_double(value);
}

fn rrfFunc(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    const args = argv[0..@intCast(argc)];
    if (anyNull(args)) return c.sqlite3_result_null(ctx);
    if (c.sqlite3_value_numeric_type(args[0]) != c.SQLITE_INTEGER) {
        return resultContractError(ctx, "rrf: rank must be a positive integer");
    }
    const rank = c.sqlite3_value_int64(args[0]);
    const k = if (args.len >= 2)
        numericDouble(args[1]) orelse
            return resultContractError(ctx, "rrf: k must be numeric")
    else
        search.fusion.default_rrf_k;
    const weight = if (args.len >= 3)
        numericDouble(args[2]) orelse
            return resultContractError(ctx, "rrf: weight must be numeric")
    else
        search.fusion.default_weight;
    const score = search.fusion.rrf(rank, k, weight) catch |err| {
        return resultContractError(ctx, switch (err) {
            error.InvalidRank => "rrf: rank must be a positive integer",
            error.InvalidK => "rrf: k must be finite and greater than zero",
            error.InvalidWeight => "rrf: weight must be finite and nonnegative",
            else => "rrf: invalid argument",
        });
    };
    c.sqlite3_result_double(ctx, score);
}

fn dbsfFunc(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    const args = argv[0..@intCast(argc)];
    if (anyNull(args)) return c.sqlite3_result_null(ctx);
    const score = numericDouble(args[0]) orelse
        return resultContractError(ctx, "dbsf: score must be numeric");
    const mean = numericDouble(args[1]) orelse
        return resultContractError(ctx, "dbsf: mean must be numeric");
    const stddev = numericDouble(args[2]) orelse
        return resultContractError(ctx, "dbsf: stddev must be numeric");
    const weight = if (args.len >= 4)
        numericDouble(args[3]) orelse
            return resultContractError(ctx, "dbsf: weight must be numeric")
    else
        search.fusion.default_weight;
    const fused = search.fusion.dbsf(score, mean, stddev, weight) catch |err| {
        return resultContractError(ctx, switch (err) {
            error.InvalidScore => "dbsf: score and mean must be finite",
            error.InvalidStddev => "dbsf: stddev must be finite and nonnegative",
            error.InvalidWeight => "dbsf: weight must be finite and nonnegative",
            else => "dbsf: invalid argument",
        });
    };
    c.sqlite3_result_double(ctx, fused);
}

fn valueBlob(value: ?*c.sqlite3_value) ?[]const u8 {
    if (c.sqlite3_value_type(value) != c.SQLITE_BLOB) return null;
    const ptr = c.sqlite3_value_blob(value);
    const len: usize = @intCast(c.sqlite3_value_bytes(value));
    if (ptr == null) return if (len == 0) "" else null;
    return @as([*]const u8, @ptrCast(ptr))[0..len];
}

fn cosineFunc(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    const args = argv[0..@intCast(argc)];
    if (anyNull(args)) return c.sqlite3_result_null(ctx);
    const a = valueBlob(args[0]) orelse
        return resultContractError(
            ctx,
            "zaxon_vec_distance_cosine: arguments must be float32 BLOBs",
        );
    const b = valueBlob(args[1]) orelse
        return resultContractError(
            ctx,
            "zaxon_vec_distance_cosine: arguments must be float32 BLOBs",
        );
    const distance = search.vector.cosineDistanceBytes(a, b) catch |err| {
        return resultContractError(ctx, switch (err) {
            error.LengthMismatch => "zaxon_vec_distance_cosine: dimension mismatch",
            error.EmptyVector => "zaxon_vec_distance_cosine: empty vector",
            error.MalformedBlob => "zaxon_vec_distance_cosine: blob length " ++
                "is not a multiple of four bytes",
            error.NonFinite => "zaxon_vec_distance_cosine: non-finite element",
            error.ZeroMagnitude => "zaxon_vec_distance_cosine: zero-magnitude vector",
        });
    };
    c.sqlite3_result_double(ctx, distance);
}

const debug_text = "simd=" ++ search.vector.backend.name();

fn debugFunc(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    _ = argc;
    _ = argv;
    // Static lifetime, so the SQLITE_STATIC (null) destructor is correct.
    c.sqlite3_result_text(ctx, debug_text.ptr, debug_text.len, null);
}

/// The 24-byte Welford state lives in the SQLite aggregate context, which
/// is zero-initialized on first use — a valid empty `Welford`.
fn welfordState(ctx: ?*c.sqlite3_context) ?*search.fusion.Welford {
    const raw = c.sqlite3_aggregate_context(
        ctx,
        @sizeOf(search.fusion.Welford),
    ) orelse return null;
    return @ptrCast(@alignCast(raw));
}

fn stddevStep(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    _ = argc;
    // Null rows are ignored, matching SQL aggregate conventions.
    if (c.sqlite3_value_type(argv[0]) == c.SQLITE_NULL) return;
    const x = numericDouble(argv[0]) orelse
        return resultContractError(ctx, "stddev_samp: value must be numeric");
    if (!std.math.isFinite(x)) {
        return resultContractError(ctx, "stddev_samp: value must be finite");
    }
    const state = welfordState(ctx) orelse
        return c.sqlite3_result_error_nomem(ctx);
    state.step(x);
}

fn stddevInverse(
    ctx: ?*c.sqlite3_context,
    argc: c_int,
    argv: [*c]?*c.sqlite3_value,
) callconv(.c) void {
    _ = argc;
    if (c.sqlite3_value_type(argv[0]) == c.SQLITE_NULL) return;
    const x = numericDouble(argv[0]) orelse return;
    const state = welfordState(ctx) orelse
        return c.sqlite3_result_error_nomem(ctx);
    state.inverse(x) catch {
        c.sqlite3_result_error(ctx, "stddev_samp: internal state error", -1);
    };
}

fn stddevResult(ctx: ?*c.sqlite3_context) void {
    const state = welfordState(ctx) orelse
        return c.sqlite3_result_error_nomem(ctx);
    if (state.sampleStddev()) |deviation| {
        c.sqlite3_result_double(ctx, deviation);
    } else {
        c.sqlite3_result_null(ctx);
    }
}

fn stddevValue(ctx: ?*c.sqlite3_context) callconv(.c) void {
    stddevResult(ctx);
}

fn stddevFinal(ctx: ?*c.sqlite3_context) callconv(.c) void {
    stddevResult(ctx);
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;
const core = @import("core.zig");

fn openMemoryDb() !core.Db {
    return core.Db.open(":memory:");
}

test "sqlite-vec registers on every connection" {
    var db = try openMemoryDb();
    defer db.close();
    var stmt = try db.prepare("select vec_version()");
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    try testing.expectEqualStrings("v0.1.9", stmt.columnText(0));
}

test "rrf arity overloads and defaults" {
    var db = try openMemoryDb();
    defer db.close();
    var one = try db.prepare("select rrf(1)");
    defer one.finalize();
    try testing.expect(try one.step());
    try testing.expectApproxEqAbs(
        @as(f64, 1.0 / 61.0),
        one.columnDouble(0),
        1e-12,
    );
    var three = try db.prepare("select rrf(1, 60, 2.0)");
    defer three.finalize();
    try testing.expect(try three.step());
    try testing.expectApproxEqAbs(
        @as(f64, 2.0 / 61.0),
        three.columnDouble(0),
        1e-12,
    );
    // Unregistered arity fails at prepare.
    try testing.expectError(
        error.SqliteError,
        db.prepare("select rrf(1, 60, 1.0, 9)"),
    );
}

test "rrf and dbsf propagate NULL and reject contract violations" {
    var db = try openMemoryDb();
    defer db.close();
    var null_rank = try db.prepare("select rrf(NULL)");
    defer null_rank.finalize();
    try testing.expect(try null_rank.step());
    try testing.expect(null_rank.isColumnNull(0));

    var bad_rank = try db.prepare("select rrf(0)");
    defer bad_rank.finalize();
    try testing.expectError(error.SqliteError, bad_rank.step());

    var bad_text = try db.prepare("select rrf(1, 'sixty')");
    defer bad_text.finalize();
    try testing.expectError(error.SqliteError, bad_text.step());

    var neutral = try db.prepare("select dbsf(7.0, 7.0, 0.0, 4.0)");
    defer neutral.finalize();
    try testing.expect(try neutral.step());
    try testing.expectApproxEqAbs(@as(f64, 2.0), neutral.columnDouble(0), 1e-12);

    var null_mean = try db.prepare("select dbsf(1.0, NULL, 1.0)");
    defer null_mean.finalize();
    try testing.expect(try null_mean.step());
    try testing.expect(null_mean.isColumnNull(0));

    var bad_sigma = try db.prepare("select dbsf(1.0, 0.0, -1.0)");
    defer bad_sigma.finalize();
    try testing.expectError(error.SqliteError, bad_sigma.step());
}

test "stddev_samp works as aggregate and window function" {
    var db = try openMemoryDb();
    defer db.close();
    try db.exec("create table s(x real)");
    try db.exec("insert into s values (2), (4), (4), (4), (5), (5), (7), (9)");

    var aggregate = try db.prepare("select stddev_samp(x) from s");
    defer aggregate.finalize();
    try testing.expect(try aggregate.step());
    try testing.expectApproxEqAbs(
        @sqrt(@as(f64, 32.0 / 7.0)),
        aggregate.columnDouble(0),
        1e-9,
    );

    // Empty set is NULL; singleton is zero (the dbsf neutral rule).
    var empty = try db.prepare("select stddev_samp(x) from s where x > 100");
    defer empty.finalize();
    try testing.expect(try empty.step());
    try testing.expect(empty.isColumnNull(0));

    var single = try db.prepare("select stddev_samp(x) from s where x = 2");
    defer single.finalize();
    try testing.expect(try single.step());
    try testing.expectEqual(@as(f64, 0), single.columnDouble(0));

    // Sliding frame exercises the Welford inverse path; compare each
    // window against direct recomputation in Zig.
    var window = try db.prepare(
        "select stddev_samp(x) over " ++
            "(order by rowid rows between 2 preceding and current row) from s",
    );
    defer window.finalize();
    const values = [_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 };
    var row: usize = 0;
    while (try window.step()) : (row += 1) {
        var fresh = search.fusion.Welford{};
        const start = if (row >= 2) row - 2 else 0;
        for (values[start .. row + 1]) |x| fresh.step(x);
        try testing.expectApproxEqAbs(
            fresh.sampleStddev().?,
            window.columnDouble(0),
            1e-9,
        );
    }
    try testing.expectEqual(values.len, row);
}

test "cosine distance function validates blobs" {
    var db = try openMemoryDb();
    defer db.close();
    var stmt = try db.prepare(
        "select zaxon_vec_distance_cosine(vec_f32('[1.0, 0.0]'), vec_f32('[0.0, 1.0]'))",
    );
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    try testing.expectApproxEqAbs(@as(f64, 1.0), stmt.columnDouble(0), 1e-6);

    var mismatch = try db.prepare(
        "select zaxon_vec_distance_cosine(vec_f32('[1.0, 0.0]'), vec_f32('[1.0, 0.0, 0.0]'))",
    );
    defer mismatch.finalize();
    try testing.expectError(error.SqliteError, mismatch.step());

    // A bit vector's blob length differs from any float32 vector of the
    // same dimension, so quantized coarse vectors are rejected.
    var bit_input = try db.prepare(
        "select zaxon_vec_distance_cosine(" ++
            "vec_quantize_binary(vec_f32('[1,-1,1,-1,1,-1,1,-1]')), " ++
            "vec_f32('[1,-1,1,-1,1,-1,1,-1]'))",
    );
    defer bit_input.finalize();
    try testing.expectError(error.SqliteError, bit_input.step());

    var not_blob = try db.prepare(
        "select zaxon_vec_distance_cosine('text', 'text')",
    );
    defer not_blob.finalize();
    try testing.expectError(error.SqliteError, not_blob.step());
}

test "search debug reports the compiled backend" {
    var db = try openMemoryDb();
    defer db.close();
    var stmt = try db.prepare("select zaxon_search_debug()");
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    const text = stmt.columnText(0);
    try testing.expect(std.mem.startsWith(u8, text, "simd="));
    try testing.expectEqualStrings(
        search.vector.backend.name(),
        text["simd=".len..],
    );
}

test "grammar functions prepare with every bind-parameter form" {
    var db = try openMemoryDb();
    defer db.close();
    // The EBNF forms (ZDS 0009) are ordinary SQLite expressions; every
    // SQLite bind-parameter form must prepare inside them.
    const forms = [_][]const u8{
        "select rrf(?, ?, ?)",
        "select rrf(?1, ?2, ?3)",
        "select rrf(:rank, :k, :weight)",
        "select rrf(@rank, @k, @weight)",
        "select rrf($rank, $k, $weight)",
        "select dbsf(?, ?, ?, ?)",
        "select dbsf(:score, :mean, :sigma, :weight)",
        "select zaxon_vec_distance_cosine(?, ?)",
        "select zaxon_vec_distance_cosine(:a, :b)",
    };
    for (forms) |sql| {
        var stmt = try db.prepare(sql);
        stmt.finalize();
    }
    // Literals, columns, and nested expressions also qualify.
    try db.exec("create table r(rank integer, score real)");
    try db.exec("insert into r values (1, 0.5), (2, 0.25)");
    var nested = try db.prepare(
        "select rrf(rank, 30 + 30, abs(-1.0)), " ++
            "dbsf(score, 0.375, 0.125, 1.0) from r order by rank",
    );
    defer nested.finalize();
    try testing.expect(try nested.step());
    try testing.expectApproxEqAbs(
        @as(f64, 1.0 / 61.0),
        nested.columnDouble(0),
        1e-12,
    );
}

test "the zds rrf example executes verbatim" {
    var db = try openMemoryDb();
    defer db.close();
    try db.exec("create virtual table media_item_fts using fts5(body)");
    try db.exec(
        "insert into media_item_fts(rowid, body) values " ++
            "(1, 'paxos replicates sqlite pages'), " ++
            "(2, 'vectors rank media results'), " ++
            "(3, 'sqlite stores media vectors')",
    );
    try db.exec("create table vector_reranked(item_id integer, exact_distance real)");
    try db.exec(
        "insert into vector_reranked values (3, 0.05), (2, 0.20), (1, 0.90)",
    );

    // The hybrid RRF query from ZDS 0009, byte for byte.
    var stmt = try db.prepare(
        \\WITH
        \\lexical AS (
        \\  SELECT rowid AS item_id,
        \\         row_number() OVER (ORDER BY bm25(media_item_fts), rowid) AS rank
        \\  FROM media_item_fts
        \\  WHERE media_item_fts MATCH :text_query
        \\  ORDER BY bm25(media_item_fts), rowid
        \\  LIMIT :lexical_candidates
        \\),
        \\semantic AS (
        \\  SELECT item_id,
        \\         row_number() OVER (ORDER BY exact_distance, item_id) AS rank
        \\  FROM vector_reranked
        \\),
        \\contributions AS (
        \\  SELECT item_id, rrf(rank, 60, :text_weight) AS score FROM lexical
        \\  UNION ALL
        \\  SELECT item_id, rrf(rank, 60, :vector_weight) AS score FROM semantic
        \\)
        \\SELECT item_id, sum(score) AS fused_score
        \\FROM contributions
        \\GROUP BY item_id
        \\ORDER BY fused_score DESC, item_id
        \\LIMIT :k;
    );
    defer stmt.finalize();
    // Named parameters index in order of first appearance.
    try stmt.bindText(1, "sqlite");
    try stmt.bindInt64(2, 10);
    try stmt.bindDouble(3, 1.0);
    try stmt.bindDouble(4, 1.0);
    try stmt.bindInt64(5, 3);

    // Item 3 matches 'sqlite' lexically and ranks first semantically;
    // fusing both retrievers must put it first.
    try testing.expect(try stmt.step());
    try testing.expectEqual(@as(i64, 3), stmt.columnInt64(0));
    var rows: usize = 1;
    while (try stmt.step()) rows += 1;
    try testing.expectEqual(@as(usize, 3), rows);
}

test "the zds dbsf example executes verbatim" {
    var db = try openMemoryDb();
    defer db.close();
    try db.exec("create virtual table media_item_fts using fts5(body)");
    try db.exec(
        "insert into media_item_fts(rowid, body) values " ++
            "(1, 'paxos replicates sqlite pages'), " ++
            "(2, 'vectors rank media results'), " ++
            "(3, 'sqlite stores media vectors')",
    );
    try db.exec("create table vector_reranked(item_id integer, exact_distance real)");
    try db.exec(
        "insert into vector_reranked values (2, 0.05), (3, 0.20), (1, 0.90)",
    );

    // The hybrid DBSF query from ZDS 0009, byte for byte.
    var stmt = try db.prepare(
        \\WITH
        \\lexical_raw AS (
        \\  SELECT rowid AS item_id, -bm25(media_item_fts) AS score
        \\  FROM media_item_fts
        \\  WHERE media_item_fts MATCH :text_query
        \\  ORDER BY bm25(media_item_fts), rowid
        \\  LIMIT :lexical_candidates
        \\),
        \\lexical AS (
        \\  SELECT item_id,
        \\         dbsf(
        \\           score,
        \\           avg(score) OVER (),
        \\           stddev_samp(score) OVER (),
        \\           :text_weight
        \\         ) AS score
        \\  FROM lexical_raw
        \\),
        \\semantic_raw AS (
        \\  SELECT item_id, -exact_distance AS score
        \\  FROM vector_reranked
        \\),
        \\semantic AS (
        \\  SELECT item_id,
        \\         dbsf(
        \\           score,
        \\           avg(score) OVER (),
        \\           stddev_samp(score) OVER (),
        \\           :vector_weight
        \\         ) AS score
        \\  FROM semantic_raw
        \\),
        \\contributions AS (
        \\  SELECT * FROM lexical
        \\  UNION ALL
        \\  SELECT * FROM semantic
        \\)
        \\SELECT item_id, sum(score) AS fused_score
        \\FROM contributions
        \\GROUP BY item_id
        \\ORDER BY fused_score DESC, item_id
        \\LIMIT :k;
    );
    defer stmt.finalize();
    try stmt.bindText(1, "sqlite");
    try stmt.bindInt64(2, 10);
    try stmt.bindDouble(3, 1.0);
    try stmt.bindDouble(4, 1.0);
    try stmt.bindInt64(5, 3);

    var rows: usize = 0;
    var previous: f64 = std.math.inf(f64);
    while (try stmt.step()) : (rows += 1) {
        const fused = stmt.columnDouble(1);
        try testing.expect(fused <= previous);
        previous = fused;
    }
    try testing.expectEqual(@as(usize, 3), rows);
}

test "typed result shape omits embedding blobs unless projected" {
    var db = try openMemoryDb();
    defer db.close();
    try db.exec(
        "create virtual table media_vec using vec0(" ++
            "item_id integer primary key, embedding float[4])",
    );
    try db.exec(
        "insert into media_vec(item_id, embedding) values " ++
            "(1, vec_f32('[1,0,0,0]')), (2, vec_f32('[0,1,0,0]'))",
    );
    // The default search projection returns IDs and scores only.
    var stmt = try db.prepare(
        "select item_id, " ++
            "zaxon_vec_distance_cosine(embedding, vec_f32('[1,0,0,0]')) " ++
            "from media_vec where embedding match vec_f32('[1,0,0,0]') " ++
            "and k = 2 order by 2, item_id",
    );
    defer stmt.finalize();
    try testing.expectEqual(@as(u32, 2), stmt.columnCount());
    try testing.expect(try stmt.step());
    // An explicit ordinary SQL projection can still request the BLOB.
    var explicit = try db.prepare(
        "select embedding from media_vec where item_id = 1",
    );
    defer explicit.finalize();
    try testing.expect(try explicit.step());
    try testing.expectEqual(@as(usize, 16), explicit.columnBlob(0).len);
}

test "coarse bit scan reranked by exact cosine in one statement" {
    var db = try openMemoryDb();
    defer db.close();
    try db.exec(
        "create virtual table media_vec using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[8], " ++
            "embedding_coarse bit[8])",
    );
    try db.exec(
        "insert into media_vec(item_id, embedding, embedding_coarse) values " ++
            "(1, vec_f32('[1,0,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))), " ++
            "(2, vec_f32('[0,1,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]'))), " ++
            "(3, vec_f32('[1,1,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[1,1,-1,-1,-1,-1,-1,-1]')))",
    );
    var stmt = try db.prepare(
        "with coarse as (" ++
            "  select item_id, embedding from media_vec" ++
            "  where embedding_coarse match " ++
            "    vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))" ++
            "  and k = 2)" ++
            "select item_id, " ++
            "  zaxon_vec_distance_cosine(embedding, vec_f32('[1,0,0,0,0,0,0,0]'))" ++
            " from coarse order by 2, item_id",
    );
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    try testing.expectEqual(@as(i64, 1), stmt.columnInt64(0));
    try testing.expectApproxEqAbs(@as(f64, 0.0), stmt.columnDouble(1), 1e-6);
    try testing.expect(try stmt.step());
    try testing.expectEqual(@as(i64, 3), stmt.columnInt64(0));
    try testing.expect(!try stmt.step());
}

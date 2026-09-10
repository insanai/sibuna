const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const helpers = @import("console_store_test.zig");

test "security aggregates freeze node and time, retain audit findings and redact legacy paths" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try helpers.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/security-summary",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try helpers.policySession(fx);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
            "violation_category,offending_payload,recorded_at) VALUES " ++
            "(1,1,'8.8.8.8','','GET','/one?secret=a','waf:sqli','',100)," ++
            "(2,1,'8.8.8.8','','GET','/one#secret=b','audit:xss','',159)," ++
            "(3,1,'1.1.1.1','','GET','/two','honeypot','',160)," ++
            "(4,2,'2.2.2.2','','GET','/two','honeypot','',170)," ++
            "(5,1,'3.3.3.3','','GET','/outside','honeypot','',220);",
    );
    const result = try fx.run(.{ .security_query = .{
        .session_digest = @splat(1),
        .request = .{ .node = 1, .from = 100, .until = 220 },
    } });
    try t.expect(result == .security_page);
    const page = result.security_page;
    try t.expectEqual(@as(u64, 3), page.total);
    const inspection = page.modules[0];
    try t.expectEqual(@as(u64, 2), inspection.total);
    try t.expectEqual(@as(u64, 1), inspection.trend[0]);
    try t.expectEqual(@as(u64, 1), inspection.trend[29]);
    try t.expectEqualStrings("8.8.8.8", inspection.sources[0].?.label.slice());
    try t.expectEqual(@as(u64, 2), inspection.sources[0].?.count);
    try t.expectEqual(@as(u64, 1), page.modules[1].trend[30]);
    try t.expectEqual(@as(u64, 0), page.modules[2].total);
    const paths = try fx.run(.{ .security_query = .{
        .session_digest = @splat(1),
        .request = .{ .view = .paths, .from = 100, .until = 220 },
    } });
    try t.expect(paths == .security_page);
    const ranks = paths.security_page;
    try t.expectEqual(@as(u64, 4), ranks.total);
    try t.expectEqualStrings("/one", ranks.rows[0].?.label.slice());
    try t.expectEqual(@as(u64, 2), ranks.rows[0].?.count);
    try t.expectEqualStrings("/two", ranks.rows[1].?.label.slice());
    try t.expectEqual(@as(u64, 2), ranks.rows[1].?.count);
    try moduleEvents(fx);
    try aggregateScope(fx);
}

fn moduleEvents(fx: *helpers.Fixture) !void {
    const result = try fx.run(.{ .events_query = .{
        .session_digest = @splat(1),
        .module = .inspection,
        .node = 1,
        .from = 100,
        .until = 219,
    } });
    try t.expect(result == .page);
    const parsed = try std.json.parseFromSlice(struct {
        rows: []const struct { category: []const u8 },
    }, t.allocator, result.page.slice(), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 2), parsed.value.rows.len);
    for (parsed.value.rows) |row|
        try t.expectEqual(p.security.Module.inspection, p.security.classify(row.category));
}

test "security reply worst-case escaping and counter precision fit the HTTP response" {
    var page: p.security.Page = .{
        .request = .{ .from = 1, .until = 2 },
        .observed_at = std.math.maxInt(i64),
        .total = std.math.maxInt(u64),
    };
    const label = [_]u8{1} ** 96;
    const row: p.security.Rank = .{
        .label = try p.Bytes(96).init(&label),
        .count = std.math.maxInt(u64),
        .truncated = true,
    };
    for ([_]p.security.View{ .modules, .categories, .paths }) |view| {
        page.request.view = view;
        page.modules = @splat(.{});
        page.rows = @splat(null);
        if (view == .modules) {
            for (&page.modules) |*module| {
                module.total = std.math.maxInt(u64);
                module.trend = @splat(std.math.maxInt(u64));
                module.sources = @splat(row);
            }
        } else page.rows = @splat(row);
        var bytes: [16 * 1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(page, .{}, &writer);
        try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"18446744073709551615\"") != null);
    }
}

fn aggregateScope(fx: *helpers.Fixture) !void {
    const result = try fx.run(.{ .security_query = .{
        .session_digest = @splat(1),
        .aggregate_only = true,
        .request = .{ .node = 1, .from = 100, .until = 220 },
    } });
    try t.expect(result == .security_page);
    const page = result.security_page;
    try t.expectEqual(@as(u64, 3), page.total);
    try t.expectEqual(@as(u64, 2), page.modules[0].total);
    try t.expectEqual(@as(u64, 1), page.modules[0].trend[29]);
    for (page.modules) |module| for (module.sources) |source| {
        try t.expect(source == null);
    };
    for (page.rows) |row| try t.expect(row == null);
    var bytes: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(page, .{}, &writer);
    for ([_][]const u8{ "8.8.8.8", "/one", "secret", "waf:sqli" }) |private|
        try t.expect(std.mem.indexOf(u8, writer.buffered(), private) == null);
}

test "sixty populated buckets per module fit native and replicated query row bounds" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try helpers.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/security-buckets",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try helpers.policySession(fx);
    try fx.owner.db.exec(
        t.allocator,
        "WITH RECURSIVE ticks(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM ticks WHERE n<59)," ++
            "modules(m,category) AS (VALUES(0,'audit:xss'),(1,'honeypot'),(2,'other')) " ++
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
            "violation_category,offending_payload,recorded_at) " ++
            "SELECT 1+m*60+n,1,'8.8.8.8','','GET','/test',category,'',100+n " ++
            "FROM ticks,modules;",
    );
    for ([_]bool{ false, true }) |aggregate_only| {
        const result = try fx.run(.{ .security_query = .{
            .session_digest = @splat(1),
            .aggregate_only = aggregate_only,
            .request = .{ .node = 1, .from = 100, .until = 160 },
        } });
        try t.expect(result == .security_page);
        const page = result.security_page;
        try t.expectEqual(@as(u64, 180), page.total);
        for (page.modules) |module| {
            try t.expectEqual(@as(u64, 60), module.total);
            try t.expectEqualSlices(u64, &@as([60]u64, @splat(1)), &module.trend);
            if (aggregate_only) {
                for (module.sources) |source| try t.expect(source == null);
            } else try t.expectEqual(@as(u64, 60), module.sources[0].?.count);
        }
    }
}

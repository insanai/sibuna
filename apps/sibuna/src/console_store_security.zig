//! Each bounded statement sees one database snapshot. No request handler owns storage.
//! Counts describe retained incident rows, not all attacks or distinct denied requests.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const access = @import("console_read_authorize.zig");

pub fn query(owner: *Persistent, input: p.security.Query) !p.StorageResult {
    try p.security.validate(input);
    const scope: p.tokens.Scope = if (input.aggregate_only) .stats_read else .events_read;
    if (try access.check(owner, input.session_digest, input.require_totp, scope)) |reason|
        return .{ .failed = reason };
    const r = input.request;
    const sql = switch (r.view) {
        .modules => if (input.aggregate_only) trend_sql else module_sql,
        .categories => category_sql,
        .paths => path_sql,
    };
    var rows = try db.query(owner.db, owner.gpa, sql, &.{
        store.integer(r.from), store.integer(r.until),
        store.integer(r.node), store.integer(r.node),
    });
    defer rows.deinit();
    var page: p.security.Page = .{ .request = r, .observed_at = owner.nowSeconds() };
    var sources: [3]usize = @splat(0);
    var ranked: usize = 0;
    for (rows.rows) |row| {
        const count = try store.number(row[4]);
        const kind = try store.number(row[1]);
        if (kind == 3) {
            page.total = count;
        } else if (r.view == .modules) {
            const index = try store.number(row[0]);
            if (index >= page.modules.len) return error.InvalidStoredValue;
            const module = &page.modules[@intCast(index)];
            switch (kind) {
                0 => module.total = count,
                1 => {
                    const bucket = try store.number(row[2]);
                    if (bucket >= p.security.buckets) return error.InvalidStoredValue;
                    module.trend[@intCast(bucket)] = count;
                },
                2 => {
                    if (sources[index] >= 3) return error.InvalidStoredValue;
                    module.sources[sources[index]] = rank(row[3] orelse "", count);
                    sources[index] += 1;
                },
                else => return error.InvalidStoredValue,
            }
        } else {
            if (ranked >= page.rows.len) return error.InvalidStoredValue;
            page.rows[ranked] = rank(row[3] orelse "", count);
            ranked += 1;
        }
    }
    if (try access.check(owner, input.session_digest, input.require_totp, scope)) |reason|
        return .{ .failed = reason };
    var output: p.Bytes(p.max_message) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try std.json.Stringify.value(page, .{}, &writer);
    output.len = writer.buffered().len;
    return .{ .page = output };
}

fn rank(label: []const u8, count: u64) p.security.Rank {
    var result: p.security.Rank = .{ .count = count };
    @import("console_store_events.zig").copy(96, &result.label, label, &result.truncated);
    return result;
}

// Numeric module tags are protocol enum ordinals. Audit findings remain inspection
// findings; their presence never asserts that a request was blocked.
pub const classification = "CASE WHEN violation_category GLOB 'waf:*' " ++
    "OR violation_category GLOB 'audit:*' THEN 0 " ++
    "WHEN violation_category='honeypot' THEN 1 ELSE 2 END";
const window = "WITH bounds(lo,hi,node,wildcard) AS (VALUES(?,?,?,?)), " ++
    "findings AS MATERIALIZED (SELECT recorded_at,client_ip,violation_category,path," ++
    classification ++ " AS module,lo,hi FROM security_incidents,bounds " ++
    "WHERE recorded_at>=lo AND recorded_at<hi AND (wildcard=0 OR node_id=node)) ";
const module_sql = window ++
    ", sources AS (SELECT module,client_ip,COUNT(*) AS n FROM findings " ++
    "GROUP BY module,client_ip), ranked AS (SELECT *,ROW_NUMBER() OVER " ++
    "(PARTITION BY module ORDER BY n DESC,client_ip) AS rank FROM sources) " ++
    "SELECT module,0,0,'',COUNT(*) FROM findings GROUP BY module UNION ALL " ++
    "SELECT module,1,(recorded_at-lo)*12/(hi-lo),'',COUNT(*) FROM findings " ++
    "GROUP BY module,(recorded_at-lo)*12/(hi-lo) UNION ALL " ++
    "SELECT module,2,0,client_ip,n FROM ranked WHERE rank<=3 UNION ALL " ++
    "SELECT 0,3,0,'',COUNT(*) FROM findings ORDER BY 1,2,5 DESC,4 LIMIT 49";
const category_sql = window ++
    ", ranked AS (SELECT violation_category AS label,COUNT(*) AS n FROM findings " ++
    "GROUP BY violation_category ORDER BY n DESC,label LIMIT 5) " ++
    "SELECT 0,2,0,label,n FROM ranked UNION ALL SELECT 0,3,0,'',COUNT(*) FROM findings " ++
    "ORDER BY 2,5 DESC,4 LIMIT 6";
// Historical paths may predate evidence redaction. Strip the query/fragment before
// grouping, so secrets cannot appear in labels, ranking keys or drill-down actions.
const path_sql = window ++
    ", clean AS (SELECT substr(path,1,MIN(instr(path||'?','?'),instr(path||'#','#'))-1) " ++
    "AS label FROM findings), ranked AS (SELECT label,COUNT(*) AS n FROM clean " ++
    "GROUP BY label ORDER BY n DESC,label LIMIT 5) " ++
    "SELECT 0,2,0,label,n FROM ranked UNION ALL SELECT 0,3,0,'',COUNT(*) FROM findings " ++
    "ORDER BY 2,5 DESC,4 LIMIT 6";

// A kiosk query never selects addresses, paths, categories or payload evidence.
const trend_sql = "WITH bounds(lo,hi,node,wildcard) AS (VALUES(?,?,?,?)), " ++
    "findings AS MATERIALIZED (SELECT recorded_at," ++ classification ++
    " AS module,lo,hi FROM security_incidents,bounds WHERE recorded_at>=lo " ++
    "AND recorded_at<hi AND (wildcard=0 OR node_id=node)) " ++
    "SELECT module,0,0,'',COUNT(*) FROM findings GROUP BY module UNION ALL " ++
    "SELECT module,1,(recorded_at-lo)*12/(hi-lo),'',COUNT(*) FROM findings " ++
    "GROUP BY module,(recorded_at-lo)*12/(hi-lo) UNION ALL " ++
    "SELECT 0,3,0,'',COUNT(*) FROM findings ORDER BY 1,2 LIMIT 40";

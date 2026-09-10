//! Owner-only bounded incident reads. Historical payloads are not evidence envelopes;
//! do not expose them through richer panels until redaction and capture metadata exist.
const std = @import("std");
const p = @import("console").protocol;
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;

pub fn query(owner: *Persistent, input: p.events.Query) !p.StorageResult {
    try p.events.validate(input);
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    const before = input.before orelse p.events.Cursor{
        .time = std.math.maxInt(i64),
        .id = std.math.maxInt(i64),
    };
    const module: u64 = if (input.module) |m| @intFromEnum(m) else 3;
    const sql = statement(input.grouped, input.campaign != 0, input.incident != 0);
    var result = try db.query(owner.db, owner.gpa, sql, &.{
        integer(input.from),             integer(input.until),
        integer(input.node),             integer(input.node),
        text(input.category.slice()),    text(input.category.slice()),
        text(input.ip.slice()),          text(input.ip.slice()),
        text(input.path_prefix.slice()), text(input.path_prefix.slice()),
        text(input.country.slice()),     text(input.country.slice()),
        integer(module),                 integer(module),
        integer(input.campaign),         integer(input.campaign),
        integer(input.incident),         integer(input.incident),
        integer(before.time),            integer(before.time),
        integer(before.id),              integer(input.limit + 1),
    });
    defer result.deinit();
    var output: p.Bytes(p.max_message) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try writer.writeAll("{\"rows\":[");
    var count: usize = 0;
    var cursor: ?p.events.Cursor = null;
    for (result.rows) |row| {
        if (count >= input.limit) break;
        var event = try decode(row);
        event.grouped = input.grouped;
        var scratch: [4096]u8 = undefined;
        var item: std.Io.Writer = .fixed(&scratch);
        try event.write(&item);
        // Reserve space for separators, cursor and closing fields, even at maximum escaping.
        if (item.buffered().len + writer.buffered().len + 160 > output.data.len) break;
        if (count != 0) try writer.writeByte(',');
        try writer.writeAll(item.buffered());
        cursor = .{ .time = event.time, .id = event.id };
        count += 1;
    }
    try writer.writeAll("],\"next\":");
    if (count < result.rows.len and cursor != null) {
        try writer.print("{{\"time\":{d},\"id\":\"{d}\"}}", .{ cursor.?.time, cursor.?.id });
    } else try writer.writeAll("null");
    try writer.writeAll("}");
    output.len = writer.buffered().len;
    if (input.export_page and !try auditExport(owner, input))
        return .{ .failed = .unauthorized };
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    return .{ .page = output };
}

fn auditExport(owner: *Persistent, input: p.events.Query) !bool {
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const now = owner.nowSeconds();
    // Export preparation is recorded before returning bytes. This does not claim delivery.
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
            "SELECT u.id,'events.export_prepared',0,? FROM console_sessions s " ++
            "JOIN console_users u ON u.id=s.user_id WHERE s.digest=? " ++
            "AND s.revision=u.revision AND u.disabled=0 AND u.must_change=0 " ++
            "AND MIN(s.expires,s.idle_expires)>?",
        &.{ integer(now), text(&digest), integer(now) },
    );
    // Zaxonlite includes trigger writes in its change count. The unique session join
    // inserts at most one audit row; zero alone means authorization did not match.
    return changes > 0;
}

fn decode(row: []const ?[]const u8) !p.events.Row {
    var result: p.events.Row = .{
        .id = try store.number(row[0]),
        .node = std.math.cast(u32, try store.number(row[1])) orelse
            return error.InvalidStoredValue,
        .time = try store.number(row[2]),
        .campaign = if (row[8] != null) try store.number(row[8]) else null,
        .count = try store.number(row[9]),
        .first_seen = try store.number(row[10]),
        .geography = try p.events.country.Mapping.decode(.{
            .code = row[17],
            .generation = row[18],
            .mixed = try store.number(row[19]) != 0,
            .recorded = try store.number(row[20]) != 0,
        }),
    };
    copy(48, &result.ip, row[3] orelse "", &result.display_truncated);
    copy(8, &result.method, row[4] orelse "", &result.display_truncated);
    const path = row[5] orelse "";
    const end = std.mem.indexOfAny(u8, path, "?#") orelse path.len;
    result.query_redacted = end != path.len;
    copy(256, &result.path, path[0..end], &result.display_truncated);
    copy(32, &result.category, row[6] orelse "", &result.display_truncated);
    copy(128, &result.user_agent, row[7] orelse "", &result.display_truncated);
    if (row[11] != null and try store.number(row[11]) == 1) {
        result.capture = .{
            .selected_status = try narrow(u16, row[12]),
            .query_bytes = try narrow(u32, row[13]),
            .body_bytes = try narrow(u32, row[14]),
            .declared_body_bytes = try narrow(u32, row[15]),
            .truncated = try narrow(u16, row[16]),
        };
        result.query_redacted = result.query_redacted or result.capture.?.query_bytes != 0;
    }
    return result;
}

fn narrow(comptime T: type, value: ?[]const u8) !T {
    return std.math.cast(T, try store.number(value)) orelse error.InvalidStoredValue;
}

pub fn copy(
    comptime size: usize,
    output: *p.Bytes(size),
    source: []const u8,
    truncated: *bool,
) void {
    // Replace malformed historical bytes and controls with '?'; never split UTF-8 at a bound.
    var position: usize = 0;
    while (position < source.len) {
        const count = std.unicode.utf8ByteSequenceLength(source[position]) catch 1;
        const available = @min(count, source.len - position);
        const bytes = source[position..][0..available];
        const valid = available == count and std.unicode.utf8ValidateSlice(bytes) and
            source[position] >= 32 and source[position] != 127;
        const needed: usize = if (valid) count else 1;
        if (output.len + needed > size) break;
        if (valid) {
            @memcpy(output.data[output.len..][0..needed], bytes);
        } else {
            output.data[output.len] = '?';
        }
        output.len += needed;
        position += if (valid) count else @as(usize, 1);
    }
    truncated.* = truncated.* or position != source.len;
}

const base_filters =
    " FROM security_incidents LEFT JOIN console_incident_evidence e ON e.incident_id=id " ++
    "LEFT JOIN console_incident_country c ON c.incident_id=id " ++
    "WHERE recorded_at BETWEEN ? AND ? " ++
    "AND (?=0 OR node_id=?) AND (?='' OR violation_category=?) AND (?='' OR client_ip=?) " ++
    "AND substr(path,1,length(?))=? AND (?='' OR " ++
    "CASE WHEN c.generation IS NULL THEN 'not_recorded' " ++
    "ELSE COALESCE(c.country,'unknown') END=?) AND (?=3 OR " ++
    @import("console_store_security.zig").classification ++ "=?) ";
const filters = base_filters ++ "AND (?=0 OR campaign_id=?) ";
const id_filter = "AND (?=0 OR id=?) ";
const exact_id = "AND id=? AND ?!=0 ";
const campaign_filters = base_filters ++ "AND campaign_id=? AND ?!=0 ";
const raw_select =
    "SELECT id,node_id,recorded_at,client_ip,method,path,violation_category,user_agent," ++
    "campaign_id,1,recorded_at,e.version,e.selected_status,e.query_bytes,e.body_bytes," ++
    "e.declared_body_bytes,e.truncated,c.country,c.generation,0,c.generation IS NOT NULL";
const raw_order =
    "AND (recorded_at<? OR (recorded_at=? AND id<?)) " ++
    "ORDER BY recorded_at DESC,id DESC LIMIT ?";
const group_select =
    "SELECT MAX(id),node_id,MAX(recorded_at),client_ip,'','','','',NULL," ++
    "COUNT(*),MIN(recorded_at),NULL,NULL,NULL,NULL,NULL,NULL," ++
    "CASE WHEN COUNT(DISTINCT COALESCE(c.country,''))=1 THEN MIN(c.country) END," ++
    "CASE WHEN COUNT(DISTINCT COALESCE(c.generation,''))=1 THEN MIN(c.generation) END," ++
    "COUNT(DISTINCT CASE WHEN c.generation IS NULL THEN 'not_recorded' " ++
    "ELSE COALESCE(c.country,'unknown') END)>1,COUNT(c.generation)=COUNT(*)";
const group_order =
    "GROUP BY node_id,client_ip HAVING MAX(recorded_at)<? OR " ++
    "(MAX(recorded_at)=? AND MAX(id)<?) ORDER BY MAX(recorded_at) DESC,MAX(id) DESC LIMIT ?";

fn statement(grouped: bool, campaign: bool, incident: bool) []const u8 {
    if (grouped) {
        if (incident) return group_select ++ filters ++ exact_id ++ group_order;
        if (campaign) return group_select ++ campaign_filters ++ id_filter ++ group_order;
        return group_select ++ filters ++ id_filter ++ group_order;
    }
    if (incident) return raw_select ++ filters ++ exact_id ++ raw_order;
    if (campaign) return raw_select ++ campaign_filters ++ id_filter ++ raw_order;
    return raw_select ++ filters ++ id_filter ++ raw_order;
}

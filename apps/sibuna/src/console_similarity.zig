//! One bounded storage-owner scan. Never use an unbounded vec0 KNN loop on a console request.
const std = @import("std");
const p = @import("console").protocol;
const embedding = @import("policy").embedding;
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");

pub fn query(owner: *Persistent, input: p.similarity.Query) !p.StorageResult {
    try p.similarity.validate(input);
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    const result = try scan(owner, input);
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    return result;
}

fn scan(owner: *Persistent, input: p.similarity.Query) !p.StorageResult {
    var source = try db.query(
        owner.db,
        owner.gpa,
        "SELECT hex(embedding) FROM incidents_vec WHERE item_id=? LIMIT 1",
        &.{store.integer(input.source)},
    );
    defer source.deinit();
    var output: p.similarity.Part = .{};
    if (source.rows.len == 0) return .{ .similarity = output };
    const vector = decode(source.rows[0][0] orelse "") catch return .{ .similarity = output };
    output.source_available = true;
    const before = input.before orelse p.events.Cursor{
        .time = input.until,
        .id = std.math.maxInt(i64),
    };
    var candidates = try db.query(owner.db, owner.gpa, scan_sql, &.{
        store.integer(input.from),  store.integer(input.until), store.integer(before.time),
        store.integer(before.time), store.integer(before.id),
    });
    defer candidates.deinit();
    for (candidates.rows) |row| {
        const id = try store.number(row[0]);
        const time = try store.number(row[1]);
        const node = std.math.cast(u32, try store.number(row[2])) orelse
            return error.InvalidStoredValue;
        output.scanned += 1;
        output.next = .{ .time = time, .id = id };
        if (id == input.source) continue;
        const candidate = decode(row[3] orelse "") catch {
            output.invalid += 1;
            continue;
        };
        const distance = std.math.clamp(1.0 - embedding.cosine(&vector, &candidate), 0, 2);
        output.best.add(.{ .id = id, .node = node, .time = time, .distance = distance });
    }
    if (candidates.rows.len < 64) output.next = null;
    return .{ .similarity = output };
}

const scan_sql =
    "SELECT s.id,s.recorded_at,s.node_id,hex(v.embedding) FROM " ++
    "(SELECT id,recorded_at,node_id FROM security_incidents WHERE recorded_at BETWEEN ? AND ? " ++
    "AND (recorded_at<? OR (recorded_at=? AND id<?)) " ++
    "ORDER BY recorded_at DESC,id DESC LIMIT 64) s " ++
    "LEFT JOIN incidents_vec v ON v.item_id=s.id ORDER BY s.recorded_at DESC,s.id DESC";

fn decode(hex: []const u8) error{InvalidVector}!embedding.Vector {
    var bytes: [embedding.dim * 4]u8 = undefined;
    if (hex.len != bytes.len * 2) return error.InvalidVector;
    _ = std.fmt.hexToBytes(&bytes, hex) catch return error.InvalidVector;
    var vector: embedding.Vector = undefined;
    var norm: f64 = 0;
    for (&vector, 0..) |*value, i| {
        value.* = @bitCast(std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little));
        if (!std.math.isFinite(value.*)) return error.InvalidVector;
        norm += @as(f64, value.*) * value.*;
    }
    if (!std.math.isFinite(norm) or norm <= 0) return error.InvalidVector;
    const scale = 1.0 / @sqrt(norm);
    for (&vector) |*value| value.* = @floatCast(@as(f64, value.*) * scale);
    return vector;
}

test "stored vectors reject empty, zero and non-finite evidence" {
    try std.testing.expectError(error.InvalidVector, decode(""));
    const zero = @as([512]u8, @splat('0'));
    try std.testing.expectError(error.InvalidVector, decode(&zero));
    const bytes = embedding.toBytes(&embedding.embed("test payload"));
    const hex = std.fmt.bytesToHex(bytes, .lower);
    const vector = try decode(&hex);
    try std.testing.expectApproxEqAbs(@as(f32, 1), embedding.cosine(&vector, &vector), 0.0001);
}

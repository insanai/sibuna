//! Validated geographic coordinates remain separate from the authentication bundle.
const std = @import("std");
pub const max_bytes = 128 * 1024;
pub const Point = struct { lon: f64, lat: f64 };
pub const Vec = struct { x: f64, y: f64, z: f64 };
pub const View = struct { lon: f64 = 0, lat: f64 = 15, flat: bool = false };
pub const Error = error{ InvalidGeometry, TooLarge };

pub fn validate(bytes: []const u8) Error!void {
    if (bytes.len > max_bytes) return error.TooLarge;
    if (bytes.len < 6 or !std.mem.eql(u8, bytes[0..4], "SBG1")) return error.InvalidGeometry;
    const rings = std.mem.readInt(u16, bytes[4..6], .little);
    if (rings == 0 or rings > 1024) return error.InvalidGeometry;
    var offset: usize = 6;
    var vertices: usize = 0;
    for (0..rings) |_| {
        if (bytes.len - offset < 4) return error.InvalidGeometry;
        if (!std.ascii.isUpper(bytes[offset]) or !std.ascii.isUpper(bytes[offset + 1]))
            return error.InvalidGeometry;
        const count = std.mem.readInt(u16, bytes[offset + 2 ..][0..2], .little);
        if (count < 4) return error.InvalidGeometry;
        vertices += count;
        if (vertices > 16384) return error.TooLarge;
        offset += 4;
        const length = @as(usize, count) * 4;
        if (length > bytes.len - offset) return error.InvalidGeometry;
        const coordinates = bytes[offset..][0..length];
        if (!std.mem.eql(u8, coordinates[0..4], coordinates[length - 4 ..]))
            return error.InvalidGeometry;
        var point: usize = 0;
        while (point < length) : (point += 4) {
            const lon = std.mem.readInt(i16, coordinates[point..][0..2], .little);
            const lat = std.mem.readInt(i16, coordinates[point + 2 ..][0..2], .little);
            if (lon < -18000 or lon > 18000 or lat < -9000 or lat > 9000)
                return error.InvalidGeometry;
        }
        offset += length;
    }
    if (offset != bytes.len) return error.InvalidGeometry;
}

pub fn project(point: Point, view: View) Vec {
    const radians = std.math.pi / 180.0;
    const phi = point.lat * radians;
    const center = view.lat * radians;
    const lambda = (point.lon - view.lon) * radians;
    return .{
        .x = @cos(phi) * @sin(lambda),
        .y = @cos(center) * @sin(phi) - @sin(center) * @cos(phi) * @cos(lambda),
        .z = @sin(center) * @sin(phi) + @cos(center) * @cos(phi) * @cos(lambda),
    };
}

/// Intersect the short spherical edge with the horizon, normalizing the chord intersection.
/// Exact antipodes have no unique short edge and are rejected rather than crossing the earth.
pub fn horizon(a: Vec, b: Vec) ?Vec {
    const denominator = a.z - b.z;
    if (@abs(denominator) < 1e-12) return null;
    const t = a.z / denominator;
    const x = a.x + (b.x - a.x) * t;
    const y = a.y + (b.y - a.y) * t;
    const magnitude = @sqrt(x * x + y * y);
    if (magnitude < 1e-12) return null;
    return .{ .x = x / magnitude, .y = y / magnitude, .z = 0 };
}

fn decodePoint(bytes: []const u8) Point {
    return .{
        .lon = @as(f64, @floatFromInt(std.mem.readInt(i16, bytes[0..2], .little))) / 100,
        .lat = @as(f64, @floatFromInt(std.mem.readInt(i16, bytes[2..4], .little))) / 100,
    };
}

/// Caller validates once before publication. Every segment is independently bounded; no
/// rear-hemisphere path may connect visible islands across an invisible coastline.
pub fn render(bytes: []const u8, view: View, w: *std.Io.Writer) std.Io.Writer.Error!void {
    std.debug.assert(bytes.len >= 6);
    const rings = std.mem.readInt(u16, bytes[4..6], .little);
    var offset: usize = 6;
    try w.writeAll("<g fill=\"none\" stroke=\"#6b8ba4\" stroke-width=\"0.5\">");
    for (0..rings) |_| {
        const count = std.mem.readInt(u16, bytes[offset + 2 ..][0..2], .little);
        offset += 4;
        const coordinates = bytes[offset..][0 .. @as(usize, count) * 4];
        try w.writeAll("<path d=\"");
        var i: usize = 4;
        while (i < coordinates.len) : (i += 4) {
            try segment(
                decodePoint(coordinates[i - 4 ..]),
                decodePoint(coordinates[i..]),
                view,
                w,
            );
        }
        try w.writeAll("\"/>");
        offset += coordinates.len;
    }
    try w.writeAll("</g>");
}

fn segment(a: Point, b: Point, view: View, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (view.flat) {
        // Split at the seam; never draw a line spanning the full map width.
        if (@abs(a.lon - b.lon) > 180) return;
        try w.print("M{d:.1},{d:.1}L{d:.1},{d:.1}", .{
            200 + a.lon, 135 - a.lat, 200 + b.lon, 135 - b.lat,
        });
        return;
    }
    var first = project(a, view);
    var last = project(b, view);
    if (first.z < 0 and last.z < 0) return;
    if (first.z < 0) first = horizon(first, last) orelse return;
    if (last.z < 0) last = horizon(first, last) orelse return;
    try w.print("M{d:.1},{d:.1}L{d:.1},{d:.1}", .{
        200 + 110 * first.x, 135 - 110 * first.y, 200 + 110 * last.x, 135 - 110 * last.y,
    });
}

test "orthographic horizon, poles and antimeridian do not expose the rear hemisphere" {
    const t = std.testing;
    const center = project(.{ .lon = 0, .lat = 0 }, .{ .lat = 0 });
    try t.expectApproxEqAbs(@as(f64, 1), center.z, 1e-12);
    const back = project(.{ .lon = 180, .lat = 0 }, .{ .lat = 0 });
    try t.expect(back.z < 0);
    const pole = project(.{ .lon = 90, .lat = 90 }, .{ .lat = 90 });
    try t.expectApproxEqAbs(@as(f64, 1), pole.z, 1e-12);
    const edge = horizon(center, project(.{ .lon = 120, .lat = 0 }, .{ .lat = 0 })).?;
    try t.expectApproxEqAbs(@as(f64, 1), edge.x, 1e-12);
    try t.expectEqual(@as(f64, 0), edge.z);
    var buffer: [100]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try segment(
        .{ .lon = 179, .lat = 1 },
        .{ .lon = -179, .lat = 1 },
        .{ .flat = true },
        &w,
    );
    try t.expectEqual(@as(usize, 0), w.buffered().len);
    try segment(.{ .lon = 150, .lat = 1 }, .{ .lon = 160, .lat = 1 }, .{}, &w);
    try t.expectEqual(@as(usize, 0), w.buffered().len);
}

test "geometry validator rejects partial headers, open rings and trailing data" {
    const t = std.testing;
    const valid = "SBG1\x01\x00US\x04\x00" ++
        "\x00\x00\x00\x00\x64\x00\x00\x00\x64\x00\x64\x00\x00\x00\x00\x00";
    try validate(valid);
    for (0..valid.len) |length| {
        try t.expectError(error.InvalidGeometry, validate(valid[0..length]));
    }
    try t.expectError(error.InvalidGeometry, validate(valid ++ "x"));
}

//! Bounded great-circle routes, projected with the same camera as Natural Earth geometry.
const std = @import("std");
const geo = @import("geography.zig");
const Vec = geo.Vec;
pub const Screen = struct { x: f64, y: f64, z: f64 };

pub const Route = struct {
    start: Vec,
    end: Vec,
    tangent: Vec,
    angle: f64,

    pub fn init(start: geo.Point, end: geo.Point) Route {
        const a = geo.project(start, .{ .lat = 0 });
        const b = geo.project(end, .{ .lat = 0 });
        const dot = std.math.clamp(a.x * b.x + a.y * b.y + a.z * b.z, -1, 1);
        const residual: Vec = .{
            .x = b.x - dot * a.x,
            .y = b.y - dot * a.y,
            .z = b.z - dot * a.z,
        };
        const length = norm(residual);
        // Exact antipodes have infinitely many routes. Pick a stable perpendicular; near
        // antipodes retain their actual endpoint and do not normalize numerical noise.
        const tangent = if (length > 1e-10) scale(residual, 1 / length) else perpendicular(a);
        return .{ .start = a, .end = b, .tangent = tangent, .angle = std.math.acos(dot) };
    }

    pub fn at(self: Route, t: f64) Vec {
        std.debug.assert(t >= 0 and t <= 1);
        if (t == 0) return self.start;
        if (t == 1) return self.end;
        const a = @cos(self.angle * t);
        const b = @sin(self.angle * t);
        return .{
            .x = a * self.start.x + b * self.tangent.x,
            .y = a * self.start.y + b * self.tangent.y,
            .z = a * self.start.z + b * self.tangent.z,
        };
    }

    pub fn screen(self: Route, view: geo.View, t: f64) Screen {
        const v = self.at(t);
        const radians = std.math.pi / 180.0;
        if (view.flat) return .{
            .x = 200 + std.math.atan2(v.x, v.z) / radians,
            .y = 135 - std.math.atan2(v.y, @sqrt(v.x * v.x + v.z * v.z)) / radians,
            .z = 1,
        };
        const lon = view.lon * radians;
        const lat = view.lat * radians;
        const across = v.x * @sin(lon) + v.z * @cos(lon);
        const radius = 110 * (1 + 0.18 * @sin(std.math.pi * t));
        return .{
            .x = 200 + radius * (v.x * @cos(lon) - v.z * @sin(lon)),
            .y = 135 - radius * (v.y * @cos(lat) - across * @sin(lat)),
            .z = v.y * @sin(lat) + across * @cos(lat),
        };
    }
};

/// Each short segment clips independently. Never draw across the rear hemisphere or join
/// the two sides of the flat map's antimeridian. The caller samples at most 48 segments.
pub fn segment(a: Screen, b: Screen, flat: bool) ?[2]Screen {
    if (flat) return if (@abs(a.x - b.x) > 180) null else .{ a, b };
    if (a.z < 0 and b.z < 0) return null;
    if (a.z >= 0 and b.z >= 0) return .{ a, b };
    const t = a.z / (a.z - b.z);
    const edge: Screen = .{ .x = a.x + t * (b.x - a.x), .y = a.y + t * (b.y - a.y), .z = 0 };
    return if (a.z < 0) .{ edge, b } else .{ a, edge };
}

fn norm(v: Vec) f64 {
    return @sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
}

fn scale(v: Vec, by: f64) Vec {
    return .{ .x = v.x * by, .y = v.y * by, .z = v.z * by };
}

fn perpendicular(v: Vec) Vec {
    const candidate: Vec = if (@abs(v.x) < @abs(v.y))
        .{ .x = 0, .y = v.z, .z = -v.y }
    else
        .{ .x = -v.z, .y = 0, .z = v.x };
    return scale(candidate, 1 / norm(candidate));
}

test "routes end at geographic markers and stay finite for coincidence and antipodes" {
    const t = std.testing;
    const start: geo.Point = .{ .lat = 0, .lon = 0 };
    for ([_]geo.Point{ start, .{ .lat = 0, .lon = 180 }, .{ .lat = 1.35, .lon = 103.82 } }) |end| {
        const route = Route.init(start, end);
        for (0..49) |index| {
            const point = route.at(@as(f64, @floatFromInt(index)) / 48);
            try t.expectApproxEqAbs(@as(f64, 1), norm(point), 0.000001);
        }
        const view: geo.View = .{ .lat = end.lat, .lon = end.lon };
        const destination = route.screen(view, 1);
        try t.expectApproxEqAbs(@as(f64, 200), destination.x, 0.000001);
        try t.expectApproxEqAbs(@as(f64, 135), destination.y, 0.000001);
    }
    const across_pole = Route.init(.{ .lat = 90, .lon = 0 }, .{ .lat = -90, .lon = 0 });
    try t.expectApproxEqAbs(@as(f64, 1), norm(across_pole.at(0.5)), 0.000001);
}

test "rear segments and flat-map dateline crossings cannot draw false connections" {
    const t = std.testing;
    const a: Screen = .{ .x = 21, .y = 90, .z = -1 };
    const b: Screen = .{ .x = 379, .y = 110, .z = -0.5 };
    try t.expect(segment(a, b, false) == null);
    try t.expect(segment(a, b, true) == null);
    const front: Screen = .{ .x = 30, .y = 110, .z = 1 };
    const clipped = segment(a, front, false).?;
    try t.expectEqual(@as(f64, 0), clipped[0].z);
    try t.expectEqual(@as(f64, 1), clipped[1].z);
    try t.expectEqual(@as(f64, 25.5), clipped[0].x);
}

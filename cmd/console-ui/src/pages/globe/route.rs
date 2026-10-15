//! Great-circle routes from a country to a node, projected with the same camera as the
//! boundaries (`geographic_route.zig`).
//!
//! A route is the arc of the great circle through its two ends: the start vector `a`,
//! the unit tangent `t` toward the end, and the angle `w` between the ends, so the point
//! at `s` in `[0, 1]` is `cos(w s) a + sin(w s) t`. On the globe the arc rises above the
//! surface, by up to 18 percent of the radius at its middle, so routes stand out from the
//! boundaries. The caller samples at most 48 segments per route.

use super::projection::{CENTER_X, CENTER_Y, RADIUS, Vector, project};
use crate::geometry::Point;
use crate::state::GlobeView;

/// A projected route point: scene coordinates and its depth (`z < 0` is hidden).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ScreenPoint {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// One great-circle route.
#[derive(Clone, Copy, Debug)]
pub(super) struct Route {
    start: Vector,
    end: Vector,
    tangent: Vector,
    angle: f64,
}

impl Route {
    /// Returns the route from `start` to `end`.
    pub fn new(start: Point, end: Point) -> Route {
        let origin = GlobeView { lon: 0.0, lat: 0.0, flat: false };
        let a = project(start, origin);
        let b = project(end, origin);
        let dot = (a.x * b.x + a.y * b.y + a.z * b.z).clamp(-1.0, 1.0);
        let residual = Vector { x: b.x - dot * a.x, y: b.y - dot * a.y, z: b.z - dot * a.z };
        let length = norm(residual);
        // Exact antipodes have infinitely many routes. Pick a stable perpendicular; near
        // antipodes keep their actual end and do not normalise numerical noise.
        let tangent =
            if length > 1e-10 { scale(residual, 1.0 / length) } else { perpendicular(a) };
        Route { start: a, end: b, tangent, angle: dot.acos() }
    }

    /// Returns the point at `t` along the route, on the unit sphere. The ends are exact.
    pub fn at(&self, t: f64) -> Vector {
        if t <= 0.0 {
            return self.start;
        }
        if t >= 1.0 {
            return self.end;
        }
        let a = (self.angle * t).cos();
        let b = (self.angle * t).sin();
        Vector {
            x: a * self.start.x + b * self.tangent.x,
            y: a * self.start.y + b * self.tangent.y,
            z: a * self.start.z + b * self.tangent.z,
        }
    }

    /// Returns the scene position of the point at `t` for `view`.
    pub fn screen(&self, view: GlobeView, t: f64) -> ScreenPoint {
        let v = self.at(t);
        let radians = std::f64::consts::PI / 180.0;
        if view.flat {
            return ScreenPoint {
                x: CENTER_X + v.x.atan2(v.z) / radians,
                y: CENTER_Y - v.y.atan2((v.x * v.x + v.z * v.z).sqrt()) / radians,
                z: 1.0,
            };
        }
        let lon = view.lon * radians;
        let lat = view.lat * radians;
        let across = v.x * lon.sin() + v.z * lon.cos();
        let radius = RADIUS * (1.0 + 0.18 * (std::f64::consts::PI * t).sin());
        ScreenPoint {
            x: CENTER_X + radius * (v.x * lon.cos() - v.z * lon.sin()),
            y: CENTER_Y - radius * (v.y * lat.cos() - across * lat.sin()),
            z: v.y * lat.sin() + across * lat.cos(),
        }
    }
}

/// Returns the visible part of the segment from `a` to `b`. Each short segment clips on
/// its own: nothing is drawn across the rear hemisphere, and the two sides of the flat
/// map's antimeridian are never joined.
pub(super) fn segment(a: ScreenPoint, b: ScreenPoint, flat: bool) -> Option<[ScreenPoint; 2]> {
    if flat {
        return ((a.x - b.x).abs() <= 180.0).then_some([a, b]);
    }
    if a.z < 0.0 && b.z < 0.0 {
        return None;
    }
    if a.z >= 0.0 && b.z >= 0.0 {
        return Some([a, b]);
    }
    let t = a.z / (a.z - b.z);
    let edge = ScreenPoint { x: a.x + t * (b.x - a.x), y: a.y + t * (b.y - a.y), z: 0.0 };
    Some(if a.z < 0.0 { [edge, b] } else { [a, edge] })
}

fn norm(v: Vector) -> f64 {
    (v.x * v.x + v.y * v.y + v.z * v.z).sqrt()
}

fn scale(v: Vector, by: f64) -> Vector {
    Vector { x: v.x * by, y: v.y * by, z: v.z * by }
}

fn perpendicular(v: Vector) -> Vector {
    let candidate = if v.x.abs() < v.y.abs() {
        Vector { x: 0.0, y: v.z, z: -v.y }
    } else {
        Vector { x: -v.z, y: 0.0, z: v.x }
    };
    scale(candidate, 1.0 / norm(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of geographic_route.zig "routes end at geographic markers and stay finite for
    // coincidence and antipodes".
    #[test]
    fn routes_end_at_geographic_markers_and_stay_finite_for_coincidence_and_antipodes() {
        let start = Point { lat: 0.0, lon: 0.0 };
        let ends = [start, Point { lat: 0.0, lon: 180.0 }, Point { lat: 1.35, lon: 103.82 }];
        for end in ends {
            let route = Route::new(start, end);
            for index in 0..49 {
                let point = route.at(f64::from(index) / 48.0);
                assert!((norm(point) - 1.0).abs() < 0.000001);
            }
            let view = GlobeView { lat: end.lat, lon: end.lon, flat: false };
            let destination = route.screen(view, 1.0);
            assert!((destination.x - 200.0).abs() < 0.000001);
            assert!((destination.y - 135.0).abs() < 0.000001);
        }
        let across_pole =
            Route::new(Point { lat: 90.0, lon: 0.0 }, Point { lat: -90.0, lon: 0.0 });
        assert!((norm(across_pole.at(0.5)) - 1.0).abs() < 0.000001);
    }

    // Port of geographic_route.zig "rear segments and flat-map dateline crossings cannot
    // draw false connections".
    #[test]
    fn rear_segments_and_flat_map_dateline_crossings_cannot_draw_false_connections() {
        let a = ScreenPoint { x: 21.0, y: 90.0, z: -1.0 };
        let b = ScreenPoint { x: 379.0, y: 110.0, z: -0.5 };
        assert_eq!(segment(a, b, false), None);
        assert_eq!(segment(a, b, true), None);
        let front = ScreenPoint { x: 30.0, y: 110.0, z: 1.0 };
        let clipped = segment(a, front, false).unwrap();
        assert_eq!(clipped[0].z, 0.0);
        assert_eq!(clipped[1].z, 1.0);
        assert_eq!(clipped[0].x, 25.5);
    }

    /// Random ends, including exact and near antipodes, give finite routes on the sphere
    /// whose visible segments never leave the scene's neighbourhood.
    #[test]
    fn random_routes_stay_finite_and_on_the_sphere() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            f64::from(u32::try_from(seed >> 32).unwrap_or(0)) / f64::from(u32::MAX)
        };
        for round in 0..20_000 {
            let start = Point { lon: next() * 360.0 - 180.0, lat: next() * 180.0 - 90.0 };
            let end = if round % 10 == 0 {
                Point { lon: start.lon + 180.0, lat: -start.lat }
            } else {
                Point { lon: next() * 360.0 - 180.0, lat: next() * 180.0 - 90.0 }
            };
            let route = Route::new(start, end);
            let view = GlobeView {
                lon: next() * 360.0 - 180.0,
                lat: next() * 180.0 - 90.0,
                flat: round % 3 == 0,
            };
            let mut previous = route.screen(view, 0.0);
            for step in 1..=48 {
                let t = f64::from(step) / 48.0;
                assert!((norm(route.at(t)) - 1.0).abs() < 1e-9);
                let next = route.screen(view, t);
                if let Some([a, b]) = segment(previous, next, view.flat) {
                    for point in [a, b] {
                        assert!(point.x.is_finite() && point.y.is_finite());
                        assert!((0.0..=400.0).contains(&point.x), "{point:?}");
                    }
                }
                previous = next;
            }
        }
    }
}

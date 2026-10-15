//! The orthographic projection and the drawing of boundaries and the graticule (the
//! projection half of `geography.zig`).
//!
//! SID 0007 gives the projection about the centre `(lon0, lat0)` of the view:
//!
//! ```text
//! x = cos(lat) sin(lon - lon0)
//! y = cos(lat0) sin(lat) - sin(lat0) cos(lat) cos(lon - lon0)
//! z = sin(lat0) sin(lat) + cos(lat0) cos(lat) cos(lon - lon0)
//! ```
//!
//! A point is visible when `z >= 0`; the screen position is `(200 + 110 x, 135 - 110 y)`
//! in the 400 by 280 scene. Each boundary edge is drawn or clipped on its own, so no line
//! crosses the rear hemisphere. The flat map draws longitude and latitude directly
//! (`(200 + lon, 135 - lat)`) and drops edges that cross the antimeridian.

use std::fmt::{self, Write};

use crate::format;
use crate::geometry::{self, Point};
use crate::state::GlobeView;

/// The scene's centre and the globe's radius, in SVG units.
pub(super) const CENTER_X: f64 = 200.0;
pub(super) const CENTER_Y: f64 = 135.0;
pub(super) const RADIUS: f64 = 110.0;

/// A point on the unit sphere in view coordinates: `x` right, `y` up, `z` toward the
/// viewer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Vector {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// Projects `point` for `view` (the flat flag is ignored).
pub(super) fn project(point: Point, view: GlobeView) -> Vector {
    let radians = std::f64::consts::PI / 180.0;
    let phi = point.lat * radians;
    let latitude = view.lat * radians;
    let lambda = (point.lon - view.lon) * radians;
    Vector {
        x: phi.cos() * lambda.sin(),
        y: latitude.cos() * phi.sin() - latitude.sin() * phi.cos() * lambda.cos(),
        z: latitude.sin() * phi.sin() + latitude.cos() * phi.cos() * lambda.cos(),
    }
}

/// Returns where the short edge from `a` to `b` meets the horizon (`z = 0`), normalised
/// onto the rim; `None` when the edge is parallel to the horizon or passes through the
/// centre of the sphere (exact antipodes, which have no unique short edge).
pub(super) fn horizon(a: Vector, b: Vector) -> Option<Vector> {
    let denominator = a.z - b.z;
    if denominator.abs() < 1e-12 {
        return None;
    }
    let t = a.z / denominator;
    let x = a.x + (b.x - a.x) * t;
    let y = a.y + (b.y - a.y) * t;
    let magnitude = (x * x + y * y).sqrt();
    if magnitude < 1e-12 {
        return None;
    }
    Some(Vector { x: x / magnitude, y: y / magnitude, z: 0.0 })
}

/// Writes one move-and-line command, `M{x1},{y1}L{x2},{y2}`, with one decimal each.
pub(super) fn line(out: &mut impl Write, from: (f64, f64), to: (f64, f64)) -> fmt::Result {
    out.write_str("M")?;
    format::decimal(out, from.0, 1)?;
    out.write_str(",")?;
    format::decimal(out, from.1, 1)?;
    out.write_str("L")?;
    format::decimal(out, to.0, 1)?;
    out.write_str(",")?;
    format::decimal(out, to.1, 1)
}

/// Writes the visible part of the edge from `a` to `b`, if any.
pub(super) fn edge(out: &mut impl Write, a: Point, b: Point, view: GlobeView) -> fmt::Result {
    if view.flat {
        // Split at the seam; never draw a line spanning the full map width.
        if (a.lon - b.lon).abs() > 180.0 {
            return Ok(());
        }
        return line(
            out,
            (CENTER_X + a.lon, CENTER_Y - a.lat),
            (CENTER_X + b.lon, CENTER_Y - b.lat),
        );
    }
    let mut first = project(a, view);
    let mut last = project(b, view);
    if first.z < 0.0 && last.z < 0.0 {
        return Ok(());
    }
    if first.z < 0.0 {
        let Some(rim) = horizon(first, last) else { return Ok(()) };
        first = rim;
    }
    if last.z < 0.0 {
        let Some(rim) = horizon(first, last) else { return Ok(()) };
        last = rim;
    }
    line(out, screen(first), screen(last))
}

/// Returns the scene position of a projected point.
pub(super) fn screen(vector: Vector) -> (f64, f64) {
    (CENTER_X + RADIUS * vector.x, CENTER_Y - RADIUS * vector.y)
}

/// Draws the country boundaries of validated geometry `bytes`, one path per ring.
pub(super) fn boundaries(out: &mut impl Write, bytes: &[u8], view: GlobeView) -> fmt::Result {
    out.write_str("<g fill=\"none\" stroke=\"#6b8ba4\" stroke-width=\"0.5\">")?;
    for ring in geometry::rings(bytes) {
        out.write_str("<path d=\"")?;
        let mut points = ring.points();
        if let Some(mut previous) = points.next() {
            for point in points {
                edge(out, previous, point, view)?;
                previous = point;
            }
        }
        out.write_str("\"/>")?;
    }
    out.write_str("</g>")
}

/// Draws the fixed 30-degree grid with the same clipping as the boundaries, in
/// five-degree edges: 12 meridians of 36 edges and 5 parallels of 72.
pub(super) fn graticule(out: &mut impl Write, view: GlobeView) -> fmt::Result {
    out.write_str(
        "<path fill=\"none\" stroke=\"#6b8ba4\" stroke-opacity=\".25\" \
         stroke-width=\".4\" d=\"",
    )?;
    for meridian in 0..12u32 {
        let lon = f64::from(meridian) * 30.0 - 180.0;
        for step in 0..36u32 {
            let lat = f64::from(step) * 5.0 - 90.0;
            edge(out, Point { lon, lat }, Point { lon, lat: lat + 5.0 }, view)?;
        }
    }
    for parallel in 0..5u32 {
        let lat = f64::from(parallel) * 30.0 - 60.0;
        for step in 0..72u32 {
            let lon = f64::from(step) * 5.0 - 180.0;
            edge(out, Point { lon, lat }, Point { lon: lon + 5.0, lat }, view)?;
        }
    }
    out.write_str("\"/>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(lon: f64, lat: f64) -> Point {
        Point { lon, lat }
    }

    fn centred(lon: f64, lat: f64) -> GlobeView {
        GlobeView { lon, lat, flat: false }
    }

    // Port of geography.zig "orthographic horizon, poles and antimeridian do not expose
    // the rear hemisphere".
    #[test]
    fn orthographic_horizon_poles_and_antimeridian_do_not_expose_the_rear_hemisphere() {
        let origin = project(at(0.0, 0.0), centred(0.0, 0.0));
        assert!((origin.z - 1.0).abs() < 1e-12);
        let back = project(at(180.0, 0.0), centred(0.0, 0.0));
        assert!(back.z < 0.0);
        let pole = project(at(90.0, 90.0), centred(0.0, 90.0));
        assert!((pole.z - 1.0).abs() < 1e-12);
        let rim = horizon(origin, project(at(120.0, 0.0), centred(0.0, 0.0))).unwrap();
        assert!((rim.x - 1.0).abs() < 1e-12);
        assert_eq!(rim.z, 0.0);
        let mut out = String::new();
        let flat = GlobeView { flat: true, ..GlobeView::default() };
        edge(&mut out, at(179.0, 1.0), at(-179.0, 1.0), flat).unwrap();
        assert_eq!(out, "");
        edge(&mut out, at(150.0, 1.0), at(160.0, 1.0), GlobeView::default()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn a_visible_edge_is_drawn_and_a_half_visible_edge_ends_on_the_rim() {
        let mut out = String::new();
        edge(&mut out, at(0.0, 0.0), at(10.0, 0.0), centred(0.0, 0.0)).unwrap();
        assert_eq!(out, "M200.0,135.0L219.1,135.0");
        out.clear();
        edge(&mut out, at(80.0, 0.0), at(100.0, 0.0), centred(0.0, 0.0)).unwrap();
        assert_eq!(out, "M308.3,135.0L310.0,135.0");
        out.clear();
        edge(
            &mut out,
            at(-10.0, 5.0),
            at(10.0, -5.0),
            GlobeView { flat: true, ..centred(0.0, 0.0) },
        )
        .unwrap();
        assert_eq!(out, "M190.0,130.0L210.0,140.0");
    }

    #[test]
    fn every_view_of_the_world_stays_on_the_disc() {
        let world = include_bytes!("../../../web/assets/world-110m.bin");
        for step in 0..24 {
            let view = centred(f64::from(step) * 15.0 - 180.0, f64::from(step) * 7.5 - 90.0);
            let mut out = String::new();
            boundaries(&mut out, world, view).unwrap();
            graticule(&mut out, view).unwrap();
            let paths = out.split('"').filter(|part| part.starts_with('M'));
            for pair in paths.flat_map(|path| path.split(['M', 'L'])).filter(|p| !p.is_empty()) {
                let (x, y) = pair.split_once(',').unwrap();
                let (x, y): (f64, f64) = (x.parse().unwrap(), y.parse().unwrap());
                // Every point lies on the disc, up to the rounding to one decimal.
                let distance = (x - CENTER_X).hypot(y - CENTER_Y);
                assert!(distance <= RADIUS + 0.08, "{pair}");
            }
        }
    }
}

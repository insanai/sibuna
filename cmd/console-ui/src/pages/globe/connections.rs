//! Observed country-to-node activity and the node markers (`globe_connections.zig`).
//!
//! A connection runs from a country's representative position to the location the
//! operator configured for the receiving node; nothing is inferred. With the aggregate of
//! several nodes selected, each flow of the dashboard scope goes to its own node; else up
//! to 16 countries go to this console's node. An arrow moves along each connection with
//! the animation's phase, offset per connection so they do not move in step.

use std::borrow::Cow;
use std::fmt::{self, Write};

use sibuna_console_protocol::CountryCount;
use sibuna_console_protocol::dashboard::Scope;

use super::activity::activity;
use super::motion::zig_mod;
use super::panel::Scene;
use super::projection::{CENTER_X, CENTER_Y, RADIUS, line, project};
use super::route::{Route, segment};
use super::tenths::tenths;
use crate::format;
use crate::geometry::{self, Point};
use crate::state::{GlobeView, State};

/// The most connections drawn toward one node (SID 0007: 16 visible arcs).
const MAX_CONNECTIONS: usize = 16;
/// Segments per connection.
const SEGMENTS: u32 = 48;
/// Statistics older than this many seconds draw no connections.
const MAX_AGE_SECONDS: u64 = 5;

/// Returns this console node's configured location, if the statistics carry a valid one.
pub(super) fn destination(state: &State) -> Option<Point> {
    let location = state.stats.as_ref()?.server_location?;
    location.is_valid().then_some(Point { lat: location.lat, lon: location.lon })
}

/// Writes the two letters of a country `code` (two big-endian bytes), escaped.
pub(super) fn write_code(out: &mut impl Write, code: u16) -> fmt::Result {
    let bytes = code.to_be_bytes();
    let text: Cow<'_, str> = String::from_utf8_lossy(&bytes);
    sibuna_html::escape(out, &text)
}

/// One connection to draw.
struct Connection<'a> {
    country: CountryCount,
    end: Point,
    node: u32,
    index: u32,
    unit: &'a str,
}

/// Draws the connections of fresh statistics with GeoIP, toward configured locations.
pub(super) fn render(
    out: &mut impl Write,
    state: &State,
    scene: &Scene,
    bytes: &[u8],
) -> fmt::Result {
    let Some(stats) = state.stats.as_ref() else { return Ok(()) };
    let Some(selected) = activity(state) else { return Ok(()) };
    let age = state.browser_time.saturating_sub(state.received_at);
    if !stats.geoip_available || state.stale || age > MAX_AGE_SECONDS {
        return Ok(());
    }
    if let Some(scope) = state.dashboard_scope.as_ref().filter(|scope| scope.selected == 0) {
        let flows = if state.globe_attacks { &scope.incident_flows } else { &scope.traffic_flows };
        for (index, flow) in (0..).zip(flows) {
            let Some(flow) = flow else { continue };
            let Some(end) = node_location(scope, flow.node) else { continue };
            let country = CountryCount { code: flow.country, samples: flow.samples };
            let activity =
                Connection { country, end, node: flow.node, index, unit: selected.unit };
            connection(out, scene, bytes, &activity)?;
        }
        return Ok(());
    }
    let Some(end) = destination(state) else { return Ok(()) };
    for (index, country) in (0..).zip(selected.countries.iter().take(MAX_CONNECTIONS)) {
        let activity =
            Connection { country: *country, end, node: stats.node, index, unit: selected.unit };
        connection(out, scene, bytes, &activity)?;
    }
    Ok(())
}

/// Returns the configured location of `node` in the scope, if valid.
fn node_location(scope: &Scope, node: u32) -> Option<Point> {
    let source = scope.sources.iter().flatten().find(|source| source.node == node)?;
    let location = source.location.filter(|location| location.is_valid())?;
    Some(Point { lat: location.lat, lon: location.lon })
}

fn connection(
    out: &mut impl Write,
    scene: &Scene,
    bytes: &[u8],
    activity: &Connection<'_>,
) -> fmt::Result {
    let country = activity.country;
    if country.samples == 0 {
        return Ok(());
    }
    let Some(start) = geometry::center(bytes, country.code) else { return Ok(()) };
    let route = Route::new(start, activity.end);
    let view = scene.view;
    out.write_str("<path class=\"sb-connection\" d=\"")?;
    let mut previous = route.screen(view, 0.0);
    for step in 1..=SEGMENTS {
        let next = route.screen(view, f64::from(step) / f64::from(SEGMENTS));
        if let Some([from, to]) = segment(previous, next, view.flat) {
            line(out, (from.x, from.y), (to.x, to.y))?;
        }
        previous = next;
    }
    out.write_str(
        "\" fill=\"none\" stroke=\"#7c5cdb\" stroke-opacity=\".7\" stroke-width=\"1\"><title>",
    )?;
    write_code(out, country.code)?;
    write!(
        out,
        " \u{2192} Sibuna: {} {} / 60 s (node {})</title></path>",
        country.samples, activity.unit, activity.node
    )?;
    // Each connection's arrow is offset along its route, so arrows do not move in step.
    let offset = f64::from(activity.index) * 0.137;
    let phase = zig_mod(scene.flow + offset, 1.0);
    arrow(out, &route, view, phase)
}

/// Draws the node markers: every located source of the aggregate, or this console's
/// node. They are drawn even during an empty window, a GeoIP outage or a disconnection,
/// since a configured location does not depend on telemetry; the dashboard shows the age.
pub(super) fn markers(out: &mut impl Write, state: &State, view: GlobeView) -> fmt::Result {
    if let Some(scope) = state.dashboard_scope.as_ref().filter(|scope| scope.selected == 0) {
        for source in scope.sources.iter().flatten() {
            if let Some(point) = node_location(scope, source.node) {
                node_marker(out, view, point, source.node)?;
            }
        }
        return Ok(());
    }
    let Some(point) = destination(state) else { return Ok(()) };
    let node = state.stats.as_ref().map_or(0, |stats| stats.node);
    node_marker(out, view, point, node)
}

fn node_marker(out: &mut impl Write, view: GlobeView, point: Point, node: u32) -> fmt::Result {
    let projected = project(point, view);
    if !view.flat && projected.z < 0.0 {
        return Ok(());
    }
    let (x, y) = if view.flat {
        (CENTER_X + point.lon, CENTER_Y - point.lat)
    } else {
        (CENTER_X + RADIUS * projected.x, CENTER_Y - RADIUS * projected.y)
    };
    write!(out, "<g id=\"sibuna-location-{node}\"><circle cx=\"")?;
    tenths(out, x)?;
    out.write_str("\" cy=\"")?;
    tenths(out, y)?;
    out.write_str("\" r=\"4\" fill=\"#7c5cdb\" stroke=\"white\"><title>Sibuna server: ")?;
    format::decimal(out, point.lat, 4)?;
    out.write_str(", ")?;
    format::decimal(out, point.lon, 4)?;
    out.write_str(" (configured)</title></circle><text x=\"")?;
    tenths(out, x)?;
    out.write_str("\" y=\"")?;
    tenths(out, y - 8.0)?;
    write!(
        out,
        "\" font-size=\"9\" text-anchor=\"middle\" fill=\"currentColor\">Sibuna {node}</text></g>"
    )
}

/// Draws the arrowhead at `t` along `route`, pointing along the route.
fn arrow(out: &mut impl Write, route: &Route, view: GlobeView, t: f64) -> fmt::Result {
    let a = route.screen(view, t);
    let b = route.screen(view, (t + 0.008).min(1.0));
    if a.z < 0.0 || b.z < 0.0 || segment(a, b, view.flat).is_none() {
        return Ok(());
    }
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let length = (dx * dx + dy * dy).sqrt();
    if length < 0.001 {
        return Ok(());
    }
    let (vx, vy) = (dx / length, dy / length);
    let tip = (a.x + 3.0 * vx, a.y + 3.0 * vy);
    let left = (a.x - 3.0 * vx + 1.8 * vy, a.y - 3.0 * vy - 1.8 * vx);
    let right = (a.x - 3.0 * vx - 1.8 * vy, a.y - 3.0 * vy + 1.8 * vx);
    out.write_str("<path class=\"sb-flow-arrow\" d=\"")?;
    line(out, tip, left)?;
    out.write_str("L")?;
    tenths(out, right.0)?;
    out.write_str(",")?;
    tenths(out, right.1)?;
    out.write_str("Z\" fill=\"#18a8b7\"/>")
}

//! The globe panel and its scene (`globe.zig`).
//!
//! The scene is the SVG inside `#globe-scene`: the ocean (a disc, or a rectangle for the
//! flat map), the graticule and boundaries clipped to the disc, country markers, the
//! connections and the node markers. The panel adds the mode buttons, the controls, the
//! notes that say what is shown and what is not, and the table of countries, which lists
//! every hemisphere so nothing depends on the rotation.

use std::fmt::{self, Write};

use sibuna_html::write_value;

use super::activity::activity;
use super::connections::{self, destination, write_code};
use super::projection::{self, CENTER_X, CENTER_Y, RADIUS, project};
use super::tenths::tenths;
use crate::format;
use crate::geometry;
use crate::render::Html;
use crate::snippets::{self, GlobeDefinitionsValues, GlobeIncidentsValues, GlobeModeValues};
use crate::state::{GlobeView, State};

/// What the scene draws beyond the shared state: the view and the animation.
#[derive(Clone, Copy, Debug)]
pub(super) struct Scene {
    /// The view to draw, turned by the animation.
    pub view: GlobeView,
    /// The globe turns by itself.
    pub rotating: bool,
    /// The arrows' phase.
    pub flow: f64,
}

/// The largest country marker radius, in SVG units.
const MAX_MARKER_RADIUS: f64 = 14.0;

/// Draws the scene: the SVG that `#globe-scene` holds, and the whole of an animation
/// frame.
pub(super) fn scene(state: &State, scene: &Scene, out: &mut Html<'_>) -> fmt::Result {
    let view = scene.view;
    out.write_str(
        "<svg viewBox=\"0 0 400 280\" role=\"img\" aria-label=\"Earth and country activity. \
         See coverage and the country table below.\">",
    )?;
    snippets::render_globe_definitions(out, &GlobeDefinitionsValues)?;
    if view.flat {
        out.write_str(
            "<rect x=\"20\" y=\"45\" width=\"360\" height=\"180\" fill=\"url(#ocean)\" \
             stroke=\"#94b6d5\"/>",
        )?;
    } else {
        out.write_str(
            "<circle cx=\"200\" cy=\"135\" r=\"110\" fill=\"url(#ocean)\" \
             stroke=\"#94b6d5\"/><g clip-path=\"url(#globe-clip)\">",
        )?;
    }
    projection::graticule(out, view)?;
    let geometry = state.geometry.bytes();
    if let Some(bytes) = geometry {
        projection::boundaries(out, bytes, view)?;
        if state.stats.as_ref().is_some_and(|stats| stats.geoip_available) {
            country_markers(out, state, bytes, view)?;
        }
    }
    if !view.flat {
        out.write_str("</g>")?;
    }
    if let Some(bytes) = geometry {
        connections::render(out, state, scene, bytes)?;
    }
    connections::markers(out, state, view)?;
    out.write_str("</svg>")
}

/// Draws the whole panel; see [`super::render`].
pub(super) fn panel(state: &State, scene: &Scene, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<h2>Live earth globe</h2>")?;
    let attacks = state.globe_attacks;
    snippets::render_globe_mode(out, &GlobeModeValues { traffic: &!attacks, attacks: &attacks })?;
    out.write_str("<div id=\"globe-scene\">")?;
    self::scene(state, scene, out)?;
    out.write_str("</div><div class=\"sb-globe-controls\">")?;
    let loaded = state.geometry.is_loaded();
    if loaded && !state.reduced_motion {
        out.write_str("<button class=\"btn btn-sm\" data-action=\"globe-motion\">")?;
        out.write_str(if scene.rotating { "Pause animation" } else { "Start animation" })?;
        out.write_str("</button>")?;
    }
    if loaded {
        out.write_str(
            "<button id=\"rotate-left\" class=\"btn btn-sm\" data-action=\"rotate-left\">\
             Rotate left</button><button id=\"rotate-right\" class=\"btn btn-sm\" \
             data-action=\"rotate-right\">Rotate right</button><button id=\"reset-globe\" \
             class=\"btn btn-sm\" data-action=\"reset-globe\">Reset</button><button \
             id=\"flat-map\" class=\"btn btn-sm\" data-action=\"flat-map\">Globe / flat \
             map</button>",
        )?;
    }
    out.write_str("</div>")?;
    server_location(state, out)?;
    out.write_str(
        "<p class=\"sb-note\"><a href=\"https://www.naturalearthdata.com\">Made with Natural \
         Earth</a>. Boundaries provide geographic context.</p>",
    )?;
    if state.stats.is_some() && !loaded {
        out.write_str(if state.geometry.busy {
            "<p class=\"sb-note\" role=\"status\">Loading world boundaries\u{2026}</p>"
        } else {
            "<p class=\"sb-note\" role=\"status\">World boundaries unavailable. Retrying \
             soon.</p>"
        })?;
    }
    description(state, out)?;
    notes(state, out)?;
    rankings(state, out)
}

/// The GeoIP note and the note on what markers and arrows mean.
fn notes(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let stats = state.stats.as_ref();
    if stats.is_some_and(|stats| !stats.geoip_available) {
        out.write_str(
            "<p class=\"sb-note\">GeoIP unavailable. Activity is counted as Unknown; no \
             locations are inferred.</p><button class=\"btn btn-sm\" data-action=\"geoip\">\
             Set up GeoIP</button>",
        )?;
    }
    out.write_str(
        "<p class=\"sb-note\">Markers show representative country positions, not client \
         coordinates. Arrows illustrate recorded inbound activity over this window toward \
         the receiving nodes' configured locations. They are not individual live \
         connections.",
    )?;
    if stats.is_some_and(|stats| stats.geoip_attribution) {
        out.write_str(" <a href=\"https://db-ip.com\">IP Geolocation by DB-IP</a>.")?;
    }
    out.write_str("</p>")
}

/// Where the arrows go: the aggregate's configured node locations, this node's location
/// with a button to centre it, or how to configure one.
fn server_location(state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.stats.is_none() {
        return Ok(());
    }
    if state.dashboard_scope.as_ref().is_some_and(|scope| scope.selected == 0 && scope.count > 1) {
        return out.write_str(
            "<p class=\"sb-note\">Destinations use configured node locations. See node \
             coverage for missing locations.</p>",
        );
    }
    let Some(location) = destination(state) else {
        return out.write_str(
            "<p class=\"sb-note\">Server location not configured. Set <code>--console-location \
             latitude,longitude</code> on this node to show its destination marker and inbound \
             arrows.</p>",
        );
    };
    out.write_str("<p class=\"sb-note\">Sibuna server: ")?;
    format::decimal(out, location.lat, 4)?;
    out.write_str(", ")?;
    format::decimal(out, location.lon, 4)?;
    out.write_str(
        " (configured). <button class=\"btn btn-sm\" data-action=\"center-server\">Center \
         Sibuna</button></p>",
    )
}

/// What the selected mode counts, and the incident coverage details in Attacks mode.
fn description(state: &State, out: &mut Html<'_>) -> fmt::Result {
    if !state.globe_attacks {
        return out.write_str(
            "<p class=\"sb-note\">Sampled traffic over 60 seconds. Sample probability: \
             1/64.</p>",
        );
    }
    let Some(stats) = state.stats.as_ref() else { return Ok(()) };
    let Some(incidents) = stats.incident_geo.as_ref().filter(|incidents| incidents.version == 1)
    else {
        return out
            .write_str("<p role=\"status\">Incident geography unavailable from this server.</p>");
    };
    out.write_str(
        "<p class=\"sb-note\">Recorded findings over 60 seconds, including audit findings. \
         Coverage is incomplete: not every blocked request creates an incident, and one \
         request can create several findings. These are not unique attacks. Findings are not \
         sampled.</p><button class=\"btn btn-ghost btn-sm\" data-action=\"globe-coverage\" \
         aria-expanded=\"",
    )?;
    out.write_str(if state.globe_coverage { "true" } else { "false" })?;
    out.write_str(
        "\" aria-controls=\"incident-geo-coverage\">Incident geography coverage</button>",
    )?;
    if !state.globe_coverage {
        return out.write_str("<div id=\"incident-geo-coverage\" hidden></div>");
    }
    let mut started = String::new();
    format::timestamp(&mut started, incidents.started_at)?;
    snippets::render_globe_incidents(
        out,
        &GlobeIncidentsValues {
            started: &started.as_str(),
            dropped: &incidents.dropped,
            expired: &incidents.expired,
            future: &incidents.future,
            storage_loss: &stats.incidents_dropped,
        },
    )
}

/// Draws a marker at the representative position of each country with activity, with an
/// area that grows with the count (radius `2 sqrt(count)`, at most 14).
fn country_markers(
    out: &mut impl Write,
    state: &State,
    bytes: &[u8],
    view: GlobeView,
) -> fmt::Result {
    let Some(selected) = activity(state) else { return Ok(()) };
    for country in selected.countries.iter().filter(|country| country.samples != 0) {
        let Some(location) = geometry::center(bytes, country.code) else { continue };
        let projected = project(location, view);
        if !view.flat && projected.z < 0.0 {
            continue;
        }
        let (x, y) = if view.flat {
            (CENTER_X + location.lon, CENTER_Y - location.lat)
        } else {
            (CENTER_X + RADIUS * projected.x, CENTER_Y - RADIUS * projected.y)
        };
        // Counts beyond 2^53 lose precision here, far beyond the cap of 14.
        let radius = (2.0 * (country.samples as f64).sqrt()).min(MAX_MARKER_RADIUS);
        out.write_str("<circle cx=\"")?;
        tenths(out, x)?;
        out.write_str("\" cy=\"")?;
        tenths(out, y)?;
        out.write_str("\" r=\"")?;
        tenths(out, radius)?;
        out.write_str("\" fill=\"#d94736\" fill-opacity=\".7\" stroke=\"white\"><title>")?;
        write_code(out, country.code)?;
        write!(out, ": {} {}</title></circle>", country.samples, selected.unit)?;
    }
    Ok(())
}

/// The table of countries with activity, from every hemisphere, with buttons that centre
/// a country and (outside a wall display) open its events.
fn rankings(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let Some(selected) = activity(state) else { return Ok(()) };
    out.write_str(
        "<table class=\"table\"><caption>Countries across all hemispheres</caption><thead><tr>\
         <th>Country</th><th>",
    )?;
    out.escaped(selected.unit)?;
    out.write_str(" / 60 s</th></tr></thead><tbody>")?;
    let mut any = false;
    for country in selected.countries.iter().filter(|country| country.samples != 0) {
        any = true;
        let code = country.code;
        write!(
            out,
            "<tr><td><button id=\"country-{code}\" class=\"btn btn-ghost btn-sm\" \
             data-action=\"country-{code}\" aria-label=\"Center country "
        )?;
        write_code(out, code)?;
        out.write_str("\">")?;
        write_code(out, code)?;
        write!(out, "</button></td><td>{}", country.samples)?;
        if !state.kiosk {
            out.write_str(
                " <button class=\"btn btn-ghost btn-sm\" data-action=\"events-country-",
            )?;
            write_code(out, code)?;
            out.write_str("\" aria-label=\"View events from ")?;
            write_code(out, code)?;
            out.write_str("\">View events</button>")?;
        }
        out.write_str("</td></tr>")?;
    }
    if !any {
        out.write_str(
            "<tr><td colspan=\"2\">No known-country activity in this window.</td></tr>",
        )?;
    }
    out.write_str("<tr><th>Other countries</th><td>")?;
    write_value(out, &selected.other)?;
    out.write_str("</td></tr><tr><th>Unknown</th><td>")?;
    write_value(out, &selected.unknown)?;
    out.write_str("</td></tr></tbody></table>")
}

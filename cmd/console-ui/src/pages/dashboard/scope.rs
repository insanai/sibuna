//! The live view's node selector and its coverage table (`dashboard_scope.zig`, render and
//! `select`; the pure labels are in [`crate::scope`]).
//!
//! Live scope is independent of retained HTTP history, whose source is labelled
//! explicitly. The security overview and the wall display draw the same selector.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::dashboard::Source;
use sibuna_html::write_value;

use crate::format;
use crate::render::Html;
use crate::snippets;
use crate::state::State;

/// Draws the node selector and the scope's coverage when the view combines several
/// nodes; nothing otherwise.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let Some(scope) = &state.dashboard_scope else { return Ok(()) };
    if scope.count <= 1 {
        return Ok(());
    }
    snippets::render_dashboard_scope(out, &snippets::DashboardScopeValues)?;
    option(out, 0, state.dashboard_node.is_none())?;
    for source in scope.sources.iter().flatten() {
        option(out, source.node, state.dashboard_node == Some(source.node))?;
    }
    out.write_str(
        "</select></div><button class=\"btn\">Apply view</button></form><p class=\"sb-note\">",
    )?;
    write_value(out, &scope.contributing)?;
    out.write_str(" / ")?;
    write_value(out, &scope.count)?;
    out.write_str(
        " nodes contribute. Stale, unavailable or clock-skewed nodes remain outside totals. \
         Totals cover each contributing node's current boot. Country windows cover 60 \
         seconds ending at each source's observed time.</p>",
    )?;
    if !scope.available {
        out.write_str("<p role=\"status\">")?;
        out.write_str(if scope.overflow {
            "Totals exceed the supported counter range."
        } else {
            "No observation is available for this view."
        })?;
        out.write_str("</p>")?;
    }
    if scope.selected == 0 {
        out.write_str(
            "<p class=\"sb-note\">Country counts are lower bounds; omitted source rankings add \
             at most ",
        )?;
        write_value(out, &scope.traffic_uncertainty)?;
        out.write_str(" samples or ")?;
        write_value(out, &scope.incident_uncertainty)?;
        out.write_str(" findings to any country. Incident geography: ")?;
        write_value(out, &scope.incident_contributing)?;
        out.write_str(" contributing nodes.</p>")?;
    }
    out.write_str(
        "<details><summary>Node coverage and locations</summary><div \
         class=\"overflow-x-auto\"><table class=\"table\"><thead><tr><th>Node</th>\
         <th>Status</th><th>Receipt age</th><th>Clock skew</th><th>GeoIP / findings</th>\
         <th>Window ending (UTC)</th><th>Location</th></tr></thead><tbody>",
    )?;
    for source in scope.sources.iter().flatten() {
        row(state, source, out)?;
    }
    out.write_str("</tbody></table></div></details>")
}

/// Draws one option of the selector; node 0 stands for every configured node.
fn option(out: &mut Html<'_>, node: u32, selected: bool) -> fmt::Result {
    out.write_str("<option value=\"")?;
    write_value(out, &node)?;
    out.write_str(if selected { "\" selected>" } else { "\">" })?;
    if node == 0 {
        out.write_str("All configured nodes")?;
    } else {
        out.write_str("Node ")?;
        write_value(out, &node)?;
    }
    out.write_str("</option>")
}

/// Draws one source's coverage row.
fn row(state: &State, source: &Source, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<tr><td>")?;
    write_value(out, &source.node)?;
    out.write_str("</td><td>")?;
    let skewed = source.clock_skew_seconds.is_some_and(|skew| skew > 2);
    out.write_str(if skewed { "clock skew" } else { source.status.name() })?;
    out.write_str("</td><td>")?;
    match source.age_seconds {
        Some(age) => {
            let since = state.browser_time.saturating_sub(state.received_at);
            write_value(out, &age.saturating_add(since))?;
            out.write_str(" s")?;
        }
        None => out.write_str("unobserved")?,
    }
    out.write_str("</td><td>")?;
    match source.clock_skew_seconds {
        Some(skew) => {
            write_value(out, &skew)?;
            out.write_str(" s")?;
        }
        None => out.write_str("unobserved")?,
    }
    out.write_str("</td><td>")?;
    out.write_str(if source.geoip_available { "available" } else { "unavailable" })?;
    out.write_str(" / ")?;
    out.write_str(if source.incident_geo_available { "recorded" } else { "unavailable" })?;
    out.write_str("</td><td>")?;
    match source.window_end {
        Some(end) => format::timestamp(out, end)?,
        None => out.write_str("unobserved")?,
    }
    out.write_str("</td><td>")?;
    match source.location {
        Some(location) => {
            format::decimal(out, location.lat, 4)?;
            out.write_str(", ")?;
            format::decimal(out, location.lon, 4)?;
        }
        None => out.write_str("not configured")?,
    }
    out.write_str("</td></tr>")
}

/// Why a node selection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectError {
    /// The value is not a node number.
    Invalid,
    /// No scope is known yet.
    Unavailable,
    /// The scope has no such node.
    UnknownNode,
}

/// Returns the node `text` selects (`None` for every node) if the scope lists it.
///
/// # Errors
///
/// [`SelectError`] for text that is not a node number, no scope, or an unknown node.
pub fn parse_selection(state: &State, text: &str) -> Result<Option<u32>, SelectError> {
    let node = super::parse_decimal(text)
        .and_then(|node| u32::try_from(node).ok())
        .ok_or(SelectError::Invalid)?;
    let scope = state.dashboard_scope.as_ref().ok_or(SelectError::Unavailable)?;
    if node == 0 {
        return Ok(None);
    }
    if !scope.sources.iter().flatten().any(|source| source.node == node) {
        return Err(SelectError::UnknownNode);
    }
    Ok(Some(node))
}

/// Applies a selection to the shared state: the live counters and series restart for
/// the new view. The geometry stays loaded.
pub fn apply(state: &mut State, node: Option<u32>) {
    state.dashboard_node = node;
    state.stats = None;
    state.points.clear();
    state.stale = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::dashboard::Scope;

    fn two_nodes() -> State {
        let mut scope = Scope { count: 2, ..Scope::default() };
        scope.sources[0] = Some(Source::new(1));
        scope.sources[1] = Some(Source::new(2));
        State { dashboard_scope: Some(scope), ..State::new() }
    }

    #[test]
    fn selection_refuses_unknown_nodes_and_text_and_reads_zero_as_every_node() {
        let state = two_nodes();
        assert_eq!(parse_selection(&state, "3"), Err(SelectError::UnknownNode));
        assert_eq!(parse_selection(&state, "two"), Err(SelectError::Invalid));
        assert_eq!(parse_selection(&state, "+2"), Ok(Some(2)));
        assert_eq!(parse_selection(&state, "0"), Ok(None));
        assert_eq!(parse_selection(&State::new(), "1"), Err(SelectError::Unavailable));
    }

    #[test]
    fn a_single_node_scope_draws_no_selector() {
        let mut state = two_nodes();
        if let Some(scope) = &mut state.dashboard_scope {
            scope.count = 1;
        }
        let mut text = String::new();
        render(&state, &mut Html::new(&mut text, 4096)).unwrap();
        assert!(text.is_empty());
        state.dashboard_scope = None;
        render(&state, &mut Html::new(&mut text, 4096)).unwrap();
        assert!(text.is_empty());
    }

    #[test]
    fn coverage_rows_name_skew_age_and_location() {
        let mut state = two_nodes();
        state.browser_time = 100;
        state.received_at = 98;
        if let Some(scope) = &mut state.dashboard_scope {
            scope.available = false;
            scope.overflow = true;
            if let Some(source) = &mut scope.sources[1] {
                source.clock_skew_seconds = Some(3);
                source.age_seconds = Some(4);
                source.location =
                    Some(sibuna_console_protocol::Location { lat: 1.25, lon: -75.5 });
            }
        }
        state.dashboard_node = Some(2);
        let mut text = String::new();
        render(&state, &mut Html::new(&mut text, 16 * 1024)).unwrap();
        assert!(text.contains("<option value=\"2\" selected>Node 2</option>"));
        assert!(text.contains("Totals exceed the supported counter range."));
        assert!(text.contains("<tr><td>2</td><td>clock skew</td><td>6 s</td><td>3 s</td>"));
        assert!(text.contains("<td>1.2500, -75.5000</td>"));
        assert!(text.contains("<td>1</td><td>unobserved</td><td>unobserved</td>"));
    }
}

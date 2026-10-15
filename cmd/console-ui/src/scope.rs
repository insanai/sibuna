//! What the live statistics show: the selected node or the aggregate, and its status.
//! The traffic dashboard, the security overview and the wall display all label their
//! views with these functions; the node selector itself belongs to the dashboard.

use std::fmt::{self, Write};

use sibuna_html::write_value;

use crate::state::State;

/// Returns the live status badge: `Paused`, `Stale`, `Disconnected`, `Live`,
/// `Unavailable` or `Connecting`.
pub fn status(state: &State) -> &'static str {
    if state.paused {
        return "Paused";
    }
    if state.stale {
        if state.dashboard_scope.as_ref().is_some_and(|scope| scope.stale) {
            return "Stale";
        }
        return "Disconnected";
    }
    if state.stats.is_some() {
        return "Live";
    }
    if state.dashboard_scope.as_ref().is_some_and(|scope| !scope.available) {
        return "Unavailable";
    }
    "Connecting"
}

/// Writes the view's name: `Node 2`, `All configured nodes` or
/// `Waiting for observations`.
///
/// # Errors
///
/// The sink's error.
pub fn view_name(state: &State, out: &mut impl Write) -> fmt::Result {
    if let Some(node) = state.dashboard_node {
        out.write_str("Node ")?;
        return write_value(out, &node);
    }
    if state.dashboard_scope.as_ref().is_some_and(|scope| scope.count > 1) {
        return out.write_str("All configured nodes");
    }
    if let Some(stats) = &state.stats {
        out.write_str("Node ")?;
        return write_value(out, &stats.node);
    }
    out.write_str("Waiting for observations")
}

/// Returns the node whose retained history a view investigates: the selected node, or the
/// only node of a one-node scope; `None` for every node.
pub fn selected_node(state: &State) -> Option<u32> {
    if let Some(node) = state.dashboard_node {
        return Some(node);
    }
    let scope = state.dashboard_scope.as_ref()?;
    if scope.count == 1 {
        return scope.sources.first().copied().flatten().map(|source| source.node);
    }
    None
}

/// Returns true when the aggregate of several nodes is shown, so retained per-node
/// history needs an explicit node.
pub fn needs_retained_node(state: &State) -> bool {
    state.dashboard_scope.as_ref().is_some_and(|scope| scope.count > 1)
        && state.dashboard_node.is_none()
}

/// Returns true when replicated minute history is available.
pub fn history_available(state: &State) -> bool {
    match &state.dashboard_scope {
        Some(scope) => scope.history_available,
        None => state.stats.as_ref().is_some_and(|stats| stats.minute_history.available),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::StatsSnapshot;
    use sibuna_console_protocol::dashboard::{Scope, Source};

    fn name(state: &State) -> String {
        let mut text = String::new();
        view_name(state, &mut text).unwrap();
        text
    }

    #[test]
    fn investigation_scope_preserves_implicit_local_and_explicit_node_selections() {
        let mut scope = Scope { count: 1, ..Scope::default() };
        scope.sources[0] = Some(Source::new(7));
        let mut state = State { dashboard_scope: Some(scope), ..State::new() };
        assert_eq!(selected_node(&state), Some(7));
        state.dashboard_node = Some(8);
        assert_eq!(selected_node(&state), Some(8));
        state.dashboard_node = None;
        if let Some(scope) = &mut state.dashboard_scope {
            scope.count = 2;
        }
        assert_eq!(selected_node(&state), None);
        assert!(needs_retained_node(&state));
    }

    #[test]
    fn labels_distinguish_missing_observations_from_connecting_and_name_aggregates() {
        let mut state = State::new();
        assert_eq!(status(&state), "Connecting");
        assert_eq!(name(&state), "Waiting for observations");
        state.dashboard_scope = Some(Scope { count: 3, available: false, ..Scope::default() });
        assert_eq!(status(&state), "Unavailable");
        assert_eq!(name(&state), "All configured nodes");
        state.dashboard_node = Some(2);
        state.stats = Some(StatsSnapshot::default());
        state.stale = true;
        assert_eq!(status(&state), "Disconnected");
        if let Some(scope) = &mut state.dashboard_scope {
            scope.stale = true;
        }
        assert_eq!(status(&state), "Stale");
        assert_eq!(name(&state), "Node 2");
        state.paused = true;
        assert_eq!(status(&state), "Paused");
        assert!(!history_available(&state));
    }
}

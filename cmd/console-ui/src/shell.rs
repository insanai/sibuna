//! The navigation shell around every signed-in page: skip link, mobile header, the
//! navigation landmark with the active section, the role badge and the preferences.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Action;
use sibuna_html::write_value;

use crate::render::Html;
use crate::snippets;
use crate::state::{Phase, State};

/// The navigation actions, which are also the route names, in menu order.
pub const ACTIONS: [&str; 12] = [
    "dashboard",
    "events",
    "challenges",
    "policies",
    "geoip",
    "users",
    "tokens",
    "audit",
    "nodes",
    "settings",
    "account",
    "security-overview",
];

/// The menu label of each action in [`ACTIONS`].
const LABELS: [&str; 12] = [
    "Statistics",
    "Events",
    "Challenges",
    "Policies",
    "GeoIP",
    "Users",
    "Tokens",
    "Audit",
    "Nodes",
    "Settings",
    "Account",
    "Security",
];

/// Returns true when `name` is a navigation action.
pub fn is_destination(name: &str) -> bool {
    ACTIONS.contains(&name)
}

/// Returns the menu label of the navigation action `name`, or `name` itself.
pub fn label(name: &str) -> &str {
    ACTIONS.iter().position(|action| *action == name).map_or(name, |index| LABELS[index])
}

/// Returns the navigation section `phase` belongs to.
pub fn section(phase: Phase) -> &'static str {
    match phase {
        Phase::Events | Phase::Similarity => "events",
        Phase::Challenges => "challenges",
        Phase::Policies => "policies",
        Phase::Geoip => "geoip",
        Phase::Users => "users",
        Phase::Tokens => "tokens",
        Phase::Audit => "audit",
        Phase::Nodes => "nodes",
        Phase::Settings => "settings",
        Phase::Password | Phase::Security => "account",
        Phase::Loading
        | Phase::Setup
        | Phase::Login
        | Phase::Dashboard
        | Phase::SecurityOverview => "dashboard",
    }
}

/// Writes the label naming the node that serves this console, which does not follow the
/// node selected for telemetry.
fn console_label(state: &State, out: &mut String) -> fmt::Result {
    match state.console_node {
        Some(node) => {
            out.write_str("Console node ")?;
            write_value(out, &node)
        }
        None => out.write_str("Node not reported"),
    }
}

/// Opens the shell: everything before the page's `<main>`.
///
/// # Errors
///
/// The sink's error.
pub fn begin(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let mut label = String::new();
    console_label(state, &mut label)?;
    snippets::render_shell_header(
        out,
        &snippets::ShellHeaderValues { open: &state.navigation_open, console_label: &label },
    )?;
    let active = section(state.phase);
    for (action, label) in ACTIONS.iter().zip(LABELS) {
        let hidden = *action == "security-overview"
            || (*action == "tokens" && !state.allows(Action::ManageUsers))
            || (*action == "settings" && !state.allows(Action::ManageSettings));
        if hidden {
            continue;
        }
        let current = *action == active;
        snippets::render_shell_item(
            out,
            &snippets::ShellItemValues {
                action,
                label: &label,
                current: &if current { "page" } else { "false" },
                class: &if current { "menu-active" } else { "" },
            },
        )?;
    }
    snippets::render_shell_content(
        out,
        &snippets::ShellContentValues {
            role: &state.role.as_str(),
            theme: &state.appearance.theme.name(),
            density: &state.appearance.density.name(),
        },
    )
}

/// Closes the shell opened by [`begin`].
///
/// # Errors
///
/// The sink's error.
pub fn end(out: &mut Html<'_>) -> fmt::Result {
    out.write_str("</div></div>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_identity_does_not_follow_the_selected_traffic_node() {
        let mut state = State { console_node: Some(7), dashboard_node: Some(2), ..State::new() };
        let mut label = String::new();
        console_label(&state, &mut label).unwrap();
        assert_eq!(label, "Console node 7");
        state.reset();
        label.clear();
        console_label(&state, &mut label).unwrap();
        assert_eq!(label, "Node not reported");
    }
}

//! Bookmarkable page routes.
//!
//! The URL fragment names a navigation section. Authentication gates precede route
//! dispatch, and history stores only public page names, never query bodies, record
//! identifiers or credentials.

use sibuna_console_protocol::Action;

use crate::commands::{Commands, Field};
use crate::error::UiError;
use crate::shell;
use crate::state::{Phase, State};

/// The route the browser asked for and the route the history shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    /// A requested route waiting for authentication to complete.
    pub pending: Option<&'static str>,
    /// The section the browser history shows.
    pub current: Option<&'static str>,
    /// The request came from the browser (load or back button): replace, do not push.
    pub restoring: bool,
}

impl Route {
    /// Records the browser's route `fragment`, interned against the navigation names so
    /// no event bytes survive the event; an unknown route means the landing page.
    pub fn request(&mut self, fragment: &str) {
        self.pending = Some(
            shell::ACTIONS.iter().copied().find(|name| *name == fragment).unwrap_or("dashboard"),
        );
        self.restoring = true;
    }
}

/// Returns the navigation action that opens the pending route, once the session has full
/// access. A wall display ignores routes; a role that may not open a page lands on the
/// dashboard; the current page is not reopened.
pub fn take(state: &mut State) -> Option<&'static str> {
    if !state.is_full_access() {
        return None;
    }
    let name = state.route.pending.take()?;
    if state.kiosk {
        return None;
    }
    if (name == "tokens" && !state.allows(Action::ManageUsers))
        || (name == "settings" && !state.allows(Action::ManageSettings))
    {
        return Some("dashboard");
    }
    if state.route.current == Some(name) {
        return None;
    }
    Some(name)
}

/// Records the shown page in the browser history: a new entry for a page change, a
/// replacement for a restored route or the first page.
///
/// # Errors
///
/// [`UiError::Write`] if the command cannot be written.
pub fn sync(state: &mut State, commands: &mut Commands) -> Result<(), UiError> {
    if !state.is_full_access() || state.kiosk {
        return Ok(());
    }
    let name = if state.phase == Phase::SecurityOverview {
        "security-overview"
    } else {
        shell::section(state.phase)
    };
    let route = &mut state.route;
    if route.current != Some(name) || route.restoring {
        commands.emit_fields(&[
            ("op", Field::Text("history")),
            ("value", Field::Text(name)),
            ("replace", Field::Bool(route.restoring || route.current.is_none())),
        ])?;
    }
    route.current = Some(name);
    route.restoring = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_interned_and_deferred_through_authentication_with_role_and_kiosk_limits() {
        let mut state = State::new();
        let untrusted = String::from("nodes");
        state.route.request(&untrusted);
        drop(untrusted);
        assert_eq!(take(&mut state), None);
        state.csrf.set("test").unwrap();
        state.must_change = true;
        assert_eq!(take(&mut state), None);
        state.must_change = false;
        state.totp_required = true;
        assert_eq!(take(&mut state), None);
        state.totp_required = false;
        assert_eq!(take(&mut state), Some("nodes"));
        state.role.set("viewer").unwrap();
        state.route.request("settings");
        assert_eq!(take(&mut state), Some("dashboard"));
        state.route.request("https://other.invalid/#nodes");
        assert_eq!(take(&mut state), Some("dashboard"));
        state.kiosk = true;
        state.route.request("events");
        assert_eq!(take(&mut state), None);
    }

    #[test]
    fn history_replaces_restored_routes_and_pushes_only_actual_page_changes() {
        let mut state = State { phase: Phase::Dashboard, ..State::new() };
        state.csrf.set("test").unwrap();
        let mut commands = Commands::default();
        commands.begin();
        sync(&mut state, &mut commands).unwrap();
        assert!(commands.as_str().contains("\"replace\":true"));
        commands.begin();
        sync(&mut state, &mut commands).unwrap();
        assert_eq!(commands.count(), 0);
        state.phase = Phase::Nodes;
        sync(&mut state, &mut commands).unwrap();
        assert!(commands.as_str().contains("\"replace\":false"));
        commands.begin();
        state.route.request("dashboard");
        assert_eq!(take(&mut state), Some("dashboard"));
        state.phase = Phase::Dashboard;
        sync(&mut state, &mut commands).unwrap();
        assert!(commands.as_str().contains("\"replace\":true"));
    }
}

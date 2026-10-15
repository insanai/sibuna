//! The retained-values controls below the request timeline (`history_controls.zig`):
//! opening the values, switching between seconds and minute history, the minute window
//! and paging. Paging pins the query scope so live snapshots cannot move an older page's
//! boundary.

use sibuna_json::Value;

use super::{Dashboard, minutes, parse_decimal};
use crate::error::UiError;
use crate::json;
use crate::state::{Phase, State};

/// What an action did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not a history action.
    None,
    /// Handled; nothing to request.
    Changed,
    /// Handled; request the shown page now.
    Query,
}

/// Handles a history action on the dashboard.
///
/// # Errors
///
/// [`UiError::InvalidRequest`] for a minute window that is not offered; nothing changes.
pub(super) fn action(
    dashboard: &mut Dashboard,
    state: &State,
    name: &str,
    fields: &Value<'_>,
) -> Result<Outcome, UiError> {
    if !state.is_full_access() || state.phase != Phase::Dashboard {
        return Ok(Outcome::None);
    }
    if name == "timeline-values" {
        dashboard.timeline_open = !dashboard.timeline_open;
        return Ok(if dashboard.timeline_open { Outcome::Query } else { Outcome::Changed });
    }
    if !dashboard.timeline_open {
        return Ok(Outcome::None);
    }
    if name == "timeline-seconds" || name == "timeline-minutes" {
        dashboard.history_minutes = name == "timeline-minutes";
        return Ok(Outcome::Query);
    }
    if dashboard.history_minutes {
        return minute_action(&mut dashboard.minutes, state, name, fields);
    }
    let model = &mut dashboard.timeline;
    if name == "timeline-latest" || name == "timeline-older" {
        if model.busy || state.paused {
            return Ok(Outcome::Changed);
        }
        let older = name == "timeline-older";
        if older && (model.next == 0 || model.conflict) {
            return Ok(Outcome::Changed);
        }
        model.before = if older { model.next } else { 0 };
        return Ok(Outcome::Query);
    }
    Ok(Outcome::None)
}

/// Handles the minute-history window and paging actions.
fn minute_action(
    model: &mut minutes::Model,
    state: &State,
    name: &str,
    fields: &Value<'_>,
) -> Result<Outcome, UiError> {
    if name == "minute-window" {
        if model.busy || state.paused {
            return Ok(Outcome::Changed);
        }
        let hours = parse_decimal(json::string(fields, "hours"))
            .and_then(|hours| u16::try_from(hours).ok())
            .filter(|hours| minutes::is_window(*hours))
            .ok_or(UiError::InvalidRequest)?;
        model.hours = hours;
        model.all_nodes = json::string(fields, "all_nodes") == "true";
        model.before = None;
        model.next = None;
        model.rows.clear();
        model.loaded = false;
        return Ok(Outcome::Query);
    }
    if name == "minute-latest" || name == "minute-older" {
        if model.busy || state.paused {
            return Ok(Outcome::Changed);
        }
        let older = name == "minute-older";
        if older && model.next.is_none() {
            return Ok(Outcome::Changed);
        }
        model.before = if older { model.next } else { None };
        return Ok(Outcome::Query);
    }
    Ok(Outcome::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::minutes::Cursor;

    fn act(
        dashboard: &mut Dashboard,
        state: &State,
        name: &str,
        fields: &str,
    ) -> Result<Outcome, UiError> {
        let value = sibuna_json::parse(fields.as_bytes()).unwrap();
        action(dashboard, state, name, &value)
    }

    #[test]
    fn history_controls_pin_pages_and_refuse_invalid_window_changes_without_partial_edits() {
        let mut dashboard = Dashboard::default();
        let mut state = State::new();
        assert_eq!(act(&mut dashboard, &state, "timeline-values", "null"), Ok(Outcome::None));
        state.csrf.set("test").unwrap();
        state.phase = Phase::Dashboard;
        assert_eq!(act(&mut dashboard, &state, "timeline-values", "null"), Ok(Outcome::Query));
        assert_eq!(act(&mut dashboard, &state, "timeline-minutes", "null"), Ok(Outcome::Query));
        let window = r#"{"hours":"2160","all_nodes":"true"}"#;
        assert_eq!(act(&mut dashboard, &state, "minute-window", window), Ok(Outcome::Query));
        assert!(dashboard.minutes.all_nodes && dashboard.minutes.hours == 2160);
        let cursor = Cursor { minute: 100, node: 3, boot: [2; 16], epoch: 1 };
        dashboard.minutes.next = Some(cursor);
        assert_eq!(act(&mut dashboard, &state, "minute-older", "null"), Ok(Outcome::Query));
        assert_eq!(dashboard.minutes.before, Some(cursor));
        dashboard.minutes.busy = true;
        assert_eq!(act(&mut dashboard, &state, "minute-latest", "null"), Ok(Outcome::Changed));
        assert_eq!(dashboard.minutes.before, Some(cursor));
        dashboard.minutes.busy = false;
        let invalid = r#"{"hours":"2161","all_nodes":"true"}"#;
        assert_eq!(
            act(&mut dashboard, &state, "minute-window", invalid),
            Err(UiError::InvalidRequest)
        );
        assert_eq!(dashboard.minutes.before, Some(cursor));
        assert_eq!(dashboard.minutes.hours, 2160);
        assert_eq!(act(&mut dashboard, &state, "timeline-seconds", "null"), Ok(Outcome::Query));
        assert!(!dashboard.history_minutes);
        assert_eq!(dashboard.minutes.before, Some(cursor));
    }
}

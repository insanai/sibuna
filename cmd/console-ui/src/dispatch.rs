//! The core's share of event handling: authentication, navigation basics, preferences,
//! timers, visibility and the live stream. Everything else is offered to the page
//! modules, in registration order, before the core's fallbacks run.

use sibuna_console_protocol::Text;
use sibuna_json::Value;

use crate::app::EventKind;
use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::live;
use crate::page::{Context, Reply};
use crate::secret::Secret;
use crate::shell;
use crate::state::Phase;
use crate::stats;

/// Dispatches one parsed event of `kind`.
///
/// # Errors
///
/// The failing handler's error; the caller shows the generic message.
pub(crate) fn event(
    cx: &mut Context<'_>,
    kind: Option<EventKind>,
    value: &Value<'_>,
) -> Result<(), UiError> {
    cx.state.browser_time = json::unsigned_or_zero(value, "browser_time");
    let Some(kind) = kind else { return Ok(()) };
    match kind {
        EventKind::Action => {
            let fields = json::field(value, "fields").unwrap_or(&Value::Null);
            action(cx, json::string(value, "action"), fields)
        }
        EventKind::Route => {
            cx.state.route.request(json::string(value, "route"));
            Ok(())
        }
        EventKind::Appearance | EventKind::SystemTheme => {
            let load = kind == EventKind::Appearance;
            cx.state.appearance.environment(value, load, cx.commands)
        }
        EventKind::Response => response(cx, value),
        EventKind::Timer => timer(cx, json::string(value, "id")),
        EventKind::Stream => stream(cx, value),
        EventKind::Motion => {
            if let Some(reduced) = json::boolean(value, "reduced_motion") {
                cx.state.reduced_motion = reduced;
            }
            Ok(())
        }
        EventKind::Visibility => visibility(cx, value),
    }
}

/// Handles the operator action `name` with its form `fields`.
///
/// # Errors
///
/// The failing handler's error.
pub(crate) fn action(cx: &mut Context<'_>, name: &str, fields: &Value<'_>) -> Result<(), UiError> {
    if name == "navigation-toggle" && cx.state.is_full_access() {
        cx.state.navigation_open = !cx.state.navigation_open;
        return Ok(());
    }
    if cx.state.navigation_open && shell::is_destination(name) {
        cx.state.navigation_open = false;
        cx.commands.focus_top("main h1")?;
    }
    if cx.action(name, fields)? || cx.state.appearance.action(name, cx.commands)? {
        return Ok(());
    }
    match name {
        "pause" => {
            cx.state.paused = !cx.state.paused;
            if cx.state.paused {
                cx.state.stats_busy = false;
            }
            return Ok(());
        }
        "dashboard" if cx.state.is_full_access() => {
            cx.state.phase = Phase::Dashboard;
            cx.state.clear_message();
            return Ok(());
        }
        "account" => {
            cx.state.phase = Phase::Password;
            cx.state.stats_busy = false;
            return Ok(());
        }
        _ => {}
    }
    if cx.state.busy {
        return Ok(());
    }
    cx.state.clear_message();
    cx.state.busy = true;
    authentication_action(cx, name, fields)
}

/// Sends the sign-in, wall-display, password and sign-out forms.
fn authentication_action(
    cx: &mut Context<'_>,
    name: &str,
    fields: &Value<'_>,
) -> Result<(), UiError> {
    match name {
        "login" => {
            cx.state.username = Text::new(json::string(fields, "username"))?;
            cx.post("login", "/console/api/login", |json| json.value(fields))
        }
        "kiosk-exchange" => {
            let code = json::string(fields, "code");
            cx.post(name, "/console/api/kiosk/exchange", |json| {
                write_fields(json, &[("code", Field::Text(code))])
            })
        }
        "change-password" => {
            cx.post("password", "/console/api/password", |json| json.value(fields))
        }
        "logout" => {
            cx.live.sign_out(cx.commands)?;
            cx.post(name, "/console/api/logout", |json| json.null())
        }
        _ => {
            cx.state.busy = false;
            Ok(())
        }
    }
}

/// Handles a server reply: the modules first, then the core's own requests and the
/// generic failure messages.
fn response(cx: &mut Context<'_>, value: &Value<'_>) -> Result<(), UiError> {
    let id = json::string(value, "id");
    let status = json::field(value, "status").and_then(json::integer);
    let body = json::field(value, "body");
    let reply = Reply { id, status, body, envelope: value };
    if cx.each(|page, cx| page.response(cx, &reply))? {
        return Ok(());
    }
    let (Some(status), Some(body)) = (status, body) else { return Ok(()) };
    if id == "stats" {
        return stats::reply(cx, status, body);
    }
    cx.state.busy = false;
    if id == "session" && status == 401 {
        return cx.get("setup", "/console/api/setup");
    }
    if status != 200 {
        cx.state.stale = status == 0;
        if cx.state.phase == Phase::Loading {
            cx.state.phase = Phase::Login;
        }
        cx.state.set_message(match status {
            429 => "Too many attempts. Please wait a minute.",
            401 => "Sign-in failed. Check your credentials.",
            _ => "Could not complete this action. Check your connection and try again.",
        });
        return Ok(());
    }
    match id {
        "setup" => {
            let required = json::is_true(body, "setup_required");
            cx.state.phase = if required { Phase::Setup } else { Phase::Login };
            Ok(())
        }
        "kiosk-exchange" => kiosk_opened(cx, body),
        "session" | "login" | "password" => authenticated(cx, body),
        "logout" => {
            cx.reset_session(Phase::Login);
            cx.disconnect()
        }
        _ => Ok(()),
    }
}

/// Starts a session from a successful session check, sign-in or password change.
fn authenticated(cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
    cx.live.authenticated();
    let state = &mut *cx.state;
    state.kiosk = json::is_true(body, "kiosk");
    state.kiosk_expires = if state.kiosk { json::unsigned_or_zero(body, "expires") } else { 0 };
    let user = json::field(body, "user").ok_or(UiError::InvalidResponse)?;
    state.user_id = json::counter(user).ok_or(UiError::InvalidResponse)?;
    state.csrf = Secret::new(json::string(body, "csrf"))?;
    state.console_node =
        u32::try_from(json::unsigned_or_zero(body, "node")).ok().filter(|node| *node != 0);
    state.role = Text::new(json::string(body, "role"))?;
    state.must_change = json::is_true(body, "must_change");
    state.totp_required = json::is_true(body, "totp_required");
    state.phase = if state.must_change {
        Phase::Password
    } else if state.totp_required {
        Phase::Security
    } else {
        Phase::Dashboard
    };
    state.clear_message();
    if state.phase == Phase::Security {
        // The account security page opens itself through its navigation action.
        cx.action("security", &Value::Null)?;
    }
    Ok(())
}

/// A wall display signed in with a one-time code: viewer role, statistics only, no
/// shell. A code exchange changes principal, so nothing of an earlier session survives.
fn kiosk_opened(cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
    let browser_time = cx.state.browser_time;
    let reduced_motion = cx.state.reduced_motion;
    let hidden = cx.state.hidden;
    cx.reset_session(Phase::Dashboard);
    let state = &mut *cx.state;
    state.browser_time = browser_time;
    state.reduced_motion = reduced_motion;
    state.hidden = hidden;
    state.csrf = Secret::new(json::string(body, "csrf"))?;
    state.role = Text::new("viewer")?;
    state.kiosk = true;
    state.kiosk_expires = json::unsigned_or_zero(body, "expires");
    state.kiosk_cycled_at = browser_time;
    state.must_change = false;
    state.totp_required = false;
    state.phase = Phase::Dashboard;
    state.clear_message();
    Ok(())
}

/// Handles a timer: the live retry here, every other timer in the modules. Timers do
/// nothing while the tab is hidden.
fn timer(cx: &mut Context<'_>, id: &str) -> Result<(), UiError> {
    if cx.state.hidden {
        return Ok(());
    }
    if id == "live-retry" {
        cx.live.retry_elapsed();
    }
    cx.each(|page, cx| page.timer(cx, id)).map(|_| ())
}

/// Handles a stream event; a completed statistics view is accepted, and a snapshot that
/// cannot be accepted restarts the connection.
fn stream(cx: &mut Context<'_>, value: &Value<'_>) -> Result<(), UiError> {
    if let Some(snapshot) = live::event(cx, value)?
        && stats::snapshot_received(cx, snapshot).is_err()
    {
        live::failed(cx, value)?;
    }
    Ok(())
}

/// Handles the tab being hidden (the connection closes) or shown (pages refresh).
fn visibility(cx: &mut Context<'_>, value: &Value<'_>) -> Result<(), UiError> {
    let Some(hidden) = json::boolean(value, "hidden") else { return Ok(()) };
    cx.state.hidden = hidden;
    cx.state.stats_busy = false;
    if hidden {
        return cx.disconnect();
    }
    cx.every(|page, cx| page.resume(cx))
}

#[cfg(test)]
mod tests;

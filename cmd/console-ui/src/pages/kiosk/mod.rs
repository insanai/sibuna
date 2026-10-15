//! The wall display ([`Screen::Kiosk`]): a read-only statistics screen without the
//! navigation shell, which shows the traffic panels, the globe in its attacks mode, or the
//! aggregate security panels, and may cycle through them. Incident evidence and management
//! controls stay outside its statistics-only authorization scope.
//!
//! Ported from `kiosk_page.zig` and the kiosk branches of `main.zig` (the cycle and the
//! security refresh on every timer). The one-time grant an operator mints on the account
//! page is the separate module [`KioskGrant`] (`kiosk_grant.zig`).
//!
//! The panels are the other modules' render functions: the dashboard's tiles, timeline
//! and retained values, the globe, and the security overview's wall view. A registry
//! without one of those modules draws it from that module's defaults.

mod grant;

#[cfg(test)]
mod tests;

use std::fmt::{self, Write as _};

use sibuna_html::write_value;
use sibuna_json::Value;

pub use grant::KioskGrant;

use crate::error::UiError;
use crate::page::{Context, Page, Screen, View};
use crate::pages::dashboard::{self, Dashboard};
use crate::pages::security_overview::SecurityOverview;
use crate::render::{self, Html};
use crate::scope;
use crate::state::{Phase, State};

/// Seconds between panels while the display cycles.
pub const CYCLE_SECONDS: u64 = 30;

/// The wall display. Its state is the session's kiosk fields in [`State`].
#[derive(Debug, Default)]
pub struct Kiosk;

/// Cycles Traffic, Attacks and Security on the display's clock; a paused or stale display
/// and a reduced-motion preference hold the current mode.
pub fn cycle(state: &mut State) {
    if !state.kiosk
        || !state.kiosk_cycle
        || state.paused
        || state.stale
        || state.reduced_motion
        || state.browser_time.saturating_sub(state.kiosk_cycled_at) < CYCLE_SECONDS
    {
        return;
    }
    state.kiosk_cycled_at = state.browser_time;
    if state.phase == Phase::SecurityOverview {
        state.phase = Phase::Dashboard;
        state.globe_attacks = false;
    } else if state.globe_attacks {
        state.phase = Phase::SecurityOverview;
    } else {
        state.globe_attacks = true;
    }
}

/// Draws the display's header, status, scope, tabs and cycle toggle.
fn header(state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<main class=\"sb-main min-h-screen\" data-kiosk=\"true\"><header class=\"sb-header\">\
         <div><p class=\"sb-subtitle\">SIBUNA \u{b7} WALL DISPLAY</p><h1 id=\"page-heading\" \
         tabindex=\"-1\">",
    )?;
    let mut name = String::new();
    scope::view_name(state, &mut name)?;
    out.escaped(&name)?;
    out.write_str(" \u{b7} ")?;
    out.write_str(if state.phase == Phase::SecurityOverview {
        "Security"
    } else if state.globe_attacks {
        "Attacks"
    } else {
        "Traffic"
    })?;
    out.write_str(
        "</h1></div><div class=\"sb-status\"><span class=\"badge badge-outline\" \
         role=\"status\">",
    )?;
    out.write_str(scope::status(state))?;
    out.write_str("</span><span class=\"badge badge-outline\">Expires in ")?;
    write_value(out, &(state.kiosk_expires.saturating_sub(state.browser_time) / 60))?;
    out.write_str(" min</span><button class=\"btn btn-sm\" data-action=\"pause\">")?;
    out.write_str(if state.paused { "Resume" } else { "Pause" })?;
    out.write_str(
        "</button><button class=\"btn btn-sm\" data-action=\"theme\">Theme</button><button \
         class=\"btn btn-sm btn-outline\" data-action=\"logout\">Exit kiosk</button></div>\
         </header>",
    )?;
    render::message(state, out)?;
    dashboard::render_last_update(state, out)?;
    dashboard::render_scope(state, out)?;
    render::statistics_tabs(state.phase == Phase::SecurityOverview, out)?;
    out.write_str(
        "<button class=\"btn btn-sm my-3\" data-action=\"kiosk-cycle\" aria-pressed=\"",
    )?;
    out.write_str(if state.kiosk_cycle {
        "true\">Auto-cycle: On"
    } else {
        "false\">Auto-cycle: Off"
    })?;
    out.write_str("</button>")
}

/// Draws the traffic view: tiles, globe, request timeline and its retained values.
fn traffic(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    let fallback;
    let found = match view.pages.find::<Dashboard>() {
        Some(found) => found,
        None => {
            fallback = Dashboard::default();
            &fallback
        }
    };
    found.render_tiles(state, out)?;
    out.write_str("<section class=\"sb-panels\"><article class=\"sb-panel\">")?;
    crate::pages::globe::render(view, out)?;
    out.write_str("</article><article class=\"sb-panel\"><h2>Request timeline</h2>")?;
    dashboard::render_timeline_chart(state, out)?;
    found.render_timeline_values(state, out)?;
    out.write_str(
        "<p class=\"sb-note\">Read-only display. Optional cycling changes panels every ",
    )?;
    write_value(out, &CYCLE_SECONDS)?;
    out.write_str(
        " seconds unless motion is reduced or the display is paused.</p></article></section>\
         </main>",
    )
}

impl Page for Kiosk {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Kiosk)
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        let state = view.state;
        header(state, out)?;
        if state.phase != Phase::SecurityOverview {
            return traffic(view, out);
        }
        match view.pages.find::<SecurityOverview>() {
            Some(found) => found.render_wall(state, out),
            None => SecurityOverview::default().render_wall(state, out),
        }
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        _fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let state = &mut *cx.state;
        if !state.kiosk || !state.is_full_access() || name != "kiosk-cycle" {
            return Ok(false);
        }
        state.kiosk_cycle = !state.kiosk_cycle;
        state.kiosk_cycled_at = state.browser_time;
        Ok(true)
    }

    /// Every timer advances the cycle; the security view refreshes its trends when it
    /// appears and then once a minute while it is shown and not paused.
    fn timer(&mut self, cx: &mut Context<'_>, _id: &str) -> Result<bool, UiError> {
        let previous = cx.state.phase;
        cycle(cx.state);
        let state = &*cx.state;
        if !state.kiosk || state.phase != Phase::SecurityOverview || state.paused {
            return Ok(false);
        }
        let Context { state, commands, pages, .. } = cx;
        if let Some(overview) = pages.find_mut::<SecurityOverview>() {
            let model = &overview.model;
            let due =
                !model.busy[0] && state.browser_time.saturating_sub(model.request.until) >= 60;
            if previous != state.phase || due {
                overview.refresh(state, commands)?;
            }
        }
        Ok(false)
    }

    fn reset(&mut self) {}
}

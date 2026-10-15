//! The live earth globe (SID 0007, "Live earth globe on the landing page"): a panel with
//! no screen of its own, drawn by the dashboard and by the wall display's traffic view.
//!
//! Ported from `globe.zig`, `globe_data.zig`, `globe_motion.zig`, `globe_connections.zig`,
//! `geographic_route.zig` and the projection half of `geography.zig` (validation and
//! reading of the world boundaries are in [`crate::geometry`]).
//!
//! # Drawing the panel
//!
//! A page that shows the globe calls one function from its own render:
//!
//! ```ignore
//! /// Draws the globe panel: heading, mode buttons, the scene (`<div id="globe-scene">`),
//! /// controls, notes and the country table.
//! pub fn render(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result;
//!
//! // In the dashboard's render, inside its globe article:
//! crate::pages::globe::render(view, out)?;
//! ```
//!
//! It reads everything from `view.state` (the statistics, the dashboard scope, the
//! geometry, the projection in `state.globe`, the Traffic/Attacks mode in
//! `state.globe_attacks`, the coverage toggle in `state.globe_coverage`, the
//! reduced-motion preference, `state.kiosk`) and the animation state of the registered
//! [`Globe`] module, found with [`crate::page::Pages::find`]. When no [`Globe`] module is
//! registered (a test registry), it draws with a new one. It fails only when the page
//! exceeds the render bound. Its markup is `globe.render` of the Zig module byte for byte.
//!
//! # Actions and animation
//!
//! [`Globe`] handles the actions of the panel on the dashboard phase: `globe-traffic`,
//! `globe-attacks`, `globe-coverage`, `globe-motion`, `rotate-left`, `rotate-right`,
//! `reset-globe`, `center-server`, `flat-map` and `country-<code>` (the code as a decimal
//! `u16`). It implements [`Page::frame`]: each animation frame advances the rotation and
//! the arrows and draws the scene alone (the inner HTML of `#globe-scene`), at most
//! [`RENDER_LIMIT`] bytes, as `globe_motion.frame` did.
//!
//! # Changes from the Zig module
//!
//! - As in Zig, each animation frame writes the turned longitude into the shared
//!   `state.globe` ([`Page::frame`] borrows the state mutably).
//! - The motion state (`rotating`, the frame clock and the arrow phase) lives in this
//!   module, so a wall-display code exchange, which resets every module, restarts rotation;
//!   Zig carried the motion of the previous session over. The reduced-motion preference
//!   stays in the shared state and survives as before.
//! - Country codes in the SVG titles of markers and connections are escaped like every
//!   other value (Zig printed the two code bytes raw; see the SID 0007 revision note).
//! - The 512 KiB frame buffer is a reused string bounded by [`RENDER_LIMIT`].
//! - Scene coordinates are written by [`crate::format::decimal`] (Zig's `{d:.1}`), whose
//!   fast path keeps a busy frame cheap.

mod activity;
mod connections;
mod motion;
mod panel;
mod projection;
mod route;

#[cfg(test)]
mod tests;

use std::fmt;

use sibuna_json::Value;

use crate::error::UiError;
use crate::page::{Context, Page, View};
use crate::render::{Html, RENDER_LIMIT};
use crate::state::{Phase, State};

pub use motion::Motion;

/// Draws the globe panel into `out`: the heading, the Traffic/Attacks buttons, the scene
/// inside `<div id="globe-scene">`, the animation and rotation controls, the location,
/// boundary and coverage notes and the table of countries. Uses the registered [`Globe`]
/// module's animation state, or a new one when none is registered.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    match view.pages.find::<Globe>() {
        Some(globe) => globe.panel(view.state, out),
        None => Globe::default().panel(view.state, out),
    }
}

/// The globe module: the animation state and the panel's actions.
#[derive(Debug, Default)]
pub struct Globe {
    /// Rotation, frame clock and arrow phase.
    pub motion: Motion,
}

impl Globe {
    /// Draws the globe panel for `state`; see [`render`].
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn panel(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        panel::panel(state, &self.scene(state), out)
    }

    /// Returns what the scene draws beyond the shared state.
    fn scene(&self, state: &State) -> panel::Scene {
        panel::Scene { view: state.globe, rotating: self.motion.rotating, flow: self.motion.flow }
    }
}

impl Page for Globe {
    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        _fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if cx.state.phase != Phase::Dashboard {
            return Ok(false);
        }
        Ok(motion::action(cx.state, &mut self.motion, name))
    }

    fn reset(&mut self) {
        *self = Globe::default();
    }

    fn frame(&mut self, state: &mut State, milliseconds: f64, out: &mut String) -> usize {
        let mut view = state.globe;
        if !self.motion.advance(state, &mut view, milliseconds) {
            return 0;
        }
        state.globe = view;
        let scene = self.scene(state);
        let mut sink = Html::new(out, RENDER_LIMIT);
        if panel::scene(state, &scene, &mut sink).is_err() {
            out.clear();
            return 0;
        }
        out.len()
    }
}

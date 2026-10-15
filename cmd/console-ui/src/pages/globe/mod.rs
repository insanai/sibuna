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
//! - Zig's animation wrote the turned longitude into the shared `State` from `sb_frame`.
//!   [`Page::frame`] borrows the state immutably, so the module keeps the turned view
//!   beside the view it was turned from ([`Globe`]'s `spin`). Every reader uses the turned
//!   view while the shared view is still the one it was turned from; the next event writes
//!   it back into `state.globe` ([`Page::finish`], and before any globe action). A change
//!   another module makes to `state.globe` in between wins, as it did in Zig.
//! - The motion state (`rotating`, the frame clock and the arrow phase) lives in this
//!   module, so a wall-display code exchange, which resets every module, restarts rotation;
//!   Zig carried the motion of the previous session over. The reduced-motion preference
//!   stays in the shared state and survives as before.
//! - Country codes in the SVG titles of markers and connections are escaped like every
//!   other value (Zig printed the two code bytes raw; see the SID 0007 revision note).
//! - The 512 KiB frame buffer is a reused string bounded by [`RENDER_LIMIT`].
//! - Scene coordinates are written by a fast path that agrees with
//!   [`crate::format::decimal`] (Zig's `{d:.1}`) and falls back to it near a rounding
//!   midpoint; see `tenths`.

mod activity;
mod connections;
mod motion;
mod panel;
mod projection;
mod route;
mod tenths;

#[cfg(test)]
mod tests;

use std::fmt;

use sibuna_json::Value;

use crate::error::UiError;
use crate::page::{Context, Page, View};
use crate::render::{Html, RENDER_LIMIT};
use crate::state::{GlobeView, Phase, State};

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

/// A turned view the next event writes back into `state.globe`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Spin {
    /// The shared view the animation started from.
    from: GlobeView,
    /// The view after the frames since then.
    to: GlobeView,
}

/// The globe module: the animation state and the panel's actions.
#[derive(Debug, Default)]
pub struct Globe {
    /// Rotation, frame clock and arrow phase.
    pub motion: Motion,
    /// The view the animation turned to since the last event, if any.
    spin: Option<Spin>,
}

impl Globe {
    /// Returns the view to draw: the turned view while `state.globe` is still the view
    /// it was turned from, else `state.globe`.
    pub fn view(&self, state: &State) -> GlobeView {
        match self.spin {
            Some(spin) if spin.from == state.globe => spin.to,
            _ => state.globe,
        }
    }

    /// Draws the globe panel for `state`; see [`render`].
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn panel(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        panel::panel(state, &self.scene(state), out)
    }

    /// Writes the turned view back into the shared state.
    fn settle(&mut self, state: &mut State) {
        state.globe = self.view(state);
        self.spin = None;
    }

    /// Returns what the scene draws beyond the shared state.
    fn scene(&self, state: &State) -> panel::Scene {
        panel::Scene {
            view: self.view(state),
            rotating: self.motion.rotating,
            flow: self.motion.flow,
        }
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
        self.settle(cx.state);
        Ok(motion::action(cx.state, &mut self.motion, name))
    }

    fn finish(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.settle(cx.state);
        Ok(())
    }

    fn reset(&mut self) {
        *self = Globe::default();
    }

    fn frame(&mut self, state: &State, milliseconds: f64, out: &mut String) -> usize {
        let mut view = self.view(state);
        if !self.motion.advance(state, &mut view, milliseconds) {
            return 0;
        }
        self.spin = Some(Spin { from: state.globe, to: view });
        let scene = self.scene(state);
        let mut sink = Html::new(out, RENDER_LIMIT);
        if panel::scene(state, &scene, &mut sink).is_err() {
            out.clear();
            return 0;
        }
        out.len()
    }
}

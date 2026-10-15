//! Rotation, the arrows' phase and the panel's actions (`globe_motion.zig`).
//!
//! The globe turns eastward at 0.004 degrees per millisecond (four degrees per second);
//! the arrows travel along their routes once every 2.4 seconds. A frame advances both by
//! the time since the previous frame, at most 100 ms, so a tab that slept does not jump.
//! Nothing moves without full access, off the dashboard, without geometry, while the tab
//! is hidden, paused or stale, or when the browser asks for reduced motion.

use crate::geometry;
use crate::state::{GlobeView, Phase, State};

/// Degrees the globe turns per millisecond.
const DEGREES_PER_MS: f64 = 0.004;
/// Milliseconds an arrow takes along its whole route.
const FLOW_PERIOD_MS: f64 = 2400.0;
/// The longest step one frame takes, in milliseconds.
const MAX_STEP_MS: f64 = 100.0;
/// Degrees one press of Rotate left or Rotate right turns.
const ROTATE_STEP: f64 = 20.0;

/// The animation state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Motion {
    /// The globe turns by itself; the operator pauses it, and manual rotation or a
    /// country selection stops it for inspection.
    pub rotating: bool,
    /// The browser clock of the previous frame, in milliseconds; 0 when the animation
    /// (re)starts.
    pub last_ms: f64,
    /// The arrows' phase along their routes, in `[0, 1)`.
    pub flow: f64,
}

impl Default for Motion {
    fn default() -> Motion {
        Motion { rotating: true, last_ms: 0.0, flow: 0.0 }
    }
}

impl Motion {
    /// Advances the rotation of `view` and the arrows to the browser clock
    /// `milliseconds`; returns false, and forgets the frame clock, when nothing may move.
    pub fn advance(&mut self, state: &State, view: &mut GlobeView, milliseconds: f64) -> bool {
        let still = !state.is_full_access()
            || state.phase != Phase::Dashboard
            || !state.geometry.is_loaded()
            || state.hidden
            || state.paused
            || state.stale
            || state.reduced_motion
            || !self.rotating
            || !milliseconds.is_finite()
            || milliseconds < 0.0;
        if still {
            self.last_ms = 0.0;
            return false;
        }
        let elapsed = if self.last_ms == 0.0 {
            0.0
        } else {
            (milliseconds - self.last_ms).clamp(0.0, MAX_STEP_MS)
        };
        self.last_ms = milliseconds;
        if !view.flat {
            view.lon = zig_mod(view.lon + elapsed * DEGREES_PER_MS + 180.0, 360.0) - 180.0;
        }
        self.flow = zig_mod(self.flow + elapsed / FLOW_PERIOD_MS, 1.0);
        true
    }
}

/// Zig's `@mod` for floats with a positive divisor: the remainder in `[0, divisor]`. As
/// in a Zig debug build, a tiny negative value yields `divisor` rather than 0; both are
/// the same longitude or arrow phase.
pub(super) fn zig_mod(value: f64, divisor: f64) -> f64 {
    value.rem_euclid(divisor)
}

/// Handles the globe action `name` on the dashboard; returns true when it is one.
pub(super) fn action(state: &mut State, motion: &mut Motion, name: &str) -> bool {
    match name {
        "globe-traffic" => state.globe_attacks = false,
        "globe-attacks" => state.globe_attacks = true,
        "globe-coverage" => state.globe_coverage = !state.globe_coverage,
        "globe-motion" => {
            motion.rotating = !motion.rotating;
            motion.last_ms = 0.0;
        }
        "rotate-left" | "rotate-right" => {
            motion.rotating = false;
            let step = if name == "rotate-left" { -ROTATE_STEP } else { ROTATE_STEP };
            state.globe.lon += step;
        }
        "reset-globe" => {
            state.globe = GlobeView::default();
            motion.rotating = true;
        }
        "center-server" => {
            let location = state.stats.as_ref().and_then(|stats| stats.server_location);
            let Some(location) = location.filter(|location| location.is_valid()) else {
                return false;
            };
            state.globe = GlobeView { lat: location.lat, lon: location.lon, flat: false };
            motion.rotating = false;
        }
        "flat-map" => state.globe.flat = !state.globe.flat,
        _ => {
            let Some(code) = name.strip_prefix("country-") else { return false };
            // Zig stopped the rotation before it parsed the code.
            motion.rotating = false;
            let Some(code) = parse_code(code) else { return false };
            let center = state.geometry.bytes().and_then(|bytes| geometry::center(bytes, code));
            if let Some(position) = center {
                state.globe = GlobeView { lon: position.lon, lat: position.lat, flat: false };
            }
        }
    }
    if state.globe.lon > 180.0 {
        state.globe.lon -= 360.0;
    }
    if state.globe.lon < -180.0 {
        state.globe.lon += 360.0;
    }
    true
}

/// Parses a decimal `u16` as Zig's `std.fmt.parseInt(u16, text, 10)` does: an optional
/// sign (`-` only for zero), digits, and underscores between digits.
fn parse_code(text: &str) -> Option<u16> {
    let (negative, digits) = match text.as_bytes() {
        [b'+', rest @ ..] => (false, rest),
        [b'-', rest @ ..] => (true, rest),
        rest => (false, rest),
    };
    if digits.first().is_none_or(|byte| *byte == b'_') || digits.last() == Some(&b'_') {
        return None;
    }
    let mut value: u16 = 0;
    for byte in digits.iter().filter(|byte| **byte != b'_') {
        let digit = byte.is_ascii_digit().then(|| u16::from(byte - b'0'))?;
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    (!negative || value == 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard() -> State {
        let mut state = State { phase: Phase::Dashboard, ..State::new() };
        let world = include_bytes!("../../../web/assets/world-110m.bin");
        state.geometry.input()[..world.len()].copy_from_slice(world);
        state.geometry.load(world.len()).unwrap();
        state
    }

    // Port of globe_motion.zig "motion requires full authentication and respects pause
    // and reduced motion".
    #[test]
    fn motion_requires_full_authentication_and_respects_pause_and_reduced_motion() {
        let mut state = dashboard();
        let mut motion = Motion::default();
        let mut view = state.globe;
        assert!(!motion.advance(&state, &mut view, 100.0));
        state.csrf.set("test").unwrap();
        assert!(motion.advance(&state, &mut view, 100.0));
        assert!(motion.advance(&state, &mut view, 200.0));
        assert!((view.lon - 0.4).abs() < 0.0001);
        state.reduced_motion = true;
        assert!(!motion.advance(&state, &mut view, 300.0));
        state.reduced_motion = false;
        state.paused = true;
        assert!(!motion.advance(&state, &mut view, 400.0));
        state.paused = false;
        view.lon = 179.9;
        assert!(motion.advance(&state, &mut view, 500.0));
        assert!(motion.advance(&state, &mut view, 100_000.0));
        assert!((-180.0..=180.0).contains(&view.lon));
        assert!(!motion.advance(&state, &mut view, f64::NAN));
    }

    #[test]
    fn a_flat_map_keeps_its_longitude_while_the_arrows_move() {
        let mut state = dashboard();
        state.csrf.set("test").unwrap();
        let mut motion = Motion::default();
        let mut view = GlobeView { flat: true, ..GlobeView::default() };
        assert!(motion.advance(&state, &mut view, 1000.0));
        assert!(motion.advance(&state, &mut view, 1100.0));
        assert_eq!(view.lon, 0.0);
        assert!((motion.flow - 100.0 / 2400.0).abs() < 1e-12);
        for stop in [Phase::Events, Phase::SecurityOverview] {
            state.phase = stop;
            assert!(!motion.advance(&state, &mut view, 1200.0));
            assert_eq!(motion.last_ms, 0.0);
        }
    }

    #[test]
    fn actions_turn_wrap_and_stop_the_rotation() {
        let mut state = dashboard();
        let mut motion = Motion::default();
        state.globe.lon = -170.0;
        assert!(action(&mut state, &mut motion, "rotate-left"));
        assert_eq!(state.globe.lon, 170.0);
        assert!(!motion.rotating);
        assert!(action(&mut state, &mut motion, "reset-globe"));
        assert!(motion.rotating && state.globe == GlobeView::default());
        assert!(!action(&mut state, &mut motion, "center-server"));
        let code = u16::from_be_bytes(*b"FR");
        assert!(action(&mut state, &mut motion, &format!("country-{code}")));
        assert!(!motion.rotating);
        let france = geometry::center(state.geometry.bytes().unwrap(), code).unwrap();
        assert_eq!((state.globe.lon, state.globe.lat), (france.lon, france.lat));
        motion.rotating = true;
        assert!(!action(&mut state, &mut motion, "country-x"));
        assert!(!motion.rotating, "Zig stops the rotation before it reads the code");
        assert!(!action(&mut state, &mut motion, "pause"));
    }

    #[test]
    fn country_codes_parse_as_zig_parse_int() {
        assert_eq!(parse_code("21843"), Some(21843));
        assert_eq!(parse_code("+7"), Some(7));
        assert_eq!(parse_code("-0"), Some(0));
        assert_eq!(parse_code("1_0"), Some(10));
        for refused in ["", "+", "-", "-5", "_1", "1_", "65536", " 1", "1a", "0x10"] {
            assert_eq!(parse_code(refused), None, "{refused}");
        }
        assert_eq!(parse_code("65535"), Some(65535));
    }
}

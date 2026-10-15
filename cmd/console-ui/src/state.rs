//! The session-wide state every page shares.
//!
//! Page-specific state lives in the page modules (see [`crate::page`]); this struct holds
//! what the core and several pages read: the phase, the session and its role, the operator
//! message, the clock, the live statistics and the presentation preferences.

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::dashboard::Scope;
use sibuna_console_protocol::{Action, Role, StatsSnapshot, Text};

use crate::appearance::Appearance;
use crate::geometry::Geometry;
use crate::live::Observations;
use crate::routing::Route;
use crate::secret::Secret;
use crate::stats::Series;

/// The screen the interface shows. Authentication phases come first; every other phase
/// is a page of the signed-in console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Waiting for the session check after start-up.
    #[default]
    Loading,
    /// No administrator exists yet.
    Setup,
    /// Sign-in.
    Login,
    /// Password change, required or chosen from the account page.
    Password,
    /// Traffic statistics, the landing page.
    Dashboard,
    /// Security statistics.
    SecurityOverview,
    /// The GeoIP database.
    Geoip,
    /// Two-factor authentication of the signed-in account.
    Security,
    /// Recorded incidents.
    Events,
    /// The challenge funnel.
    Challenges,
    /// Incidents similar to one incident.
    Similarity,
    /// Policies, address groups and response pages.
    Policies,
    /// Console users.
    Users,
    /// API tokens.
    Tokens,
    /// The audit log.
    Audit,
    /// Cluster members.
    Nodes,
    /// Console settings.
    Settings,
}

impl Phase {
    /// Every phase, in declaration order.
    pub const ALL: [Phase; 17] = [
        Phase::Loading,
        Phase::Setup,
        Phase::Login,
        Phase::Password,
        Phase::Dashboard,
        Phase::SecurityOverview,
        Phase::Geoip,
        Phase::Security,
        Phase::Events,
        Phase::Challenges,
        Phase::Similarity,
        Phase::Policies,
        Phase::Users,
        Phase::Tokens,
        Phase::Audit,
        Phase::Nodes,
        Phase::Settings,
    ];

    /// Returns the phase's name, as the Zig enum spelled it (the golden fixture names).
    pub fn name(self) -> &'static str {
        match self {
            Phase::Loading => "loading",
            Phase::Setup => "setup",
            Phase::Login => "login",
            Phase::Password => "password",
            Phase::Dashboard => "dashboard",
            Phase::SecurityOverview => "security_overview",
            Phase::Geoip => "geoip",
            Phase::Security => "security",
            Phase::Events => "events",
            Phase::Challenges => "challenges",
            Phase::Similarity => "similarity",
            Phase::Policies => "policies",
            Phase::Users => "users",
            Phase::Tokens => "tokens",
            Phase::Audit => "audit",
            Phase::Nodes => "nodes",
            Phase::Settings => "settings",
        }
    }
}

/// The browser's view of the globe: the centre of the orthographic projection, or a flat
/// map.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlobeView {
    /// Longitude of the centre, in degrees.
    pub lon: f64,
    /// Latitude of the centre, in degrees.
    pub lat: f64,
    /// Draw a flat map instead of the globe.
    pub flat: bool,
}

impl Default for GlobeView {
    fn default() -> GlobeView {
        GlobeView { lon: 0.0, lat: 15.0, flat: false }
    }
}

/// The state the core owns. Every field has a meaning across pages; see the field docs.
#[derive(Debug, Default)]
pub struct State {
    /// The screen shown.
    pub phase: Phase,
    /// The narrow-screen navigation drawer is open.
    pub navigation_open: bool,
    /// The bookmarkable route.
    pub route: Route,
    /// Freshness of each live topic.
    pub live: Observations,
    /// The operator message shown under the page heading; empty for none.
    pub message: Text<256>,
    /// The message reports a success rather than a problem.
    pub message_success: bool,
    /// The name typed at sign-in, kept to refill the form.
    pub username: Text<64>,
    /// The session's CSRF token; empty when signed out.
    pub csrf: Secret<64>,
    /// The signed-in role's name: `viewer`, `operator` or `admin`.
    pub role: Text<16>,
    /// The signed-in user's id.
    pub user_id: u64,
    /// The node serving this console, independent of the selected telemetry source.
    pub console_node: Option<u32>,
    /// An authentication form or account request is in flight.
    pub busy: bool,
    /// The password must be changed before anything else.
    pub must_change: bool,
    /// Two-factor enrollment is required before anything else.
    pub totp_required: bool,
    /// A statistics request is in flight.
    pub stats_busy: bool,
    /// The live connection's next retry delay, in milliseconds (1 s to 30 s).
    pub reconnect_ms: u32,
    /// The operator paused live statistics.
    pub paused: bool,
    /// The browser tab is hidden.
    pub hidden: bool,
    /// The browser's clock at the current event, in Unix seconds.
    pub browser_time: u64,
    /// When the shown statistics arrived, in browser seconds.
    pub received_at: u64,
    /// The shown statistics are not current.
    pub stale: bool,
    /// Theme and density.
    pub appearance: Appearance,
    /// The world boundaries for the globe.
    pub geometry: Geometry,
    /// The globe's projection.
    pub globe: GlobeView,
    /// The globe shows attacks rather than traffic.
    pub globe_attacks: bool,
    /// The globe shows country coverage.
    pub globe_coverage: bool,
    /// The browser asks for reduced motion.
    pub reduced_motion: bool,
    /// The latest live statistics.
    pub stats: Option<StatsSnapshot>,
    /// Per-second points of the last minute, indexed by second modulo 60.
    pub points: Series,
    /// What the live statistics combine.
    pub dashboard_scope: Option<Scope>,
    /// The node selected on the dashboard; `None` for every node.
    pub dashboard_node: Option<u32>,
    /// A wall-display session: read-only, statistics only.
    pub kiosk: bool,
    /// When the wall-display session expires, in Unix seconds.
    pub kiosk_expires: u64,
    /// When the wall display last changed panels.
    pub kiosk_cycled_at: u64,
    /// The wall display cycles its panels.
    pub kiosk_cycle: bool,
}

impl State {
    /// Returns a signed-out state at the loading phase.
    pub fn new() -> State {
        State { reconnect_ms: 1000, ..State::default() }
    }

    /// Drops every session value and returns to the loading phase. Credentials are
    /// dropped, not cleared in place, so the module's allocator erases them.
    pub fn reset(&mut self) {
        *self = State::new();
    }

    /// Returns true when the session may use the console: signed in, with no required
    /// password change or two-factor enrollment pending.
    pub fn is_full_access(&self) -> bool {
        !self.csrf.is_empty() && !self.must_change && !self.totp_required
    }

    /// Returns true when the session has full access and its role permits `action`.
    pub fn allows(&self, action: Action) -> bool {
        self.is_full_access()
            && Role::from_name(self.role.as_str()).is_some_and(|role| role.allows(action))
    }

    /// Shows `message` as a problem.
    pub fn set_message(&mut self, message: &str) {
        self.message_success = false;
        // Messages are constants of at most 256 bytes; a longer one is shown truncated
        // at a character boundary rather than dropped.
        let mut end = message.len().min(256);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        self.message = Text::new(message.get(..end).unwrap_or_default()).unwrap_or_default();
    }

    /// Removes the operator message.
    pub fn clear_message(&mut self) {
        self.message = Text::default();
    }

    /// Returns the state after a sign-out or an expired session: everything reset to
    /// `phase`, keeping the appearance preferences.
    pub fn reset_to(&mut self, phase: Phase) {
        let appearance = self.appearance;
        self.reset();
        self.phase = phase;
        self.appearance = appearance;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_reset_drops_credentials_and_restores_defaults() {
        let mut state = State {
            phase: Phase::Policies,
            navigation_open: true,
            reconnect_ms: 8000,
            ..State::new()
        };
        state.csrf.set("private csrf").unwrap();
        state.console_node = Some(7);
        state.dashboard_node = Some(2);
        state.reset();
        assert_eq!(state.phase, Phase::Loading);
        assert!(!state.navigation_open);
        assert_eq!(state.reconnect_ms, 1000);
        assert_eq!(state.globe.lat, 15.0);
        assert!(state.csrf.is_empty());
        assert_eq!(state.console_node, None);
    }

    #[test]
    fn roles_need_full_access() {
        let mut state = State::new();
        state.role.set("operator").unwrap();
        assert!(!state.allows(Action::Read));
        state.csrf.set("token").unwrap();
        assert!(state.allows(Action::ManagePolicy));
        assert!(!state.allows(Action::ManageUsers));
        state.must_change = true;
        assert!(!state.allows(Action::Read));
        state.must_change = false;
        state.role.set("root").unwrap();
        assert!(!state.allows(Action::Read));
    }

    #[test]
    fn phase_names_are_the_fixture_names() {
        let names: Vec<&str> = Phase::ALL.iter().map(|phase| phase.name()).collect();
        assert_eq!(names.len(), 17);
        assert_eq!(names[5], "security_overview");
    }
}

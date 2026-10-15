//! The page registry: every page and panel module of this build, in dispatch order.
//!
//! To add a module, declare it below and add one line to [`load_pages`]. Order matters
//! only where two modules would claim the same action, reply id or timer; the list keeps
//! the order in which the Zig `main.zig` consulted its controllers (see the crate
//! documentation for the full order the remaining pages take).

mod account_security;
mod audit;
pub mod challenges;
pub mod dashboard;
pub mod events;
mod geoip;
pub mod globe;
pub mod kiosk;
mod management;
mod nodes;
mod policies;
pub mod request_headers;
pub mod security_overview;
mod settings;
pub mod similarity;
mod tokens;
mod users;

pub use account_security::AccountSecurity;
pub use audit::Audit;
pub use challenges::Challenges;
pub use dashboard::Dashboard;
pub use events::Events;
pub use geoip::Geoip;
pub use globe::Globe;
pub use kiosk::{Kiosk, KioskGrant};
pub use nodes::Nodes;
pub use policies::Policies;
pub use security_overview::SecurityOverview;
pub use settings::Settings;
pub use similarity::Similarity;
pub use tokens::Tokens;
pub use users::Users;

use crate::page::{Page, Pages};

/// Returns every module of this build, in dispatch order.
pub fn load_pages() -> Pages {
    let pages: Vec<Box<dyn Page>> = vec![
        // The wall display: its cycle toggle and timer (no phase; draws the kiosk screen).
        Box::new(Kiosk),
        // Traffic dashboard and the node selector (phase `dashboard`).
        Box::new(Dashboard::default()),
        // Security overview (phase `security_overview`), after the dashboard, which passes
        // it the node selector; and the wall-display grant of the account page.
        Box::new(SecurityOverview::default()),
        Box::new(KioskGrant::default()),
        // Management: users, tokens, audit, settings with response pages, nodes (phases
        // `users`, `tokens`, `audit`, `settings`, `nodes`).
        Box::new(Users::default()),
        Box::new(Tokens::default()),
        Box::new(Audit::default()),
        Box::new(Settings::default()),
        Box::new(Nodes::default()),
        // Policies: applied and managed rules, IP groups and rule hit history (phase
        // `policies`); before the events page, which handles the other `events-` actions.
        Box::new(Policies::default()),
        // Investigation: similarity, challenges and events (phases `similarity`,
        // `challenges`, `events`).
        Box::new(Similarity::default()),
        Box::new(Challenges::default()),
        Box::new(Events::default()),
        // Account: two-factor authentication (phase `security`).
        Box::new(AccountSecurity::default()),
        // Geography: the GeoIP database (phase `geoip`).
        Box::new(Geoip::default()),
        // Geography: the globe panel's actions and animation frames (no screen).
        Box::new(Globe::default()),
    ];
    Pages::new(pages)
}

//! The page registry: every page and panel module of this build, in dispatch order.
//!
//! To add a module, declare it below and add one line to [`load_pages`]. Order matters
//! only where two modules would claim the same action, reply id or timer; the list keeps
//! the order in which the Zig `main.zig` consulted its controllers (see the crate
//! documentation for the full order the remaining pages take).

mod account_security;

pub use account_security::AccountSecurity;

use crate::page::{Page, Pages};

/// Returns every module of this build, in dispatch order.
pub fn load_pages() -> Pages {
    let pages: Vec<Box<dyn Page>> = vec![
        // Account: two-factor authentication (phase `security`).
        Box::new(AccountSecurity::default()),
    ];
    Pages::new(pages)
}

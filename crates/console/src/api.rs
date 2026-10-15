//! Route handlers, one module per route group. The dispatcher ([`crate::dispatch`]) maps each
//! [`crate::routes::Handler`] to exactly one module's `handle` function, which every module
//! declares with the same signature:
//!
//! ```text
//! pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call)
//!     -> Result<(), RouteError>
//! ```
//!
//! A handler decodes its body with [`crate::http::body::read_json`], builds its storage
//! credential with [`crate::dispatch::Call::credential`], reads the time from `call.now`,
//! runs one storage function through [`crate::storage::ConsoleStorage::transact`], and
//! answers with [`crate::http::reply`] or a [`RouteError`](crate::http::RouteError).

pub mod audit;
pub mod challenges;
pub mod country;
pub mod events;
pub mod export;
pub mod geoip;
pub mod kiosk;
pub mod live;
pub mod minutes;
pub mod nodes;
pub mod notifications;
pub mod pages;
pub mod peer;
pub mod policies;
pub mod ranking_history;
pub mod rule_hits;
pub mod security;
pub mod session;
pub mod settings;
pub mod stream;
pub mod tokens;
pub mod totp;
pub mod users;
pub mod workflows;

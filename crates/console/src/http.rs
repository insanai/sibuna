//! The console's HTTP helpers, shared by every route (Zig's `http.zig`, `bearer.zig`,
//! `ingress.zig` and `origin.zig`).
//!
//! - [`reply`]: JSON replies, failure bodies with their hints, and [`RouteError`], the one
//!   error type of route handlers.
//! - [`body`]: a bounded JSON body decoded into a protocol type.
//! - [`credential`]: the session cookie or bearer token a request presents, the CSRF check
//!   and the CSRF token of a session.
//! - [`ingress`]: forwarded fields are trusted only from configured proxy networks.
//! - [`origin`]: the client address and User-Agent digest a mutation records.

pub mod body;
pub mod credential;
pub mod ingress;
pub mod origin;
pub mod reply;

pub use reply::RouteError;

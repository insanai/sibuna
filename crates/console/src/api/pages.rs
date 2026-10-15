//! The routes `pages/read`, `pages/edit`, `pages/preview` and the `pages/preview/<kind>` reads,
//! rendered with `respond_isolated`.
//!
//! Owned by unit U3 of the console port; the Zig specification is `page_routes.zig`. Until the
//! unit lands, every route here answers 503 `CONSOLE004`.

use sibuna_serve::Context;

use crate::dispatch::Call;
use crate::http::RouteError;
use crate::shared::{Setup, Shared};

/// Unsaved template drafts per session, previewed before they are saved; bounded per
/// session and in all.
#[derive(Debug, Default)]
pub struct Drafts {}

impl Drafts {
    /// Returns an empty draft store.
    pub fn new(setup: &Setup<'_>) -> Drafts {
        let _ = setup;
        Drafts {}
    }
}

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with; [`RouteError::Unavailable`] until
/// the module is implemented.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let _ = (shared, context, call);
    Err(RouteError::Unavailable)
}

//! The routes `GET` and `POST /console/api/geoip`: the active generation's metadata and import
//! status, and starting an import.
//!
//! Owned by unit U6 of the console port; the Zig specification is `geoip_routes.zig`. Until the
//! unit lands, every route here answers 503 `CONSOLE004`.

use sibuna_serve::Context;

use crate::dispatch::Call;
use crate::http::RouteError;
use crate::shared::Shared;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with; [`RouteError::Unavailable`] until
/// the module is implemented.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let _ = (shared, context, call);
    Err(RouteError::Unavailable)
}

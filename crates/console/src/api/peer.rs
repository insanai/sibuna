//! The routes `/console/peer`: the inbound management stream, behind a proxy only, under the peer
//! admission class.
//!
//! Owned by unit U7 of the console port; the Zig specification is `stream.zig (peer part)`. Until
//! the unit lands, every route here answers 503 `CONSOLE004`.

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

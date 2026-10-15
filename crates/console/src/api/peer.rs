//! The route `/console/peer`: the inbound management stream (Zig's `stream.zig`, peer
//! part), behind a proxy only, under the peer admission class.
//!
//! The dispatcher has already required a trusted ingress with `X-Forwarded-Proto: https`.
//! A console without a proxy or without configured peers answers 404 `CONSOLE404`. The
//! upgrade must carry a transcript and proof (`peer::read_request`, 400 `CONSOLE002`
//! otherwise) that the store admits: addressed to this node, from a configured peer with
//! no other inbound stream, within the clock skew, proved under the peer key and never seen
//! before (403 `CONSOLEPEER` otherwise). The reply carries this console's boot, a fresh
//! nonce and the server proof. The stream then runs as a peer party of `api/stream.rs`:
//! local statistics and peer queries only, never browser roles or another node's data.

use sibuna_http::Header;
use sibuna_serve::{Class, Context, ServeError};

use super::stream::{Attached, Party, serve};
use crate::dispatch::Call;
use crate::http::RouteError;
use crate::hub::{Hub, HubError, Subscription};
use crate::peer::{self, ReplyFields};
use crate::random;
use crate::shared::Shared;

/// How long an inbound peer stream lives, in seconds.
const STREAM_SECONDS: u64 = 3600;

/// Serves `call.route`, the inbound peer stream, after the dispatcher's checks.
///
/// Fails with 404 `CONSOLE404` without a proxy or peers, 400 `CONSOLE002` for an invalid
/// upgrade, 403 `CONSOLEPEER` when the peer is not admitted, 503 `CONSOLE503` when the peer
/// partition or admission class is full, and 503 `CONSOLE004` while the console stops.
/// Once upgraded, the stream ends without an error.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    if !shared.config.behind_proxy || shared.peers.targets().is_empty() {
        return Err(RouteError::fail(404, "CONSOLE404"));
    }
    let request = peer::read_request(context).map_err(|_| RouteError::BadRequest)?;
    let key = shared.peers.key().ok_or_else(|| RouteError::fail(403, "CONSOLEPEER"))?;
    let inbound = shared
        .peers
        .admit(&request.transcript, &request.proof, call.now)
        .map_err(|_| RouteError::fail(403, "CONSOLEPEER"))?;
    let attached = Attached { hub: &shared.hub, subscription: Some(attach(&shared.hub)?) };
    let reply = peer::Reply {
        boot: shared.identity.boot,
        nonce: random::array().map_err(|_| RouteError::Unavailable)?,
    };
    let fields = ReplyFields::new(key, &request.transcript, &reply);
    let extra = [
        Header { name: b"X-Sibuna-Peer", value: fields.identity.as_bytes() },
        Header { name: b"X-Sibuna-Proof", value: fields.proof.as_bytes() },
    ];
    let socket = match context.upgrade(Class::Peer, &extra) {
        Ok(socket) => socket,
        Err(ServeError::Full) => return Err(RouteError::fail(503, "CONSOLE503")),
        Err(error) => return Err(error.into()),
    };
    let Some(subscription) = attached.subscription.as_ref() else {
        return Err(RouteError::Unavailable);
    };
    let expires = shared.now().saturating_add(STREAM_SECONDS);
    serve(shared, socket, subscription, Party::Peer { node: inbound.node, expires });
    drop(inbound);
    Ok(())
}

/// Attaches a peer subscriber, mapping a full partition to 503 `CONSOLE503`.
fn attach(hub: &Hub) -> Result<Subscription, RouteError> {
    hub.attach_peer().map_err(|error| match error {
        HubError::Full => RouteError::fail(503, "CONSOLE503"),
        _ => RouteError::Unavailable,
    })
}

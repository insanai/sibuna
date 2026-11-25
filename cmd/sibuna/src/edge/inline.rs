//! The firewall decision for in-process exchanges (SID 0017).
//!
//! The protocol runtime calls [`Decision::decide`] on the thread that decoded an HTTP/2 or
//! HTTP/3 stream. The checks and the dispatch are those of every other request path. An
//! admitted request is planned, as on an event-driven worker, and the runtime sends it.

use std::cell::RefCell;
use std::sync::Arc;

use sibuna_http::chunked::Decoder;
use sibuna_http::{Method, parse_request};
use sibuna_ingress::{Decide, Forward, Offer, Verdict};
use sibuna_net::{Activity, Upload, Workspace};

use crate::client_writer::ClientWriter;
use crate::connection::{self, Ingress, Link, MAX_HEAD_BYTES, PeerText, UNKNOWN_LENGTH};
use crate::dispatch::Defer;
use crate::server::Server;
use crate::slot::EngineCache;

/// Judges the requests of the multiplexed transports of one server.
pub(super) struct Decision {
    pub server: Arc<Server>,
}

/// What one runtime thread lends to every decision it runs.
struct Scratch {
    workspace: Workspace,
    cache: EngineCache,
    defer: Defer,
    activity: Activity,
    /// The normal forms of the request path and of a forwarded path.
    paths: Box<[u8]>,
    /// Sibuna's own response, when it answers.
    output: Vec<u8>,
    /// What the access log learns of the request being decided (SID 0020).
    trace: crate::access::Trace,
}

impl Scratch {
    fn new() -> Self {
        Self {
            workspace: Workspace::new(),
            cache: EngineCache::new(),
            defer: Defer::default(),
            activity: Activity::new(),
            paths: vec![0; MAX_HEAD_BYTES].into_boxed_slice(),
            output: Vec::new(),
            trace: crate::access::Trace::default(),
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::new());
}

impl Decide for Decision {
    fn decide(&self, offer: &Offer<'_>) -> Verdict {
        SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
            Ok(mut scratch) => judge(&self.server, offer, &mut scratch),
            // A decision never calls itself; a fresh scratch keeps that an invariant
            // we do not depend on.
            Err(_) => judge(&self.server, offer, &mut Scratch::new()),
        })
    }

    fn refused(&self, refused: &sibuna_ingress::Refused<'_>) {
        crate::access::refused(&self.server, refused);
    }

    fn retry(&self, failed: &sibuna_lb::HttpTarget) -> Option<sibuna_lb::HttpTarget> {
        self.server.edge_routes.as_ref()?.retry(failed)
    }
}

fn judge(server: &Server, offer: &Offer<'_>, scratch: &mut Scratch) -> Verdict {
    let Scratch { workspace, cache, defer, activity, paths, output, trace } = scratch;
    output.clear();
    defer.plan = None;
    trace.protocol = offer.protocol;
    let mut peer = PeerText::default();
    peer.format(Some(offer.peer));
    let ingress = Ingress {
        peer: offer.peer,
        vip: offer.vip,
        secure: true,
        cert: offer.client_cert,
        tls: (offer.tls_version, offer.tls_cipher),
        trusted: false,
    };
    let mut link = Link {
        server,
        ingress: Some(ingress),
        stream: None,
        writer: ClientWriter::new(&mut *output),
        workspace,
        cache,
        defer: Some(&mut *defer),
        activity,
        last: false,
        admission: None,
        trace: &mut *trace,
    };
    answer(&mut link, offer, peer.as_bytes(), paths);
    let tally = link.writer.tally();
    drop(link);
    let Some(plan) = defer.plan.take() else {
        crate::access::settle_written(server, trace, tally, Some(ingress), peer.as_bytes());
        return Verdict::Answer(std::mem::take(output));
    };
    // The runtime sends the body itself, so it takes the head alone.
    let end = connection::find_blank_line(&defer.wire).map_or(defer.wire.len(), |at| at + 4);
    let head = defer.wire.get(..end).unwrap_or_default().to_vec();
    let report = crate::access::report(server, trace);
    Verdict::Forward(Forward { target: plan.target, head, guard: Box::new(plan.tunnel), report })
}

/// Runs the checks of the connection loop on one request and dispatches it. The response,
/// if Sibuna answers, is in the link's writer.
fn answer(
    link: &mut Link<'_, ClientWriter<&mut Vec<u8>>>,
    offer: &Offer<'_>,
    peer: &[u8],
    paths: &mut [u8],
) {
    link.writer.begin_response(false);
    let mut request = match parse_request(offer.head) {
        Ok(request) => request,
        Err(error) => {
            connection::reject_head(link, error);
            return;
        }
    };
    link.writer.begin_response(request.method == Method::Head);
    link.writer.set_own(crate::traffic::own_policy(link.server, link.ingress, &request));
    if connection::has_repeated_host(&request) {
        connection::reject_repeated_host(link);
        return;
    }
    request.body = offer.body;
    let (upload, declared) = match offer.declared {
        Some(0) => (Upload::declared(&request), 0),
        Some(length) => {
            (Upload::Length(length), usize::try_from(length).unwrap_or(UNKNOWN_LENGTH - 1))
        }
        // The length is unknown: the runtime sends the body chunked.
        None => (Upload::Chunked(Decoder::new()), UNKNOWN_LENGTH),
    };
    connection::dispatch(link, request, &[], upload, declared, peer, paths);
}

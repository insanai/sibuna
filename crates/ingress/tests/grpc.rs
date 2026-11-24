//! gRPC through the edge: an HTTP/2 client over TLS, the in-process decision, and an
//! HTTP/2 server pool. The four kinds of call must work as gRPC specifies them:
//! length-prefixed messages, `TE: trailers` on the request, and the status in trailers.
//! The edge never looks inside a message.
#![allow(clippy::unwrap_used)]

#[path = "support/grpc.rs"]
mod support;

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sibuna_ingress::{
    Decide, Egress, Forward, Handler, Identity, Ingress, Limits, Offer, Verdict,
};
use sibuna_lb::{Config, Edge, HttpRoutes, TlsOptions};
use support::{calls, fixture, server};

/// Admits every request as it was offered.
struct Admit {
    routes: HttpRoutes,
    decisions: AtomicUsize,
}

impl Decide for Admit {
    fn decide(&self, offer: &Offer<'_>) -> Verdict {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        let head = std::str::from_utf8(offer.head).unwrap();
        let path = head.split(' ').nth(1).unwrap();
        let host = format!("localhost:{}", offer.vip.port());
        let target = (0..4)
            .find_map(|revision| {
                let (host, path) = (host.as_bytes(), path.as_bytes());
                self.routes.select(offer.vip, offer.peer, host, path, revision)
            })
            .unwrap();
        Verdict::Forward(Forward { target, head: offer.head.to_vec(), guard: Box::new(()) })
    }
}

#[test]
fn every_kind_of_grpc_call_crosses_the_edge_to_an_http2_pool() {
    let servers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let origin = server(&servers, connections.clone());
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"grpc"}}}},"backends":{{"grpc":{{"mode":"http","http_version":"2",
        "servers":[{{"name":"origin","addr":"{origin}"}}]}}}}}}"#
    );
    let mut config = Config::parse(topology.as_bytes()).unwrap();
    let mut egress = Egress::new().unwrap();
    egress.configure(&mut config).unwrap();
    let mut edge = Edge::bind(config).unwrap();
    egress.commit();
    let tls = TlsOptions {
        cert_file: Some(fixture("localhost.pem")),
        key_file: Some(fixture("localhost.key")),
        ..TlsOptions::default()
    };
    let handoffs = Arc::new(AtomicUsize::new(0));
    let counted = handoffs.clone();
    let handler: Handler = Arc::new(move |_, _, _| {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let admit = Arc::new(Admit { routes: edge.http_routes(), decisions: AtomicUsize::new(0) });
    let identities = [(vip, Identity::load(&tls).unwrap())].into();
    let budget = edge.flow_budget();
    let ingress =
        Ingress::start(identities, budget, handler, Some(admit.clone()), Limits::default())
            .unwrap();
    ingress.attach(egress.directory());
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(20), calls(vip)).await.unwrap();
        });
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    runner.join().unwrap();
    assert_eq!(admit.decisions.load(Ordering::SeqCst), 6);
    // No call crossed the socket pair, and all of them shared one HTTP/2 session.
    assert_eq!(handoffs.load(Ordering::SeqCst), 0);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

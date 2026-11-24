//! gRPC through the edge: an HTTP/2 client over TLS, the in-process decision, and an
//! HTTP/2 server pool. The four kinds of call must work as gRPC specifies them:
//! length-prefixed messages, `TE: trailers` on the request, and the status in trailers.
//! The edge never looks inside a message.
#![allow(clippy::unwrap_used)]

#[path = "support/grpc.rs"]
mod support;

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sibuna_ingress::{
    Completion, Decide, Egress, Forward, Handler, Identity, Ingress, Limits, Offer, Report,
    Verdict,
};
use sibuna_lb::{Config, Edge, HttpRoutes, TlsOptions};
use support::{calls, fixture, server};

/// Admits every request as it was offered.
struct Admit {
    routes: HttpRoutes,
    decisions: AtomicUsize,
    /// Requests that asked for another server (SID 0019).
    retries: AtomicUsize,
    /// Moves that the runtime told a report of (SID 0019).
    moves: Arc<AtomicUsize>,
    /// What the runtime reported of each call (SID 0020).
    reports: Arc<Mutex<Vec<(&'static str, Completion)>>>,
}

/// Notes the outcome of one call.
struct Note {
    reports: Arc<Mutex<Vec<(&'static str, Completion)>>>,
    moves: Arc<AtomicUsize>,
    protocol: &'static str,
}

impl Report for Note {
    fn done(self: Box<Self>, completion: &Completion) {
        self.reports.lock().unwrap().push((self.protocol, *completion));
    }

    fn moved(&mut self, target: &sibuna_lb::HttpTarget) {
        let _ = target;
        self.moves.fetch_add(1, Ordering::SeqCst);
    }
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
        let note = Note {
            reports: self.reports.clone(),
            moves: self.moves.clone(),
            protocol: offer.protocol,
        };
        Verdict::Forward(Forward {
            target,
            head: offer.head.to_vec(),
            guard: Box::new(()),
            report: Some(Box::new(note)),
        })
    }

    fn retry(&self, failed: &sibuna_lb::HttpTarget) -> Option<sibuna_lb::HttpTarget> {
        self.retries.fetch_add(1, Ordering::SeqCst);
        self.routes.retry(failed)
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
    // Nothing listens on the first server. The first call finds its session closed and
    // moves to the second server before it sent a byte (SID 0019).
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"grpc"}}}},"backends":{{"grpc":{{"mode":"http","http_version":"2",
        "servers":[{{"name":"dead","addr":"{dead}"}},
        {{"name":"origin","addr":"{origin}"}}]}}}}}}"#
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
    let admit = Arc::new(Admit {
        routes: edge.http_routes(),
        decisions: AtomicUsize::new(0),
        retries: AtomicUsize::new(0),
        moves: Arc::default(),
        reports: Arc::default(),
    });
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
    // The dead server was tried once and then marked. Its call was told of the move.
    assert_eq!(admit.retries.load(Ordering::SeqCst), 1);
    assert_eq!(admit.moves.load(Ordering::SeqCst), 1);
    // No call crossed the socket pair, and all of them shared one HTTP/2 session.
    assert_eq!(handoffs.load(Ordering::SeqCst), 0);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    // Every call on the shared session is reported once, when its trailers or its end
    // passed, with the status and the wait for the response head (SID 0020).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while admit.reports.lock().unwrap().len() < 6 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let reports = admit.reports.lock().unwrap();
    assert_eq!(reports.len(), 6, "{reports:?}");
    for (protocol, completion) in reports.iter() {
        assert_eq!((*protocol, completion.status), ("h2", 200), "{completion:?}");
        assert!(completion.first_byte.is_some(), "{completion:?}");
    }
    assert!(reports.iter().any(|(_, completion)| completion.bytes_out > 0), "{reports:?}");
}

//! gRPC through the edge: an HTTP/2 client over TLS, the in-process decision, and an
//! HTTP/2 server pool. The four kinds of call must work as gRPC specifies them:
//! length-prefixed messages, `TE: trailers` on the request, and the status in trailers.
//! The edge never looks inside a message.
#![allow(clippy::unwrap_used)]

#[path = "../../lb/tests/free/mod.rs"]
mod free;
#[path = "support/grpc.rs"]
mod support;

use std::future::Future;
use std::net::{SocketAddr, TcpListener};
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

/// An edge with one TLS frontend and one HTTP/2 pool, and what its tests count.
struct Bench {
    vip: SocketAddr,
    edge: Edge,
    ingress: Ingress,
    admit: Arc<Admit>,
    handoffs: Arc<AtomicUsize>,
    _egress: Egress,
}

/// Starts an edge whose pool has the servers `servers`, a list of JSON objects.
fn bench(servers: &str) -> Bench {
    // An address of its own: a port that was bound and released may be taken meanwhile.
    let vip = free::tcp();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"grpc"}}}},"backends":{{"grpc":{{"mode":"http","http_version":"2",
        "servers":[{servers}]}}}}}}"#
    );
    let mut config = Config::parse(topology.as_bytes()).unwrap();
    let mut egress = Egress::new().unwrap();
    egress.configure(&mut config).unwrap();
    let edge = Edge::bind(config).unwrap();
    egress.commit();
    let tls = TlsOptions {
        cert_file: Some(fixture("localhost.pem")),
        key_file: Some(fixture("localhost.key")),
        ..TlsOptions::default()
    };
    let handoffs = Arc::new(AtomicUsize::new(0));
    let counted = handoffs.clone();
    let handler: Handler = Arc::new(move |_, _, _, _| {
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
    Bench { vip, edge, ingress, admit, handoffs, _egress: egress }
}

impl Bench {
    /// Steps the edge until `client` ends, and returns what it returned.
    fn run<T, F>(&mut self, client: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let runner = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(20), client).await.unwrap()
            })
        });
        while !runner.is_finished() {
            self.edge.step().unwrap();
            for (bind, stream, permit) in self.edge.accepted_http() {
                self.ingress.accept(bind, stream, permit);
            }
        }
        runner.join().unwrap()
    }
}

fn servers_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

#[test]
fn every_kind_of_grpc_call_crosses_the_edge_to_an_http2_pool() {
    let servers = servers_runtime();
    let connections = Arc::new(AtomicUsize::new(0));
    let origin = server(&servers, connections.clone());
    // Nothing listens on the first server. The first call finds its session closed and
    // moves to the second server before it sent a byte (SID 0019).
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut bench = bench(&format!(
        r#"{{"name":"dead","addr":"{dead}"}},{{"name":"origin","addr":"{origin}"}}"#
    ));
    let vip = bench.vip;
    bench.run(calls(vip));
    let Bench { admit, handoffs, .. } = &bench;
    assert_eq!(admit.decisions.load(Ordering::SeqCst), 6);
    // The dead server was tried once and then marked. Its call was told of the move.
    assert_eq!(admit.retries.load(Ordering::SeqCst), 1);
    assert_eq!(admit.moves.load(Ordering::SeqCst), 1);
    // No call crossed the socket pair, and all of them shared one HTTP/2 session.
    assert_eq!(handoffs.load(Ordering::SeqCst), 0);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    assert_reports(admit);
}

/// Every call on the shared session is reported once, when its trailers or its end
/// passed, with the status and the wait for the response head (SID 0020).
fn assert_reports(admit: &Admit) {
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

/// A server that completes the HTTP/2 preface and closes the connection soon after,
/// before it answers anything. It counts its connections.
fn breaker(runtime: &tokio::runtime::Runtime, connections: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    runtime.spawn(async move {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // An empty SETTINGS frame is the whole server preface.
                let _ = socket.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
        }
    });
    address
}

#[test]
fn a_safe_request_moves_when_its_session_fails_after_the_send() {
    let servers = servers_runtime();
    let (broken, good) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let first = breaker(&servers, broken.clone());
    let second = server(&servers, good.clone());
    let mut bench = bench(&format!(
        r#"{{"name":"breaker","addr":"{first}"}},{{"name":"origin","addr":"{second}"}}"#
    ));
    let vip = bench.vip;
    let status = bench.run(async move {
        let mut sender = support::connect(vip).await;
        let url = format!("https://localhost:{}/echo.Echo/Missing", vip.port());
        let empty = http_body_util::Empty::<bytes::Bytes>::new();
        let body = http_body_util::BodyExt::boxed_unsync(empty);
        let request = hyper::Request::get(url).body(body).unwrap();
        let response = sender.send_request(request).await.unwrap();
        (response.status().as_u16(), response.headers().contains_key("x-version"))
    });
    // The answer is that of the second server, not our 502.
    assert_eq!(status, (200, true));
    // The first server lost the request on its shared session and on a fresh one. Only
    // then did the request move, once.
    assert_eq!(broken.load(Ordering::SeqCst), 2);
    assert_eq!(bench.admit.retries.load(Ordering::SeqCst), 1);
    assert_eq!(bench.admit.moves.load(Ordering::SeqCst), 1);
    assert_eq!(good.load(Ordering::SeqCst), 1);
}

/// An HTTP/2 server that refuses every stream with `REFUSED_STREAM`. It counts the
/// streams it refused.
fn refuser(runtime: &tokio::runtime::Runtime, refusals: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let refusals = refusals.clone();
            tokio::spawn(async move {
                let Ok(mut session) = h2::server::handshake(socket).await else { return };
                while let Some(Ok((_request, mut respond))) = session.accept().await {
                    refusals.fetch_add(1, Ordering::SeqCst);
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
            });
        }
    });
    address
}

/// Sends a `POST` with a small body through a bench whose first server is `first`, and
/// returns the status and whether the answer is that of the good server.
fn post_through(first: SocketAddr, second: SocketAddr) -> ((u16, bool), Bench) {
    let mut bench = bench(&format!(
        r#"{{"name":"first","addr":"{first}"}},{{"name":"origin","addr":"{second}"}}"#
    ));
    let vip = bench.vip;
    let status = bench.run(async move {
        let mut sender = support::connect(vip).await;
        let url = format!("https://localhost:{}/echo.Echo/Missing", vip.port());
        let whole = http_body_util::Full::new(bytes::Bytes::from_static(b"abc"));
        let body = http_body_util::BodyExt::boxed_unsync(whole);
        let request = hyper::Request::post(url).body(body).unwrap();
        let response = sender.send_request(request).await.unwrap();
        (response.status().as_u16(), response.headers().contains_key("x-version"))
    });
    (status, bench)
}

#[test]
fn a_post_moves_only_when_its_server_refused_the_stream() {
    let servers = servers_runtime();
    let (refused, good) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let second = server(&servers, good.clone());
    // The server said that it did not act on the request. So the POST is sent again:
    // once more to the same server, and then to the next one.
    let (status, bench) = post_through(refuser(&servers, refused.clone()), second);
    assert_eq!(status, (200, true));
    assert_eq!(refused.load(Ordering::SeqCst), 2);
    assert_eq!(bench.admit.moves.load(Ordering::SeqCst), 1);
    drop(bench);
    // A session that is lost proves nothing: the server may have acted on the POST.
    let broken = Arc::new(AtomicUsize::new(0));
    let (status, bench) = post_through(breaker(&servers, broken.clone()), second);
    assert_eq!(status.0, 502);
    assert_eq!(bench.admit.moves.load(Ordering::SeqCst), 0);
}

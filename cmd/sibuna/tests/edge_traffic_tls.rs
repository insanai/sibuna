//! Traffic management through the edge binary over TLS (SID 0019): an HTTP/2 client on a
//! TLS frontend gets failover, a `Secure` sticky cookie, the header edits and HSTS, on
//! the answers of the server and on our own.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;
mod traffic;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use support::{connect, fixture};
use traffic::{Origin, Topology, both, refused};

/// What a test reads of one answer.
struct Answer {
    status: u16,
    fields: Vec<(String, String)>,
    text: String,
}

impl Answer {
    /// The values of the field `name`.
    fn all(&self, name: &str) -> Vec<&str> {
        let named = self.fields.iter().filter(|(key, _)| key == name);
        named.map(|(_, value)| value.as_str()).collect()
    }

    /// The sticky cookie as `name=token`, with its attributes.
    fn sticky(&self) -> Option<(&str, &str)> {
        let cookies = self.all("set-cookie");
        let ours = cookies.into_iter().find(|cookie| !cookie.starts_with("app="))?;
        ours.split_once("; ")
    }
}

/// One request over a new HTTP/2 connection to the TLS frontend at `vip`.
async fn send(vip: SocketAddr, method: &str, path: &str, cookie: &str, body: &[u8]) -> Answer {
    let mut client = connect(vip).await;
    let url = format!("https://localhost:{}{path}", vip.port());
    let mut request = Request::builder().method(method).uri(url);
    if !cookie.is_empty() {
        request = request.header("cookie", cookie);
    }
    let body = Full::new(Bytes::copy_from_slice(body)).boxed_unsync();
    let response = client.send_request(request.body(body).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let fields = response.headers().iter();
    let fields = fields.map(|(name, value)| (name.to_string(), value.to_str().unwrap().into()));
    let fields = fields.collect();
    let text = response.into_body().collect().await.map(|body| body.to_bytes());
    Answer { status, fields, text: String::from_utf8(text.unwrap_or_default().to_vec()).unwrap() }
}

/// The members of a TLS frontend with the HTTP policy under test.
fn frontend() -> String {
    format!(
        r#""tls":{{"cert_file":"{}","key_file":"{}"}},"hsts":{{"max_age":600}},"max_body":"1k",
        "request_headers":{{"set":{{"X-Tenant":"blue"}}}},
        "response_headers":{{"set":{{"X-Frame-Options":"DENY"}},"remove":["Server"]}},
        "routes":[{{"path_prefix":"/open","backend":"app","hsts":false}}],"#,
        fixture("localhost.pem"),
        fixture("localhost.key")
    )
}

const HSTS: &str = "max-age=600";

#[test]
fn an_http2_client_on_a_tls_frontend_gets_the_whole_traffic_policy() {
    let (first, second) = (Origin::start("first"), Origin::start("second"));
    both(|event_loop| {
        // Round robin begins at the server that refuses its connections.
        let servers = [refused(), first.address, second.address];
        let pool = r#""balance":{"kind":"round_robin"},"sticky":"cookie","#;
        let edge = Topology::new(&servers).frontend(&frontend()).backend(pool).start(event_loop);
        let vip = edge.vip;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let case = async {
            // Failover: the request leaves the refused server and is answered.
            let answer = send(vip, "GET", "/cookie", "", b"").await;
            assert_eq!(answer.status, 200, "{event_loop}");
            let home = answer.text.clone();
            assert!(home == "first" || home == "second", "{home}");
            // The edits of the response and HSTS, beside the cookie of the application.
            assert_eq!(answer.all("strict-transport-security"), [HSTS]);
            assert_eq!(answer.all("x-frame-options"), ["DENY"]);
            assert!(answer.all("server").is_empty());
            assert!(answer.all("set-cookie").contains(&"app=1"));
            // The sticky cookie is `Secure` on a TLS frontend.
            let (pair, attributes) = answer.sticky().expect("a sticky cookie");
            assert!(attributes.contains("Secure") && attributes.contains("HttpOnly"));
            // The cookie holds the client on its server, whatever round robin would do.
            for _ in 0..6 {
                let again = send(vip, "GET", "/who", pair, b"").await;
                assert_eq!((again.status, again.text.as_str()), (200, home.as_str()));
                assert!(again.sticky().is_none(), "the cookie is not sent again");
            }
            // The edit of the request reaches the server.
            let head = send(vip, "GET", "/head", pair, b"").await.text;
            assert!(head.contains("x-tenant: blue\n") || head.contains("X-Tenant: blue\n"));
            // Our own answer carries HSTS too, and nothing that describes a server.
            let refused = send(vip, "POST", "/length", pair, &[b'x'; 2000]).await;
            assert_eq!(refused.status, 413, "{event_loop}");
            assert_eq!(refused.all("strict-transport-security"), [HSTS], "{event_loop}");
            assert!(refused.all("x-frame-options").is_empty());
            // An answer of our own has the route of the path in normal form. This path
            // is under `/open`, which has no HSTS, although it does not begin with it.
            let open = send(vip, "POST", "/a/../open/length", pair, &[b'x'; 2000]).await;
            assert_eq!(open.status, 413, "{event_loop}");
            assert!(open.all("strict-transport-security").is_empty(), "{event_loop}");
            // The server that was left counts the request that moved.
            let metrics = send(vip, "GET", "/__sibuna/metrics", "", b"").await.text;
            let moved = "sibuna_edge_server_failovers_total{backend=\"app\",server=\"s0\"} ";
            let count = metrics.split(moved).nth(1).and_then(|rest| rest.lines().next());
            assert!(count.is_some_and(|count| count != "0"), "{event_loop}\n{metrics}");
        };
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(30), case).await.unwrap();
        });
    });
}

#[test]
fn an_http2_request_with_a_kept_body_moves_when_its_method_is_idempotent() {
    both(|event_loop| {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        // Each case has its own edge, so the server that closes is chosen first.
        let case = |members: &'static str, method: &'static str, body: &'static [u8]| {
            let closing = Origin::start("closing");
            closing.closing.store(true, std::sync::atomic::Ordering::SeqCst);
            let good = Origin::start("good");
            let servers = [closing.address, good.address];
            let topology = Topology::new(&servers).frontend(&frontend()).backend(members);
            let edge = topology.start(event_loop);
            let answer = runtime.block_on(async {
                let sent = send(edge.vip, method, "/length", "", body);
                tokio::time::timeout(Duration::from_secs(20), sent).await.unwrap()
            });
            assert_eq!(
                closing.requests.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{event_loop} {method}"
            );
            (answer.status, answer.text, good.requests.load(std::sync::atomic::Ordering::SeqCst))
        };
        // The first server read the PUT and closed. The second gets the whole body.
        assert_eq!(case("", "PUT", b"abc"), (200, "3".into(), 1), "{event_loop}");
        // A body above `retry_body` is not kept.
        assert_eq!(case(r#""retry_body":2,"#, "PUT", b"abc").0, 502, "{event_loop}");
        // A POST may have been carried out, so no other server sees it.
        let post = case("", "POST", b"abc");
        assert_eq!((post.0, post.2), (502, 0), "{event_loop}");
    });
}

//! A gRPC client and server that speak the wire protocol by hand, with opaque message
//! bytes in place of protocol buffers. The tests of the ingress crate and of the binary
//! share this file.
#![allow(dead_code, clippy::unwrap_used)]

use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::sync::mpsc;

type Body = UnsyncBoxBody<Bytes, Infallible>;
type Frames = mpsc::Sender<Frame<Bytes>>;

/// One gRPC message on the wire: a flag byte, a length and the bytes.
fn message(bytes: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + bytes.len());
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.freeze()
}

/// Splits complete messages off the front of `held`.
fn take_messages(held: &mut BytesMut) -> Vec<Bytes> {
    let mut messages = Vec::new();
    while held.len() >= 5 {
        let length = u32::from_be_bytes([held[1], held[2], held[3], held[4]]) as usize;
        if held.len() < 5 + length {
            break;
        }
        held.advance(5);
        messages.push(held.split_to(length).freeze());
    }
    messages
}

/// A body fed through a channel, so that frames leave when the test sends them.
fn channel() -> (Frames, Body) {
    let (send, receive) = mpsc::channel::<Frame<Bytes>>(16);
    let frames = futures_util::stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|frame| (Ok::<_, Infallible>(frame), receive))
    });
    (send, StreamBody::new(frames).boxed_unsync())
}

fn status(code: &str) -> Frame<Bytes> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_str(code).unwrap());
    Frame::trailers(trailers)
}

/// The server side of one call. It answers each kind of call as a gRPC server does.
async fn serve_call(request: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_owned();
    let saw_te = request.headers().get("te").is_some_and(|te| te == "trailers");
    let mut response = Response::builder()
        .header("content-type", "application/grpc")
        .header("x-saw-te", if saw_te { "yes" } else { "no" })
        .header("x-version", format!("{:?}", request.version()));
    if path == "/echo.Echo/Missing" {
        // A call that fails at once has no body: the status is in the header block.
        response = response.header("grpc-status", "5").header("grpc-message", "no such thing");
        return Ok(response.body(http_body_util::Empty::new().boxed_unsync()).unwrap());
    }
    let (send, body) = channel();
    let mut upload = request.into_body();
    tokio::spawn(async move {
        let mut held = BytesMut::new();
        let mut count = 0usize;
        while let Some(Ok(frame)) = upload.frame().await {
            let Ok(data) = frame.into_data() else { continue };
            held.extend_from_slice(&data);
            for received in take_messages(&mut held) {
                count += 1;
                match path.as_str() {
                    // One answer for each message, as soon as it arrives.
                    "/echo.Echo/Chat" | "/echo.Echo/Unary" => {
                        send.send(Frame::data(message(&received))).await.unwrap();
                    }
                    // The message names how many answers follow.
                    "/echo.Echo/Stream" => {
                        for i in 0..received[0] {
                            send.send(Frame::data(message(&[i; 100]))).await.unwrap();
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                    // One answer at the end: the number of messages received.
                    _ => {}
                }
            }
        }
        if path == "/echo.Echo/Collect" {
            send.send(Frame::data(message(&[count as u8]))).await.unwrap();
        }
        send.send(status("0")).await.unwrap();
    });
    Ok(response.body(body).unwrap())
}

/// A gRPC server on cleartext HTTP/2. It counts its connections.
pub fn server(runtime: &tokio::runtime::Runtime, connections: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service_fn(serve_call))
                    .await;
            });
        }
    });
    address
}

/// A file of the TLS test data. Both users of this file sit two levels below the root.
pub fn fixture(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../../crates/tls/tests/data").join(name).to_str().unwrap().to_owned()
}

/// Whether a new TLS connection to the edge completes its handshake.
pub async fn handshakes(
    vip: SocketAddr,
) -> Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(fixture("ca.pem")).unwrap()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(trust)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(vip).await.ok()?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector.connect("localhost".try_into().unwrap(), tcp).await.ok()
}

/// A gRPC client connection: HTTP/2 over TLS to the edge.
pub async fn connect(vip: SocketAddr) -> hyper::client::conn::http2::SendRequest<Body> {
    connect_after(vip, b"").await
}

/// As [`connect`], with `preface` written before the TLS handshake: a PROXY header.
pub async fn connect_after(
    vip: SocketAddr,
    preface: &[u8],
) -> hyper::client::conn::http2::SendRequest<Body> {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(fixture("ca.pem")).unwrap()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(trust)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut tcp, preface).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    sender
}

/// The client side of one call: the request frames to send and the response.
struct Call {
    send: Option<Frames>,
    response: Response<Incoming>,
    held: BytesMut,
}

impl Call {
    async fn start(
        client: &mut hyper::client::conn::http2::SendRequest<Body>,
        vip: SocketAddr,
        method: &str,
        first: Option<&[u8]>,
    ) -> Call {
        let (send, body) = channel();
        if let Some(first) = first {
            send.send(Frame::data(message(first))).await.unwrap();
        }
        let request =
            Request::post(format!("https://localhost:{}/echo.Echo/{method}", vip.port()))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(body)
                .unwrap();
        let response = client.send_request(request).await.unwrap();
        assert_eq!(response.status(), 200, "{method}");
        assert_eq!(response.headers()["content-type"], "application/grpc", "{method}");
        Call { send: Some(send), response, held: BytesMut::new() }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.send.as_ref().unwrap().send(Frame::data(message(bytes))).await.unwrap();
    }

    /// Ends the request: the client has no more messages.
    fn finish(&mut self) {
        self.send = None;
    }

    /// The next message of the response.
    async fn receive(&mut self) -> Bytes {
        loop {
            if let Some(found) = take_messages(&mut self.held).into_iter().next() {
                return found;
            }
            let frame = self.response.body_mut().frame().await.unwrap().unwrap();
            self.held.extend_from_slice(&frame.into_data().unwrap());
        }
    }

    /// The status in the trailers, which end the response.
    async fn status(mut self) -> String {
        assert!(self.held.is_empty(), "messages after the last one read");
        let frame = self.response.body_mut().frame().await.unwrap().unwrap();
        let trailers = frame.into_trailers().unwrap();
        assert!(self.response.body_mut().frame().await.is_none());
        trailers["grpc-status"].to_str().unwrap().to_owned()
    }
}

pub async fn calls(vip: SocketAddr) {
    let mut client = connect(vip).await;
    // Unary: one message each way, then the status.
    let mut call = Call::start(&mut client, vip, "Unary", Some(b"hello")).await;
    // The server saw a real gRPC request: HTTP/2 with TE: trailers.
    assert_eq!(call.response.headers()["x-saw-te"], "yes");
    assert_eq!(call.response.headers()["x-version"], "HTTP/2.0");
    call.finish();
    assert_eq!(call.receive().await, "hello");
    assert_eq!(call.status().await, "0");

    // Server streaming: one request message, forty answers.
    let mut call = Call::start(&mut client, vip, "Stream", Some(&[40])).await;
    call.finish();
    for i in 0..40 {
        assert_eq!(call.receive().await, vec![i; 100]);
    }
    assert_eq!(call.status().await, "0");

    // Client streaming: thirty messages over time, one answer after the last.
    let mut call = Call::start(&mut client, vip, "Collect", None).await;
    for i in 0..30u8 {
        call.send(&[i; 2000]).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    call.finish();
    assert_eq!(call.receive().await, vec![30]);
    assert_eq!(call.status().await, "0");

    // Bidirectional: the client sends the next message only after it read the answer
    // to the last one, so nothing on the way may wait for the end of either side.
    let mut call = Call::start(&mut client, vip, "Chat", Some(b"turn 0")).await;
    assert_eq!(call.receive().await, "turn 0");
    for turn in 1..20 {
        let text = format!("turn {turn}");
        call.send(text.as_bytes()).await;
        assert_eq!(call.receive().await, text);
    }
    call.finish();
    assert_eq!(call.status().await, "0");

    // A large message crosses whole: 300,000 bytes each way.
    let big = vec![7u8; 300_000];
    let mut call = Call::start(&mut client, vip, "Unary", Some(&big)).await;
    call.finish();
    assert_eq!(call.receive().await, big);
    assert_eq!(call.status().await, "0");

    // A call that fails at once: the status is in the header block and no body follows.
    let (_send, body) = channel();
    let request = Request::post(format!("https://localhost:{}/echo.Echo/Missing", vip.port()))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body)
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["grpc-status"], "5");
    assert_eq!(response.headers()["grpc-message"], "no such thing");
    assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
}

/// A bidirectional call of `turns` messages with `pause` before each. Every message
/// must come back.
pub async fn slow_conversation(vip: SocketAddr, turns: usize, pause: Duration) {
    let mut client = connect(vip).await;
    let mut call = Call::start(&mut client, vip, "Chat", Some(b"turn 0")).await;
    assert_eq!(call.receive().await, "turn 0");
    for turn in 1..turns {
        tokio::time::sleep(pause).await;
        let text = format!("turn {turn}");
        call.send(text.as_bytes()).await;
        assert_eq!(call.receive().await, text);
    }
    call.finish();
    assert_eq!(call.status().await, "0");
}

/// Opens a call on which neither side sends a message, and returns how long it took
/// until the response ended. It must end without a status: the call was cut.
pub async fn silence(vip: SocketAddr) -> Duration {
    let mut client = connect(vip).await;
    let mut call = Call::start(&mut client, vip, "Collect", None).await;
    let started = std::time::Instant::now();
    match call.response.body_mut().frame().await {
        None | Some(Err(_)) => {}
        Some(Ok(frame)) => panic!("a silent call received {frame:?}"),
    }
    started.elapsed()
}

//! Connections to a local rustls server that presents the fixed certificates of
//! `tests/data` (see its README.txt): accepted, refused for the wrong name, an untrusted
//! or expired certificate, and cut short by the deadline.

// Test helpers panic on failed setup, like the tests that call them.
#![allow(clippy::unwrap_used)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion};
use sibuna_tls::{CertificateProblem, Connector, TlsError, Trust, connect, connect_plain};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

fn test_ca() -> Connector {
    Connector::load(&Trust::from_ca_file(data("ca.pem"))).unwrap()
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn server_config(leaf: &str, versions: &[&'static SupportedProtocolVersion]) -> ServerConfig {
    let certificate = CertificateDer::from_pem_file(data(&format!("{leaf}.pem"))).unwrap();
    let key = PrivateKeyDer::from_pem_file(data(&format!("{leaf}.key"))).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap()
}

/// What the test server does after the handshake.
#[derive(Clone, Copy)]
enum After {
    /// Reads a request head and answers [`RESPONSE`].
    Respond,
    /// Says nothing for two seconds.
    Stall,
}

/// Serves one TLS connection on 127.0.0.1 with the certificate `leaf`. The thread returns
/// the request head it read, or the server-side error (a refused client shows here).
fn serve_once(leaf: &str, after: After) -> (SocketAddr, JoinHandle<Result<Vec<u8>, String>>) {
    serve_with(server_config(leaf, rustls::DEFAULT_VERSIONS), after)
}

fn serve_with(
    config: ServerConfig,
    after: After,
) -> (SocketAddr, JoinHandle<Result<Vec<u8>, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(config);
    let handle = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
        let connection = ServerConnection::new(config).map_err(|e| e.to_string())?;
        let mut stream = StreamOwned::new(connection, tcp);
        let mut head = Vec::new();
        if let After::Stall = after {
            stream.conn.complete_io(&mut stream.sock).map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_secs(2));
            return Ok(head);
        }
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).map_err(|e| e.to_string())?;
            head.push(byte[0]);
        }
        stream.write_all(RESPONSE).map_err(|e| e.to_string())?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|e| e.to_string())?;
        Ok(head)
    });
    (address, handle)
}

fn get(stream: &mut impl ReadWrite, host: &str) -> io::Result<Vec<u8>> {
    write!(stream, "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn certificate_problem(result: Result<sibuna_tls::TlsStream, TlsError>) -> CertificateProblem {
    match result {
        Err(TlsError::Certificate { problem, .. }) => problem,
        Err(other) => panic!("expected a certificate error, got {other}"),
        Ok(_) => panic!("expected a certificate error, got a connection"),
    }
}

#[test]
fn a_server_signed_by_the_trusted_ca_is_accepted() {
    let connector = test_ca();
    assert_eq!(connector.root_count(), 1);
    for name in ["localhost", "127.0.0.1"] {
        let (address, server) = serve_once("localhost", After::Respond);
        let mut stream = connector.connect_address(address, name, soon()).unwrap();
        assert_eq!(get(&mut stream, name).unwrap(), RESPONSE);
        let head = server.join().unwrap().unwrap();
        assert!(head.starts_with(b"GET / HTTP/1.1\r\n"));
    }
}

#[test]
fn the_staged_api_accepts_a_connected_socket() {
    let (address, server) = serve_once("localhost", After::Respond);
    let tcp = TcpStream::connect(address).unwrap();
    let mut stream = test_ca().connect(tcp, "localhost", soon()).unwrap();
    assert_eq!(stream.tcp().peer_addr().unwrap(), address);
    assert_eq!(get(&mut stream, "localhost").unwrap(), RESPONSE);
    server.join().unwrap().unwrap();
}

#[test]
fn the_one_call_path_resolves_and_connects() {
    // `localhost` may resolve to ::1 first; the server listens on 127.0.0.1 only, so this
    // also shows that a refused address is skipped for the next one.
    let (address, server) = serve_once("localhost", After::Respond);
    let trust = Trust::from_ca_file(data("ca.pem"));
    let mut stream = connect("localhost", address.port(), &trust, soon()).unwrap();
    assert_eq!(get(&mut stream, "localhost").unwrap(), RESPONSE);
    server.join().unwrap().unwrap();
}

#[test]
fn tls_1_2_servers_are_accepted() {
    let config = server_config("localhost", &[&rustls::version::TLS12]);
    let (address, server) = serve_with(config, After::Respond);
    let mut stream = test_ca().connect_address(address, "localhost", soon()).unwrap();
    assert_eq!(get(&mut stream, "localhost").unwrap(), RESPONSE);
    server.join().unwrap().unwrap();
}

#[test]
fn a_wrong_host_name_is_refused() {
    let (address, server) = serve_once("wrong-name", After::Respond);
    let refused = test_ca().connect_address(address, "localhost", soon());
    assert_eq!(certificate_problem(refused), CertificateProblem::NameMismatch);
    assert!(server.join().unwrap().is_err());
    // The right certificate, asked for under another name.
    let (address, server) = serve_once("localhost", After::Respond);
    let refused = test_ca().connect_address(address, "peer.example", soon());
    let problem = certificate_problem(refused);
    assert_eq!(problem, CertificateProblem::NameMismatch);
    assert!(server.join().unwrap().is_err());
}

#[test]
fn an_untrusted_issuer_is_refused() {
    let (address, server) = serve_once("untrusted", After::Respond);
    let refused = test_ca().connect_address(address, "localhost", soon());
    assert_eq!(certificate_problem(refused), CertificateProblem::UnknownIssuer);
    assert!(server.join().unwrap().is_err());
}

#[test]
fn the_private_ca_is_not_trusted_through_the_system_roots() {
    let system = match Connector::load(&Trust::default()) {
        Ok(connector) => connector,
        Err(error @ TlsError::SystemRoots(_)) => {
            eprintln!("skipped: no system trust store here ({error})");
            return;
        }
        Err(error) => panic!("{error}"),
    };
    assert!(system.root_count() > 0);
    let (address, server) = serve_once("localhost", After::Respond);
    let refused = system.connect_address(address, "localhost", soon());
    let error = refused.err().unwrap();
    assert!(error.hint().contains("CA file"), "{}", error.hint());
    assert_eq!(error.title(), "UNKNOWN CERTIFICATE ISSUER");
    assert!(server.join().unwrap().is_err());
}

#[test]
fn an_expired_certificate_is_refused_with_a_hint() {
    let (address, server) = serve_once("expired", After::Respond);
    let refused = test_ca().connect_address(address, "localhost", soon());
    let error = refused.err().unwrap();
    assert!(
        matches!(error, TlsError::Certificate { problem: CertificateProblem::Expired, .. }),
        "{error}"
    );
    assert!(error.hint().contains("expired"));
    assert!(server.join().unwrap().is_err());
}

#[test]
fn the_deadline_ends_a_stalled_handshake() {
    // The listener's backlog completes the TCP connection, but nothing ever answers the
    // ClientHello.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(300);
    let refused = test_ca().connect_address(address, "localhost", deadline);
    let elapsed = started.elapsed();
    assert!(matches!(refused, Err(TlsError::HandshakeTimeout)), "{:?}", refused.err());
    assert!(elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3));
    drop(listener);
    let past = test_ca().connect_address(address, "localhost", Instant::now());
    assert!(matches!(past, Err(TlsError::ConnectTimeout)));
}

#[test]
fn the_deadline_covers_the_exchange() {
    let (address, server) = serve_once("localhost", After::Stall);
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut stream = test_ca().connect_address(address, "localhost", deadline).unwrap();
    assert_eq!(stream.deadline(), Some(deadline));
    let mut buffer = [0u8; 16];
    let error = stream.read(&mut buffer).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() >= deadline);
    let error = stream.write(b"late").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    stream.set_deadline(None).unwrap();
    assert_eq!(stream.tcp().read_timeout().unwrap(), None);
    server.join().unwrap().unwrap();
}

#[test]
fn a_server_that_closes_during_the_handshake_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || drop(listener.accept().unwrap()));
    let refused = test_ca().connect_address(address, "localhost", soon());
    assert!(matches!(refused, Err(TlsError::Closed | TlsError::Io(_))), "{:?}", refused.err());
    server.join().unwrap();
}

#[test]
fn plain_http_only_to_literal_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let tcp = connect_plain("127.0.0.1", port, soon()).unwrap();
    assert_eq!(tcp.peer_addr().unwrap().port(), port);
    // Refused before connecting: TEST-NET-1 would otherwise hang until the deadline.
    let started = Instant::now();
    let refused = connect_plain("192.0.2.1", 80, soon());
    assert!(matches!(refused, Err(TlsError::PlaintextRefused(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(sibuna_tls::is_plaintext_allowed("[::1]"));
    assert!(!sibuna_tls::is_plaintext_allowed("localhost"));
}

#[test]
fn invalid_server_names_are_refused_before_connecting() {
    let started = Instant::now();
    let refused = test_ca().connect_address("192.0.2.1:443".parse().unwrap(), "a b", soon());
    assert!(matches!(refused, Err(TlsError::InvalidServerName(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// Needs the network: fetches the response head of https://github.com with the system
/// roots. Skips (passes) when the network or the system store is unavailable; a
/// certificate failure still fails.
#[test]
#[ignore = "needs network access"]
fn github_headers_with_system_roots() {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stream = match connect("github.com", 443, &Trust::default(), deadline) {
        Ok(stream) => stream,
        Err(
            error @ (TlsError::Unresolved(_)
            | TlsError::Connect(_)
            | TlsError::ConnectTimeout
            | TlsError::SystemRoots(_)),
        ) => {
            eprintln!("skipped: {error}");
            return;
        }
        Err(error) => panic!("{}: {error}\nHint: {}", error.title(), error.hint()),
    };
    write!(stream, "HEAD / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut head = vec![0u8; 4096];
    let length = stream.read(&mut head).unwrap();
    let head = String::from_utf8_lossy(&head[..length]);
    assert!(head.starts_with("HTTP/1.1 "), "{head}");
    eprintln!("{}", head.lines().next().unwrap_or_default());
}

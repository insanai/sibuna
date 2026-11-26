//! The key exchange that `sibuna_tls::provider()` negotiates (SID 0035): in memory with
//! rustls on both sides, and with OpenSSL 3.5 or later as the peer when it is installed.

// Test helpers panic on failed setup, like the tests that call them.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, NamedGroup, RootCertStore, ServerConfig,
    ServerConnection, SupportedProtocolVersion,
};
use sibuna_tls::{Connector, Trust, provider};

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

fn server(provider: CryptoProvider) -> Arc<ServerConfig> {
    let certificate = CertificateDer::from_pem_file(data("localhost.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_file(data("localhost.key")).unwrap();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    Arc::new(config)
}

fn client(
    provider: CryptoProvider,
    versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(data("ca.pem")).unwrap()).unwrap();
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Runs a handshake in memory and returns the group and the kind of handshake.
fn handshake(client: ClientConfig, server: Arc<ServerConfig>) -> (NamedGroup, HandshakeKind) {
    let name = ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(Arc::new(client), name).unwrap();
    let mut server = ServerConnection::new(server).unwrap();
    let mut wire = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        wire.clear();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets().unwrap();
    }
    let group = client.negotiated_key_exchange_group().unwrap().name();
    assert_eq!(server.negotiated_key_exchange_group().unwrap().name(), group);
    (group, client.handshake_kind().unwrap())
}

const TLS13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];
const BOTH: &[&SupportedProtocolVersion] = rustls::DEFAULT_VERSIONS;

fn ring() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[test]
fn sibuna_on_both_sides_negotiates_the_hybrid_group_in_one_round_trip() {
    let (group, kind) = handshake(client(provider(), BOTH), server(provider()));
    assert_eq!(group, NamedGroup::X25519MLKEM768);
    assert_eq!(kind, HandshakeKind::Full);
}

#[test]
fn a_server_without_the_group_gets_x25519_with_no_retry() {
    let (group, kind) = handshake(client(provider(), BOTH), server(ring()));
    assert_eq!(group, NamedGroup::X25519);
    assert_eq!(kind, HandshakeKind::Full);
}

#[test]
fn a_client_without_the_group_negotiates_as_before() {
    let before = handshake(client(ring(), BOTH), server(ring()));
    let after = handshake(client(ring(), BOTH), server(provider()));
    assert_eq!(after, before);
    assert_eq!(after, (NamedGroup::X25519, HandshakeKind::Full));
}

#[test]
fn tls_1_2_never_uses_the_hybrid_group() {
    let (group, _) = handshake(client(provider(), TLS12), server(provider()));
    assert_eq!(group, NamedGroup::X25519);
}

#[test]
fn the_connector_offers_the_hybrid_group() {
    let connector = Connector::load(&Trust::from_ca_file(data("ca.pem"))).unwrap();
    let config = (*connector.client_config()).clone();
    let (group, _) = handshake(config, server(provider()));
    assert_eq!(group, NamedGroup::X25519MLKEM768);
    let (group, _) = handshake(client(provider(), TLS13), server(provider()));
    assert_eq!(group, NamedGroup::X25519MLKEM768);
}

/// Whether the installed `openssl` knows X25519MLKEM768 (OpenSSL 3.5 and later).
fn openssl_has_the_group() -> bool {
    let listed = Command::new("openssl").args(["list", "-kem-algorithms"]).output();
    let Ok(listed) = listed else { return false };
    listed.status.success() && String::from_utf8_lossy(&listed.stdout).contains("X25519MLKEM768")
}

#[test]
fn openssl_negotiates_the_hybrid_group_with_a_sibuna_server() {
    if !openssl_has_the_group() {
        eprintln!("skipped: openssl without X25519MLKEM768");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = server(provider());
    let serving = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream = rustls::StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
        let mut byte = [0u8; 1];
        let _ = stream.read(&mut byte);
        stream.conn.negotiated_key_exchange_group().map(|group| group.name())
    });
    let output = Command::new("openssl")
        .args(["s_client", "-connect", &format!("127.0.0.1:{port}"), "-servername", "localhost"])
        .args(["-groups", "X25519MLKEM768", "-CAfile"])
        .arg(data("ca.pem"))
        .args(["-verify_return_error", "-brief"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = output;
    output.stdin.take().unwrap().write_all(b"x").unwrap();
    let output = output.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(serving.join().unwrap(), Some(NamedGroup::X25519MLKEM768), "{said}");
    assert!(said.contains("X25519MLKEM768"), "openssl said: {said}");
}

/// An `openssl s_server` on a free port that offers only X25519MLKEM768.
struct OpensslServer {
    child: Child,
    port: u16,
}

impl OpensslServer {
    fn start() -> OpensslServer {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut child = Command::new("openssl")
            .args(["s_server", "-accept", &format!("127.0.0.1:{port}"), "-naccept", "1"])
            .args(["-groups", "X25519MLKEM768", "-tls1_3", "-www", "-cert"])
            .arg(data("localhost.pem"))
            .arg("-key")
            .arg(data("localhost.key"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match lines.next() {
                Some(Ok(line)) if line.contains("ACCEPT") => break,
                Some(_) => {}
                None => break,
            }
        }
        OpensslServer { child, port }
    }
}

impl Drop for OpensslServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_sibuna_client_negotiates_the_hybrid_group_with_openssl() {
    if !openssl_has_the_group() {
        eprintln!("skipped: openssl without X25519MLKEM768");
        return;
    }
    let server = OpensslServer::start();
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let connection = ClientConnection::new(Arc::new(client(provider(), BOTH)), name).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut page = Vec::new();
    let _ = stream.read_to_end(&mut page);
    let group = stream.conn.negotiated_key_exchange_group().unwrap().name();
    assert_eq!(group, NamedGroup::X25519MLKEM768);
    // `-www` answers with a page that names the group the server used.
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("X25519MLKEM768"), "{page}");
}

/// The time of a whole handshake in memory, both sides on one thread, with and without
/// the hybrid group (SID 0035, Measurement). Run with
/// `cargo test --release -p sibuna-tls --test key_exchange cost -- --ignored`.
#[test]
#[ignore = "a measurement, not a check"]
fn cost_of_a_whole_handshake() {
    const ROUNDS: u32 = 1000;
    for (name, ours) in [("X25519MLKEM768", provider()), ("X25519", ring())] {
        let server = server(ours.clone());
        let client = client(ours, TLS13);
        let started = Instant::now();
        for _ in 0..ROUNDS {
            handshake(client.clone(), server.clone());
        }
        eprintln!("{name}: {:?} per handshake", started.elapsed() / ROUNDS);
    }
}
